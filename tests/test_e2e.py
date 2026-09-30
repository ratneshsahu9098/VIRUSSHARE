"""End-to-end integration tests over real loopback sockets.

No transport monkeypatching: a real ``TransferManager`` pushes through a real
``TransferClient`` (TLS + handshake + pairing) to a real ``TransferServer``
whose session handler mirrors ``app.py``.  Files are written to a temp
receive root and verified byte-for-byte.
"""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.security import TrustStore, load_identity
from models import TransferStatus
from network.protocol import DeviceInfo
from network.tcp_server import TransferServer
from transfer.manager import TransferManager
from transfer.receiver import (
    ConflictAction,
    ConflictDecision,
    handle_incoming,
)
from transfer.resume import prepare_partial, update_received
from utils.network import find_free_port

TERMINAL = (
    TransferStatus.COMPLETED,
    TransferStatus.FAILED,
    TransferStatus.CANCELLED,
)

RECEIVER_ID = "e2e-receiver"
SENDER_ID = "e2e-sender"


def _device(name: str, device_id: str, port: int = 0) -> DeviceInfo:
    return DeviceInfo(
        name=name,
        ip="127.0.0.1",
        port=port,
        device_id=device_id,
        os_version="test",
        app_version="1.0.0",
        capabilities=["file_transfer"],
    )


def write_file(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


@pytest.fixture
def pair(tmp_path):
    send_dir = tmp_path / "send"
    recv_dir = tmp_path / "recv"
    send_dir.mkdir()
    recv_dir.mkdir()

    s_identity = load_identity(tmp_path / "sender.pem")
    s_trust = TrustStore(tmp_path / "sender_trust.json")
    r_identity = load_identity(tmp_path / "receiver.pem")
    r_trust = TrustStore(tmp_path / "receiver_trust.json")

    harness = SimpleNamespace(conflict=None, approve=True)
    approvals = {"client": [], "server": []}

    def client_approve(peer, peer_fp, our_fp, code):
        approvals["client"].append(code.canonical)
        return True

    def server_approve(peer, peer_fp, our_fp, code):
        approvals["server"].append(code.canonical)
        return bool(harness.approve)

    recv_manager = TransferManager(
        identity=r_identity,
        trust_store=r_trust,
        device_provider=lambda: _device("RECEIVER", RECEIVER_ID),
        approve_callback=server_approve,
        settings={"save_received_files_to": str(recv_dir)},
    )

    def session_handler(conn_session):
        model = recv_manager.begin_receive(conn_session.peer_device)
        ctx = recv_manager.receive_context(
            model, conflict_callback=harness.conflict
        )
        report = handle_incoming(conn_session, ctx)
        recv_manager.finish_receive(model, report)

    def make_server(port: int = 0) -> TransferServer:
        return TransferServer(
            device_provider=lambda: _device("RECEIVER", RECEIVER_ID, port),
            identity=r_identity,
            trust_store=r_trust,
            host="127.0.0.1",
            port=port,
            encryption=True,
            require_approval=True,
            approve_callback=server_approve,
            session_handler=session_handler,
        )

    server = make_server()
    server.start()

    send_manager = TransferManager(
        identity=s_identity,
        trust_store=s_trust,
        device_provider=lambda: _device("SENDER", SENDER_ID),
        approve_callback=client_approve,
        settings={},
    )

    ns = SimpleNamespace(
        send_dir=send_dir,
        recv_dir=recv_dir,
        send=send_manager,
        recv=recv_manager,
        server=server,
        make_server=make_server,
        target=_device("RECEIVER", RECEIVER_ID, server.bound_port),
        approvals=approvals,
        harness=harness,
        s_trust=s_trust,
        r_trust=r_trust,
    )
    yield ns

    send_manager.shutdown(timeout=5)
    server.stop()
    recv_manager.shutdown(timeout=5)


def send_and_wait(pair, paths, timeout: float = 30.0):
    session = pair.send.send_files(pair.target, [Path(p) for p in paths])
    assert pair.send.wait_all(timeout=timeout), "sender worker did not finish"
    return session


def wait_receiver(pair, timeout: float = 10.0):
    """Wait until every receiver-side session reaches a terminal state."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sessions = pair.recv.sessions
        if sessions and all(s.status in TERMINAL for s in sessions):
            return sessions
        time.sleep(0.05)
    return pair.recv.sessions


# --------------------------------------------------------------------------- #
# happy path
# --------------------------------------------------------------------------- #

def test_e2e_single_file_roundtrip(pair):
    data = os.urandom(2 * 1024 * 1024 + 12345)
    src = write_file(pair.send_dir / "photo.bin", data)

    session = send_and_wait(pair, [src])
    assert session.status is TransferStatus.COMPLETED, session.error_message

    recv_sessions = wait_receiver(pair)
    assert recv_sessions, "receiver never registered a session"
    assert recv_sessions[0].status is TransferStatus.COMPLETED, (
        recv_sessions[0].error_message
    )

    dest = pair.recv_dir / "photo.bin"
    assert dest.exists()
    assert sha256_file(dest) == sha256_bytes(data)

    # exactly one pairing prompt per side, and both computed the same code
    assert len(pair.approvals["client"]) == 1
    assert len(pair.approvals["server"]) == 1
    assert pair.approvals["client"][0] == pair.approvals["server"][0]

    # both trust stores now know the peer
    assert pair.s_trust.is_trusted(RECEIVER_ID)
    assert pair.r_trust.is_trusted(SENDER_ID)


def test_e2e_directory_tree_with_unicode(pair):
    payloads = {
        "tree/a.txt": b"hello " * 500,
        "tree/sub/blob.bin": os.urandom(700_000),
        "tree/sub/don\u2019t (test) \u2014 caf\u00e9.txt": "unicode ok ✓".encode(),
    }
    for rel, payload in payloads.items():
        write_file(pair.send_dir / rel, payload)

    session = send_and_wait(pair, [pair.send_dir / "tree"])
    assert session.status is TransferStatus.COMPLETED, session.error_message

    recv_sessions = wait_receiver(pair)
    assert recv_sessions[0].status is TransferStatus.COMPLETED, (
        recv_sessions[0].error_message
    )
    for rel, payload in payloads.items():
        matches = list(pair.recv_dir.rglob(Path(rel).name))
        assert matches, f"{rel} did not arrive"
        assert matches[0].read_bytes() == payload


def test_e2e_second_transfer_is_already_trusted(pair):
    first = write_file(pair.send_dir / "one.bin", os.urandom(64_000))
    s1 = send_and_wait(pair, [first])
    assert s1.status is TransferStatus.COMPLETED, s1.error_message
    wait_receiver(pair)
    assert len(pair.approvals["client"]) == 1
    assert len(pair.approvals["server"]) == 1

    second = write_file(pair.send_dir / "two.bin", os.urandom(64_000))
    s2 = send_and_wait(pair, [second])
    assert s2.status is TransferStatus.COMPLETED, s2.error_message
    wait_receiver(pair)

    # trusted peer: no new pairing prompts, transfer still lands
    assert len(pair.approvals["client"]) == 1
    assert len(pair.approvals["server"]) == 1
    assert (pair.recv_dir / "one.bin").exists()
    assert (pair.recv_dir / "two.bin").exists()


# --------------------------------------------------------------------------- #
# security / conflicts
# --------------------------------------------------------------------------- #

def test_e2e_receiver_declines_connection(pair):
    pair.harness.approve = False
    data = os.urandom(50_000)
    src = write_file(pair.send_dir / "nope.bin", data)

    session = send_and_wait(pair, [src])
    assert session.status is TransferStatus.FAILED
    assert "reject" in (session.error_message or "").lower()

    # server rejected before the client ever prompted, and nothing was written
    assert len(pair.approvals["client"]) == 0
    assert list(pair.recv_dir.iterdir()) == []


def test_e2e_conflict_keep_both_leaves_original(pair):
    data = os.urandom(300_000)
    src = write_file(pair.send_dir / "report.bin", data)
    existing = write_file(pair.recv_dir / "report.bin", b"OLD VERSION")
    pair.harness.conflict = lambda req: ConflictDecision(
        ConflictAction.KEEP_BOTH
    )

    session = send_and_wait(pair, [src])
    assert session.status is TransferStatus.COMPLETED, session.error_message
    recv_sessions = wait_receiver(pair)
    assert recv_sessions[0].status is TransferStatus.COMPLETED, (
        recv_sessions[0].error_message
    )

    assert existing.read_bytes() == b"OLD VERSION"
    copies = list(pair.recv_dir.glob("report (*).bin"))
    assert len(copies) == 1
    assert copies[0].read_bytes() == data


# --------------------------------------------------------------------------- #
# reliability
# --------------------------------------------------------------------------- #

def test_e2e_connects_when_receiver_starts_late(pair):
    port = find_free_port()
    target = _device("RECEIVER", RECEIVER_ID, port)
    src = write_file(pair.send_dir / "late.bin", os.urandom(150_000))

    session = pair.send.send_files(target, [src])
    time.sleep(0.2)  # first connect attempt fails fast (nothing listening)

    late = pair.make_server(port)
    try:
        late.start()
        assert pair.send.wait_all(timeout=30.0), "sender never finished"
        assert session.status is TransferStatus.COMPLETED, session.error_message
        wait_receiver(pair)
        assert (pair.recv_dir / "late.bin").exists()
    finally:
        late.stop()


def test_e2e_resume_from_prepared_partial(pair):
    data = os.urandom(3 * 1024 * 1024 + 7)
    src = write_file(pair.send_dir / "big.bin", data)
    offset = 2 * 1024 * 1024  # 2 MiB = chunk-aligned for the 1 MiB default

    dest = pair.recv_dir / "big.bin"
    partial, resume_offset = prepare_partial(
        dest,
        file_id="big.bin",
        size=len(data),
        mtime=src.stat().st_mtime,
        chunk_size=1024 * 1024,
    )
    assert resume_offset == 0
    partial.write_bytes(data[:offset])
    update_received(dest, offset)

    session = send_and_wait(pair, [src])
    assert session.status is TransferStatus.COMPLETED, session.error_message
    recv_sessions = wait_receiver(pair)
    assert recv_sessions[0].status is TransferStatus.COMPLETED, (
        recv_sessions[0].error_message
    )

    # full file committed, only the remainder crossed the wire
    assert dest.read_bytes() == data
    assert session.transferred_size == len(data) - offset
    assert not partial.exists()
