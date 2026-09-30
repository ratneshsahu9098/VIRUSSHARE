"""virusShare - end-to-end file transfer tests (send/receive/chunking)."""

import hashlib
import os
import random
import threading
import time
from pathlib import Path

import pytest

from core.security import TrustStore, load_identity
from network.protocol import DeviceInfo, FileInfo, Message, ProtocolError
from network.tcp_client import TransferClient
from network.tcp_server import TransferServer
from transfer import receiver as receiver_mod
from transfer import resume as resume_mod
from transfer.receiver import ConflictAction, ConflictDecision, ReceiveContext, handle_incoming
from transfer.sender import (
    TransferControls,
    build_manifest,
    push_files,
)


def device(name, device_id):
    return DeviceInfo(
        name=name,
        ip="127.0.0.1",
        port=54322,
        device_id=device_id,
        os_version="Windows 11",
        app_version="1.0.0",
        capabilities=["file_transfer"],
    )


CHUNK = 8192


@pytest.fixture
def peer(tmp_path):
    """A connected client/server pair with a receiving directory on disk."""
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    source_dir = tmp_path / "source"
    source_dir.mkdir()

    server_id = load_identity(tmp_path / "server.pem")
    client_id = load_identity(tmp_path / "client.pem")
    server_trust = TrustStore(tmp_path / "server_trust.json")
    client_trust = TrustStore(tmp_path / "client_trust.json")

    reports = []
    decisions = []

    ctx_factory = {"decision": None, "ctx_kwargs": {}}

    def _conflict(req):
        decisions.append(req)
        if ctx_factory["decision"] is not None:
            return ctx_factory["decision"]
        return ConflictDecision(ConflictAction.SKIP)

    def handler(session):
        ctx = ReceiveContext(
            receive_dir=incoming,
            conflict_callback=_conflict,
            verify=True,
            **ctx_factory["ctx_kwargs"],
        )
        reports.append(handle_incoming(session, ctx))

    server = TransferServer(
        device_provider=lambda: device("SERVER-PC", "srv"),
        identity=server_id,
        trust_store=server_trust,
        host="127.0.0.1",
        port=0,
        encryption=True,
        approve_callback=lambda *a: True,
        session_handler=handler,
    )
    port = server.start()
    client = TransferClient(
        device_provider=lambda: device("CLIENT-PC", "cli"),
        identity=client_id,
        trust_store=client_trust,
        encryption=True,
        approve_callback=lambda *a: True,
    )

    env = type("Env", (), {})()
    env.incoming = incoming
    env.source_dir = source_dir
    env.server = server
    env.client = client
    env.port = port
    env.reports = reports
    env.set_decision = lambda action: ctx_factory.__setitem__(
        "decision", ConflictDecision(action)
    )
    env.decisions = decisions
    env.ctx_kwargs = ctx_factory["ctx_kwargs"]
    env.server_id = server_id
    env.client_id = client_id
    yield env

    server.stop()


def push(env, paths, *, chunk_size=CHUNK, controls=None, timeout=60, verify=True):
    entries = build_manifest(paths)
    session = env.client.connect("127.0.0.1", env.port, timeout=5)
    session.sock.settimeout(timeout)
    try:
        report = push_files(
            session, entries, chunk_size=chunk_size, controls=controls,
            verify=verify,
        )
    finally:
        session.close()
    return report


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def wait_for(predicate, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


# --------------------------------------------------------------------------- #
# basic transfers
# --------------------------------------------------------------------------- #

def test_single_small_file(peer):
    src = peer.source_dir / "hello.txt"
    src.write_text("hello virusShare\n", encoding="utf-8")

    report = push(peer, [src])

    assert report.success, report.error
    dest = peer.incoming / "hello.txt"
    assert dest.read_text(encoding="utf-8") == "hello virusShare\n"
    assert not (peer.incoming / "hello.txt.etherpartial").exists()
    assert wait_for(lambda: len(peer.reports) == 1)
    assert peer.reports[0].success
    assert peer.reports[0].files[0].checksum == sha256_of(dest)


def test_empty_file(peer):
    src = peer.source_dir / "empty.bin"
    src.write_bytes(b"")

    report = push(peer, [src])

    assert report.success, report.error
    dest = peer.incoming / "empty.bin"
    assert dest.exists() and dest.stat().st_size == 0
    assert sha256_of(dest) == hashlib.sha256(b"").hexdigest()


def test_binary_file_with_null_bytes(peer):
    rng = random.Random(1234)
    blob = bytes(rng.randrange(256) for _ in range(200_000))
    src = peer.source_dir / "random.bin"
    src.write_bytes(blob)

    report = push(peer, [src])

    assert report.success, report.error
    dest = peer.incoming / "random.bin"
    assert dest.read_bytes() == blob


def test_large_file_streams_in_many_chunks(peer):
    size = 5 * 1024 * 1024 + 12345  # ~5 MB, many 8 KiB chunks, ragged tail
    rng = random.Random(99)
    src = peer.source_dir / "large.bin"
    with open(src, "wb") as f:
        remaining = size
        while remaining:
            block = bytes(rng.randrange(256) for _ in range(min(remaining, 65536)))
            f.write(block)
            remaining -= len(block)

    progress_calls = []
    entries = build_manifest([src])
    session = peer.client.connect("127.0.0.1", peer.port, timeout=5)
    session.sock.settimeout(60)
    try:
        report = push_files(
            session,
            entries,
            chunk_size=CHUNK,
            progress=lambda *a: progress_calls.append(a),
        )
    finally:
        session.close()

    assert report.success, report.error
    dest = peer.incoming / "large.bin"
    assert dest.stat().st_size == size
    assert sha256_of(dest) == sha256_of(src)
    assert report.results[0].sent == size
    # progress reported roughly per chunk
    assert len(progress_calls) >= size // CHUNK
    # monotonically increasing byte counts
    sent_values = [c[2] for c in progress_calls]
    assert sent_values == sorted(sent_values)


def test_multiple_files_one_job(peer):
    files = {}
    for i in range(5):
        content = (f"file number {i}\n" * (i + 1)).encode()
        (peer.source_dir / f"f{i}.txt").write_bytes(content)
        files[f"f{i}.txt"] = content

    report = push(peer, [peer.source_dir / name for name in files])

    assert report.success, report.error
    assert len([r for r in report.results if r.success]) == 5
    for name, content in files.items():
        assert (peer.incoming / name).read_bytes() == content


def test_empty_directory_is_created(peer):
    (peer.source_dir / "emptydir").mkdir()

    report = push(peer, [peer.source_dir / "emptydir"])

    assert report.success, report.error
    assert (peer.incoming / "emptydir").is_dir()


# --------------------------------------------------------------------------- #
# folder transfer
# --------------------------------------------------------------------------- #

def make_project(root: Path) -> dict:
    """Create a nested project tree; returns {relpath: content}."""
    tree = {
        "project/README.md": "# Project\n",
        "project/frontend/package.json": '{"name": "x"}\n',
        "project/frontend/src/app.ts": "export const a = 1;\n",
        "project/backend/app.py": "print('hi')\n",
        "project/backend/data/blob.bin": bytes(range(256)) * 100,
        "project/notes/deep/nested/file.txt": "deep\n",
    }
    for rel, content in tree.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    (root / "project/empty_folder/.keep")  # noqa: B018 - placeholder
    (root / "project/empty_folder").mkdir(exist_ok=True)
    return tree


def test_folder_transfer_preserves_structure(peer):
    tree = make_project(peer.source_dir)

    report = push(peer, [peer.source_dir / "project"])

    assert report.success, report.error
    for rel, content in tree.items():
        dest = peer.incoming / rel
        assert dest.exists(), rel
        if isinstance(content, bytes):
            assert dest.read_bytes() == content
        else:
            assert dest.read_text(encoding="utf-8") == content
    assert (peer.incoming / "project/empty_folder").is_dir()


def test_multiple_roots_including_folder_and_file(peer):
    tree = make_project(peer.source_dir)
    single = peer.source_dir / "standalone.log"
    single.write_text("log\n", encoding="utf-8")

    report = push(peer, [peer.source_dir / "project", single])

    assert report.success, report.error
    assert (peer.incoming / "standalone.log").exists()
    assert (peer.incoming / "project/README.md").read_text(encoding="utf-8") == tree[
        "project/README.md"
    ]


def test_duplicate_root_names_are_deduplicated(peer):
    a = peer.source_dir / "a"
    b = peer.source_dir / "b"
    a.mkdir()
    b.mkdir()
    (a / "same.txt").write_text("from a", encoding="utf-8")
    (b / "same.txt").write_text("from b", encoding="utf-8")

    report = push(peer, [a, b])

    assert report.success, report.error
    names = sorted(p.name for p in peer.incoming.iterdir())
    assert names == ["a", "b"]


def test_case_differing_manifest_entries_are_deduplicated(peer):
    """H8: on Windows a.txt and A.txt are the same file - the case-sensitive
    seen-set lets both through, so the second commit destroys the first and
    both report success.

    Sources live in separate directories so they are distinct physical files;
    build_manifest gives single-file roots their bare names, so the manifest
    relpaths collide on purpose.
    """
    dir_one = peer.source_dir / "one"
    dir_one.mkdir()
    dir_two = peer.source_dir / "two"
    dir_two.mkdir()
    src_a = dir_one / "a.txt"
    src_a.write_text("first", encoding="utf-8")
    src_A = dir_two / "A.txt"
    src_A.write_text("second", encoding="utf-8")

    report = push(peer, [src_a, src_A])

    assert wait_for(lambda: peer.reports)
    receiver_report = peer.reports[0]
    names = [f.relpath for f in receiver_report.files]
    assert len(names) == 1, f"case-colliding entries accepted: {names}"
    assert len(receiver_report.rejected_paths) == 1
    dest = peer.incoming / "a.txt"
    assert dest.read_text(encoding="utf-8") == "first"


# --------------------------------------------------------------------------- #
# verification
# --------------------------------------------------------------------------- #

def test_checksum_mismatch_is_reported_and_file_not_committed(
    peer, monkeypatch
):
    src = peer.source_dir / "corrupt-me.bin"
    src.write_bytes(b"x" * 50_000)

    class LyingHasher(receiver_mod.StreamingHasher):
        def hexdigest(self):
            return "0" * 64

    monkeypatch.setattr(receiver_mod, "StreamingHasher", LyingHasher)

    report = push(peer, [src])

    assert not report.success
    result = report.results[0]
    assert not result.success
    assert "Checksum mismatch" in result.error
    assert not (peer.incoming / "corrupt-me.bin").exists()
    assert not (peer.incoming / "corrupt-me.bin.etherpartial").exists()


def test_sender_checksum_matches_receiver_record(peer):
    src = peer.source_dir / "verified.txt"
    src.write_bytes(os.urandom(100_000))

    report = push(peer, [src])

    assert report.success, report.error
    assert wait_for(lambda: peer.reports)
    assert report.results[0].checksum == sha256_of(peer.incoming / "verified.txt")


def test_receiver_accepts_when_sender_disables_checksums(peer):
    """H1: an empty declared checksum means the sender opted out, not corruption.

    Receiver has verification ON, sender OFF: today every file mismatches an
    empty declared value, is discarded, and the manager retries 3x.
    """
    src = peer.source_dir / "nocheck.bin"
    src.write_bytes(os.urandom(60_000))

    report = push(peer, [src], verify=False)

    assert report.success, report.error
    result = report.results[0]
    assert result.success, result.error
    dest = peer.incoming / "nocheck.bin"
    assert dest.exists()
    assert dest.read_bytes() == src.read_bytes()
    assert wait_for(lambda: peer.reports)
    assert peer.reports[0].files[0].success


def test_file_created_during_transfer_is_not_overwritten(peer):
    """H9: the conflict decision taken at manifest time must be re-checked
    right before commit — a file that appears mid-transfer is silently
    destroyed by os.replace today."""
    src = peer.source_dir / "late.txt"
    src.write_bytes(b"S" * 40_000)
    dest = peer.incoming / "late.txt"
    planted = {"done": False}

    def plant_on_first_chunk(file_id, relpath, received, total):
        if not planted["done"]:
            planted["done"] = True
            dest.write_bytes(b"NEWCOMER-DURING-TRANSFER")

    peer.ctx_kwargs["progress"] = plant_on_first_chunk

    report = push(peer, [src])

    assert wait_for(lambda: peer.reports)
    assert len(peer.decisions) == 1, "mid-transfer change was not escalated"
    assert dest.read_bytes() == b"NEWCOMER-DURING-TRANSFER", (
        "file created during the transfer was overwritten"
    )
    result = report.results[0]
    assert not result.success
    assert "destination" in (result.error or "").lower()


# --------------------------------------------------------------------------- #
# conflict handling
# --------------------------------------------------------------------------- #

def test_conflict_replace_overwrites_existing(peer):
    dest = peer.incoming / "data.txt"
    dest.write_text("OLD CONTENT", encoding="utf-8")
    src = peer.source_dir / "data.txt"
    src.write_text("NEW CONTENT", encoding="utf-8")

    peer.set_decision(ConflictAction.REPLACE)
    report = push(peer, [src])

    assert report.success, report.error
    assert dest.read_text(encoding="utf-8") == "NEW CONTENT"


def test_conflict_skip_leaves_existing_and_reports_skipped(peer):
    dest = peer.incoming / "data.txt"
    dest.write_text("OLD CONTENT", encoding="utf-8")
    src = peer.source_dir / "data.txt"
    src.write_text("NEW CONTENT", encoding="utf-8")

    peer.set_decision(ConflictAction.SKIP)
    report = push(peer, [src])

    assert dest.read_text(encoding="utf-8") == "OLD CONTENT"
    assert report.results[0].skipped
    assert not report.results[0].success


def test_conflict_keep_both_creates_sibling(peer):
    dest = peer.incoming / "data.txt"
    dest.write_text("OLD CONTENT", encoding="utf-8")
    src = peer.source_dir / "data.txt"
    src.write_text("NEW CONTENT", encoding="utf-8")

    peer.set_decision(ConflictAction.KEEP_BOTH)
    report = push(peer, [src])

    assert report.success, report.error
    assert dest.read_text(encoding="utf-8") == "OLD CONTENT"
    sibling = peer.incoming / "data (1).txt"
    assert sibling.read_text(encoding="utf-8") == "NEW CONTENT"


def test_conflict_cancel_aborts_job(peer):
    (peer.incoming / "one.txt").write_text("old", encoding="utf-8")
    src1 = peer.source_dir / "one.txt"
    src1.write_text("new1", encoding="utf-8")
    src2 = peer.source_dir / "two.txt"
    src2.write_text("new2", encoding="utf-8")

    peer.set_decision(ConflictAction.CANCEL)
    report = push(peer, [src1, src2])

    assert not report.success
    assert report.cancelled or report.error
    assert (peer.incoming / "one.txt").read_text(encoding="utf-8") == "old"
    assert not (peer.incoming / "two.txt").exists()


def test_default_is_never_overwrite_without_callback(peer):
    dest = peer.incoming / "data.txt"
    dest.write_text("KEEP ME", encoding="utf-8")
    src = peer.source_dir / "data.txt"
    src.write_text("REPLACE ME", encoding="utf-8")

    # env's default callback returns SKIP; also test no-callback path below
    peer.set_decision(ConflictAction.SKIP)
    report = push(peer, [src])
    assert dest.read_text(encoding="utf-8") == "KEEP ME"
    assert report.results[0].skipped


def test_no_conflict_callback_skips(tmp_path):
    """Without any callback an existing file must never be overwritten."""
    incoming = tmp_path / "in"
    incoming.mkdir()
    (incoming / "x.txt").write_text("OLD", encoding="utf-8")
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "x.txt").write_text("NEW", encoding="utf-8")

    server_id = load_identity(tmp_path / "s.pem")
    client_id = load_identity(tmp_path / "c.pem")
    reports = []

    def handler(session):
        reports.append(
            handle_incoming(session, ReceiveContext(receive_dir=incoming, verify=True))
        )

    server = TransferServer(
        device_provider=lambda: device("S", "s"),
        identity=server_id,
        trust_store=TrustStore(tmp_path / "st.json"),
        host="127.0.0.1",
        port=0,
        encryption=False,
        approve_callback=lambda *a: True,
        session_handler=handler,
    )
    port = server.start()
    client = TransferClient(
        device_provider=lambda: device("C", "c"),
        identity=client_id,
        trust_store=TrustStore(tmp_path / "ct.json"),
        encryption=False,
        approve_callback=lambda *a: True,
    )
    try:
        session = client.connect("127.0.0.1", port, timeout=5)
        report = push_files(session, build_manifest([src_dir / "x.txt"]), chunk_size=CHUNK)
        session.close()
        assert report.results[0].skipped
        assert (incoming / "x.txt").read_text(encoding="utf-8") == "OLD"
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# manifest / request validation
# --------------------------------------------------------------------------- #

def test_manifest_is_never_absolute_paths(peer):
    src = peer.source_dir / "relative-only.txt"
    src.write_text("hi", encoding="utf-8")

    entries = build_manifest([src])
    assert all(not e.relpath.startswith("/") for e in entries)
    assert all(":" not in e.relpath for e in entries)
    assert all(not e.relpath.startswith("\\\\") for e in entries)


def test_unknown_file_id_is_rejected_by_receiver(peer):
    """A FILE_REQUEST for something outside the accepted manifest errors out."""
    src = peer.source_dir / "known.txt"
    src.write_text("known", encoding="utf-8")

    report = push(peer, [src])
    assert report.success, report.error

    # second job: sender requests an id that was never in the manifest
    entries = build_manifest([src])
    session = peer.client.connect("127.0.0.1", peer.port, timeout=5)
    session.sock.settimeout(10)
    try:
        session.send(Message.create_file_list([]))
        session.expect("FILE_LIST")
        session.send(Message.create_file_request("../../../etc/passwd", 0))
        reply = session.expect("ERROR")
        code, text = reply.parse_error()
        assert code == 0x02
        assert "Unknown file" in text
        session.send(Message.create_disconnect())
    finally:
        session.close()


def test_sender_handles_peer_refusal(tmp_path):
    """When the receiver cancels at the manifest stage, the push fails cleanly."""
    src = tmp_path / "f.txt"
    src.write_text("data", encoding="utf-8")

    server_id = load_identity(tmp_path / "s.pem")
    client_id = load_identity(tmp_path / "c.pem")

    def handler(session):
        session.expect("FILE_LIST")
        session.send(Message.create_error(0x08, "Transfer cancelled by user"))

    server = TransferServer(
        device_provider=lambda: device("S", "s"),
        identity=server_id,
        trust_store=TrustStore(tmp_path / "st.json"),
        host="127.0.0.1",
        port=0,
        encryption=False,
        approve_callback=lambda *a: True,
        session_handler=handler,
    )
    port = server.start()
    client = TransferClient(
        device_provider=lambda: device("C", "c"),
        identity=client_id,
        trust_store=TrustStore(tmp_path / "ct.json"),
        encryption=False,
        approve_callback=lambda *a: True,
    )
    try:
        session = client.connect("127.0.0.1", port, timeout=5)
        report = push_files(session, build_manifest([src]), chunk_size=CHUNK)
        session.close()
        assert not report.success
        assert report.cancelled
        assert "cancelled" in report.error.lower()
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# M15: the declared manifest size is a hard cap on the wire
# --------------------------------------------------------------------------- #

def test_file_growing_during_send_does_not_abort_batch(peer):
    """M15: the sender reads to EOF with no cap at the declared size.

    A file that grows after build_manifest makes the sender push more bytes
    than it declared; the receiver's oversize guard raises ProtocolError and
    the whole batch dies (retried 3x by the manager).  The manifest size is
    the contract - send exactly that many bytes.
    """
    src = peer.source_dir / "growing.bin"
    src.write_bytes(b"A" * 50_000)
    second = peer.source_dir / "stable.txt"
    second.write_text("stable\n", encoding="utf-8")

    entries = build_manifest([src, second])
    with open(src, "ab") as fh:
        fh.write(b"B" * 20_000)  # grows after the manifest was taken

    session = peer.client.connect("127.0.0.1", peer.port, timeout=5)
    session.sock.settimeout(30)
    try:
        report = push_files(session, entries, chunk_size=CHUNK)
    finally:
        session.close()

    assert report.success, report.error
    assert report.results[0].success, report.results[0].error
    assert report.results[0].sent == 50_000
    dest = peer.incoming / "growing.bin"
    assert dest.exists()
    assert dest.read_bytes() == b"A" * 50_000
    assert (peer.incoming / "stable.txt").read_text(encoding="utf-8") == "stable\n"
    assert wait_for(lambda: peer.reports)
    assert peer.reports[0].success


# --------------------------------------------------------------------------- #
# M16: a peer cancel / disconnect is never reported as success
# --------------------------------------------------------------------------- #

def test_pre_cancelled_push_reports_receiver_as_cancelled(peer):
    """M16: sender cancels before requesting any file -> the receiver must
    not report the empty session as COMPLETED."""
    src = peer.source_dir / "early.txt"
    src.write_text("payload", encoding="utf-8")
    controls = TransferControls()
    controls.cancel()

    report = push(peer, [src], controls=controls)

    assert report.cancelled
    assert not report.success
    assert wait_for(lambda: peer.reports)
    recv = peer.reports[0]
    assert not recv.success, "peer cancel was reported as success"
    assert recv.cancelled
    assert not (peer.incoming / "early.txt").exists()


def test_immediate_disconnect_is_not_reported_as_completed(peer):
    """M16: a peer that disconnects without ever sending a manifest leaves
    an empty session - that is not a completed transfer."""
    session = peer.client.connect("127.0.0.1", peer.port, timeout=5)
    session.sock.settimeout(10)
    try:
        session.send(Message.create_disconnect())
    finally:
        session.close()

    assert wait_for(lambda: peer.reports)
    recv = peer.reports[0]
    assert not recv.success, "an empty session was reported as success"
    assert recv.cancelled


def test_sender_mid_file_cancel_reports_receiver_as_cancelled(peer):
    """M16: sender cancels mid-file (FILE_CANCEL) -> receiver keeps the
    partial but must not report the session as COMPLETED."""
    src = peer.source_dir / "big.bin"
    src.write_bytes(os.urandom(300_000))
    controls = TransferControls()
    cancel_at = {"done": False}

    def progress(file_id, relpath, sent, size, total):
        if not cancel_at["done"] and sent >= CHUNK * 3:
            cancel_at["done"] = True
            controls.cancel()

    entries = build_manifest([src])
    session = peer.client.connect("127.0.0.1", peer.port, timeout=5)
    session.sock.settimeout(30)
    try:
        report = push_files(
            session, entries, chunk_size=CHUNK, controls=controls,
            progress=progress,
        )
    finally:
        session.close()

    assert report.cancelled
    assert wait_for(lambda: peer.reports)
    recv = peer.reports[0]
    assert not recv.success, "mid-file peer cancel was reported as success"
    assert recv.cancelled
    assert not (peer.incoming / "big.bin").exists()


# --------------------------------------------------------------------------- #
# M17: a push where the receiver skipped everything transferred nothing
# --------------------------------------------------------------------------- #

def test_all_skipped_push_is_not_success(peer):
    """M17: every file skipped -> all([]) is True, so the push reports
    COMPLETED with 0 bytes.  Nothing was transferred: that is not success."""
    dest = peer.incoming / "data.txt"
    dest.write_text("OLD CONTENT", encoding="utf-8")
    src = peer.source_dir / "data.txt"
    src.write_text("NEW CONTENT", encoding="utf-8")

    peer.set_decision(ConflictAction.SKIP)
    report = push(peer, [src])

    assert report.results[0].skipped
    assert not report.success, "all-skipped push reported success"
    assert "skip" in report.error.lower()
    assert dest.read_text(encoding="utf-8") == "OLD CONTENT"


# --------------------------------------------------------------------------- #
# M22: socket failures are connection errors, never "disk error"
# --------------------------------------------------------------------------- #

class ScriptedSession:
    """Minimal ConnectionSession stand-in for driving handle_incoming."""

    def __init__(self, messages, fail_on_call=None, error="timed out"):
        self._messages = list(messages)
        self._fail_on_call = fail_on_call
        self._error = error
        self._calls = 0
        self.sent = []

    def send(self, message):
        self.sent.append(message)

    def expect(self, *types, timeout=None):
        self._calls += 1
        if self._fail_on_call is not None and self._calls == self._fail_on_call:
            raise OSError(self._error)
        if not self._messages:
            raise AssertionError(f"unexpected expect #{self._calls} for {types}")
        message = self._messages.pop(0)
        assert message.type_name in types, (
            f"script gave {message.type_name}, expected {types}"
        )
        return message


def _scripted_messages():
    manifest = Message.create_file_list(
        [
            FileInfo(
                name="f.bin",
                size=1000,
                path="f.bin",
                is_directory=False,
                modified_time=0.0,
            )
        ]
    )
    request = Message.create_file_request(
        "f.bin",
        offset=0,
        metadata={
            "name": "f.bin",
            "size": 1000,
            "path": "f.bin",
            "mtime": 0.0,
            "chunk_size": CHUNK,
        },
    )
    return [manifest, request]


def test_socket_error_in_chunk_loop_reported_as_connection_error(tmp_path):
    """M22: a socket failure while waiting for the next chunk is a
    connection problem; it must never surface as 'disk error: timed out'."""
    incoming = tmp_path / "in"
    ctx = ReceiveContext(receive_dir=incoming, verify=True)
    session = ScriptedSession(_scripted_messages(), fail_on_call=3,
                              error="timed out")

    report = handle_incoming(session, ctx)

    assert not report.success
    assert "connection error" in report.error, report.error
    assert "disk error" not in report.error, report.error
    assert "connection error" in report.files[0].error, report.files[0].error


def test_disk_error_still_reported_as_disk_error(tmp_path, monkeypatch):
    """M22 companion: local write failures keep the 'disk error' label."""
    incoming = tmp_path / "in"
    ctx = ReceiveContext(receive_dir=incoming, verify=True)
    session = ScriptedSession(_scripted_messages())

    def no_disk(*args, **kwargs):
        raise OSError("disk full")

    # shadow the builtin inside the receiver module only (module globals win
    # over builtins at call time; getattr on the module itself does not)
    monkeypatch.setattr(receiver_mod, "open", no_disk, raising=False)

    report = handle_incoming(session, ctx)

    assert not report.success
    assert "disk error" in report.error, report.error
    assert "disk full" in report.error
