"""virusShare - pause, cancel and resume tests."""

import os
import threading
import time
from pathlib import Path

import pytest

from core.security import TrustStore, load_identity
from network.protocol import DeviceInfo, Message, ProtocolError
from network.tcp_client import TransferClient
from network.tcp_server import TransferServer
from transfer import resume as resume_mod
from transfer import sender as sender_mod
from transfer.receiver import ConflictAction, ConflictDecision, ReceiveContext, handle_incoming
from transfer.resume import (
    meta_path,
    partial_path,
    prepare_partial,
    read_meta,
)
from transfer.sender import SendEntry, TransferControls, build_manifest, push_files

CHUNK = 8192


def device(name, device_id):
    return DeviceInfo(
        name=name, ip="127.0.0.1", port=54322, device_id=device_id,
        os_version="Windows 11", app_version="1.0.0", capabilities=[],
    )


@pytest.fixture
def env(tmp_path):
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    source_dir = tmp_path / "source"
    source_dir.mkdir()

    reports = []
    spy = {"offsets": []}
    real_prepare = resume_mod.prepare_partial

    def spying_prepare(dest, **kwargs):
        path, offset = real_prepare(dest, **kwargs)
        spy["offsets"].append(offset)
        return path, offset

    def handler(session):
        original = resume_mod.prepare_partial
        resume_mod.prepare_partial = spying_prepare
        try:
            ctx = ReceiveContext(
                receive_dir=incoming,
                conflict_callback=lambda req: ConflictDecision(ConflictAction.SKIP),
                verify=True,
            )
            reports.append(handle_incoming(session, ctx))
        finally:
            resume_mod.prepare_partial = original

    server = TransferServer(
        device_provider=lambda: device("S", "srv"),
        identity=load_identity(tmp_path / "server.pem"),
        trust_store=TrustStore(tmp_path / "server_trust.json"),
        host="127.0.0.1",
        port=0,
        encryption=True,
        approve_callback=lambda *a: True,
        session_handler=handler,
    )
    port = server.start()
    client = TransferClient(
        device_provider=lambda: device("C", "cli"),
        identity=load_identity(tmp_path / "client.pem"),
        trust_store=TrustStore(tmp_path / "client_trust.json"),
        encryption=True,
        approve_callback=lambda *a: True,
    )

    e = type("Env", (), {})()
    e.incoming = incoming
    e.source_dir = source_dir
    e.server = server
    e.client = client
    e.port = port
    e.reports = reports
    e.spy = spy
    yield e
    server.stop()


def new_session(env):
    session = env.client.connect("127.0.0.1", env.port, timeout=5)
    session.sock.settimeout(60)
    return session


def make_file(path: Path, size: int, seed: int = 7) -> bytes:
    import random

    rng = random.Random(seed)
    blob = bytes(rng.randrange(256) for _ in range(size))
    path.write_bytes(blob)
    return blob


def wait_for(predicate, timeout: float = 10.0) -> bool:
    """Poll ``predicate`` until true or timeout (receiver state lags the sender)."""
    deadline = time.time() + timeout
    while not predicate():
        if time.time() >= deadline:
            return False
        time.sleep(0.02)
    return True


# --------------------------------------------------------------------------- #
# prepare_partial unit behaviour
# --------------------------------------------------------------------------- #

def test_prepare_partial_starts_at_zero_for_new_file(tmp_path):
    dest = tmp_path / "out.bin"
    partial, offset = prepare_partial(
        dest, file_id="f", size=1000, mtime=1.0, chunk_size=CHUNK
    )
    assert offset == 0
    assert partial == partial_path(dest)
    assert partial.exists()
    assert read_meta(dest)["size"] == 1000


def test_prepare_partial_resumes_aligned_partial(tmp_path):
    dest = tmp_path / "out.bin"
    partial = partial_path(dest)
    partial.write_bytes(b"a" * (CHUNK * 3 + 100))
    resume_mod.write_meta(
        dest, {"file_id": "f", "size": 100_000, "mtime": 1.0, "chunk_size": CHUNK}
    )

    _, offset = prepare_partial(
        dest, file_id="f", size=100_000, mtime=1.0, chunk_size=CHUNK
    )
    # 3 full chunks + a partial chunk: resume at the last complete boundary
    assert offset == CHUNK * 3
    assert partial.stat().st_size == CHUNK * 3


def test_prepare_partial_discards_when_sidecar_missing(tmp_path):
    dest = tmp_path / "out.bin"
    partial = partial_path(dest)
    partial.write_bytes(b"a" * 5000)

    _, offset = prepare_partial(
        dest, file_id="f", size=100_000, mtime=1.0, chunk_size=CHUNK
    )
    assert offset == 0


def test_prepare_partial_discards_on_size_mismatch(tmp_path):
    dest = tmp_path / "out.bin"
    partial = partial_path(dest)
    partial.write_bytes(b"a" * 4000)
    resume_mod.write_meta(
        dest, {"file_id": "f", "size": 999, "mtime": 1.0, "chunk_size": CHUNK}
    )

    _, offset = prepare_partial(
        dest, file_id="f", size=100_000, mtime=1.0, chunk_size=CHUNK
    )
    assert offset == 0
    assert partial_path(dest).stat().st_size == 0


def test_prepare_partial_discards_on_mtime_change(tmp_path):
    """A source file changed since the partial was written must restart."""
    dest = tmp_path / "out.bin"
    partial = partial_path(dest)
    partial.write_bytes(b"a" * 4000)
    resume_mod.write_meta(
        dest, {"file_id": "f", "size": 100_000, "mtime": 1.0, "chunk_size": CHUNK}
    )

    _, offset = prepare_partial(
        dest, file_id="f", size=100_000, mtime=2.0, chunk_size=CHUNK
    )
    assert offset == 0


def test_prepare_partial_discards_oversized_partial(tmp_path):
    dest = tmp_path / "out.bin"
    partial = partial_path(dest)
    partial.write_bytes(b"a" * 20_000)
    resume_mod.write_meta(
        dest, {"file_id": "f", "size": 10_000, "mtime": 1.0, "chunk_size": CHUNK}
    )

    _, offset = prepare_partial(
        dest, file_id="f", size=10_000, mtime=1.0, chunk_size=CHUNK
    )
    assert offset == 0
    assert partial_path(dest).stat().st_size == 0


def test_prepare_partial_realigns_to_new_chunk_size(tmp_path):
    """A partial written with a different chunk size is truncated to a boundary."""
    dest = tmp_path / "out.bin"
    partial = partial_path(dest)
    partial.write_bytes(b"a" * (CHUNK * 2 + 512))
    resume_mod.write_meta(
        dest, {"file_id": "f", "size": 100_000, "mtime": 1.0, "chunk_size": CHUNK}
    )

    new_chunk = CHUNK * 4
    _, offset = prepare_partial(
        dest, file_id="f", size=100_000, mtime=1.0, chunk_size=new_chunk
    )
    assert offset % new_chunk == 0
    assert offset <= CHUNK * 2 + 512
    assert partial_path(dest).stat().st_size == offset


def test_commit_removes_partial_and_sidecar(tmp_path):
    dest = tmp_path / "final.bin"
    partial = partial_path(dest)
    partial.write_bytes(b"data")
    resume_mod.write_meta(dest, {"file_id": "f", "size": 4, "mtime": 1.0})

    resume_mod.commit(partial, dest)

    assert dest.read_bytes() == b"data"
    assert not partial.exists()
    assert not meta_path(dest).exists()


# --------------------------------------------------------------------------- #
# invalid offsets (sender side)
# --------------------------------------------------------------------------- #

def test_sender_rejects_invalid_resume_offset(tmp_path):
    entry = SendEntry(
        source=tmp_path / "x.bin", relpath="x.bin", size=1000, mtime=0.0
    )
    entry.source.write_bytes(b"a" * 1000)

    for bad in (-1, 1001, CHUNK // 2):  # negative, beyond EOF, misaligned
        msg = Message.create_file_resume("x.bin", bad)
        with pytest.raises(ProtocolError):
            sender_mod._parse_resume(msg, entry, CHUNK)


# --------------------------------------------------------------------------- #
# integration: cancel + resume
# --------------------------------------------------------------------------- #

def test_cancel_mid_file_keeps_partial_and_resume_continues(env):
    src = env.source_dir / "movie.bin"
    blob = make_file(src, size=400_000)

    controls = TransferControls()
    paused_at = {"n": None}

    def progress(file_id, relpath, sent, size, total):
        if paused_at["n"] is None and sent >= 100_000:
            paused_at["n"] = sent
            controls.cancel()

    session = new_session(env)
    try:
        report = push_files(
            session, build_manifest([src]), chunk_size=CHUNK,
            controls=controls, progress=progress,
        )
    finally:
        session.close()

    assert report.cancelled
    dest = env.incoming / "movie.bin"
    partial = partial_path(dest)
    assert not dest.exists()          # never committed
    assert partial.exists()           # partial kept for resume
    assert 0 < partial.stat().st_size < len(blob)

    # second attempt resumes from the partial
    env.spy["offsets"].clear()
    session = new_session(env)
    try:
        report2 = push_files(session, build_manifest([src]), chunk_size=CHUNK)
    finally:
        session.close()

    assert report2.success, report2.error
    assert env.spy["offsets"] and env.spy["offsets"][0] > 0
    assert dest.read_bytes() == blob
    assert not partial.exists()


def test_pause_stalls_then_resume_completes(env):
    src = env.source_dir / "slow.bin"
    blob = make_file(src, size=300_000)

    controls = TransferControls()
    state = {"paused": False, "progress_times": []}

    def progress(file_id, relpath, sent, size, total):
        state["progress_times"].append((sent, time.monotonic()))
        if not state["paused"] and sent >= 60_000:
            state["paused"] = True
            controls.pause()

    result = {}

    def run():
        session = new_session(env)
        try:
            result["report"] = push_files(
                session, build_manifest([src]), chunk_size=CHUNK,
                controls=controls, progress=progress,
            )
        finally:
            session.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    # wait until the sender paused itself
    deadline = time.time() + 5
    while not state["paused"] and time.time() < deadline:
        time.sleep(0.02)
    assert state["paused"], "sender never paused"

    count_at_pause = len(state["progress_times"])
    time.sleep(0.5)
    assert len(state["progress_times"]) == count_at_pause, "progress continued while paused"
    assert controls.paused
    assert not (env.incoming / "slow.bin").exists()

    controls.resume()
    thread.join(timeout=60)
    assert not thread.is_alive()
    assert result["report"].success, result["report"].error
    dest = env.incoming / "slow.bin"
    assert dest.read_bytes() == blob


def test_connection_drop_mid_transfer_resumes(env):
    """Abrupt socket death leaves a partial; the next job continues it."""
    src = env.source_dir / "dropme.bin"
    blob = make_file(src, size=400_000)

    state = {"killed": False}
    session = new_session(env)

    def progress(file_id, relpath, sent, size, total):
        if not state["killed"] and sent >= 80_000:
            state["killed"] = True
            session.sock.close()  # simulate cable pull

    try:
        report = push_files(
            session, build_manifest([src]), chunk_size=CHUNK, progress=progress
        )
    except OSError:
        report = None
    finally:
        session.close()

    assert report is not None and not report.success

    # the receiver handler is still draining the dead connection; wait for it
    # to flush the partial and release the file handle before inspecting it
    assert wait_for(lambda: bool(env.reports)), "receiver never reported"

    dest = env.incoming / "dropme.bin"
    partial = partial_path(dest)
    assert not dest.exists()
    assert partial.exists()
    partial_size = partial.stat().st_size
    assert partial_size > 0

    # wait for the server handler to release the file handle
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with open(partial, "r+b") as fh:
                fh.seek(0, os.SEEK_END)
            break
        except OSError:
            time.sleep(0.05)

    env.spy["offsets"].clear()
    session = new_session(env)
    try:
        report2 = push_files(session, build_manifest([src]), chunk_size=CHUNK)
    finally:
        session.close()

    assert report2.success, report2.error
    assert env.spy["offsets"] and env.spy["offsets"][0] > 0
    assert dest.read_bytes() == blob


def test_resume_after_partial_file_left_from_previous_run(env):
    """A partial left on disk (crash/restart) with valid sidecar is reused."""
    src = env.source_dir / "resume-later.bin"
    blob = make_file(src, size=200_000)
    dest = env.incoming / "resume-later.bin"

    # simulate a crash: partial + sidecar written by a previous process
    partial = partial_path(dest)
    partial.write_bytes(blob[: CHUNK * 5])
    resume_mod.write_meta(
        dest,
        {
            "file_id": "resume-later.bin",
            "size": len(blob),
            "mtime": os.path.getmtime(src),
            "chunk_size": CHUNK,
        },
    )

    env.spy["offsets"].clear()
    session = new_session(env)
    try:
        report = push_files(session, build_manifest([src]), chunk_size=CHUNK)
    finally:
        session.close()

    assert report.success, report.error
    assert env.spy["offsets"][0] == CHUNK * 5
    assert dest.read_bytes() == blob


def test_stale_partial_with_changed_source_restarts_from_zero(env):
    src = env.source_dir / "changed.bin"
    blob = make_file(src, size=150_000)
    dest = env.incoming / "changed.bin"

    partial = partial_path(dest)
    partial.write_bytes(os.urandom(CHUNK * 3))
    resume_mod.write_meta(
        dest,
        {
            "file_id": "changed.bin",
            "size": 10_000,           # wrong size on purpose
            "mtime": 1.0,
            "chunk_size": CHUNK,
        },
    )

    env.spy["offsets"].clear()
    session = new_session(env)
    try:
        report = push_files(session, build_manifest([src]), chunk_size=CHUNK)
    finally:
        session.close()

    assert report.success, report.error
    assert env.spy["offsets"][0] == 0  # discarded, full restart
    assert dest.read_bytes() == blob


def test_checksum_matches_after_resume(env):
    """End-to-end: interrupt, resume, verify SHA-256 on both sides."""
    src = env.source_dir / "verify-resume.bin"
    blob = make_file(src, size=250_000, seed=42)

    controls = TransferControls()
    hit = {"done": False}

    def progress(file_id, relpath, sent, size, total):
        if not hit["done"] and sent >= 50_000:
            hit["done"] = True
            controls.cancel()

    session = new_session(env)
    try:
        push_files(
            session, build_manifest([src]), chunk_size=CHUNK,
            controls=controls, progress=progress,
        )
    finally:
        session.close()

    session = new_session(env)
    try:
        report = push_files(session, build_manifest([src]), chunk_size=CHUNK)
    finally:
        session.close()

    assert report.success, report.error
    import hashlib

    dest = env.incoming / "verify-resume.bin"
    assert hashlib.sha256(dest.read_bytes()).hexdigest() == report.results[0].checksum
    assert dest.read_bytes() == blob
    # wait for the receiver handler of the *second* connection to publish its
    # report (the first connection's cancelled report has an empty checksum)
    assert wait_for(
        lambda: any(
            r.files and r.files[0].checksum for r in env.reports
        )
    ), "receiver report with checksum never appeared"
    done = next(r for r in env.reports if r.files and r.files[0].checksum)
    assert done.files[0].checksum == report.results[0].checksum
