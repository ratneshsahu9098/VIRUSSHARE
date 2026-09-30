"""virusShare - TransferManager orchestration tests."""

import threading
import time
from pathlib import Path

import pytest

import transfer.manager as manager_mod
from core.security import TrustStore, load_identity
from models import TransferSession, TransferStatus
from network.protocol import DeviceInfo, Message
from network.tcp_server import TransferServer
from transfer.manager import TransferManager
from transfer.receiver import ReceiveContext, handle_incoming
from transfer.sender import TransferControls, build_manifest

CHUNK = 64 * 1024


def device(name, device_id, port=54322):
    return DeviceInfo(
        name=name, ip="127.0.0.1", port=port, device_id=device_id,
        os_version="Windows 11", app_version="1.0.0", capabilities=[],
    )


def make_file(path: Path, size: int, seed: int = 3) -> bytes:
    import random

    rng = random.Random(seed)
    blob = bytes(rng.randrange(256) for _ in range(size))
    path.write_bytes(blob)
    return blob


def start_env(tmp_path, handler=None, *, encryption=False, approve=None):
    incoming = tmp_path / "incoming"
    incoming.mkdir(exist_ok=True)
    state = {"handler": handler}
    if state["handler"] is None:
        def default(session):
            state.setdefault("reports", []).append(
                handle_incoming(
                    session, ReceiveContext(receive_dir=incoming, verify=True)
                )
            )
        state["handler"] = default
    server = TransferServer(
        device_provider=lambda: device("SERVER", "srv"),
        identity=load_identity(tmp_path / "server.pem"),
        trust_store=TrustStore(tmp_path / "server_trust.json"),
        host="127.0.0.1",
        port=0,
        encryption=encryption,
        approve_callback=approve or (lambda *a: True),
        session_handler=lambda s: state["handler"](s),
    )
    port = server.start()
    env = type("Env", (), {})()
    env.server = server
    env.port = port
    env.incoming = incoming
    env.state = state
    return env


def make_manager(env, tmp_path, **overrides):
    settings = {
        "max_concurrent_transfers": 3,
        "reconnect_attempts": 2,
        "chunk_size": CHUNK,
        "verify_checksums": True,
        "enable_encryption": False,
        "save_received_files_to": str(env.incoming),
    }
    settings.update(overrides)
    updates, finished = [], []
    manager = TransferManager(
        identity=load_identity(tmp_path / "client.pem"),
        trust_store=TrustStore(tmp_path / "client_trust.json"),
        device_provider=lambda: device("CLIENT", "cli"),
        approve_callback=lambda *a: True,
        settings=settings,
        on_update=lambda m: updates.append(
            (m.id, m.status, m.transferred_size, m.current_file)
        ),
        on_finished=lambda m: finished.append(m.id),
        connect_timeout=2.0,
    )
    manager._test_updates = updates
    manager._test_finished = finished
    return manager


def blocking_handler_factory(incoming, entered, release, *, complete=True):
    """Handler that parks the connection until ``release`` fires.

    With ``complete=True`` it then runs the real receive path so the sender
    can finish; otherwise it just drops the session (simulates a dead peer
    that the sender still waits on).
    """

    def handler(session):
        entered.set()
        release.wait(15)
        if complete:
            handle_incoming(
                session, ReceiveContext(receive_dir=incoming, verify=True)
            )

    return handler


@pytest.fixture
def tmp(tmp_path):
    yield tmp_path


# --------------------------------------------------------------------------- #
# happy path
# --------------------------------------------------------------------------- #

def test_send_files_completes_and_updates_model(tmp_path):
    src = tmp_path / "data.bin"
    blob = make_file(src, 200_000)
    env = start_env(tmp_path)
    manager = make_manager(env, tmp_path)
    target = device("SERVER", "srv", env.port)
    try:
        model = manager.send_files(target, [src])
        assert model.status in (
            TransferStatus.PENDING,
            TransferStatus.ACTIVE,
            TransferStatus.COMPLETED,
        )
        assert manager.wait(model.id, timeout=30)

        assert model.status is TransferStatus.COMPLETED, model.error_message
        assert model.direction == "send"
        assert model.computer_name == "SERVER"
        assert model.transferred_size == len(blob)
        assert model.end_time is not None
        assert [f.name for f in model.files] == ["data.bin"]
        assert (env.incoming / "data.bin").read_bytes() == blob
        # exactly one finished event, several progress updates
        assert manager._test_finished == [model.id]
        assert len(manager._test_updates) >= 2
    finally:
        manager.shutdown(timeout=5)
        env.server.stop()


def test_send_files_rejects_empty_selection(tmp_path):
    env = start_env(tmp_path)
    manager = make_manager(env, tmp_path)
    try:
        with pytest.raises(ValueError):
            manager.send_files(device("SERVER", "srv", env.port), [])
    finally:
        manager.shutdown(timeout=5)
        env.server.stop()


def test_send_reports_fp_verified_peer(tmp_path):
    """H7: after a fingerprint-verified handshake the sender reports the peer
    so the GUI badge comes from verification, never from discovery packets."""
    src = tmp_path / "verified.bin"
    make_file(src, 40_000)
    env = start_env(tmp_path)
    manager = make_manager(env, tmp_path)
    verified = []
    manager.on_peer_trusted = lambda device_id: verified.append(device_id)
    try:
        model = manager.send_files(device("SERVER", "srv", env.port), [src])
        assert manager.wait(model.id, timeout=30)
        assert model.status is TransferStatus.COMPLETED, model.error_message
        assert verified == ["srv"], "fp-verified peer was not reported"
    finally:
        manager.shutdown(timeout=5)
        env.server.stop()


def test_apply_settings_updates_receive_dir_and_tunables(tmp_path):
    """H4: settings are snapshotted at construction; apply_settings must
    refresh them so 'Change Location' and the dialog take effect."""
    env = start_env(tmp_path)
    manager = make_manager(env, tmp_path)
    try:
        new_dir = tmp_path / "elsewhere"
        manager.apply_settings(
            {
                "save_received_files_to": str(new_dir),
                "chunk_size": 12_345,
                "verify_checksums": False,
                "max_concurrent_transfers": 5,
                "enable_encryption": True,
                "reconnect_attempts": 7,
            }
        )
        assert manager.receive_dir == new_dir
        assert manager.chunk_size == 12_345
        assert manager.verify is False
        assert manager.max_concurrent == 5
        assert manager.encryption is True
        assert manager.reconnect_attempts == 7

        model = manager.begin_receive(device("SERVER", "srv"))
        ctx = manager.receive_context(model)
        assert ctx.receive_dir == new_dir
        assert ctx.verify is False
    finally:
        manager.shutdown(timeout=5)
        env.server.stop()


# --------------------------------------------------------------------------- #
# concurrency
# --------------------------------------------------------------------------- #

def test_max_concurrent_transfers_limits_parallel_jobs(tmp_path):
    entered = threading.Event()
    release = threading.Event()

    env = start_env(tmp_path)
    env.state["handler"] = blocking_handler_factory(
        env.incoming, entered, release
    )
    manager = make_manager(env, tmp_path, max_concurrent_transfers=1)
    target = device("SERVER", "srv", env.port)
    src = tmp_path / "a.txt"
    src.write_text("hello", encoding="utf-8")
    src2 = tmp_path / "b.txt"
    src2.write_text("world", encoding="utf-8")
    try:
        first = manager.send_files(target, [src])
        assert entered.wait(5)
        # first occupies the only slot (blocked in handshake/manifest)
        second = manager.send_files(target, [src2])
        time.sleep(0.5)
        assert second.status is TransferStatus.PENDING
        assert first.status is TransferStatus.ACTIVE

        release.set()
        assert manager.wait(first.id, timeout=20)
        assert manager.wait(second.id, timeout=20)
        # second only started after the first finished
        first_end = first.end_time
        assert second.start_time is not None
        assert second.start_time >= first_end
        assert second.status is TransferStatus.COMPLETED
    finally:
        release.set()
        manager.shutdown(timeout=5)
        env.server.stop()


def test_cancel_queued_job_never_starts(tmp_path):
    entered = threading.Event()
    release = threading.Event()

    env = start_env(tmp_path)
    env.state["handler"] = blocking_handler_factory(
        env.incoming, entered, release
    )
    manager = make_manager(env, tmp_path, max_concurrent_transfers=1)
    target = device("SERVER", "srv", env.port)
    src = tmp_path / "a.txt"
    src.write_text("x", encoding="utf-8")
    try:
        first = manager.send_files(target, [src])
        assert entered.wait(5)
        second = manager.send_files(target, [src])
        time.sleep(0.3)

        assert manager.cancel(second.id) is True
        assert second.status is TransferStatus.CANCELLED
        assert second.end_time is not None

        release.set()
        assert manager.wait(first.id, timeout=20)
        assert manager.wait(second.id, timeout=20)
        # the worker observed the cancel and reported finish exactly once
        assert manager._test_finished.count(second.id) == 1
        assert second.status is TransferStatus.CANCELLED
        assert first.status is TransferStatus.COMPLETED
    finally:
        release.set()
        manager.shutdown(timeout=5)
        env.server.stop()


def test_cancel_active_job_unblocks(tmp_path):
    entered = threading.Event()
    release = threading.Event()

    env = start_env(tmp_path)
    env.state["handler"] = blocking_handler_factory(
        env.incoming, entered, release
    )
    manager = make_manager(env, tmp_path)
    target = device("SERVER", "srv", env.port)
    src = tmp_path / "big.bin"
    src.write_bytes(b"z" * 100_000)
    try:
        model = manager.send_files(target, [src])
        assert entered.wait(5)
        time.sleep(0.2)
        assert model.status is TransferStatus.ACTIVE

        assert manager.cancel(model.id) is True
        assert model.status is TransferStatus.CANCELLED

        release.set()  # let the peer answer; sender notices the cancel
        assert manager.wait(model.id, timeout=20)
        assert manager._test_finished.count(model.id) == 1
        assert model.status is TransferStatus.CANCELLED
    finally:
        release.set()
        manager.shutdown(timeout=5)
        env.server.stop()


def test_pause_and_resume(tmp_path):
    env = start_env(tmp_path)
    manager = make_manager(env, tmp_path)
    target = device("SERVER", "srv", env.port)
    src = tmp_path / "huge.bin"
    make_file(src, 6_000_000)

    # Pause from inside the progress callback: it runs on the sender thread
    # between chunks, so the pause always lands mid-file (no race with the
    # transfer finishing at loopback speed).
    paused = {"done": False}
    base_update = manager.on_update

    def hook(m):
        base_update(m)
        if (
            not paused["done"]
            and m.status is TransferStatus.ACTIVE
            and m.transferred_size >= 100_000
        ):
            paused["done"] = True
            manager.pause(m.id)

    manager.on_update = hook

    try:
        model = manager.send_files(target, [src])
        deadline = time.time() + 15
        while time.time() < deadline and model.status not in (
            TransferStatus.PAUSED,
            TransferStatus.COMPLETED,
            TransferStatus.FAILED,
            TransferStatus.CANCELLED,
        ):
            time.sleep(0.02)

        if model.status is TransferStatus.PAUSED:
            seen = model.transferred_size
            time.sleep(0.5)
            assert model.status is TransferStatus.PAUSED
            assert model.transferred_size == seen  # no bytes moved while paused
            assert manager.resume(model.id) is True
            assert model.status is TransferStatus.ACTIVE

        assert manager.wait(model.id, timeout=60)
        assert model.status is TransferStatus.COMPLETED, model.error_message
        assert (env.incoming / "huge.bin").stat().st_size == 6_000_000
    finally:
        manager.shutdown(timeout=5)
        env.server.stop()


# --------------------------------------------------------------------------- #
# reconnection
# --------------------------------------------------------------------------- #

def test_retries_transient_connection_failure_then_succeeds(tmp_path):
    env = start_env(tmp_path)
    manager = make_manager(env, tmp_path, reconnect_attempts=3)
    target = device("SERVER", "srv", env.port)
    src = tmp_path / "retry.txt"
    src.write_text("retry-me", encoding="utf-8")

    real_client = manager_mod.TransferClient
    calls = {"n": 0}
    fail_first = {"left": 1}

    class FlakyClient(real_client):
        def connect(self, *args, **kwargs):
            if fail_first["left"] > 0:
                fail_first["left"] -= 1
                calls["n"] += 1
                raise OSError("simulated connection reset")
            calls["n"] += 1
            return super().connect(*args, **kwargs)

    manager_mod.TransferClient = FlakyClient
    try:
        model = manager.send_files(target, [src])
        assert manager.wait(model.id, timeout=30)
        assert model.status is TransferStatus.COMPLETED, model.error_message
        assert calls["n"] == 2  # one failure + one success
        assert (env.incoming / "retry.txt").read_text(encoding="utf-8") == "retry-me"
    finally:
        manager_mod.TransferClient = real_client
        manager.shutdown(timeout=5)
        env.server.stop()


def test_gives_up_after_reconnect_attempts(tmp_path):
    env = start_env(tmp_path)
    manager = make_manager(env, tmp_path, reconnect_attempts=2)
    target = device("DEAD", "dead", 1)  # never dialed for real
    src = tmp_path / "x.txt"
    src.write_text("x", encoding="utf-8")

    real_client = manager_mod.TransferClient
    calls = {"n": 0}

    class DeadClient(real_client):
        def connect(self, *args, **kwargs):
            calls["n"] += 1
            raise OSError("connection refused (simulated)")

    manager_mod.TransferClient = DeadClient
    try:
        model = manager.send_files(target, [src])
        assert manager.wait(model.id, timeout=30)
        assert model.status is TransferStatus.FAILED
        assert model.error_message
        assert calls["n"] == 3  # initial + 2 retries
    finally:
        manager_mod.TransferClient = real_client
        manager.shutdown(timeout=5)
        env.server.stop()


def test_rejected_handshake_is_not_retried(tmp_path):
    env = start_env(tmp_path, approve=lambda *a: False)
    manager = make_manager(env, tmp_path, reconnect_attempts=3)
    target = device("SERVER", "srv", env.port)
    src = tmp_path / "x.txt"
    src.write_text("x", encoding="utf-8")

    real_client = manager_mod.TransferClient
    calls = {"n": 0}

    class CountingClient(real_client):
        def connect(self, *args, **kwargs):
            calls["n"] += 1
            return super().connect(*args, **kwargs)

    manager_mod.TransferClient = CountingClient
    try:
        model = manager.send_files(target, [src])
        assert manager.wait(model.id, timeout=30)
        assert model.status is TransferStatus.FAILED
        assert "rejected" in model.error_message.lower()
        assert calls["n"] == 1  # auth failures are not hammered
    finally:
        manager_mod.TransferClient = real_client
        manager.shutdown(timeout=5)
        env.server.stop()


# --------------------------------------------------------------------------- #
# incoming sessions
# --------------------------------------------------------------------------- #

def test_incoming_transfer_tracked_as_receive_session(tmp_path):
    env = start_env(tmp_path)
    manager = make_manager(env, tmp_path)
    captured = {}

    def handler(session):
        model = manager.begin_receive(session.peer_device)
        captured["model"] = model
        ctx = manager.receive_context(model)
        report = handle_incoming(session, ctx)
        manager.finish_receive(model, report)

    env.state["handler"] = handler

    src = tmp_path / "inbound.bin"
    blob = make_file(src, 120_000)
    client = manager_mod.TransferClient(
        device_provider=lambda: device("CLIENT", "cli"),
        identity=manager.identity,
        trust_store=manager.trust_store,
        encryption=False,
        approve_callback=lambda *a: True,
    )
    try:
        conn = client.connect("127.0.0.1", env.port, timeout=5)
        conn.sock.settimeout(30)
        from transfer.sender import push_files

        report = push_files(
            conn, build_manifest([src]), chunk_size=CHUNK, verify=True
        )
        conn.close()
        assert report.success, report.error

        # the receiver finalizes asynchronously (it still has to consume the
        # DISCONNECT) - wait for the finished event before asserting
        deadline = time.time() + 5
        while time.time() < deadline and not manager._test_finished:
            time.sleep(0.02)

        model = captured["model"]
        assert model.direction == "receive"
        assert manager._test_finished == [model.id]
        assert model.status is TransferStatus.COMPLETED, model.error_message
        assert model.transferred_size == len(blob)
        assert [f.name for f in model.files] == ["inbound.bin"]
        assert (env.incoming / "inbound.bin").read_bytes() == blob
    finally:
        manager.shutdown(timeout=5)
        env.server.stop()


def test_shutdown_cancels_and_waits(tmp_path):
    entered = threading.Event()
    release = threading.Event()

    env = start_env(tmp_path)
    # dead peer: sender stays blocked in the handshake until released
    env.state["handler"] = blocking_handler_factory(
        env.incoming, entered, release, complete=False
    )
    manager = make_manager(env, tmp_path)
    target = device("SERVER", "srv", env.port)
    src = tmp_path / "a.txt"
    src.write_text("x", encoding="utf-8")
    try:
        model = manager.send_files(target, [src])
        assert entered.wait(5)
        manager.shutdown(timeout=3)
        assert model.status in (
            TransferStatus.CANCELLED,
            TransferStatus.COMPLETED,
            TransferStatus.FAILED,
        )
    finally:
        release.set()
        manager.wait(model.id, timeout=15)
        env.server.stop()


# --------------------------------------------------------------------------- #
# result semantics (M17 / M21)
# --------------------------------------------------------------------------- #

def test_all_files_skipped_is_not_reported_as_completed(tmp_path):
    """M17: the receiver skipped everything -> 0 bytes moved, but the
    session is finalized COMPLETED because all([]) is True."""
    env = start_env(tmp_path)
    (env.incoming / "data.bin").write_bytes(b"OLD" * 1000)  # conflict -> skip
    manager = make_manager(env, tmp_path, reconnect_attempts=0)
    target = device("SERVER", "srv", env.port)
    src = tmp_path / "data.bin"
    make_file(src, 50_000)
    try:
        model = manager.send_files(target, [src])
        assert manager.wait(model.id, timeout=30)
        assert model.status is not TransferStatus.COMPLETED, (
            "all-skipped push was reported as completed"
        )
        assert model.status is TransferStatus.FAILED, model.error_message
        assert "skip" in (model.error_message or "").lower()
        assert (env.incoming / "data.bin").read_bytes() == b"OLD" * 1000
    finally:
        manager.shutdown(timeout=5)
        env.server.stop()


def test_file_level_error_surfaces_in_model_error(tmp_path, monkeypatch):
    """M21: only session-level errors reach model.error_message, so a
    per-file 'Checksum mismatch' shows up as the generic 'transfer failed'."""
    import transfer.receiver as receiver_mod

    class LyingHasher(receiver_mod.StreamingHasher):
        def hexdigest(self):
            return "0" * 64

    monkeypatch.setattr(receiver_mod, "StreamingHasher", LyingHasher)

    env = start_env(tmp_path)
    manager = make_manager(env, tmp_path, reconnect_attempts=0)
    target = device("SERVER", "srv", env.port)
    src = tmp_path / "corrupt.bin"
    make_file(src, 40_000)
    try:
        model = manager.send_files(target, [src])
        assert manager.wait(model.id, timeout=30)
        assert model.status is TransferStatus.FAILED
        assert "Checksum mismatch" in (model.error_message or ""), (
            model.error_message
        )
    finally:
        manager.shutdown(timeout=5)
        env.server.stop()


# --------------------------------------------------------------------------- #
# cancel / shutdown races (M18 / M24)
# --------------------------------------------------------------------------- #

def test_cancel_racing_finalize_never_flips_completed(tmp_path):
    """M18: cancel() checks model.status and writes CANCELLED with no lock
    and no _finalized guard.  If the worker finalizes between the read and
    the write (history already written as COMPLETED), the session flips to
    CANCELLED afterwards."""
    from datetime import datetime

    env = start_env(tmp_path)
    manager = make_manager(env, tmp_path)
    model = TransferSession(
        id="race-1",
        computer_id="peer",
        computer_name="PEER",
        status=TransferStatus.ACTIVE,
        start_time=datetime.now(),
        direction="send",
    )
    controls = TransferControls()

    race = {"arm": True}

    class RacingModel:
        """Forwards to the real model, but simulates the worker finalizing
        in the instant after cancel() read ``status`` and before it writes."""

        def __init__(self, real):
            object.__setattr__(self, "_real", real)

        def __getattr__(self, name):
            return getattr(object.__getattribute__(self, "_real"), name)

        def __setattr__(self, name, value):
            if name == "_real":
                object.__setattr__(self, name, value)
            else:
                setattr(object.__getattribute__(self, "_real"), name, value)

        def _read_status(self):
            real = object.__getattribute__(self, "_real")
            status = real.status
            if race.pop("arm", False):
                manager._finalize(real, TransferStatus.COMPLETED)
            return status

    RacingModel.status = property(
        RacingModel._read_status,
        lambda self, value: setattr(
            object.__getattribute__(self, "_real"), "status", value
        ),
    )

    with manager._lock:
        manager._sessions[model.id] = RacingModel(model)
        manager._controls[model.id] = controls

    assert manager.cancel(model.id) is True

    assert manager._test_finished == [model.id], "finalize never ran"
    assert model.status is TransferStatus.COMPLETED, (
        f"finalized COMPLETED session was flipped to {model.status}"
    )


def test_shutdown_keeps_hung_workers_visible(tmp_path):
    """M24: shutdown() clears _sessions/_threads even when wait_all() timed
    out, so a hung worker vanishes and the next wait_all() lies about it."""
    entered = threading.Event()
    release = threading.Event()

    env = start_env(tmp_path)
    env.state["handler"] = blocking_handler_factory(
        env.incoming, entered, release, complete=False
    )
    manager = make_manager(env, tmp_path)
    target = device("SERVER", "srv", env.port)
    src = tmp_path / "a.txt"
    src.write_text("x", encoding="utf-8")
    try:
        model = manager.send_files(target, [src])
        assert entered.wait(5)
        manager.shutdown(timeout=1.0)
        assert manager.wait_all(timeout=0.1) is False, (
            "hung worker became invisible after shutdown"
        )
        assert manager.sessions, "hung worker's session was dropped"
    finally:
        release.set()
        manager.wait(model.id, timeout=15)
        env.server.stop()


def test_shutdown_pumps_gui_while_waiting(tmp_path):
    """M27: on_shutdown runs on the GUI thread, so shutdown() must give the
    caller a chance to process events while workers wind down."""
    entered = threading.Event()
    release = threading.Event()

    env = start_env(tmp_path)
    env.state["handler"] = blocking_handler_factory(
        env.incoming, entered, release, complete=False
    )
    manager = make_manager(env, tmp_path)
    target = device("SERVER", "srv", env.port)
    src = tmp_path / "a.txt"
    src.write_text("x", encoding="utf-8")
    pumps = []
    try:
        model = manager.send_files(target, [src])
        assert entered.wait(5)
        manager.shutdown(timeout=5, on_wait=lambda: pumps.append(1))
        assert pumps, "on_wait was never called during shutdown (M27)"
    finally:
        release.set()
        manager.wait(model.id, timeout=15)
        env.server.stop()
