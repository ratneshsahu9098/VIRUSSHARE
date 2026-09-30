"""virusShare - release asset tests (icon, version resource, flags)."""

import os
import socket
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from core.constants import APP_NAME, APP_VERSION

ROOT = Path(__file__).resolve().parents[1]
ICON_PATH = ROOT / "assets" / "virusShare.ico"
VERSION_PATH = ROOT / "assets" / "version_info.txt"


def _parse_ico(data: bytes):
    """Return [(width, height, offset, size)] plus verify the container."""
    assert len(data) >= 6, "ico too small"
    reserved, itype, count = struct.unpack("<HHH", data[:6])
    assert reserved == 0 and itype == 1  # reserved, ICON (not CURSOR)
    assert 1 <= count <= 64
    entries = []
    for i in range(count):
        raw = data[6 + i * 16 : 6 + (i + 1) * 16]
        w, h, colors, res, planes, bpp, size, offset = struct.unpack(
            "<BBBBHHII", raw
        )
        assert colors == 0 and res == 0 and planes == 1
        assert offset + size <= len(data)
        entries.append((w or 256, h or 256, offset, size))
    # entries must be contiguous and ordered
    pos = 6 + 16 * count
    for w, h, offset, size in entries:
        assert offset == pos, "image data must follow the directory"
        pos += size
    assert pos == len(data)
    return entries


def _png_size(blob: bytes) -> tuple:
    assert blob[:8] == b"\x89PNG\r\n\x1a\n", "image must be PNG"
    assert blob[12:16] == b"IHDR"
    return struct.unpack(">II", blob[16:24])


def test_write_ico_roundtrip(tmp_path):
    from gui.icons import ICO_SIZES, write_ico

    out = write_ico(tmp_path / "app.ico")
    data = out.read_bytes()
    entries = _parse_ico(data)
    assert [w for w, *_ in entries] == list(ICO_SIZES)
    for (w, h, offset, size) in entries:
        assert _png_size(data[offset : offset + size]) == (w, h)


def test_committed_icon_is_valid():
    assert ICON_PATH.exists(), "committed ico missing - run scripts/make_release_assets.py"
    entries = _parse_ico(ICON_PATH.read_bytes())
    assert max(w for w, *_ in entries) >= 256  # has the shell size


def test_committed_version_info_loads():
    pytest.importorskip("PyInstaller.utils.win32.versioninfo")
    from PyInstaller.utils.win32.versioninfo import (
        VSVersionInfo,
        load_version_info_from_text_file,
    )

    assert VERSION_PATH.exists(), "committed version file missing"
    info = load_version_info_from_text_file(str(VERSION_PATH))
    assert isinstance(info, VSVersionInfo)
    text = VERSION_PATH.read_text(encoding="utf-8")
    assert f"StringStruct('FileVersion', '{APP_VERSION}')" in text
    assert f"StringStruct('ProductName', '{APP_NAME}')" in text


def test_ensure_assets_is_idempotent(tmp_path, monkeypatch):
    import scripts.make_release_assets as mod

    # point at a scratch directory so the repo assets are never touched
    monkeypatch.setattr(mod, "ICO_FILE", tmp_path / "assets" / "app.ico")
    monkeypatch.setattr(mod, "VERSION_FILE", tmp_path / "assets" / "version.txt")

    ico, ver = mod.ensure_assets()
    first_ico = Path(ico).read_bytes()
    first_ver = Path(ver).read_bytes()
    ico2, ver2 = mod.ensure_assets()
    assert (ico, ver) == (ico2, ver2)
    assert Path(ico2).read_bytes() == first_ico
    assert Path(ver2).read_bytes() == first_ver
    _parse_ico(first_ico)


def test_version_tuple_pads_to_four_components():
    from scripts.make_release_assets import version_tuple

    assert version_tuple("1.0.0") == (1, 0, 0, 0)
    assert version_tuple("2.10.3.7") == (2, 10, 3, 7)
    assert version_tuple("9") == (9, 0, 0, 0)


def test_version_flag_prints_and_exits(capsys):
    import app

    with pytest.raises(SystemExit) as exc:
        app.main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert APP_NAME in out and APP_VERSION in out


def test_version_flag_survives_missing_streams(monkeypatch):
    """Windowed exe without a console: sys.stdout/stderr are None."""
    import sys as _sys

    import app

    monkeypatch.setattr(_sys, "stdout", None)
    monkeypatch.setattr(_sys, "stderr", None)
    with pytest.raises(SystemExit) as exc:
        app.main(["--version"])
    assert exc.value.code == 0


def test_version_flag_survives_invalid_flush(monkeypatch):
    """Flush on an invalid handle raises OSError EINVAL (reported crash)."""
    import sys as _sys

    import app

    class BrokenFlush:
        def write(self, text):
            return len(text)

        def flush(self):
            raise OSError(22, "Invalid argument")

    monkeypatch.setattr(_sys, "stdout", BrokenFlush())
    with pytest.raises(SystemExit) as exc:
        app.main(["--version"])
    assert exc.value.code == 0


def test_version_flag_survives_broken_write(monkeypatch):
    """Dead pipe: write itself can raise OSError too."""
    import sys as _sys

    import app

    class BrokenWrite:
        def write(self, text):
            raise OSError(22, "Invalid argument")

        def flush(self):
            pass

    monkeypatch.setattr(_sys, "stdout", BrokenWrite())
    with pytest.raises(SystemExit) as exc:
        app.main(["--version"])
    assert exc.value.code == 0


def test_about_text_mentions_version_and_environment():
    from gui.main_window import MainWindow

    text = MainWindow._about_text()
    assert APP_NAME in text
    assert APP_VERSION in text
    assert "Qt" in text and "Python" in text
    assert "virusShare" in text  # data dir path


# --------------------------------------------------------------------------- #
# H3 / H6 - port conflict and single instance
# --------------------------------------------------------------------------- #

def test_app_exits_cleanly_when_transfer_port_is_taken(tmp_path):
    """H3: server.start() surfaces a bound port as RuntimeError; app.py must
    exit 2 with no traceback (and must not silently double-bind)."""
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    env = os.environ.copy()
    env["APPDATA"] = str(tmp_path)
    env["QT_QPA_PLATFORM"] = "offscreen"
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "app.py"),
                "--no-discovery",
                "--transfer-port",
                str(port),
            ],
            capture_output=True,
            text=True,
            timeout=45,
            env=env,
            cwd=str(ROOT),
        )
    finally:
        blocker.close()
    assert "Traceback" not in (proc.stderr or ""), proc.stderr
    assert proc.returncode == 2, (
        f"rc={proc.returncode}\nout={proc.stdout}\nerr={proc.stderr}"
    )


def test_instance_lock_blocks_second_holder(tmp_path):
    """H6: while one holder has the lock, a second acquire must fail."""
    from app import acquire_instance_lock

    lock_path = tmp_path / "instance.lock"
    first = acquire_instance_lock(lock_path)
    assert first is not None, "could not take the initial lock"
    try:
        assert acquire_instance_lock(lock_path) is None, (
            "second acquire succeeded while the first holder was alive"
        )
    finally:
        first.unlock()
    third = acquire_instance_lock(lock_path)
    assert third is not None, "lock not released after unlock"
    third.unlock()


def test_second_instance_bows_out(tmp_path):
    """H6 end-to-end: with another instance holding the lock, app.py prints
    the already-running message and exits 1 without starting the server."""
    env = os.environ.copy()
    env["APPDATA"] = str(tmp_path)
    env["QT_QPA_PLATFORM"] = "offscreen"
    holder_script = (
        "import time\n"
        "from pathlib import Path\n"
        "from PySide6.QtCore import QLockFile\n"
        f"lock_path = Path({str(tmp_path)!r}) / 'virusShare' / 'virusShare.lock'\n"
        "lock_path.parent.mkdir(parents=True, exist_ok=True)\n"
        f"lock = QLockFile(str(lock_path))\n"
        "if not lock.lock():\n"
        "    raise SystemExit('could not take lock')\n"
        "print('holder-ready', flush=True)\n"
        "time.sleep(60)\n"
    )
    holder = subprocess.Popen(
        [sys.executable, "-c", holder_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        ready = holder.stdout.readline().strip()
        assert ready == "holder-ready", (
            f"holder failed: {ready!r} {holder.stderr.read()}"
        )
        env["VIRUSSHARE_NO_DIALOG"] = "1"
        second = subprocess.run(
            [sys.executable, str(ROOT / "app.py"), "--no-discovery"],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
            cwd=str(ROOT),
        )
    finally:
        holder.kill()
        holder.wait(timeout=10)
    assert second.returncode == 1, (
        f"rc={second.returncode}\nout={second.stdout}\nerr={second.stderr}"
    )
    assert "already running" in second.stdout.lower()
    assert "Traceback" not in (second.stderr or ""), second.stderr


def test_startup_failure_after_bind_shuts_everything_down(
    monkeypatch, tmp_path, caplog
):
    """H6: an exception between server.start() and app.exec() must run the
    shutdown path (server, history) instead of leaking them."""
    import logging as logging_mod

    import app as app_mod
    import database.history as hist_mod
    import gui.main_window as mw_mod
    from network.tcp_server import TransferServer
    from utils.network import find_free_port

    monkeypatch.setenv("APPDATA", str(tmp_path))

    class BoomWindow:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("window blew up")

    monkeypatch.setattr(mw_mod, "MainWindow", BoomWindow)

    state = {"history_closed": False, "server_stops": 0}

    class FakeHistory:
        def __init__(self, *args, **kwargs):
            pass

        def close(self):
            state["history_closed"] = True

        def record(self, *args, **kwargs):
            pass

    monkeypatch.setattr(hist_mod, "HistoryDB", FakeHistory)

    real_stop = TransferServer.stop

    def stop_spy(self_):
        state["server_stops"] += 1
        return real_stop(self_)

    monkeypatch.setattr(TransferServer, "stop", stop_spy)

    port = find_free_port()
    with caplog.at_level(logging_mod.ERROR):
        rc = app_mod.main(["--no-discovery", "--transfer-port", str(port)])

    assert rc == 1, f"startup failure returned {rc}"
    assert state["history_closed"], "history DB leaked on startup failure"
    assert state["server_stops"] >= 1, "accept loop leaked on startup failure"
    assert any("startup failed" in r.message for r in caplog.records)


# --------------------------------------------------------------------------- #
# M30 - port flag validation
# --------------------------------------------------------------------------- #

def test_port_flags_reject_out_of_range_values(capsys):
    """M30: bad ports must be argparse usage errors (exit 2, no traceback),
    not SettingsError crashes and not silently ignored values."""
    import app

    cases = [
        ("--transfer-port", "80"),
        ("--transfer-port", "0"),
        ("--transfer-port", "65536"),
        ("--transfer-port", "not-a-port"),
        ("--discovery-port", "80"),
        ("--discovery-port", "65536"),
    ]
    for flag, value in cases:
        with pytest.raises(SystemExit) as exc:
            app.parse_args([flag, value])
        assert exc.value.code == 2, f"{flag} {value}: expected usage error"
        err = capsys.readouterr().err
        assert flag in err, f"{flag} {value}: option missing from usage error"
        assert "Traceback" not in err


def test_bad_port_flag_exits_without_traceback(tmp_path):
    """M30 end to end: --transfer-port 80 exits 2 with a clean usage message
    instead of an uncaught SettingsError traceback."""
    env = os.environ.copy()
    env["APPDATA"] = str(tmp_path)
    env["QT_QPA_PLATFORM"] = "offscreen"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "app.py"),
            "--no-discovery",
            "--transfer-port",
            "80",
        ],
        capture_output=True,
        text=True,
        timeout=45,
        env=env,
        cwd=str(ROOT),
    )
    assert "Traceback" not in (proc.stderr or ""), proc.stderr
    assert proc.returncode == 2, (
        f"rc={proc.returncode}\nout={proc.stdout}\nerr={proc.stderr}"
    )
    assert "transfer-port" in (proc.stderr or "").lower()


# --------------------------------------------------------------------------- #
# M27 - shutdown factory
# --------------------------------------------------------------------------- #

def _shutdown_env(calls):
    from app import make_shutdown

    class Bridge:
        def cancel_all_prompts(self):
            calls.append("bridge.cancel")

    class Manager:
        def __init__(self):
            self.on_wait = None

        def shutdown(self, timeout=10.0, on_wait=None):
            self.on_wait = on_wait
            calls.append("manager.shutdown")

    class Server:
        def stop(self):
            calls.append("server.stop")

    class History:
        def close(self):
            calls.append("history.close")

    class Discovery:
        def stop(self):
            calls.append("discovery.stop")

    class Window:
        def flush_history(self):
            calls.append("window.flush")

    parts = type("Parts", (), {})()
    parts.bridge = Bridge()
    parts.manager = Manager()
    parts.server = Server()
    parts.history = History()
    parts.discovery = Discovery()
    parts.window = Window()
    parts.shutdown = make_shutdown(
        bridge=parts.bridge,
        manager=parts.manager,
        server=parts.server,
        history=parts.history,
        get_discovery=lambda: parts.discovery,
        get_window=lambda: parts.window,
        process_events=lambda: calls.append("events"),
    )
    return parts


def test_shutdown_stops_accept_loop_before_workers():
    """M27: the accept loop must close before workers, or new peers keep
    arriving while the manager is tearing down."""
    calls = []
    env = _shutdown_env(calls)
    env.shutdown()
    assert calls[0] == "bridge.cancel", "prompts not cancelled first"
    assert "server.stop" in calls and "manager.shutdown" in calls
    assert calls.index("server.stop") < calls.index("manager.shutdown"), (
        "accept loop still running while workers shut down (M27)"
    )


def test_shutdown_is_idempotent():
    """M27: closeEvent runs on_shutdown and app.py's finally runs it again."""
    calls = []
    env = _shutdown_env(calls)
    env.shutdown()
    env.shutdown()
    for name in ("bridge.cancel", "server.stop", "manager.shutdown", "history.close"):
        assert calls.count(name) == 1, f"{name} ran twice (M27)"


def test_shutdown_flushes_history_before_close():
    """M27: sessionFinished signals still queued during teardown must be
    written before the history DB is closed."""
    calls = []
    env = _shutdown_env(calls)
    env.shutdown()
    assert "window.flush" in calls, (
        "pending history writes were never flushed (M27)"
    )
    assert calls.index("window.flush") < calls.index("history.close"), (
        "history closed before the pending writes were flushed (M27)"
    )


def test_shutdown_pumps_events_while_waiting():
    """M27: the GUI must keep processing events while manager.shutdown blocks."""
    calls = []
    env = _shutdown_env(calls)
    env.shutdown()
    assert env.manager.on_wait is not None, (
        "GUI event pump not wired into manager.shutdown (M27)"
    )
