"""virusShare - GUI smoke tests (offscreen Qt).

These verify that every GUI module imports, that the main window wires up
without a real display, and that model -> widget updates behave.  Modal
dialogs are constructed but never ``exec()``-ed (nothing can click them
headless).
"""

import os
import time
import uuid
from datetime import datetime

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def ctx(tmp_path, qapp):
    """A wired-up MainWindow with real non-network components."""
    from core.config import Settings
    from core.security import TrustStore, load_identity
    from database.history import HistoryDB
    from gui.bridge import ThreadBridge
    from gui.main_window import MainWindow
    from network.protocol import DeviceInfo
    from transfer.manager import TransferManager

    settings = Settings(path=tmp_path / "settings.json", create_dirs=False)
    settings.set("minimize_to_tray", False, save=False)
    bridge = ThreadBridge()
    manager = TransferManager(
        identity=load_identity(tmp_path / "id.pem"),
        trust_store=TrustStore(tmp_path / "trust.json"),
        device_provider=lambda: DeviceInfo(
            name="ME", ip="127.0.0.1", port=54322, device_id="me",
            os_version="", app_version="1.0.0", capabilities=[],
        ),
        settings=settings.as_dict(),
    )
    history = HistoryDB(tmp_path / "history.db")
    trust = TrustStore(tmp_path / "trust2.json")
    window = MainWindow(
        settings=settings,
        manager=manager,
        history=history,
        bridge=bridge,
        trust_store=trust,
        on_shutdown=None,
    )
    window.show()
    qapp.processEvents()

    ns = type("Ctx", (), {})()
    ns.settings, ns.bridge, ns.manager, ns.history, ns.window = (
        settings, bridge, manager, history, window,
    )
    ns.queue = window.queue
    ns.devices = window.devices
    ns.trust_store = trust
    yield ns
    window.close()
    qapp.processEvents()
    manager.shutdown(timeout=3)
    window.flush_history()
    history.close()


def make_device(name="PEER-1", device_id="peer-1"):
    from network.discovery import DiscoveredDevice
    from network.protocol import DeviceInfo

    return DiscoveredDevice(
        info=DeviceInfo(
            name=name, ip="192.168.1.50", port=54322, device_id=device_id,
            os_version="Windows 11", app_version="1.0.0", capabilities=[],
        ),
        last_seen=time.time(),
    )


def make_session(status=None, direction="send", sid=None):
    from models import TransferFile, TransferSession, TransferStatus

    session = TransferSession(
        id=sid or f"s-{uuid.uuid4().hex}",
        computer_id="peer-1",
        computer_name="PEER-1",
        status=status or TransferStatus.COMPLETED,
        start_time=datetime.now(),
        end_time=datetime.now(),
        direction=direction,
    )
    session.add_file(TransferFile(id="f", name="a.bin", path="", size=1234))
    session.transferred_size = session.total_size
    return session


# --------------------------------------------------------------------------- #
# modules, styles, icons
# --------------------------------------------------------------------------- #

def test_all_gui_modules_import():
    import importlib

    for name in (
        "gui.animations",
        "gui.bridge",
        "gui.styles",
        "gui.icons",
        "gui.widgets",
        "gui.device_panel",
        "gui.transfer_queue",
        "gui.role_screen",
        "gui.sender_screen",
        "gui.receiver_screen",
        "gui.pairing_dialog",
        "gui.conflict_dialog",
        "gui.history_dialog",
        "gui.settings_dialog",
        "gui.tray",
        "gui.main_window",
    ):
        importlib.import_module(name)


def test_stylesheet_builds_for_all_themes():
    from gui.styles import stylesheet

    for theme in ("light", "dark", "system"):
        css = stylesheet(theme)
        assert "QProgressBar" in css
        assert "%(" not in css  # every placeholder substituted


def test_icons_render(qapp):
    from gui import icons

    for maker in (
        icons.app_icon,
        icons.tray_icon,
        lambda s: icons.file_icon(s),
        lambda s: icons.device_icon(s),
        lambda s: icons.direction_icon(True, s),
        lambda s: icons.direction_icon(False, s),
        lambda s: icons.status_dot(s, "ok"),
    ):
        pm = maker(32)
        assert not pm.isNull()
        assert pm.width() == 32


# --------------------------------------------------------------------------- #
# main window + panels
# --------------------------------------------------------------------------- #

def test_main_window_visible_with_title(ctx, qapp):
    window = ctx.window
    assert window.isVisible()
    assert "virusShare" in window.windowTitle()
    assert window.devices is not None
    assert window.queue is not None


def test_device_panel_upsert_and_remove(ctx, qapp):
    panel = ctx.window.devices
    ctx.bridge.deviceFound.emit(make_device())
    qapp.processEvents()
    assert panel.list.count() == 1

    # update in place (same id) does not duplicate
    ctx.bridge.deviceFound.emit(make_device(name="PEER-1-RENAMED"))
    qapp.processEvents()
    assert panel.list.count() == 1
    assert "PEER-1-RENAMED" in panel.list.item(0).text()

    ctx.bridge.deviceLost.emit("peer-1")
    qapp.processEvents()
    assert panel.list.count() == 0


def test_removing_selected_device_clears_selection(ctx, qapp):
    """C4: removing the selected peer must not silently retarget selection."""
    panel = ctx.window.devices
    for suffix in ("a", "b", "c"):
        ctx.bridge.deviceFound.emit(
            make_device(name="PC-" + suffix, device_id="peer-" + suffix)
        )
    qapp.processEvents()
    assert panel.list.count() == 3

    panel.list.setCurrentRow(0)
    selected_before = panel.selected()
    assert selected_before is not None

    removed_id = panel.list.item(0).data(
        __import__("PySide6.QtCore", fromlist=["Qt"]).Qt.ItemDataRole.UserRole
    )
    panel.remove_device(removed_id)
    qapp.processEvents()

    assert panel.selected() is None, "selection must not jump to a neighbour"
    assert not panel.send_button.isEnabled()


def test_discovery_packet_never_earns_trusted_badge(tmp_path):
    """H7: a self-asserted UDP device_id must not light the trusted badge.

    The trust store contains the id, but without a fingerprint-verified
    handshake the badge stays off — spoofing a known id currently shows
    "Trusted" in the list.
    """
    from app import make_device_found_handler
    from core.security import TrustStore
    from gui.bridge import ThreadBridge

    store = TrustStore(tmp_path / "trust.json")
    store.add("peer-1", "PEER-1", "ab" * 32)
    assert store.is_trusted("peer-1")  # the spoofed id IS in the store

    bridge = ThreadBridge()
    seen = []
    bridge.deviceFound.connect(lambda d: seen.append(d))
    handler = make_device_found_handler(bridge)

    handler(make_device(device_id="peer-1"))
    assert len(seen) == 1
    assert seen[0].is_trusted is False, "discovery packet earned the badge"


def test_device_trusted_signal_updates_badge(ctx, qapp):
    """H7: the fp-verified signal lights/clears the badge in the device list."""
    panel = ctx.window.devices
    ctx.bridge.deviceFound.emit(make_device(name="PC-V", device_id="peer-v"))
    qapp.processEvents()
    assert panel._devices["peer-v"].is_trusted is False

    ctx.bridge.deviceTrusted.emit("peer-v", True)
    qapp.processEvents()
    assert panel._devices["peer-v"].is_trusted is True
    assert "Trusted: yes" in panel.list.item(0).toolTip()

    ctx.bridge.deviceTrusted.emit("peer-v", False)
    qapp.processEvents()
    assert panel._devices["peer-v"].is_trusted is False
    assert "Trusted: no" in panel.list.item(0).toolTip()


def test_session_handler_marks_fp_verified_peer(qapp):
    """H7: only a fingerprint-verified handshake may light the badge."""
    from types import SimpleNamespace

    from app import make_session_handler
    from gui.bridge import ThreadBridge
    from network.protocol import ProtocolError

    bridge = ThreadBridge()
    trusted_seen = []
    bridge.deviceTrusted.connect(lambda did, ok: trusted_seen.append((did, ok)))

    class FakeManager:
        def __init__(self):
            self.calls = []

        def begin_receive(self, peer):
            self.calls.append("begin")
            return object()

        def receive_context(self, model, **kw):
            return None

        def finish_receive(self, model, report):
            self.calls.append("finish")

    class FakeConn:
        def __init__(self, trusted):
            self.result = SimpleNamespace(
                trusted=trusted,
                device=SimpleNamespace(device_id="peer-v"),
            )
            self.peer_device = SimpleNamespace(device_id="peer-v", name="PC")

        def expect(self, *args, **kw):
            raise ProtocolError("test stub - no wire here")

    manager = FakeManager()
    handler = make_session_handler(manager, bridge, conflict=None)

    handler(FakeConn(trusted=True))
    assert trusted_seen == [("peer-v", True)]
    assert manager.calls == ["begin", "finish"]

    handler(FakeConn(trusted=False))
    assert trusted_seen == [("peer-v", True)], "unverified peer got a badge"
    assert manager.calls == ["begin", "finish", "begin", "finish"]


def test_session_handler_finishes_receive_on_crash(qapp, monkeypatch):
    """H2: an unexpected exception must not leave the session ACTIVE forever.

    ``handle_incoming`` only catches ProtocolError/OSError; a TypeError from
    a malformed FILE_LIST escaped the handler, ``finish_receive`` never ran,
    and the session stayed ACTIVE with no history row.
    """
    from types import SimpleNamespace

    import transfer.receiver as receiver_mod
    from app import make_session_handler
    from gui.bridge import ThreadBridge
    from network.protocol import ProtocolError

    def boom(session, ctx):
        raise TypeError("malformed FILE_LIST")

    monkeypatch.setattr(receiver_mod, "handle_incoming", boom)

    bridge = ThreadBridge()

    class FakeManager:
        def __init__(self):
            self.calls = []
            self.reports = []

        def begin_receive(self, peer):
            self.calls.append("begin")
            return object()

        def receive_context(self, model, **kw):
            return None

        def finish_receive(self, model, report):
            self.calls.append("finish")
            self.reports.append(report)

    class FakeConn:
        result = SimpleNamespace(
            trusted=False, device=SimpleNamespace(device_id="peer-x")
        )
        peer_device = SimpleNamespace(device_id="peer-x", name="PC")

    manager = FakeManager()
    handler = make_session_handler(manager, bridge, conflict=None)
    handler(FakeConn())  # pre-fix: TypeError escapes here

    assert manager.calls == ["begin", "finish"], "finish_receive never ran"
    assert "malformed" in manager.reports[0].error


def test_settings_changes_reach_transfer_manager(ctx, qapp, monkeypatch):
    """H4: the settings dialog must refresh the manager's snapshot."""
    import gui.main_window as mw_mod

    applied = []
    monkeypatch.setattr(
        ctx.manager, "apply_settings", lambda cfg: applied.append(cfg)
    )

    class FakeSettingsDialog:
        def __init__(self, settings, parent=None):
            pass

        def exec(self):
            return True

    monkeypatch.setattr(mw_mod, "SettingsDialog", FakeSettingsDialog)
    ctx.window.show_settings()
    assert applied, "settings dialog did not apply settings to the manager"


def test_receive_location_change_updates_manager(ctx, qapp, monkeypatch, tmp_path):
    """H4: 'Change Location' must make new files land in the new dir."""
    new_dir = tmp_path / "new-loc"
    monkeypatch.setattr(
        ctx.window.receiver_screen, "pick_location", lambda: str(new_dir)
    )
    ctx.window._change_receive_location()
    qapp.processEvents()
    assert ctx.manager.receive_dir == new_dir, (
        "manager still receives into the old directory"
    )


def test_queue_upsert_select_and_buttons(ctx, qapp):
    from models import TransferStatus

    queue = ctx.window.queue
    session = make_session(status=TransferStatus.ACTIVE)
    session.status = TransferStatus.ACTIVE
    ctx.bridge.sessionUpdate.emit(session)
    qapp.processEvents()
    assert queue.session_count() == 1

    queue.table.selectRow(0)
    qapp.processEvents()
    assert queue.selected_session_id() == session.id
    assert queue.pause_btn.isEnabled()
    assert not queue.resume_btn.isEnabled()
    assert queue.cancel_btn.isEnabled()
    assert not queue.open_btn.isEnabled()

    # move to completed
    session.status = TransferStatus.COMPLETED
    session.end_time = datetime.now()
    ctx.bridge.sessionUpdate.emit(session)
    qapp.processEvents()
    assert not queue.pause_btn.isEnabled()
    assert queue.open_btn.isEnabled()


def test_session_finished_recorded_in_history(ctx, qapp):
    session = make_session()
    ctx.bridge.sessionFinished.emit(session)
    qapp.processEvents()
    ctx.window.flush_history()
    assert ctx.history.count() == 1
    entry = ctx.history.recent()[0]
    assert entry.peer_name == "PEER-1"
    assert entry.status == "completed"
    # the queue row reflects the final state too
    assert ctx.queue.session_count() == 1


def test_queue_clear_finished(ctx, qapp):
    from models import TransferStatus

    ctx.bridge.sessionUpdate.emit(make_session(status=TransferStatus.COMPLETED))
    ctx.bridge.sessionUpdate.emit(make_session(status=TransferStatus.FAILED))
    qapp.processEvents()
    assert ctx.queue.session_count() == 2
    ctx.queue.clear_finished()
    assert ctx.queue.session_count() == 0


def test_trust_removal_updates_store(ctx, qapp):
    ctx.window._toggle_trust("some-device", False)
    assert not ctx.trust_store.is_trusted("some-device")
    toast = ctx.window.toasts.toast
    assert toast is not None
    assert toast.title_label.text() == "Trust removed"


# --------------------------------------------------------------------------- #
# dialogs (constructed only - never exec'd)
# --------------------------------------------------------------------------- #

def test_approval_dialog_constructs(qapp):
    from gui.pairing_dialog import ApprovalDialog

    dialog = ApprovalDialog(
        {
            "name": "LAPTOP-7",
            "ip": "192.168.1.7",
            "device_id": "x",
            "fingerprint": "ab" * 32,
            "code": "482913",
            "code_full": "4829-1122-3344-5566",
        }
    )
    assert dialog.windowTitle() == "Connection request"
    dialog.close()


def test_conflict_dialog_constructs_and_choose(qapp):
    from gui.conflict_dialog import ConflictDialog

    dialog = ConflictDialog(
        {
            "relpath": "docs/report.pdf",
            "dest_path": "C:/recv/docs/report.pdf",
            "incoming_size": 5000,
            "existing_size": 4000,
        }
    )
    dialog._choose("keep_both")
    assert dialog.action == "keep_both"
    assert dialog.apply_all is False
    from PySide6.QtWidgets import QDialog

    assert dialog.result() == QDialog.DialogCode.Accepted
    dialog.close()


def test_conflict_dialog_reject_maps_to_skip(qapp, monkeypatch):
    """M1: Esc/X (reject) must behave like the default button - Skip - and
    must NOT abort the whole transfer the way 'cancel' does."""
    from gui.conflict_dialog import ConflictDialog

    def exec_and_reject(self):
        self.reject()
        return int(self.result())

    monkeypatch.setattr(ConflictDialog, "exec", exec_and_reject)
    action, apply_all = ConflictDialog.ask({"relpath": "a.txt"})
    assert action == "skip"
    assert apply_all is False


def test_conflict_dialog_explicit_cancel_still_cancels(qapp, monkeypatch):
    """M1: the explicit 'Cancel transfer' button keeps its meaning."""
    from gui.conflict_dialog import ConflictDialog

    def exec_cancel(self):
        self._choose("cancel")
        return int(self.result())

    monkeypatch.setattr(ConflictDialog, "exec", exec_cancel)
    action, apply_all = ConflictDialog.ask({"relpath": "a.txt"})
    assert action == "cancel"
    assert apply_all is False


def test_conflict_dialog_apply_all_survives_accept(qapp, monkeypatch):
    """M1: checkbox + Skip returns apply_to_all=True (unchanged behavior)."""
    from gui.conflict_dialog import ConflictDialog

    def exec_skip_all(self):
        self._apply_all.setChecked(True)
        self._choose("skip")
        return int(self.result())

    monkeypatch.setattr(ConflictDialog, "exec", exec_skip_all)
    action, apply_all = ConflictDialog.ask({"relpath": "a.txt"})
    assert action == "skip"
    assert apply_all is True


def test_settings_dialog_saves_to_settings(qapp, tmp_path):
    from core.config import Settings
    from gui.settings_dialog import SettingsDialog

    settings = Settings(path=tmp_path / "s.json", create_dirs=False)
    dialog = SettingsDialog(settings)
    dialog.concurrency.setValue(9)
    dialog.theme.setCurrentIndex(2)  # dark
    dialog.verify.setChecked(False)
    dialog._save()

    assert settings.get("max_concurrent_transfers") == 9
    assert settings.get("theme") == "dark"
    assert settings.get("verify_checksums") is False
    # persisted to disk
    on_disk = Settings(path=tmp_path / "s.json", create_dirs=False)
    assert on_disk.get("max_concurrent_transfers") == 9
    dialog.close()


def test_history_dialog_fills_table(qapp, tmp_path):
    from database.history import HistoryDB
    from gui.history_dialog import HistoryDialog

    db = HistoryDB(tmp_path / "h.db")
    db.record(make_session())
    dialog = HistoryDialog(db)
    assert dialog.table.rowCount() == 1
    assert "PEER-1" in dialog.table.item(0, 2).text()
    dialog.close()
    db.close()


# --------------------------------------------------------------------------- #
# bridge
# --------------------------------------------------------------------------- #

def test_bridge_future_roundtrip(qapp):
    from gui.bridge import ThreadBridge

    bridge = ThreadBridge()
    request_id = bridge._new_request()
    bridge.resolve_approval(request_id, True)
    assert bridge._wait(request_id, 1.0, False) is True


def test_bridge_timeout_uses_default():
    from gui.bridge import ThreadBridge

    bridge = ThreadBridge()
    request_id = bridge._new_request()
    assert bridge._wait(request_id, 0.05, "skip") == "skip"
    assert request_id not in bridge._pending


def test_bridge_conflict_apply_all_answer_stored_in_scope():
    """M19: 'apply to all' must land in the session scope, not on the shared
    bridge where the next session would inherit it."""
    from gui.bridge import ThreadBridge

    bridge = ThreadBridge()
    scope = {}
    bridge.conflictRequested.connect(
        lambda rid, payload: bridge.resolve_conflict(
            rid, "replace", apply_all=True
        )
    )
    action = bridge.request_conflict({"relpath": "x"}, scope=scope, timeout=5)
    assert action == "replace"
    assert scope.get("override") == "replace", (
        "apply-all answer was not stored in the session scope"
    )


def test_bridge_conflict_timeout_defaults_to_skip():
    from gui.bridge import ThreadBridge

    bridge = ThreadBridge()
    # nobody resolves the prompt -> timeout path returns the safe default
    assert (
        bridge.request_conflict({"relpath": "x"}, default="skip", timeout=0.05)
        == "skip"
    )
    assert not bridge._pending


def test_prompt_timeouts_never_outlive_peer_socket_waits():
    """M20: approval/conflict prompts wait 300 s while the peer's control
    socket gives up at 180 s - the dialog stays open after the other side
    already abandoned the connection, so the user answers a dead prompt."""
    from core.constants import CONTROL_MESSAGE_TIMEOUT
    from gui.bridge import APPROVAL_TIMEOUT, CONFLICT_TIMEOUT

    assert APPROVAL_TIMEOUT < CONTROL_MESSAGE_TIMEOUT, (
        f"approval prompt ({APPROVAL_TIMEOUT}s) outlives the peer socket wait "
        f"({CONTROL_MESSAGE_TIMEOUT}s)"
    )
    assert CONFLICT_TIMEOUT < CONTROL_MESSAGE_TIMEOUT, (
        f"conflict prompt ({CONFLICT_TIMEOUT}s) outlives the peer socket wait "
        f"({CONTROL_MESSAGE_TIMEOUT}s)"
    )


def test_bridge_queued_prompt_roundtrip(qapp):
    """C1: a GUI answer delivered after the emit must reach the worker.

    Reproduces the real queued-signal flow: worker emits, then blocks in
    ``_wait``; the GUI thread answers a moment later.  If ``_wait`` pops the
    future before waiting, the answer is discarded and the worker times out.
    """
    import threading

    from gui.bridge import ThreadBridge

    bridge = ThreadBridge()
    seen = []
    bridge.approvalRequested.connect(lambda rid, payload: seen.append(rid))

    result = {}

    def worker():
        result["value"] = bridge.request_approval(
            {"name": "PEER"}, default=False, timeout=3.0
        )

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    deadline = time.time() + 2.0
    while not seen and time.time() < deadline:
        qapp.processEvents()
        time.sleep(0.01)
    assert seen, "prompt never reached the GUI"

    resolved_at = time.time()
    bridge.resolve_approval(seen[0], True)
    t.join(timeout=5.0)
    assert not t.is_alive()
    assert result.get("value") is True, "GUI answer was discarded"
    assert time.time() - resolved_at < 2.0, "worker slept through the answer"
    assert not bridge._pending


def test_auto_accept_only_for_trusted_peers(qapp, tmp_path):
    """C2: auto_accept_trusted must never pair an unknown device."""
    import threading
    import time as _time

    from core.security import TrustStore, compute_pairing_code
    from gui.bridge import ThreadBridge, make_approval_callback
    from network.protocol import DeviceInfo

    store = TrustStore(tmp_path / "trust.json")
    store.add("dev-1", "PEER-1", "aa" * 32)

    def make(dev_id, name):
        return DeviceInfo(
            name=name, ip="1.2.3.4", port=54322, device_id=dev_id,
            os_version="", app_version="1.0.0", capabilities=[],
        )

    code = compute_pairing_code("aa" * 32, "bb" * 32)
    bridge = ThreadBridge()
    seen = []
    bridge.approvalRequested.connect(lambda rid, payload: seen.append(rid))
    approve = make_approval_callback(bridge, lambda: True, trust_store=store)

    # trusted fingerprint -> auto-accepted, no dialog
    assert approve(make("dev-1", "PEER-1"), "aa" * 32, "cc" * 32, code) is True
    assert not seen, "trusted peer must not prompt"

    # unknown device -> must go through the human prompt, never auto-accept
    result = {}

    def worker():
        result["value"] = approve(make("evil", "EVIL"), "dd" * 32, "cc" * 32, code)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    deadline = _time.time() + 2.0
    while not seen and _time.time() < deadline:
        qapp.processEvents()
        _time.sleep(0.01)
    assert seen, "untrusted peer was auto-accepted without prompting"

    bridge.resolve_approval(seen[0], False)
    t.join(timeout=5.0)
    assert not t.is_alive()
    assert result.get("value") is False
    assert not bridge._pending


def test_conflict_callback_maps_to_enum(monkeypatch):
    from gui.bridge import ThreadBridge, make_conflict_callback
    from transfer.receiver import ConflictAction, ConflictRequest
    from pathlib import Path
    import tempfile

    bridge = ThreadBridge()
    monkeypatch.setattr(
        bridge, "request_conflict", lambda payload, **kw: "keep_both"
    )
    callback = make_conflict_callback(bridge)

    decision = callback(
        ConflictRequest(
            relpath="a.txt",
            dest_path=Path(tempfile.gettempdir()) / "a.txt",
            incoming_size=1,
            existing_size=2,
        )
    )
    assert decision.action is ConflictAction.KEEP_BOTH


# --------------------------------------------------------------------------- #
# tray
# --------------------------------------------------------------------------- #

def test_tray_constructs_safely(qapp):
    from gui.tray import AppTray

    tray = AppTray(None)
    assert isinstance(tray.available, bool)
    # offscreen platform has no tray -> notify must be a no-op, not a crash
    tray.notify("t", "b")
    tray.show_warning("t", "b")
    tray.set_icon_state(True)

def test_connect_by_ip_dispatches(ctx, qapp, monkeypatch, tmp_path):
    from PySide6.QtWidgets import QFileDialog, QInputDialog

    seen = {}

    def fake_send(_self, target, paths, *, title=None):
        seen["target"] = target
        seen["paths"] = paths
        return make_session()

    monkeypatch.setattr(type(ctx.window.manager), "send_files", fake_send)
    monkeypatch.setattr(
        QInputDialog,
        "getText",
        lambda *a, **k: ("10.0.0.5:60000", True),
    )
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"x" * 16)
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileNames",
        lambda *a, **k: ([str(sample)], ""),
    )

    ctx.window.connect_by_ip()
    qapp.processEvents()

    assert seen["target"].ip == "10.0.0.5"
    assert seen["target"].port == 60000
    assert seen["target"].device_id == "ip:10.0.0.5:60000"
    assert ctx.queue.session_count() == 1


def test_connect_by_ip_rejects_bad_port(ctx, qapp, monkeypatch):
    from PySide6.QtWidgets import QFileDialog, QInputDialog, QMessageBox

    warned = []
    monkeypatch.setattr(
        QInputDialog, "getText", lambda *a, **k: ("10.0.0.5:zzz", True)
    )
    monkeypatch.setattr(
        QMessageBox, "warning", lambda *a, **k: warned.append(a)
    )
    monkeypatch.setattr(
        QFileDialog, "getOpenFileNames", lambda *a, **k: ([], "")
    )

    ctx.window.connect_by_ip()
    qapp.processEvents()

    assert warned and "Invalid port" in warned[0][2]
    assert ctx.queue.session_count() == 0


def test_connect_by_ip_cancel_is_noop(ctx, qapp, monkeypatch):
    from PySide6.QtWidgets import QInputDialog

    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("", False))
    ctx.window.connect_by_ip()
    qapp.processEvents()
    assert ctx.queue.session_count() == 0


# --------------------------------------------------------------------------- #
# animations
# --------------------------------------------------------------------------- #

def test_fade_in_and_out_run_to_completion(qapp):
    from gui import animations
    from PySide6.QtWidgets import QWidget

    widget = QWidget()
    widget.show()
    qapp.processEvents()

    animations.complete(animations.fade_in(widget, 60))
    qapp.processEvents()
    assert widget.isVisible()
    assert widget.graphicsEffect() is None  # effect cleaned up after fade

    animations.complete(animations.fade_out(widget, 60))
    qapp.processEvents()
    assert not widget.isVisible()
    assert widget.graphicsEffect() is None


def test_pulse_restores_opacity(qapp):
    from gui import animations
    from PySide6.QtWidgets import QWidget

    widget = QWidget()
    widget.show()
    animations.complete(animations.pulse(widget, 80))
    qapp.processEvents()
    assert widget.isVisible()
    assert widget.graphicsEffect() is None


def test_row_insert_animation_grows_row(qapp):
    from gui import animations
    from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

    table = QTableWidget(1, 1)
    table.setItem(0, 0, QTableWidgetItem("some fairly tall content"))
    anim = animations.animate_row_insert(table, 0, 60)
    assert table.rowHeight(0) <= 2  # starts collapsed
    animations.complete(anim)
    qapp.processEvents()
    assert table.rowHeight(0) >= 8
    table.deleteLater()


def test_queue_insert_animation_lifecycle(ctx, qapp):
    from gui import animations
    from models import TransferStatus

    ctx.bridge.sessionUpdate.emit(make_session(status=TransferStatus.ACTIVE))
    qapp.processEvents()
    anims = ctx.queue._row_anims
    assert anims, "new row should have an insert animation"
    for anim in list(anims.values()):
        animations.complete(anim)
    qapp.processEvents()
    assert not ctx.queue._row_anims
    assert ctx.queue.table.rowHeight(0) >= 20


def test_device_empty_state_transitions(ctx, qapp):
    panel = ctx.devices
    assert panel.empty.isVisible()
    assert not panel.list.isVisible()

    ctx.bridge.deviceFound.emit(make_device())
    qapp.processEvents()
    assert panel.list.isVisible()
    assert not panel.empty.isVisible()

    ctx.bridge.deviceLost.emit("peer-1")
    qapp.processEvents()
    assert panel.empty.isVisible()
    assert not panel.list.isVisible()


def test_queue_empty_state_transitions(ctx, qapp):
    from models import TransferStatus

    queue = ctx.queue
    assert queue.empty.isVisible()
    assert not queue.table.isVisible()

    ctx.bridge.sessionUpdate.emit(make_session(status=TransferStatus.COMPLETED))
    qapp.processEvents()
    assert queue.table.isVisible()
    assert not queue.empty.isVisible()

    queue.clear_finished()
    qapp.processEvents()
    assert queue.empty.isVisible()
    assert not queue.table.isVisible()


def test_progress_delegate_interpolates_toward_target(ctx, qapp):
    from models import TransferStatus

    queue = ctx.queue
    session = make_session(status=TransferStatus.ACTIVE)
    session.status = TransferStatus.ACTIVE
    session.transferred_size = 0
    ctx.bridge.sessionUpdate.emit(session)
    qapp.processEvents()

    delegate = queue.delegate
    assert session.id in delegate._targets

    delegate.set_progress(session.id, 90.0, "active", fresh=True)
    assert delegate.value_for(session.id) == 0.0  # fresh rows fill from zero
    for _ in range(80):
        delegate._tick()
    assert delegate.value_for(session.id) == 90.0

    delegate.drop(session.id)
    assert session.id not in delegate._targets


def test_progress_delegate_paints(qapp):
    from PySide6.QtCore import QRect, Qt
    from PySide6.QtGui import QImage, QPainter
    from PySide6.QtWidgets import (
        QStyleOptionViewItem,
        QTableWidget,
        QTableWidgetItem,
    )

    from gui.transfer_queue import ProgressDelegate

    table = QTableWidget(1, 3)
    table.setItem(0, 0, QTableWidgetItem("sid-1"))
    table.setItem(0, 2, QTableWidgetItem("photo.bin"))
    table.item(0, 0).setData(Qt.ItemDataRole.UserRole, "sid-1")

    delegate = ProgressDelegate(table)
    delegate.set_progress("sid-1", 100.0, "ok")
    delegate._display["sid-1"] = 62.0  # mid-animation frame

    index = table.model().index(0, 2)
    option = QStyleOptionViewItem()
    option.initFrom(table)
    option.rect = QRect(0, 0, 240, 36)

    image = QImage(240, 36, QImage.Format.Format_ARGB32)
    image.fill(0)
    painter = QPainter(image)
    delegate.paint(painter, option, index)
    painter.end()

    painted = any(
        image.pixelColor(x, y).alpha() > 0
        for x in range(image.width())
        for y in range(image.height())
    )
    assert painted, "delegate should paint text and a progress bar"
    table.deleteLater()


# --------------------------------------------------------------------------- #
# toasts
# --------------------------------------------------------------------------- #

def test_toast_shows_and_places_inside_window(ctx, qapp):
    window = ctx.window
    toast = window.toasts.show(
        "Transfer complete", "Sent to PEER-1 - 3 file(s)", "ok", duration_ms=0
    )
    qapp.processEvents()
    assert toast.isVisible()
    assert window.toasts.toast is toast
    assert toast.title_label.text() == "Transfer complete"
    # placed bottom-right, fully inside the window
    assert toast.x() >= 0 and toast.y() >= 0
    assert toast.x() + toast.width() <= window.width()
    assert toast.y() + toast.height() <= window.height()

    window.toasts.dismiss(immediate=True)
    assert window.toasts.toast is None
    assert not toast.isVisible()


def test_session_finished_shows_toast(ctx, qapp):
    ctx.bridge.sessionFinished.emit(make_session())
    qapp.processEvents()
    toast = ctx.window.toasts.toast
    assert toast is not None
    assert "Transfer complete" in toast.title_label.text()


def test_notifications_disabled_means_no_toast(ctx, qapp):
    ctx.settings.set("show_notifications", False, save=False)
    ctx.bridge.sessionFinished.emit(make_session())
    qapp.processEvents()
    assert ctx.window.toasts.toast is None


# --------------------------------------------------------------------------- #
# drag & drop
# --------------------------------------------------------------------------- #

def test_drop_dispatches_to_selected_device(ctx, qapp, monkeypatch, tmp_path):
    captured = {}
    monkeypatch.setattr(
        ctx.window,
        "_dispatch",
        lambda info, paths: captured.update(info=info, paths=paths),
    )
    ctx.bridge.deviceFound.emit(make_device())
    qapp.processEvents()
    ctx.devices.list.setCurrentRow(0)

    sample = tmp_path / "dropped.bin"
    sample.write_bytes(b"x" * 8)
    ctx.window._handle_drop([sample])

    assert captured["info"].ip == "192.168.1.50"
    assert captured["paths"] == [sample]


def test_drop_without_device_prompts(ctx, qapp, monkeypatch):
    from pathlib import Path

    from PySide6.QtWidgets import QMessageBox

    prompted = []
    monkeypatch.setattr(
        QMessageBox, "information", lambda *a: prompted.append(a)
    )
    dispatched = []
    monkeypatch.setattr(
        ctx.window, "_dispatch", lambda info, paths: dispatched.append(paths)
    )

    ctx.window._handle_drop([Path("C:/nowhere.bin")])
    qapp.processEvents()

    assert dispatched == []
    assert len(prompted) == 1
    assert "Select a device" in prompted[0][2]


def test_drag_enter_accepts_urls_only(ctx, qapp):
    from PySide6.QtCore import QMimeData, QPoint, Qt, QUrl
    from PySide6.QtGui import QDragEnterEvent

    def make_event(mime):
        return QDragEnterEvent(
            QPoint(5, 5),
            Qt.DropAction.CopyAction,
            mime,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
        )

    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile("C:/tmp/x.bin")])
    event = make_event(mime)
    ctx.window.dragEnterEvent(event)
    assert event.isAccepted()

    mime_text = QMimeData()
    mime_text.setText("no files")
    event2 = make_event(mime_text)
    ctx.window.dragEnterEvent(event2)
    assert not event2.isAccepted()


# --------------------------------------------------------------------------- #
# Phase 3 GUI group - M1..M14 (reproduce-first)
# --------------------------------------------------------------------------- #

def _make_row_device(name, device_id, ip="192.168.1.50", trusted=False):
    import time as _time

    from network.discovery import DiscoveredDevice
    from network.protocol import DeviceInfo

    return DiscoveredDevice(
        info=DeviceInfo(
            name=name, ip=ip, port=54322, device_id=device_id,
            os_version="", app_version="", capabilities=[],
        ),
        last_seen=_time.time(),
        is_trusted=trusted,
    )


def test_sender_row_refreshes_on_device_update(qapp):
    """M3: an existing sender row must repaint name/IP/status on re-emit."""
    from gui.sender_screen import SenderScreen

    screen = SenderScreen()
    screen.upsert_device(_make_row_device("OLD-NAME", "peer-1", ip="10.0.0.1"))
    row = screen._rows["peer-1"]
    assert row._name.text() == "OLD-NAME"

    screen.upsert_device(
        _make_row_device("NEW-NAME", "peer-1", ip="10.0.0.2", trusted=True)
    )
    assert row._name.text() == "NEW-NAME"
    assert row._meta.text() == "10.0.0.2"
    assert "trusted" in row._status.text().lower()
    screen.deleteLater()


def test_sender_remove_device_disables_send_button(qapp, tmp_path):
    """M4: removing the selected device must refresh the send button."""
    from gui.sender_screen import SenderScreen

    screen = SenderScreen()
    screen.upsert_device(make_device())  # auto-selects
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"x")
    screen.add_paths([sample])
    assert screen.send_button.isEnabled()

    screen.remove_device("peer-1")
    assert screen.selected() is None
    assert not screen.send_button.isEnabled(), "send button left enabled (M4)"
    screen.deleteLater()


def test_sender_click_highlights_selected_row(qapp):
    """M5: clicking a row's Select button must set the #devrow[selected state."""
    from gui.sender_screen import SenderScreen

    screen = SenderScreen()
    screen.upsert_device(make_device(device_id="a"))
    screen.upsert_device(make_device(device_id="b"))
    row_b = screen._rows["b"]
    row_b.select_button.click()

    assert screen.selected() is not None
    assert screen.selected().device_id == "b"
    assert row_b.property("selected") is True, "clicked row never highlighted (M5)"
    assert screen._rows["a"].property("selected") is False
    screen.deleteLater()


def _drop_on_page(ctx, qapp, monkeypatch, tmp_path, show_page):
    from PySide6.QtWidgets import QMessageBox

    monkeypatch.setattr(QMessageBox, "information", lambda *a: None)
    dispatched = []
    monkeypatch.setattr(
        ctx.window, "_dispatch", lambda info, paths: dispatched.append(paths)
    )
    sample = tmp_path / "dropped.bin"
    sample.write_bytes(b"x" * 8)
    show_page()
    ctx.window._handle_drop([sample])
    qapp.processEvents()
    return sample, dispatched


def test_drop_on_role_screen_opens_sender_with_paths(ctx, qapp, monkeypatch, tmp_path):
    """M6: a drop on the role screen must land visibly in the sender screen."""
    sample, dispatched = _drop_on_page(
        ctx, qapp, monkeypatch, tmp_path, ctx.window.show_role_screen
    )
    assert ctx.window.current_page == "sender"
    assert ctx.window.sender_screen.paths == [sample]
    assert dispatched == []


def test_drop_on_receiver_screen_opens_sender_with_paths(ctx, qapp, monkeypatch, tmp_path):
    """M6: a drop on the receiver screen must not dispatch invisibly."""
    sample, dispatched = _drop_on_page(
        ctx, qapp, monkeypatch, tmp_path, ctx.window.show_receiver_screen
    )
    assert ctx.window.current_page == "sender"
    assert ctx.window.sender_screen.paths == [sample]
    assert dispatched == []


def _find_menu_action(menu, needle):
    for action in menu.actions():
        if action.isSeparator():
            continue
        if needle.lower() in action.text().lower():
            return action
        if action.menu() is not None:
            found = _find_menu_action(action.menu(), needle)
            if found is not None:
                return found
    return None


def test_mode_menu_action_returns_to_role_screen(ctx, qapp):
    """M7: home menu must offer a route back to the role chooser."""
    ctx.window.show_home()
    action = _find_menu_action(ctx.window.menuBar(), "mode")
    assert action is not None, "no Mode action in the menu bar (M7)"
    action.trigger()
    qapp.processEvents()
    assert ctx.window.current_page == "role"


def test_tray_offers_switch_mode_action(qapp, monkeypatch):
    """M7: the tray menu carries the same switch-mode route."""
    from PySide6.QtWidgets import QSystemTrayIcon

    from gui.tray import AppTray

    monkeypatch.setattr(QSystemTrayIcon, "isSystemTrayAvailable", lambda: True)
    tray = AppTray(None)
    assert tray.available
    texts = [a.text() for a in tray._menu.actions() if a.text()]
    assert any("mode" in t.lower() for t in texts), f"no mode action: {texts}"

    fired = []
    tray.modeRequested.connect(lambda: fired.append(True))
    for action in tray._menu.actions():
        if "mode" in action.text().lower():
            action.trigger()
    assert fired == [True]


def test_dialogs_declare_delete_on_close(qapp, tmp_path):
    """M8: per-request dialogs must not accumulate as children of the window."""
    from PySide6.QtCore import Qt

    from core.config import Settings
    from database.history import HistoryDB
    from gui.conflict_dialog import ConflictDialog
    from gui.history_dialog import HistoryDialog
    from gui.pairing_dialog import ApprovalDialog
    from gui.sender_screen import ManualConnectDialog
    from gui.settings_dialog import SettingsDialog

    settings = Settings(path=tmp_path / "s.json", create_dirs=False)
    db = HistoryDB(tmp_path / "h.db")
    try:
        dialogs = [
            ConflictDialog({"relpath": "a.txt"}),
            ApprovalDialog(
                {
                    "name": "X",
                    "ip": "1.2.3.4",
                    "device_id": "x",
                    "fingerprint": "ab" * 32,
                    "code": "123456",
                    "code_full": "1234-5678-9012-3456",
                }
            ),
            HistoryDialog(db),
            SettingsDialog(settings),
            ManualConnectDialog(),
        ]
        for dialog in dialogs:
            assert dialog.testAttribute(Qt.WidgetAttribute.WA_DeleteOnClose), (
                f"{type(dialog).__name__} lacks WA_DeleteOnClose (M8)"
            )
            dialog.close()
    finally:
        db.close()


def test_flash_ticks_are_safe_after_item_deletion(qapp, capfd, monkeypatch):
    """M9: flashing a list item that was cleared must not raise every frame."""
    import sys

    from PySide6.QtGui import QColor
    from PySide6.QtWidgets import QListWidget

    from gui.animations import flash_item_background

    lw = QListWidget()
    lw.addItem("probe")
    item = lw.item(0)
    anim = flash_item_background(lw, item, duration=10_000)
    lw.clear()  # deletes the item while the flash is still running

    captured = []
    monkeypatch.setattr(sys, "excepthook", lambda *args: captured.append(args))
    anim.valueChanged.emit(QColor(0, 0, 0, 40))
    anim.finished.emit()

    _, err = capfd.readouterr()
    assert not [a for a in captured if a[0] is RuntimeError], captured
    assert "RuntimeError" not in err, err


def test_settings_dialog_reports_invalid_value_and_stays_open(
    qapp, tmp_path, monkeypatch
):
    """M10: a rejected value must be reported, not silently dropped."""
    from PySide6.QtWidgets import QMessageBox

    from core.config import Settings
    from gui.settings_dialog import SettingsDialog

    monkeypatch.chdir(tmp_path)  # any mkdir side-effect stays in tmp
    settings = Settings(path=tmp_path / "s.json", create_dirs=False)
    original = str(settings.get("save_received_files_to"))

    dialog = SettingsDialog(settings)
    dialog.receive_dir.setText("relative/download")  # Settings rejects this
    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a: warnings.append(a))
    dialog._save()

    assert warnings, "invalid value was dropped silently (M10)"
    assert dialog.result() != dialog.DialogCode.Accepted
    assert str(settings.get("save_received_files_to")) == original


def test_settings_dialog_autostart_only_after_successful_save(
    qapp, tmp_path, monkeypatch
):
    """M10: registry autostart must not be written before settings persist."""
    from PySide6.QtWidgets import QMessageBox

    from core.config import Settings
    from gui.settings_dialog import SettingsDialog
    import utils.windows as win

    settings = Settings(path=tmp_path / "s.json", create_dirs=False)
    applied = []
    monkeypatch.setattr(win, "set_autostart", lambda on: applied.append(on))
    monkeypatch.setattr(QMessageBox, "warning", lambda *a: None)

    def boom():
        raise OSError("disk full")

    monkeypatch.setattr(settings, "save", boom)

    dialog = SettingsDialog(settings)
    dialog.autostart.setChecked(True)
    dialog._save()

    assert applied == [], "registry touched before settings were persisted (M10)"
    assert dialog.result() != dialog.DialogCode.Accepted


def test_settings_dialog_flags_network_restart(qapp, tmp_path):
    """M10: port/encryption changes must be marked as restart-needed."""
    from core.config import Settings
    from gui.settings_dialog import SettingsDialog

    settings = Settings(path=tmp_path / "s.json", create_dirs=False)
    dialog = SettingsDialog(settings)
    assert dialog.restart_needed is False

    dialog.discovery_port.setValue(55555)
    dialog._save()
    assert dialog.restart_needed is True


def test_show_settings_mentions_restart_for_port_change(ctx, qapp, monkeypatch):
    """M10: the save confirmation must say when a restart is required."""
    from PySide6.QtWidgets import QMessageBox

    monkeypatch.setattr(QMessageBox, "warning", lambda *a: None)

    class FakeDialog:
        def __init__(self, *args, **kwargs):
            self.restart_needed = True

        def exec(self):
            return 1  # QDialog.Accepted

    monkeypatch.setattr("gui.main_window.SettingsDialog", FakeDialog)
    ctx.window.show_settings()
    message = ctx.window.statusBar().currentMessage().lower()
    assert "restart" in message, f"no restart hint: {message!r}"


def test_cleared_finished_row_stays_cleared(ctx, qapp):
    """M11: a late duplicate finish event must not resurrect a cleared row."""
    session = make_session()
    ctx.bridge.sessionFinished.emit(session)
    qapp.processEvents()
    assert ctx.queue.session_count() == 1

    ctx.queue.clear_finished()
    assert ctx.queue.session_count() == 0

    ctx.window._on_session_finished(session)  # late queued duplicate
    qapp.processEvents()
    ctx.window.flush_history()
    assert ctx.queue.session_count() == 0, "cleared row resurrected (M11)"
    assert ctx.history.count() >= 1, "history must still record the transfer"


def test_status_bar_stays_visible_off_home(ctx, qapp):
    """M12: status messages must be readable on every page."""
    for page in (
        ctx.window.show_role_screen,
        ctx.window.show_sender_screen,
        ctx.window.show_receiver_screen,
        ctx.window.show_home,
    ):
        page()
        qapp.processEvents()
        assert ctx.window.statusBar().isVisible(), f"hidden on {page.__name__} (M12)"


def test_close_dismiss_first_dialog_stops_quit(ctx, qapp, monkeypatch):
    """M13: X/ESC on the first close prompt must abort, not stack a second."""
    from PySide6.QtGui import QCloseEvent
    from PySide6.QtWidgets import QMessageBox

    from models import TransferStatus

    ctx.settings.set("minimize_to_tray", True, save=False)
    active = make_session(status=TransferStatus.ACTIVE)
    monkeypatch.setattr(
        type(ctx.manager), "sessions", property(lambda self: [active])
    )

    answers = []

    def question_dismissed(parent, title, *args, **kwargs):
        answers.append(title)
        return QMessageBox.StandardButton.NoButton  # user pressed X

    monkeypatch.setattr(QMessageBox, "question", question_dismissed)
    event = QCloseEvent()
    ctx.window.closeEvent(event)
    assert len(answers) == 1, "stacked a second dialog on dismiss (M13)"
    assert event.isAccepted() is False

    # explicit No on the first dialog still asks the quit confirmation
    answers.clear()

    def question_no(parent, title, *args, **kwargs):
        answers.append(title)
        return QMessageBox.StandardButton.No

    monkeypatch.setattr(QMessageBox, "question", question_no)
    event2 = QCloseEvent()
    ctx.window.closeEvent(event2)
    assert len(answers) == 2
    assert event2.isAccepted() is False


def test_open_folder_available_for_cancelled(ctx, qapp):
    """M14: cancelled transfers keep their partials - Open folder must work."""
    from models import TransferStatus

    cancelled = make_session(status=TransferStatus.CANCELLED)
    ctx.queue.upsert_session(cancelled)
    ctx.queue.table.selectRow(0)
    qapp.processEvents()
    assert ctx.queue.open_btn.isEnabled(), "Open folder disabled for CANCELLED (M14)"
    assert ctx.queue._can_open_folder(TransferStatus.CANCELLED)
    assert ctx.queue._can_open_folder(TransferStatus.COMPLETED)
    assert not ctx.queue._can_open_folder(TransferStatus.ACTIVE)


# --------------------------------------------------------------------------- #
# M19 / M26 - conflict scoping and off-thread history writes
# --------------------------------------------------------------------------- #

def test_conflict_apply_all_scoped_to_one_session(ctx, qapp, monkeypatch):
    """M19: 'apply to all' must not leak into the next receive session."""
    from pathlib import Path

    import gui.main_window as mw_mod
    from gui.bridge import make_conflict_callback
    from transfer.receiver import ConflictAction, ConflictRequest

    prompts = []

    def fake_ask(payload, parent):
        prompts.append(payload.get("relpath"))
        return ("replace", True)

    monkeypatch.setattr(mw_mod.ConflictDialog, "ask", fake_ask)

    def req():
        return ConflictRequest(
            relpath="f.bin",
            dest_path=Path("incoming") / "f.bin",
            incoming_size=10,
            existing_size=20,
        )

    session_a = make_conflict_callback(ctx.bridge)
    first = session_a(req())
    assert prompts == ["f.bin"], "conflict dialog was not shown"
    second = session_a(req())
    assert prompts == ["f.bin"], "apply-all choice was not reused in-session"
    assert first.action is ConflictAction.REPLACE
    assert second.action is ConflictAction.REPLACE

    session_b = make_conflict_callback(ctx.bridge)
    third = session_b(req())
    assert prompts == ["f.bin", "f.bin"], (
        "apply-all leaked into the next session (M19)"
    )
    assert third.action is ConflictAction.REPLACE
    assert not ctx.bridge._pending


def test_session_finished_records_history_off_gui_thread(ctx, qapp):
    """M26: history writes must leave the GUI thread - a slow commit (up to
    the 15 s sqlite timeout) would freeze the window."""
    import threading

    calls = []
    original = ctx.history.record

    def spy(session):
        calls.append(threading.get_ident())
        return original(session)

    ctx.history.record = spy
    ctx.window._on_session_finished(make_session())
    deadline = time.time() + 5.0
    while not calls and time.time() < deadline:
        qapp.processEvents()
        time.sleep(0.01)
    assert calls, "history.record never ran"
    assert calls[0] != threading.get_ident(), (
        "history.record ran on the GUI thread (M26)"
    )
    ctx.window.flush_history()


# --------------------------------------------------------------------------- #
# M36 - approval/conflict dialogs must never stack modally
# --------------------------------------------------------------------------- #

def test_approval_dialogs_do_not_stack_modally(ctx, monkeypatch):
    """M36: while one peer's approval dialog is open, a second peer's request
    must queue behind it instead of opening a nested modal exec() on top."""
    from concurrent.futures import Future

    from gui.pairing_dialog import ApprovalDialog

    ctx.bridge._pending["req-a"] = Future()
    ctx.bridge._pending["req-b"] = Future()

    state = {"depth": 0, "max_depth": 0, "order": []}

    def fake_ask(payload, parent):
        state["depth"] += 1
        state["max_depth"] = max(state["max_depth"], state["depth"])
        state["order"].append(payload["name"])
        if payload["name"] == "PC-A":
            # a concurrent peer connects while this dialog is still open
            ctx.bridge.approvalRequested.emit("req-b", {"name": "PC-B"})
            QApplication.processEvents()
        state["depth"] -= 1
        return True

    monkeypatch.setattr(ApprovalDialog, "ask", fake_ask)

    ctx.window._on_approval_requested("req-a", {"name": "PC-A"})

    assert state["max_depth"] == 1, "approval dialogs stacked modally (M36)"
    assert state["order"] == ["PC-A", "PC-B"], (
        "queued approval was not shown after the first dialog closed (M36)"
    )
    assert ctx.bridge._pending["req-a"].result() is True
    assert ctx.bridge._pending["req-b"].result() is True


def test_conflict_prompt_waits_for_open_approval_dialog(ctx, monkeypatch):
    """M36: approval and conflict prompts share a single dialog slot - a
    conflict raised during an approval must not nest a second exec()."""
    from concurrent.futures import Future

    from gui.conflict_dialog import ConflictDialog
    from gui.pairing_dialog import ApprovalDialog

    ctx.bridge._pending["req-a"] = Future()
    ctx.bridge._pending["req-c"] = Future()

    state = {"depth": 0, "max_depth": 0, "order": []}

    def fake_approval(payload, parent):
        state["depth"] += 1
        state["max_depth"] = max(state["max_depth"], state["depth"])
        state["order"].append("approval:" + payload["name"])
        ctx.bridge.conflictRequested.emit("req-c", {"relpath": "x.txt"})
        QApplication.processEvents()
        state["depth"] -= 1
        return True

    def fake_conflict(payload, parent):
        state["depth"] += 1
        state["max_depth"] = max(state["max_depth"], state["depth"])
        state["order"].append("conflict:" + payload["relpath"])
        state["depth"] -= 1
        return ("skip", False)

    monkeypatch.setattr(ApprovalDialog, "ask", fake_approval)
    monkeypatch.setattr(ConflictDialog, "ask", fake_conflict)

    ctx.window._on_approval_requested("req-a", {"name": "PC-A"})

    assert state["max_depth"] == 1, (
        "conflict dialog nested inside an open approval (M36)"
    )
    assert state["order"] == ["approval:PC-A", "conflict:x.txt"]
    assert ctx.bridge._pending["req-a"].result() is True
    assert ctx.bridge._pending["req-c"].result() == ("skip", False)
