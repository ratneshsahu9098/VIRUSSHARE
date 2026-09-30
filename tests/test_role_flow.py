"""virusShare - role selection / sender / receiver mode tests (offscreen)."""

import os
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def ctx(tmp_path, qapp):
    """MainWindow wired like the real app, starting on the role screen."""
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
        start_on_role_screen=True,
    )
    window.show()
    qapp.processEvents()

    ns = type("Ctx", (), {})()
    ns.settings, ns.bridge, ns.manager, ns.window = (
        settings, bridge, manager, window,
    )
    ns.queue = window.queue
    yield ns
    window.close()
    qapp.processEvents()
    manager.shutdown(timeout=3)
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


# --------------------------------------------------------------------------- #
# role screen
# --------------------------------------------------------------------------- #

def test_role_screen_texts_and_signals(qapp):
    from gui.role_screen import RoleScreen

    screen = RoleScreen()
    assert screen.send_card.title_label.text() == "SEND FILES"
    assert screen.receive_card.title_label.text() == "RECEIVE FILES"
    assert "another computer" in screen.send_card.hint_label.text()
    assert "another PC" in screen.receive_card.hint_label.text()

    got = []
    screen.sendChosen.connect(lambda: got.append("send"))
    screen.receiveChosen.connect(lambda: got.append("receive"))
    screen.settingsRequested.connect(lambda: got.append("settings"))

    screen.send_card.clicked.emit()
    screen.receive_card.clicked.emit()

    settings_btns = [
        b
        for b in screen.findChildren(
            __import__("PySide6.QtWidgets", fromlist=["QPushButton"]).QPushButton
        )
        if b.objectName() == "link"
    ]
    assert settings_btns, "settings link button missing"
    settings_btns[0].click()
    assert got == ["send", "receive", "settings"]


# --------------------------------------------------------------------------- #
# navigation (MainWindow)
# --------------------------------------------------------------------------- #

def test_window_starts_on_role_screen(ctx, qapp):
    window = ctx.window
    assert window.current_page == "role"
    assert not window.menuBar().isVisible()
    # M12: the status bar stays visible on every page so status messages
    # (settings saved, location updated, ...) are never hidden
    assert window.statusBar().isVisible()


def test_role_navigation_send_flow(ctx, qapp):
    window = ctx.window
    window.role_screen.sendChosen.emit()
    assert window.current_page == "sender"
    window.sender_screen.backRequested.emit()
    assert window.current_page == "role"

    window.role_screen.receiveChosen.emit()
    assert window.current_page == "receiver"
    window.receiver_screen.backRequested.emit()
    assert window.current_page == "role"


def test_home_shows_menu_and_status(ctx, qapp):
    window = ctx.window
    window.show_home()
    assert window.current_page == "home"
    assert window.menuBar().isVisible()
    assert window.statusBar().isVisible()


def test_default_construction_starts_on_home(tmp_path, qapp):
    from core.config import Settings
    from core.security import TrustStore, load_identity
    from database.history import HistoryDB
    from gui.bridge import ThreadBridge
    from gui.main_window import MainWindow
    from network.protocol import DeviceInfo
    from transfer.manager import TransferManager

    settings = Settings(path=tmp_path / "settings.json", create_dirs=False)
    settings.set("minimize_to_tray", False, save=False)
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
    window = MainWindow(
        settings=settings, manager=manager, history=history,
        bridge=ThreadBridge(), trust_store=TrustStore(tmp_path / "t.json"),
    )
    assert window.current_page == "home"
    window.close()
    manager.shutdown(timeout=3)
    history.close()


# --------------------------------------------------------------------------- #
# sender screen
# --------------------------------------------------------------------------- #

def test_sender_empty_state_until_device_appears(ctx, qapp):
    window = ctx.window
    window.show_sender_screen()
    qapp.processEvents()
    screen = window.sender_screen
    assert screen.empty.isVisible()
    assert not screen.scroll.isVisible()
    assert screen.retry_button.isVisible()
    assert "No computers found" in screen.empty.title_label.text()

    ctx.bridge.deviceFound.emit(make_device())
    qapp.processEvents()
    assert screen.scroll.isVisible()
    assert not screen.empty.isVisible()
    assert len(screen._rows) == 1
    assert screen.selected() is not None
    assert screen.selected().name == "PEER-1"

    ctx.bridge.deviceLost.emit("peer-1")
    qapp.processEvents()
    assert screen.empty.isVisible()
    assert screen.selected() is None


def test_sender_select_is_exclusive(ctx, qapp):
    screen = ctx.window.sender_screen
    ctx.bridge.deviceFound.emit(make_device("PEER-1", "peer-1"))
    ctx.bridge.deviceFound.emit(make_device("PEER-2", "peer-2"))
    qapp.processEvents()
    assert screen.selected().device_id == "peer-1"  # first auto-selected

    screen._on_row_selected("peer-2", True)
    assert screen.selected().device_id == "peer-2"
    screen._on_row_selected("peer-2", True)  # re-emit idempotent
    assert screen.selected().device_id == "peer-2"


def test_sender_file_picking_and_send_button(ctx, qapp, monkeypatch, tmp_path):
    from PySide6.QtWidgets import QFileDialog

    screen = ctx.window.sender_screen
    assert not screen.send_button.isEnabled()

    sample = tmp_path / "hello.txt"
    sample.write_bytes(b"x" * 10)
    folder = tmp_path / "folder"
    folder.mkdir()

    monkeypatch.setattr(
        QFileDialog, "getOpenFileNames",
        lambda *a, **k: ([str(sample)], ""),
    )
    screen.add_files_button.click()
    monkeypatch.setattr(
        QFileDialog, "getExistingDirectory",
        lambda *a, **k: str(folder),
    )
    screen.add_folder_button.click()

    assert screen.paths == [sample, folder]
    assert screen.count_label.text() == "Selected files: 2"
    assert screen.files_list.count() == 2

    screen.clear_button.click()
    assert screen.paths == []
    assert screen.count_label.text() == "Selected files: 0"

    # device alone is not enough
    ctx.bridge.deviceFound.emit(make_device())
    qapp.processEvents()
    assert not screen.send_button.isEnabled()
    screen.add_paths([sample])
    assert screen.send_button.isEnabled()


def test_sender_drop_adds_files_and_duplicates_ignored(ctx, qapp):
    screen = ctx.window.sender_screen
    ctx.window.show_sender_screen()
    sample = Path("C:/some/file.bin")
    ctx.window._handle_drop([sample, sample])
    assert screen.paths == [sample]
    assert screen.count_label.text() == "Selected files: 1"


def test_drop_on_workspace_routes_to_device(ctx, qapp, monkeypatch):
    from types import SimpleNamespace

    captured = []
    monkeypatch.setattr(
        ctx.window, "_dispatch", lambda info, paths: captured.append(paths)
    )
    monkeypatch.setattr(
        ctx.window.devices,
        "selected",
        lambda: SimpleNamespace(info=make_device().info),
    )
    ctx.window.show_home()
    sample = Path("C:/tmp/a.bin")
    ctx.window._handle_drop([sample])
    assert captured == [[sample]]


def test_sender_send_enqueues_and_returns_home(ctx, qapp, tmp_path, monkeypatch):
    from models import TransferStatus

    window = ctx.window
    screen = window.sender_screen
    ctx.bridge.deviceFound.emit(make_device())
    sample = tmp_path / "doc.bin"
    sample.write_bytes(b"data")
    screen.add_paths([sample])
    qapp.processEvents()

    window.show_sender_screen()
    assert window.current_page == "sender"

    session = None

    def fake_send(device_info, paths):
        nonlocal session
        from models import TransferFile, TransferSession

        session = TransferSession(
            computer_id=device_info.device_id,
            computer_name=device_info.name,
            status=TransferStatus.ACTIVE,
        )
        session.add_file(TransferFile(id="f", name="doc.bin", path=str(sample), size=4))
        return session

    monkeypatch.setattr(type(ctx.manager), "send_files", staticmethod(fake_send))
    screen.send_button.click()

    assert session is not None
    assert window.current_page == "home"
    assert window.queue.table.rowCount() == 1

    session.status = TransferStatus.COMPLETED  # clean teardown (no quit dialog)


def test_manual_connect_dialog_validation(qapp):
    from gui.sender_screen import ManualConnectDialog

    dialog = ManualConnectDialog()
    dialog.host_edit.setText("")
    dialog.port_edit.setText("54322")
    dialog._validate_accept()
    assert not dialog.isVisible()
    assert "IP address" in dialog.error_label.text()

    dialog.host_edit.setText("192.168.10.2")
    dialog.port_edit.setText("99999")
    dialog._validate_accept()
    assert "between" in dialog.error_label.text()

    dialog.host_edit.setText("192.168.10.2")
    dialog.port_edit.setText("54323")
    dialog._validate_accept()
    assert not dialog.error_label.isVisible() or dialog.error_label.text() == ""
    device = dialog.device_info()
    assert device.ip == "192.168.10.2"
    assert device.port == 54323
    assert device.device_id == "ip:192.168.10.2:54323"


def test_manual_device_select_via_window(ctx, qapp):
    window = ctx.window
    window.show_sender_screen()
    from gui.sender_screen import ManualConnectDialog

    dialog = ManualConnectDialog()
    dialog.host_edit.setText("10.0.0.7")
    dialog.port_edit.setText("54322")
    dialog._validate_accept()
    window.sender_screen.select_manual_device(dialog.device_info())

    selected = window.sender_screen.selected()
    assert selected.ip == "10.0.0.7"
    assert len(window.sender_screen._rows) == 1


# --------------------------------------------------------------------------- #
# receiver screen
# --------------------------------------------------------------------------- #

def test_receiver_screen_shows_identity_and_location(ctx, qapp):
    screen = ctx.window.receiver_screen
    assert screen.device_name.text()
    assert screen.ip_label.text()
    assert screen.link_label.text()
    assert "Waiting for connection" in screen.status_label.text()
    assert screen.location_label.text() == str(
        ctx.settings.get("save_received_files_to")
    )
    assert screen.location_label.toolTip() == screen.location_label.text()


def test_receiver_change_location(ctx, qapp, monkeypatch, tmp_path):
    window = ctx.window
    screen = window.receiver_screen
    new_dir = tmp_path / "incoming_here"

    monkeypatch.setattr(
        type(screen), "pick_location", lambda self: str(new_dir)
    )
    window._change_receive_location()
    assert ctx.settings.get("save_received_files_to") == str(new_dir)
    assert screen.location_label.text() == str(new_dir)
    assert new_dir.is_dir()

    # cancelling keeps the old location
    monkeypatch.setattr(type(screen), "pick_location", lambda self: None)
    window._change_receive_location()
    assert ctx.settings.get("save_received_files_to") == str(new_dir)


def test_receiver_set_location_rejects_blank(ctx, qapp):
    screen = ctx.window.receiver_screen
    before = str(ctx.settings.get("save_received_files_to"))
    assert screen.set_save_location("   ") is False
    assert str(ctx.settings.get("save_received_files_to")) == before


# --------------------------------------------------------------------------- #
# dispatch failure paths stay on the sender page
# --------------------------------------------------------------------------- #

def test_failed_dispatch_keeps_sender_page(ctx, qapp, monkeypatch, tmp_path):
    window = ctx.window
    screen = window.sender_screen
    ctx.bridge.deviceFound.emit(make_device())
    sample = tmp_path / "x.bin"
    sample.write_bytes(b"x")
    screen.add_paths([sample])
    qapp.processEvents()
    window.show_sender_screen()

    warnings = []
    monkeypatch.setattr(
        QMessageBox, "warning", lambda *a, **k: warnings.append(a)
    )

    def boom(device_info, paths):
        raise ValueError("nothing")

    monkeypatch.setattr(type(ctx.manager), "send_files", staticmethod(boom))
    screen.send_button.click()
    assert window.current_page == "sender"
    assert warnings, "failure must be reported"
