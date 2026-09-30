"""virusShare - main application window."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QCloseEvent, QDragEnterEvent, QDropEvent, QKeySequence
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core import constants
from core.config import Settings
from database.history import HistoryDB
from gui import icons
from gui.conflict_dialog import ConflictDialog
from gui.device_panel import DevicePanel
from gui.history_dialog import HistoryDialog
from gui.pairing_dialog import ApprovalDialog
from gui.receiver_screen import ReceiverScreen
from gui.role_screen import RoleScreen
from gui.sender_screen import ManualConnectDialog, SenderScreen
from gui.settings_dialog import SettingsDialog
from gui.transfer_queue import TransferQueue
from gui.widgets import ToastManager
from models import TransferSession, TransferStatus
from network.protocol import DeviceInfo
from transfer.manager import TransferManager

log = logging.getLogger(__name__)

_ACTIVE_STATUSES = (
    TransferStatus.PENDING,
    TransferStatus.ACTIVE,
    TransferStatus.PAUSED,
)


class MainWindow(QMainWindow):
    """Device list + transfer queue + menus, wired to the app context."""

    def __init__(
        self,
        *,
        settings: Settings,
        manager: TransferManager,
        history: HistoryDB,
        bridge,
        trust_store,
        on_shutdown: Optional[Callable[[], None]] = None,
        start_on_role_screen: bool = False,
    ) -> None:
        super().__init__()
        self.settings = settings
        self.manager = manager
        self.history = history
        self.bridge = bridge
        self.trust_store = trust_store
        self.on_shutdown = on_shutdown
        self._force_quit = False
        self._history_executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="history-write"
        )
        self._prompt_queue: List[Tuple[str, str, dict]] = []
        self._prompt_active = False

        self.setWindowTitle(f"{constants.APP_NAME} {constants.APP_VERSION}")
        self.setWindowIcon(icons.app_icon(64))
        self.resize(1020, 660)
        self.setAcceptDrops(True)

        self.toasts = ToastManager(self)
        self._build_central()
        self._build_menu()
        self._wire_bridge()
        self._wire_panels()
        self.statusBar().showMessage(
            f"Ready · UDP {settings.discovery_port} · TCP {settings.transfer_port}"
        )
        if start_on_role_screen:
            self.show_role_screen()
        else:
            self.show_home()

    # ------------------------------------------------------------------ #
    # construction
    # ------------------------------------------------------------------ #

    def _build_central(self) -> None:
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        left = QFrame()
        left.setObjectName("panel")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(10, 10, 10, 10)
        self.devices = DevicePanel()
        left_layout.addWidget(self.devices)
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(10, 10, 10, 0)
        self.queue = TransferQueue()
        right_layout.addWidget(self.queue, 1)
        splitter.addWidget(right)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([280, 720])

        # role -> sender/receiver -> home(workspace) page stack
        self.role_screen = RoleScreen()
        self.sender_screen = SenderScreen()
        self.receiver_screen = ReceiverScreen(self.settings)
        self._stack = QStackedWidget()
        self._stack.addWidget(self.role_screen)
        self._stack.addWidget(self.sender_screen)
        self._stack.addWidget(self.receiver_screen)
        self._stack.addWidget(splitter)
        self._home_widget = splitter
        self.setCentralWidget(self._stack)

        self.role_screen.sendChosen.connect(self.show_sender_screen)
        self.role_screen.receiveChosen.connect(self.show_receiver_screen)
        self.role_screen.settingsRequested.connect(self.show_settings)
        self.sender_screen.backRequested.connect(self.show_role_screen)
        self.receiver_screen.backRequested.connect(self.show_role_screen)
        self.sender_screen.sendRequested.connect(self._on_sender_send)
        self.sender_screen.manualConnectRequested.connect(
            self._sender_manual_connect
        )
        self.receiver_screen.changeLocationRequested.connect(
            self._change_receive_location
        )

    # ------------------------------------------------------------------ #
    # page navigation (role selection -> mode screens -> workspace)
    # ------------------------------------------------------------------ #

    def _goto(self, page: QWidget) -> None:
        self._stack.setCurrentWidget(page)
        on_home = page is self._home_widget
        self.menuBar().setVisible(on_home)
        # the status bar stays visible on every page so status messages
        # (settings saved, location updated, ...) are never hidden (M12)
        if not on_home:
            self.toasts.dismiss(immediate=True)
        self.toasts.reposition()

    def show_role_screen(self) -> None:
        self._goto(self.role_screen)

    def show_sender_screen(self) -> None:
        self._goto(self.sender_screen)

    def show_receiver_screen(self) -> None:
        self._goto(self.receiver_screen)
        self.receiver_screen.refresh_location()

    def show_home(self) -> None:
        self._goto(self._home_widget)

    @property
    def current_page(self) -> str:
        page = self._stack.currentWidget()
        names = {
            self.role_screen: "role",
            self.sender_screen: "sender",
            self.receiver_screen: "receiver",
            self._home_widget: "home",
        }
        return names.get(page, "home")

    def _on_sender_send(self, device_info, paths) -> None:
        if self._dispatch(device_info, paths):
            self.show_home()

    def _sender_manual_connect(self) -> None:
        dialog = ManualConnectDialog(self)
        if dialog.exec():
            # read the value captured at accept time: with WA_DeleteOnClose
            # the dialog's widgets are gone once exec() returns (M8)
            info = dialog.result_info
            if info is not None:
                self.sender_screen.select_manual_device(info)

    def _change_receive_location(self) -> None:
        directory = self.receiver_screen.pick_location()
        if directory and self.receiver_screen.set_save_location(directory):
            self.manager.apply_settings(self.settings.as_dict())
            self.statusBar().showMessage("Save location updated", 4000)

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("&File")

        send_files = QAction("Send &files…", self)
        send_files.setShortcut(QKeySequence.StandardKey.Open)
        send_files.triggered.connect(self.send_files)
        file_menu.addAction(send_files)

        send_folder = QAction("Send fol&der…", self)
        send_folder.triggered.connect(self.send_folder)
        file_menu.addAction(send_folder)

        connect_ip = QAction("Connect to &IP…", self)
        connect_ip.triggered.connect(self.connect_by_ip)
        file_menu.addAction(connect_ip)

        mode = QAction("&Mode…", self)
        mode.triggered.connect(self.show_role_screen)
        file_menu.addAction(mode)
        file_menu.addSeparator()

        history = QAction("&History", self)
        history.setShortcut("Ctrl+H")
        history.triggered.connect(self.show_history)
        file_menu.addAction(history)

        settings = QAction("&Settings…", self)
        settings.setShortcut("Ctrl+,")
        settings.triggered.connect(self.show_settings)
        file_menu.addAction(settings)

        file_menu.addSeparator()
        quit_action = QAction("&Quit", self)
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.request_quit)
        file_menu.addAction(quit_action)

        view_menu = self.menuBar().addMenu("&View")
        clear_done = QAction("Clear finished transfers", self)
        clear_done.triggered.connect(self.queue.clear_finished)
        view_menu.addAction(clear_done)
        refresh = QAction("&Refresh device list", self)
        refresh.setShortcut(QKeySequence.StandardKey.Refresh)
        refresh.triggered.connect(self.devices.clear)
        view_menu.addAction(refresh)

        help_menu = self.menuBar().addMenu("&Help")
        about = QAction(f"&About {constants.APP_NAME}", self)
        about.triggered.connect(self._about)
        help_menu.addAction(about)

    def _wire_bridge(self) -> None:
        self.bridge.deviceFound.connect(self.devices.upsert_device)
        self.bridge.deviceFound.connect(self.sender_screen.upsert_device)
        self.bridge.deviceLost.connect(self.devices.remove_device)
        self.bridge.deviceLost.connect(self.sender_screen.remove_device)
        self.bridge.deviceTrusted.connect(self.devices.set_trusted)
        self.bridge.sessionUpdate.connect(self.queue.upsert_session)
        self.bridge.sessionFinished.connect(self._on_session_finished)
        self.bridge.approvalRequested.connect(self._on_approval_requested)
        self.bridge.conflictRequested.connect(self._on_conflict_requested)

    def _wire_panels(self) -> None:
        self.devices.sendRequested.connect(self._send_to_device)
        self.devices.trustToggled.connect(self._toggle_trust)
        self.queue.pauseRequested.connect(self.manager.pause)
        self.queue.resumeRequested.connect(self.manager.resume)
        self.queue.cancelRequested.connect(self.manager.cancel)
        self.queue.openFolderRequested.connect(self._open_session_folder)
        self.queue.showHistoryRequested.connect(self.show_history)

    # ------------------------------------------------------------------ #
    # bridge handlers (GUI thread)
    # ------------------------------------------------------------------ #

    def _on_approval_requested(self, request_id: str, payload: dict) -> None:
        self._prompt_queue.append(("approval", request_id, payload))
        self._pump_prompts()

    def _on_conflict_requested(self, request_id: str, payload: dict) -> None:
        self._prompt_queue.append(("conflict", request_id, payload))
        self._pump_prompts()

    def _pump_prompts(self) -> None:
        """Show exactly one prompt dialog at a time (M36).

        Each concurrent peer emits its own signal; without this queue the
        handler opened a modal ``exec()`` inside the one already running,
        stacking dialogs and nesting the event loop once per peer.
        """
        if self._prompt_active:
            return
        self._prompt_active = True
        try:
            while self._prompt_queue:
                kind, request_id, payload = self._prompt_queue.pop(0)
                if not self.bridge.is_prompt_pending(request_id):
                    continue  # timed out or cancelled while queued
                if kind == "approval":
                    accepted = ApprovalDialog.ask(payload, self)
                    self.bridge.resolve_approval(request_id, accepted)
                else:
                    action, apply_all = ConflictDialog.ask(payload, self)
                    self.bridge.resolve_conflict(request_id, action, apply_all)
        finally:
            self._prompt_active = False

    def _on_session_finished(self, session: TransferSession) -> None:
        self.queue.upsert_session(session)
        try:
            self._history_executor.submit(self._record_history, session)
        except RuntimeError:
            # executor already shut down during teardown - nothing to write
            log.debug("history executor is closed; skipping record")

        if self.settings.get("show_notifications", True):
            verb = "Sent to" if session.direction == "send" else "Received from"
            window_visible = self.isVisible() and not self.isMinimized()
            if window_visible:
                # in-window toast: no need to interrupt with an OS balloon
                kind = {
                    TransferStatus.COMPLETED: "ok",
                    TransferStatus.FAILED: "error",
                }.get(session.status, "info")
                title = {
                    TransferStatus.COMPLETED: "Transfer complete",
                    TransferStatus.FAILED: "Transfer failed",
                    TransferStatus.CANCELLED: "Transfer cancelled",
                }.get(session.status, "Transfer update")
                body = f"{verb} {session.computer_name} · {len(session.files)} file(s)"
                if session.status is TransferStatus.FAILED:
                    body = session.error_message or "Unknown error"
                self.toasts.show(title, body, kind)
            else:
                tray = getattr(self, "tray", None)
                if tray is not None and tray.available:
                    if session.status is TransferStatus.COMPLETED:
                        tray.notify(
                            "Transfer complete",
                            f"{verb} {session.computer_name} · "
                            f"{len(session.files)} file(s)",
                        )
                    elif session.status is TransferStatus.FAILED:
                        tray.show_warning(
                            "Transfer failed",
                            session.error_message or "Unknown error",
                        )

        active = sum(
            1
            for s in self.manager.sessions
            if s.status in _ACTIVE_STATUSES
        )
        if active:
            self.statusBar().showMessage(f"{active} transfer(s) in progress")

    def _record_history(self, session: TransferSession) -> None:
        try:
            self.history.record(session)
        except Exception:  # noqa: BLE001 - history failure is not fatal
            log.exception("could not record history for %s", session.id)

    def flush_history(self) -> None:
        """Wait until every queued history write has hit the database."""
        self._history_executor.shutdown(wait=True, cancel_futures=False)

    # ------------------------------------------------------------------ #
    # actions
    # ------------------------------------------------------------------ #

    def send_files(self) -> None:
        device = self.devices.selected()
        if device is None:
            QMessageBox.information(
                self,
                "Send files",
                "Select a device from the list first.",
            )
            return
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose files to send")
        if paths:
            self._dispatch(device.info, [Path(p) for p in paths])

    def send_folder(self) -> None:
        device = self.devices.selected()
        if device is None:
            QMessageBox.information(
                self, "Send folder", "Select a device from the list first."
            )
            return
        directory = QFileDialog.getExistingDirectory(self, "Choose folder to send")
        if directory:
            self._dispatch(device.info, [Path(directory)])

    def connect_by_ip(self) -> None:
        """Manual connect when UDP discovery is blocked (firewall, VLAN)."""
        text, ok = QInputDialog.getText(
            self,
            "Connect to device",
            "Peer address (IP or IP:port):",
        )
        if not ok or not text.strip():
            return
        host, _, port_text = text.strip().partition(":")
        host = host.strip()
        if not host:
            return
        port = constants.TRANSFER_PORT
        if port_text:
            try:
                port = int(port_text)
            except ValueError:
                port = -1
            if not 1 <= port <= 65535:
                QMessageBox.warning(
                    self, "Connect to device", f"Invalid port: {port_text}"
                )
                return
        device_info = DeviceInfo(
            name=host,
            ip=host,
            port=port,
            device_id=f"ip:{host}:{port}",
            os_version="",
            app_version="",
            capabilities=[],
        )
        paths, _ = QFileDialog.getOpenFileNames(
            self, f"Send to {host}"
        )
        if paths:
            self._dispatch(device_info, [Path(p) for p in paths])

    def _send_to_device(self, device) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, f"Send to {device.info.name}"
        )
        if not paths:
            return
        self._dispatch(device.info, [Path(p) for p in paths])

    def _dispatch(self, device_info, paths: List[Path]) -> bool:
        """Create and enqueue a send session; True on success (errors are shown)."""
        try:
            session = self.manager.send_files(device_info, paths)
        except ValueError:
            QMessageBox.warning(self, "Send", "Nothing to send.")
            return False
        except OSError as exc:
            QMessageBox.warning(self, "Send", f"Could not start transfer:\n{exc}")
            return False
        self.queue.upsert_session(session)
        self.statusBar().showMessage(
            f"Sending {len(paths)} item(s) to {device_info.name}"
        )
        return True

    # ------------------------------------------------------------------ #
    # drag & drop
    # ------------------------------------------------------------------ #

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        paths = [
            Path(url.toLocalFile())
            for url in event.mimeData().urls()
            if url.isLocalFile()
        ]
        if paths:
            event.acceptProposedAction()
            self._handle_drop(paths)
        else:
            event.ignore()

    def _handle_drop(self, paths: List[Path]) -> None:
        """Route by page: sender collects files, workspace sends to device."""
        if not paths:
            return
        if self._stack.currentWidget() is self.sender_screen:
            self.sender_screen.add_paths(paths)
            return
        if self._stack.currentWidget() is not self._home_widget:
            # role/receiver page: a dropped file is a send intent - show it
            # in the sender screen instead of dispatching invisibly (M6)
            self.show_sender_screen()
            self.sender_screen.add_paths(paths)
            return
        device = self.devices.selected()
        if device is None:
            QMessageBox.information(
                self,
                "Send files",
                "Select a device from the list first, then drop files here.",
            )
            return
        self._dispatch(device.info, paths)

    def show_history(self) -> None:
        dialog = HistoryDialog(self.history, self)
        dialog.exec()

    def show_settings(self) -> None:
        dialog = SettingsDialog(self.settings, self)
        if dialog.exec():
            from gui.styles import apply_theme

            apply_theme(self, str(self.settings.get("theme")))
            self.manager.apply_settings(self.settings.as_dict())
            if getattr(dialog, "restart_needed", False):
                self.statusBar().showMessage(
                    "Settings saved — restart virusShare to apply network changes",
                    6000,
                )
            else:
                self.statusBar().showMessage("Settings saved", 4000)

    def _toggle_trust(self, device_id: str, trusted: bool) -> None:
        # trust is *granted* during pairing; from the list you can only
        # revoke it (re-pairing will prompt again)
        if trusted:
            return
        try:
            self.trust_store.remove(device_id)
        except Exception:  # noqa: BLE001
            log.exception("trust update failed for %s", device_id)
            return
        # fan out: device list badge + app-side discovery record (H7)
        self.bridge.deviceTrusted.emit(device_id, False)
        self.toasts.show(
            "Trust removed",
            "The device will need to be paired again.",
            "info",
            duration_ms=3000,
        )

    def _open_session_folder(self, session_or_id) -> None:
        from utils.windows import open_in_file_manager

        session = (
            self.manager.get(session_or_id)
            if isinstance(session_or_id, str)
            else session_or_id
        )
        target: Optional[Path] = None
        if session is not None:
            for f in session.files:
                if f.path and Path(f.path).exists():
                    target = Path(f.path)
                    break
            if target is None and session.direction == "receive":
                target = Path(self.settings.get("save_received_files_to"))
        if target is None:
            target = Path(self.settings.get("save_received_files_to"))
        open_in_file_manager(target)

    @staticmethod
    def _about_text() -> str:
        """HTML body of the About dialog (pure - testable without a dialog)."""
        import platform

        import PySide6
        from PySide6.QtCore import qVersion

        from core.constants import get_app_data_dir

        return (
            f"<b>{constants.APP_NAME} {constants.APP_VERSION}</b><br><br>"
            "Peer-to-peer LAN file transfer.<br>"
            "Devices find each other over UDP broadcast and move files over "
            "authenticated, optionally encrypted TCP sessions with resume and "
            "SHA-256 verification."
            "<br><br>"
            "<table cellspacing='2'>"
            f"<tr><td>Qt</td><td>{PySide6.__version__} (runtime {qVersion()})</td></tr>"
            f"<tr><td>Python</td><td>{platform.python_version()}</td></tr>"
            f"<tr><td>Data</td><td>{get_app_data_dir()}</td></tr>"
            "</table>"
        )

    def _about(self) -> None:
        QMessageBox.about(
            self,
            f"About {constants.APP_NAME}",
            self._about_text(),
        )

    def request_quit(self) -> None:
        self._force_quit = True
        self.close()

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        active = [
            s
            for s in self.manager.sessions
            if s.status in _ACTIVE_STATUSES
        ]
        if (
            not self._force_quit
            and active
            and self.settings.get("minimize_to_tray", True)
        ):
            answer = QMessageBox.question(
                self,
                "Transfers in progress",
                f"{len(active)} transfer(s) are still running.\n"
                "Hide to tray and keep them going?",
            )
            if answer == QMessageBox.StandardButton.Yes:
                event.ignore()
                self.hide()
                return
            if answer != QMessageBox.StandardButton.No:
                # X/ESC on the prompt: never mind - abort the close instead
                # of falling through to a second dialog (M13)
                event.ignore()
                return
            # fall through to a real quit only on explicit No
        if not self._force_quit and active:
            answer = QMessageBox.question(
                self,
                "Quit",
                f"{len(active)} transfer(s) will be cancelled. Quit anyway?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return

        if self.on_shutdown is not None:
            try:
                self.on_shutdown()
            except Exception:  # noqa: BLE001
                log.exception("shutdown hook failed")
        self._force_quit = True
        event.accept()

    def toggle_visibility(self) -> None:
        if self.isVisible() and not self.isMinimized():
            self.hide()
        else:
            self.showNormal()
            self.raise_()
            self.activateWindow()

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self.toasts.reposition()

    def start_minimized(self) -> None:
        if self.settings.get("minimize_to_tray", True):
            self.hide()
        else:
            self.show()
