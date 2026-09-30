"""virusShare - sender mode: pick a receiver, pick files, send."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import constants
from gui import icons
from gui.styles import current_palette
from gui.widgets import EmptyState
from network.protocol import DeviceInfo
from utils.formatting import human_size


class ManualConnectDialog(QDialog):
    """Advanced fallback: connect by IP when UDP discovery is blocked."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Connect manually")
        self.setModal(True)
        # dialogs are one-shot; never accumulate as window children (M8)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._device_info: Optional[DeviceInfo] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        layout.addWidget(QLabel("IP Address:"))
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("192.168.10.2")
        layout.addWidget(self.host_edit)

        layout.addWidget(QLabel("Port:"))
        self.port_edit = QLineEdit(str(constants.TRANSFER_PORT))
        layout.addWidget(self.port_edit)

        self.error_label = QLabel("")
        self.error_label.setObjectName("danger")
        self.error_label.setWordWrap(True)
        self.error_label.setVisible(False)
        layout.addWidget(self.error_label)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Connect")
        buttons.accepted.connect(self._validate_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _validate_accept(self) -> None:
        host = self.host_edit.text().strip()
        if not host:
            self._error("Enter an IP address.")
            return
        try:
            port = int(self.port_edit.text().strip())
        except ValueError:
            self._error("Port must be a number.")
            return
        if not 1 <= port <= 65535:
            self._error("Port must be between 1 and 65535.")
            return
        # capture before accept: with WA_DeleteOnClose the widget is gone
        # once exec() returns, so text() can no longer be read (M8)
        self._device_info = self.device_info()
        self.accept()

    @property
    def result_info(self) -> Optional[DeviceInfo]:
        """Peer captured at accept time (Python attr - safe post-exec)."""
        return self._device_info

    def _error(self, message: str) -> None:
        self.error_label.setText(message)
        self.error_label.setVisible(True)

    def device_info(self) -> DeviceInfo:
        """The peer described by the (validated) fields."""
        host = self.host_edit.text().strip()
        port = int(self.port_edit.text().strip())
        return DeviceInfo(
            name=host,
            ip=host,
            port=port,
            device_id=f"ip:{host}:{port}",
            os_version="",
            app_version="",
            capabilities=[],
        )


class DeviceRow(QFrame):
    """One candidate receiver in the sender list."""

    selectedChanged = Signal(str, bool)  # device_id, selected

    def __init__(self, device, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("devrow")
        self.device = device

        row = QHBoxLayout(self)
        row.setContentsMargins(12, 9, 12, 9)
        row.setSpacing(10)

        self._icon = QLabel()
        row.addWidget(self._icon, 0, Qt.AlignmentFlag.AlignTop)

        texts = QVBoxLayout()
        texts.setSpacing(1)
        self._name = QLabel()
        self._name.setObjectName("devname")
        texts.addWidget(self._name)

        self._meta = QLabel()
        self._meta.setObjectName("devmeta")
        texts.addWidget(self._meta)

        self._status = QLabel()
        self._status.setObjectName("devmeta")
        palette = current_palette()
        self._status.setStyleSheet(
            f"color: {palette.get('ok', '#16a34a')}; font-size: 12px;"
        )
        texts.addWidget(self._status)
        row.addLayout(texts, 1)

        self.select_button = QPushButton("Select")
        self.select_button.setCheckable(True)
        self.select_button.setFixedWidth(90)
        self.select_button.clicked.connect(self._on_clicked)
        row.addWidget(self.select_button, 0, Qt.AlignmentFlag.AlignVCenter)

        self.refresh()

    def refresh(self) -> None:
        """Repaint name/IP/status from the current device (M3)."""
        device = self.device
        alive = getattr(device, "is_alive", True)
        self._icon.setPixmap(
            icons.device_icon(20, "#22c55e" if alive else "#98a2b3")
        )
        self._name.setText(device.info.name)
        self._meta.setText(device.info.ip)
        status_text = getattr(device, "status_text", None) or "Available"
        if getattr(device, "is_trusted", False):
            status_text = f"{status_text} · trusted"
        self._status.setText(f"● {status_text}")

    @property
    def device_id(self) -> str:
        return self.device.info.device_id

    def _on_clicked(self) -> None:
        self.selectedChanged.emit(self.device_id, self.select_button.isChecked())

    def set_selected(self, selected: bool) -> None:
        self.select_button.setChecked(selected)
        self.setProperty("selected", selected)
        self.style().unpolish(self)
        self.style().polish(self)


class SenderScreen(QWidget):
    """Guided send flow: choose receiver, choose files, dispatch."""

    backRequested = Signal()
    sendRequested = Signal(object, list)  # DeviceInfo, [Path]
    manualConnectRequested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: Dict[str, DeviceRow] = {}
        self._selected_id: Optional[str] = None
        self._paths: List[Path] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 16, 24, 20)
        root.setSpacing(12)

        # ---- header -------------------------------------------------- #
        header = QHBoxLayout()
        self.back_button = QPushButton("\u2190 Back")
        self.back_button.setObjectName("link")
        self.back_button.clicked.connect(self.backRequested)
        header.addWidget(self.back_button)
        header.addStretch(1)
        title = QLabel("Send Files")
        title.setObjectName("screentitle")
        header.addWidget(title)
        header.addStretch(1)
        root.addLayout(header)

        # ---- receivers ------------------------------------------------ #
        heading = QLabel("Select receiver")
        heading.setObjectName("heading")
        root.addWidget(heading)

        self.list_host = QWidget()
        self.list_layout = QVBoxLayout(self.list_host)
        self.list_layout.setContentsMargins(0, 0, 0, 0)
        self.list_layout.setSpacing(8)
        self.list_layout.addStretch(1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(self.list_host)
        scroll.setMinimumHeight(120)
        self.scroll = scroll
        root.addWidget(scroll, 3)

        self.empty = EmptyState(
            title="No computers found.",
            hint="Make sure:\n"
            "\u2713 Both PCs are connected through Ethernet\n"
            "\u2713 virusShare is running on both PCs\n"
            "\u2713 Windows Firewall allows virusShare",
        )
        root.addWidget(self.empty, 3)

        list_actions = QHBoxLayout()
        self.retry_button = QPushButton("Retry")
        self.retry_button.clicked.connect(self._on_retry)
        list_actions.addWidget(self.retry_button)
        self.manual_button = QPushButton("Manual IP \u2026")
        self.manual_button.clicked.connect(self.manualConnectRequested)
        list_actions.addWidget(self.manual_button)
        list_actions.addStretch(1)
        root.addLayout(list_actions)

        # ---- files ---------------------------------------------------- #
        files_heading = QLabel("Files to send")
        files_heading.setObjectName("heading")
        root.addWidget(files_heading)

        self.drop_zone = QFrame()
        self.drop_zone.setObjectName("dropzone")
        zone_layout = QVBoxLayout(self.drop_zone)
        zone_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        zone_layout.setSpacing(6)

        drop_hint = QLabel("Drag files or folders here")
        drop_hint.setObjectName("emptytitle")
        drop_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        zone_layout.addWidget(drop_hint, 0, Qt.AlignmentFlag.AlignCenter)

        or_label = QLabel("or")
        or_label.setObjectName("muted")
        or_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        zone_layout.addWidget(or_label, 0, Qt.AlignmentFlag.AlignCenter)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.add_files_button = QPushButton("+ Add Files")
        self.add_files_button.clicked.connect(self._pick_files)
        self.add_folder_button = QPushButton("+ Add Folder")
        self.add_folder_button.clicked.connect(self._pick_folder)
        buttons.addWidget(self.add_files_button)
        buttons.addWidget(self.add_folder_button)
        zone_layout.addLayout(buttons)
        root.addWidget(self.drop_zone)

        self.files_list = QListWidget()
        self.files_list.setMaximumHeight(120)
        self.files_list.itemDoubleClicked.connect(self._remove_item)
        root.addWidget(self.files_list)

        footer = QHBoxLayout()
        self.count_label = QLabel("Selected files: 0")
        self.count_label.setObjectName("muted")
        footer.addWidget(self.count_label)
        footer.addStretch(1)
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_paths)
        footer.addWidget(self.clear_button)
        root.addLayout(footer)

        root.addStretch(1)

        bottom = QHBoxLayout()
        bottom.addStretch(1)
        self.send_button = QPushButton("Send Files \u2192")
        self.send_button.setObjectName("primary")
        self.send_button.setEnabled(False)
        self.send_button.clicked.connect(self._on_send)
        bottom.addWidget(self.send_button)
        root.addLayout(bottom)

        self._refresh_empty_state()

    # ------------------------------------------------------------------ #
    # receivers (fed by bridge.deviceFound / deviceLost)
    # ------------------------------------------------------------------ #

    def upsert_device(self, device) -> None:
        device_id = device.info.device_id
        row = self._rows.get(device_id)
        if row is None:
            row = DeviceRow(device)
            row.selectedChanged.connect(self._on_row_selected)
            self._rows[device_id] = row
            self.list_layout.insertWidget(self.list_layout.count() - 1, row)
            if self._selected_id is None:
                row.set_selected(True)
                self._selected_id = device_id
                self._update_send_button()
        else:
            row.device = device
            row.refresh()
        self._refresh_empty_state()

    def remove_device(self, device_id: str) -> None:
        row = self._rows.pop(device_id, None)
        if row is not None:
            row.setParent(None)
            row.deleteLater()
            if self._selected_id == device_id:
                self._selected_id = None
                # the send button must drop its "enabled" state too (M4)
                self._update_send_button()
        self._refresh_empty_state()

    def clear(self) -> None:
        for device_id in list(self._rows):
            self.remove_device(device_id)

    def _on_row_selected(self, device_id: str, selected: bool) -> None:
        if not selected:
            if self._selected_id == device_id:
                self._selected_id = None
            self._update_send_button()
            return
        row = self._rows.get(device_id)
        if row is not None:
            # apply the #devrow[selected] highlight to the clicked row (M5)
            row.set_selected(True)
        for other_id, other in self._rows.items():
            if other_id != device_id:
                other.set_selected(False)
        self._selected_id = device_id
        self._update_send_button()

    def selected(self) -> Optional[DeviceInfo]:
        if self._selected_id is None:
            return None
        row = self._rows.get(self._selected_id)
        return row.device.info if row is not None else None

    def select_manual_device(self, device_info: DeviceInfo) -> None:
        """Register a manually entered peer and select it."""
        manual = type("ManualDevice", (), {})()
        manual.info = device_info
        manual.is_alive = True
        manual.is_trusted = False
        manual.status_text = "Manual"
        manual.last_seen = None
        self.clear()
        self.upsert_device(manual)
        row = self._rows[device_info.device_id]
        row.set_selected(True)
        self._selected_id = device_info.device_id
        self._update_send_button()

    def _on_retry(self) -> None:
        # discovery beacons continue every 2 s; just re-emphasise the search
        self.empty.set_content(
            "Searching for computers\u2026",
            "virusShare broadcasts on this network every 2 seconds.",
        )

    def _refresh_empty_state(self) -> None:
        empty = not self._rows
        self.empty.setVisible(empty)
        self.scroll.setVisible(not empty)
        self.retry_button.setVisible(empty)
        if not empty:
            self.empty.set_content(
                "No computers found.",
                "Make sure:\n"
                "\u2713 Both PCs are connected through Ethernet\n"
                "\u2713 virusShare is running on both PCs\n"
                "\u2713 Windows Firewall allows virusShare",
            )

    # ------------------------------------------------------------------ #
    # files
    # ------------------------------------------------------------------ #

    @property
    def paths(self) -> List[Path]:
        return list(self._paths)

    def add_paths(self, paths) -> None:
        for raw in paths:
            path = Path(raw)
            if path not in self._paths:
                self._paths.append(path)
                item = QListWidgetItem(self._display_text(path))
                item.setData(Qt.ItemDataRole.UserRole, str(path))
                item.setToolTip(str(path))
                self.files_list.addItem(item)
        self._update_counts()

    def remove_path(self, path: Path) -> None:
        path = Path(path)
        if path in self._paths:
            self._paths.remove(path)
            for row in range(self.files_list.count()):
                item = self.files_list.item(row)
                if Path(item.data(Qt.ItemDataRole.UserRole)) == path:
                    self.files_list.takeItem(row)
                    break
        self._update_counts()

    def clear_paths(self) -> None:
        self._paths.clear()
        self.files_list.clear()
        self._update_counts()

    @staticmethod
    def _display_text(path: Path) -> str:
        if path.is_dir():
            return f"\U0001f4c1 {path.name}"
        try:
            return f"{path.name}    {human_size(path.stat().st_size)}"
        except OSError:
            return path.name

    def _remove_item(self, item: QListWidgetItem) -> None:
        self.remove_path(Path(item.data(Qt.ItemDataRole.UserRole)))

    def _pick_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose files to send")
        self.add_paths(paths)

    def _pick_folder(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Choose folder to send")
        if directory:
            self.add_paths([directory])

    def _update_counts(self) -> None:
        self.count_label.setText(f"Selected files: {len(self._paths)}")
        self._update_send_button()

    # ------------------------------------------------------------------ #
    # dispatch
    # ------------------------------------------------------------------ #

    def _update_send_button(self) -> None:
        self.send_button.setEnabled(
            self.selected() is not None and bool(self._paths)
        )

    def _on_send(self) -> None:
        device = self.selected()
        if device is None or not self._paths:
            return
        self.sendRequested.emit(device, list(self._paths))
