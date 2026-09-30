"""virusShare - discovered peers panel (left side of the main window)."""

from __future__ import annotations

from typing import Dict, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui import animations, icons
from gui.styles import current_palette
from gui.widgets import EmptyState
from utils.formatting import format_timestamp

_TRUSTED_SUFFIX = "  \u2713 trusted"


class DevicePanel(QWidget):
    """Lists LAN peers; double-click or press Send to push files."""

    sendRequested = Signal(object)          # DiscoveredDevice
    trustToggled = Signal(str, bool)        # device_id, trusted
    inspectRequested = Signal(str)          # device_id (open pairing details)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._items: Dict[str, QListWidgetItem] = {}
        self._devices: Dict[str, object] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)

        title = QLabel("Devices")
        title.setObjectName("heading")
        root.addWidget(title)

        hint = QLabel("Peers on this network")
        hint.setObjectName("muted")
        root.addWidget(hint)

        self.list = QListWidget()
        self.list.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.list.customContextMenuRequested.connect(self._context_menu)
        self.list.itemDoubleClicked.connect(
            lambda item: self._emit_selected(self.sendRequested)
        )
        self.list.setMinimumWidth(220)
        root.addWidget(self.list, 1)

        self.empty = EmptyState(
            title="Searching for devices\u2026",
            hint="Devices on this LAN appear here automatically.\n"
            "Same network + Private firewall profile required.",
        )
        root.addWidget(self.empty, 1)

        self.send_button = QPushButton("Send files\u2026")
        self.send_button.setObjectName("primary")
        self.send_button.setEnabled(False)
        self.send_button.clicked.connect(
            lambda: self._emit_selected(self.sendRequested)
        )
        root.addWidget(self.send_button)

        self.list.currentItemChanged.connect(
            lambda *_: self.send_button.setEnabled(self.selected() is not None)
        )

        self._empty_shown: Optional[bool] = None  # first refresh applies silently
        self._refresh_empty_state()

    # ------------------------------------------------------------------ #
    # model updates (called from the GUI thread via bridge signals)
    # ------------------------------------------------------------------ #

    def upsert_device(self, device) -> None:
        device_id = device.info.device_id
        self._devices[device_id] = device
        text = f"{device.info.name}\n{device.info.ip} · {device.status_text}"
        if getattr(device, "is_trusted", False):
            text += _TRUSTED_SUFFIX

        item = self._items.get(device_id)
        is_new = item is None
        if is_new:
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, device_id)
            self.list.addItem(item)
            self._items[device_id] = item
        item.setText(text)
        item.setIcon(
            icons.device_icon(18, "#22c55e" if device.is_alive else "#98a2b3")
        )
        item.setToolTip(
            f"{device.info.name}\n{device.info.ip}:{device.info.port}\n"
            f"Last seen: {format_timestamp(_last_seen(device))}\n"
            f"Trusted: {'yes' if device.is_trusted else 'no'}"
        )
        if is_new:
            # subtle highlight so a newly discovered peer draws the eye
            animations.flash_item_background(
                self.list, item, current_palette().get("accent", "#3b82f6")
            )
        self._refresh_empty_state()

    def remove_device(self, device_id: str) -> None:
        item = self._items.pop(device_id, None)
        self._devices.pop(device_id, None)
        if item is not None:
            row = self.list.row(item)
            was_current = self.list.currentRow() == row
            self.list.takeItem(row)
            if was_current:
                # takeItem slides the current-row marker onto a neighbour,
                # which would silently retarget the next transfer; clear it.
                self.list.setCurrentItem(None)
        self._refresh_empty_state()

    def clear(self) -> None:
        self.list.clear()
        self._items.clear()
        self._devices.clear()
        self._refresh_empty_state()

    def set_trusted(self, device_id: str, trusted: bool) -> None:
        device = self._devices.get(device_id)
        if device is not None:
            device.is_trusted = trusted
            self.upsert_device(device)

    # ------------------------------------------------------------------ #
    # selection
    # ------------------------------------------------------------------ #

    def selected(self) -> Optional[object]:
        item = self.list.currentItem()
        if item is None:
            return None
        device_id = item.data(Qt.ItemDataRole.UserRole)
        return self._devices.get(device_id)

    def select_first(self) -> None:
        if self.list.count() and self.list.currentRow() < 0:
            self.list.setCurrentRow(0)

    def _emit_selected(self, signal: Signal) -> None:
        device = self.selected()
        if device is not None:
            signal.emit(device)

    def _context_menu(self, pos) -> None:
        device = self.selected()
        if device is None:
            return
        menu = QMenu(self)
        send = menu.addAction("Send files…")
        send.triggered.connect(lambda: self.sendRequested.emit(device))
        if device.is_trusted:
            menu.addSeparator()
            trust = menu.addAction("Remove trust")
            trust.triggered.connect(
                lambda: self.trustToggled.emit(device.info.device_id, False)
            )
        menu.exec(self.list.mapToGlobal(pos))

    def _refresh_empty_state(self) -> None:
        empty = self.list.count() == 0
        if empty:
            self.empty.set_content(
                "Searching for devices\u2026",
                "Devices on this LAN appear here automatically.\n"
                "Same network + Private firewall profile required.",
            )
        # plain visibility swap: opacity effects are unsafe on item views
        self.empty.setVisible(empty)
        self.list.setVisible(not empty)
        self._empty_shown = empty


def _last_seen(device):
    return getattr(device, "last_seen", None)
