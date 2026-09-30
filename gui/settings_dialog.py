"""virusShare - settings dialog."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.config import Settings

log = logging.getLogger(__name__)

_CHUNK_CHOICES = (
    ("64 KB (slow links)", 64 * 1024),
    ("256 KB", 256 * 1024),
    ("1 MB (recommended)", 1024 * 1024),
    ("4 MB (fast LAN)", 4 * 1024 * 1024),
)


class SettingsDialog(QDialog):
    def __init__(self, settings: Settings, parent=None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("Settings")
        self.setModal(True)
        # one dialog per open; never accumulate as a child (M8)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.restart_needed = False
        self.setMinimumWidth(520)

        root = QVBoxLayout(self)
        tabs = QTabWidget(self)
        root.addWidget(tabs)

        tabs.addTab(self._general_tab(), "General")
        tabs.addTab(self._transfer_tab(), "Transfers")
        tabs.addTab(self._network_tab(), "Network")
        tabs.addTab(self._behavior_tab(), "Behavior")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    # ------------------------------------------------------------------ #

    def _general_tab(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)

        self.receive_dir = QLineEdit(
            str(self.settings.get("save_received_files_to"))
        )
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._pick_dir)
        row = QHBoxLayout()
        row.addWidget(self.receive_dir, 1)
        row.addWidget(browse)
        wrap = QWidget()
        wrap.setLayout(row)
        form.addRow("Save received files to", wrap)

        self.theme = QComboBox()
        self.theme.addItem("Follow system", "system")
        self.theme.addItem("Light", "light")
        self.theme.addItem("Dark", "dark")
        self._select(self.theme, str(self.settings.get("theme")))
        form.addRow("Theme", self.theme)
        return widget

    def _transfer_tab(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)

        self.chunk = QComboBox()
        for label, value in _CHUNK_CHOICES:
            self.chunk.addItem(label, value)
        self._select(self.chunk, int(self.settings.get("chunk_size", 1024 * 1024)))
        form.addRow("Chunk size", self.chunk)

        self.concurrency = QSpinBox()
        self.concurrency.setRange(1, 16)
        self.concurrency.setValue(
            int(self.settings.get("max_concurrent_transfers", 3))
        )
        form.addRow("Max parallel transfers", self.concurrency)

        self.retries = QSpinBox()
        self.retries.setRange(0, 10)
        self.retries.setValue(int(self.settings.get("reconnect_attempts", 3)))
        form.addRow("Reconnect attempts", self.retries)

        self.verify = QCheckBox("Verify SHA-256 checksums after every file")
        self.verify.setChecked(bool(self.settings.get("verify_checksums", True)))
        form.addRow("", self.verify)
        return widget

    def _network_tab(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)

        self.discovery_port = QSpinBox()
        self.discovery_port.setRange(1024, 65535)
        self.discovery_port.setValue(
            int(self.settings.get("discovery_port", 54321))
        )
        form.addRow("Discovery port (UDP)", self.discovery_port)

        self.transfer_port = QSpinBox()
        self.transfer_port.setRange(1024, 65535)
        self.transfer_port.setValue(int(self.settings.get("transfer_port", 54322)))
        form.addRow("Transfer port (TCP)", self.transfer_port)

        self.encryption = QCheckBox(
            "Encrypt transfers with TLS (recommended)"
        )
        self.encryption.setChecked(bool(self.settings.get("enable_encryption", True)))
        form.addRow("", self.encryption)
        return widget

    def _behavior_tab(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)

        self.approval = QCheckBox("Ask before accepting unknown devices")
        self.approval.setChecked(
            bool(self.settings.get("require_connection_approval", True))
        )
        form.addRow("", self.approval)

        self.auto_trusted = QCheckBox("Accept trusted devices without asking")
        self.auto_trusted.setChecked(
            bool(self.settings.get("auto_accept_trusted", False))
        )
        form.addRow("", self.auto_trusted)

        self.tray = QCheckBox("Minimize to tray when closing")
        self.tray.setChecked(bool(self.settings.get("minimize_to_tray", True)))
        form.addRow("", self.tray)

        self.notifications = QCheckBox(
            "Show a notification when a transfer finishes"
        )
        self.notifications.setChecked(
            bool(self.settings.get("show_notifications", True))
        )
        form.addRow("", self.notifications)

        self.autostart = QCheckBox("Start automatically with Windows")
        self.autostart.setChecked(
            bool(self.settings.get("start_with_windows", False))
        )
        try:
            from utils.windows import autostart_available

            self.autostart.setEnabled(autostart_available())
        except Exception:  # noqa: BLE001
            self.autostart.setEnabled(False)
        form.addRow("", self.autostart)
        return widget

    # ------------------------------------------------------------------ #

    def _pick_dir(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Choose download folder", self.receive_dir.text()
        )
        if chosen:
            self.receive_dir.setText(chosen)

    @staticmethod
    def _select(combo: QComboBox, value: Any) -> None:
        for index in range(combo.count()):
            if combo.itemData(index) == value:
                combo.setCurrentIndex(index)
                return

    def _save(self) -> None:
        from core.config import SettingsError

        directory = self.receive_dir.text().strip()
        pending: Dict[str, Any] = {
            "save_received_files_to": directory
            or str(self.settings.get("save_received_files_to")),
            "theme": self.theme.currentData(),
            "chunk_size": self.chunk.currentData(),
            "max_concurrent_transfers": self.concurrency.value(),
            "reconnect_attempts": self.retries.value(),
            "verify_checksums": self.verify.isChecked(),
            "discovery_port": self.discovery_port.value(),
            "transfer_port": self.transfer_port.value(),
            "enable_encryption": self.encryption.isChecked(),
            "require_connection_approval": self.approval.isChecked(),
            "auto_accept_trusted": self.auto_trusted.isChecked(),
            "minimize_to_tray": self.tray.isChecked(),
            "show_notifications": self.notifications.isChecked(),
            "start_with_windows": self.autostart.isChecked(),
        }

        original = {key: self.settings.get(key) for key in pending}
        old_network = (
            int(self.settings.get("discovery_port", 54321)),
            int(self.settings.get("transfer_port", 54322)),
            bool(self.settings.get("enable_encryption", True)),
        )

        for key, value in pending.items():
            try:
                self.settings.set(key, value, save=False)
            except SettingsError:
                self._restore(original)
                log.warning("rejected settings value for %s", key)
                QMessageBox.warning(
                    self,
                    "Settings",
                    f'Invalid value for "{key}". Settings were not saved.',
                )
                return

        try:
            self.settings.save()
        except (OSError, SettingsError) as exc:
            self._restore(original)
            log.exception("could not save settings")
            QMessageBox.warning(
                self, "Settings", f"Could not save settings:\n{exc}"
            )
            return

        # port/encryption knobs only take effect on a restart - say so (M10)
        self.restart_needed = old_network != (
            int(self.settings.get("discovery_port")),
            int(self.settings.get("transfer_port")),
            bool(self.settings.get("enable_encryption")),
        )

        if directory:
            try:
                Path(directory).mkdir(parents=True, exist_ok=True)
            except OSError:
                log.warning("could not create receive directory %s", directory)

        # registry autostart only after the settings are on disk, so a failed
        # save can never leave the two out of sync (M10)
        try:
            from utils.windows import IS_WINDOWS, set_autostart

            if IS_WINDOWS:
                set_autostart(pending["start_with_windows"])
        except Exception:  # noqa: BLE001
            log.exception("could not update autostart")
        self.accept()

    def _restore(self, original: Dict[str, Any]) -> None:
        """Roll staged values back after a rejected/failed save."""
        for key, value in original.items():
            self.settings.set(key, value, save=False)
