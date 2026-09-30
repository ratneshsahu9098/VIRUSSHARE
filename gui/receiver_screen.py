"""virusShare - receiver mode: waiting-for-sender status screen."""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from utils.network import format_link, primary_interface, primary_ip


class ReceiverScreen(QWidget):
    """Shows who we are, where files land, and that we are listening."""

    backRequested = Signal()
    changeLocationRequested = Signal()

    def __init__(self, settings, parent=None) -> None:
        super().__init__(parent)
        self.settings = settings

        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.setContentsMargins(24, 16, 24, 20)

        content = QWidget()
        content.setMaximumWidth(520)
        box = QVBoxLayout(content)
        box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.setSpacing(6)

        # ---- header (aligned like the sender screen) ------------------- #
        header = QHBoxLayout()
        self.back_button = QPushButton("\u2190 Back")
        self.back_button.setObjectName("link")
        self.back_button.clicked.connect(self.backRequested)
        header.addWidget(self.back_button)
        header.addStretch(1)
        title = QLabel("Receive Files")
        title.setObjectName("screentitle")
        header.addWidget(title)
        header.addStretch(1)
        box.addLayout(header)

        box.addSpacing(24)

        hero = QLabel("\U0001f4e5")
        hero.setStyleSheet("font-size: 40px;")
        hero.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.addWidget(hero, 0, Qt.AlignmentFlag.AlignCenter)

        ready = QLabel("Ready to Receive")
        ready.setObjectName("roletitle")
        ready.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.addWidget(ready, 0, Qt.AlignmentFlag.AlignCenter)

        waiting_hint = QLabel("Your computer is waiting for a sender")
        waiting_hint.setObjectName("muted")
        waiting_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.addWidget(waiting_hint, 0, Qt.AlignmentFlag.AlignCenter)

        box.addSpacing(14)

        self.device_name = QLabel(platform.node() or "PC")
        self.device_name.setObjectName("devname")
        self.device_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.addWidget(self.device_name, 0, Qt.AlignmentFlag.AlignCenter)

        self.ip_label = QLabel(primary_ip())
        self.ip_label.setObjectName("devmeta")
        self.ip_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.addWidget(self.ip_label, 0, Qt.AlignmentFlag.AlignCenter)

        interface = primary_interface()
        self.link_label = QLabel(format_link(interface.name) if interface else "Network")
        self.link_label.setObjectName("devmeta")
        self.link_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.addWidget(self.link_label, 0, Qt.AlignmentFlag.AlignCenter)

        box.addSpacing(14)

        save_caption = QLabel("Save location:")
        save_caption.setObjectName("muted")
        save_caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.addWidget(save_caption, 0, Qt.AlignmentFlag.AlignCenter)

        self.location_label = QLabel("")
        self.location_label.setObjectName("pathlabel")
        self.location_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.location_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        box.addWidget(self.location_label, 0, Qt.AlignmentFlag.AlignCenter)

        self.change_button = QPushButton("Change Location")
        self.change_button.clicked.connect(self.changeLocationRequested)
        box.addWidget(self.change_button, 0, Qt.AlignmentFlag.AlignCenter)

        box.addSpacing(26)

        self.status_label = QLabel("Waiting for connection\u2026")
        self.status_label.setObjectName("muted")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.addWidget(self.status_label, 0, Qt.AlignmentFlag.AlignCenter)

        outer.addWidget(content, 0, Qt.AlignmentFlag.AlignCenter)
        self.refresh_location()

    # ------------------------------------------------------------------ #

    @property
    def save_location(self) -> Path:
        return Path(str(self.settings.get("save_received_files_to")))

    def refresh_location(self) -> None:
        path = str(self.save_location)
        self.location_label.setText(path)
        self.location_label.setToolTip(path)

    def set_save_location(self, path) -> bool:
        """Persist a new receive root (False when the caller cancelled)."""
        target = Path(path)
        if not str(target).strip():
            return False
        try:
            target.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False
        self.settings.set("save_received_files_to", str(target), save=True)
        self.refresh_location()
        return True

    def pick_location(self) -> Optional[str]:
        """File-dialog helper (separable for tests); returns None on cancel."""
        current = str(self.save_location)
        directory = QFileDialog.getExistingDirectory(
            self, "Choose save location", current
        )
        return directory or None
