"""virusShare - system tray icon and menu."""

from __future__ import annotations

import logging
from typing import Optional

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from gui import icons

log = logging.getLogger(__name__)


class AppTray(QObject):
    """Tray icon with menu. All signals fire on the GUI thread."""

    toggleWindow = Signal()
    sendRequested = Signal()
    modeRequested = Signal()
    historyRequested = Signal()
    settingsRequested = Signal()
    quitRequested = Signal()

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._tray: Optional[QSystemTrayIcon] = None
        self._available = QSystemTrayIcon.isSystemTrayAvailable()
        if not self._available:
            log.info("system tray is not available on this host")
            return

        self._tray = QSystemTrayIcon(icons.tray_icon(64), parent)
        self._tray.setToolTip("virusShare")
        self._tray.activated.connect(self._on_activated)

        menu = QMenu()
        toggle = QAction("Show / hide window", menu)
        toggle.triggered.connect(self.toggleWindow.emit)
        menu.addAction(toggle)
        menu.addSeparator()

        send = QAction("Send files…", menu)
        send.triggered.connect(self.sendRequested.emit)
        menu.addAction(send)

        mode = QAction("Switch mode", menu)
        mode.triggered.connect(self.modeRequested.emit)
        menu.addAction(mode)

        history = QAction("History", menu)
        history.triggered.connect(self.historyRequested.emit)
        menu.addAction(history)

        settings = QAction("Settings", menu)
        settings.triggered.connect(self.settingsRequested.emit)
        menu.addAction(settings)

        menu.addSeparator()
        quit_action = QAction("Quit", menu)
        quit_action.triggered.connect(self.quitRequested.emit)
        menu.addAction(quit_action)

        self._menu = menu
        self._tray.setContextMenu(menu)
        self._tray.show()

    @property
    def available(self) -> bool:
        return self._available and self._tray is not None

    def notify(self, title: str, body: str) -> None:
        if self.available and self._tray is not None:
            self._tray.showMessage(title, body, QSystemTrayIcon.MessageIcon.Information, 4000)

    def show_warning(self, title: str, body: str) -> None:
        if self.available and self._tray is not None:
            self._tray.showMessage(title, body, QSystemTrayIcon.MessageIcon.Warning, 5000)

    def set_icon_state(self, busy: bool) -> None:
        if self.available:
            self._tray.setIcon(icons.tray_icon(64))
            self._tray.setToolTip(
                "virusShare — transferring…" if busy else "virusShare"
            )

    def _on_activated(self, reason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self.toggleWindow.emit()
