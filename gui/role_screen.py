"""virusShare - first screen: choose Send or Receive mode."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import constants
from gui import icons


class RoleCard(QFrame):
    """One large clickable option on the role-selection screen."""

    clicked = Signal()

    def __init__(self, emoji: str, title: str, hint: str, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("rolecard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(6)
        layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        icon = QLabel(emoji)
        icon.setStyleSheet("font-size: 30px;")
        layout.addWidget(icon)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("cardtitle")
        layout.addWidget(self.title_label)

        self.hint_label = QLabel(hint)
        self.hint_label.setObjectName("cardhint")
        self.hint_label.setWordWrap(True)
        layout.addWidget(self.hint_label)

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)

    def keyPressEvent(self, event) -> None:  # noqa: N802
        if event.key() in (
            Qt.Key.Key_Return,
            Qt.Key.Key_Enter,
            Qt.Key.Key_Space,
        ):
            self.clicked.emit()
            return
        super().keyPressEvent(event)


class RoleScreen(QWidget):
    """'What do you want to do?' - shown before the main workspace."""

    sendChosen = Signal()
    receiveChosen = Signal()
    settingsRequested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.setContentsMargins(40, 40, 40, 40)

        content = QWidget()
        content.setMaximumWidth(620)
        box = QVBoxLayout(content)
        box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.setSpacing(6)

        icon = QLabel()
        icon.setPixmap(icons.app_icon(56))
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.addWidget(icon, 0, Qt.AlignmentFlag.AlignCenter)

        title = QLabel(constants.APP_NAME)
        title.setObjectName("roletitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.addWidget(title, 0, Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel("PC-to-PC Ethernet File Transfer")
        subtitle.setObjectName("rolesubtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.addWidget(subtitle, 0, Qt.AlignmentFlag.AlignCenter)

        spacer = QWidget()
        spacer.setFixedHeight(18)
        box.addWidget(spacer)

        question = QLabel("What do you want to do?")
        question.setObjectName("rolequestion")
        question.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.addWidget(question, 0, Qt.AlignmentFlag.AlignCenter)

        cards = QHBoxLayout()
        cards.setSpacing(16)
        cards.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.send_card = RoleCard(
            "\U0001f4e4",
            "SEND FILES",
            "Send files to\nanother computer",
        )
        self.receive_card = RoleCard(
            "\U0001f4e5",
            "RECEIVE FILES",
            "Receive files\nfrom another PC",
        )
        self.send_card.clicked.connect(self.sendChosen)
        self.receive_card.clicked.connect(self.receiveChosen)
        cards.addWidget(self.send_card)
        cards.addWidget(self.receive_card)
        box.addLayout(cards)

        box.addSpacing(10)

        settings = QPushButton("\u2699 Settings")
        settings.setObjectName("link")
        settings.setCursor(Qt.CursorShape.PointingHandCursor)
        settings.clicked.connect(self.settingsRequested)
        box.addWidget(settings, 0, Qt.AlignmentFlag.AlignCenter)

        outer.addWidget(content, 0, Qt.AlignmentFlag.AlignCenter)
