"""virusShare - composite widgets: empty states and toasts."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QObject, QPoint, Qt, QTimer
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from gui import animations, icons


class EmptyState(QWidget):
    """Centered icon + title + hint used when a pane has nothing to show."""

    def __init__(
        self,
        title: str = "",
        hint: str = "",
        icon_size: int = 34,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._icon_size = icon_size

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(4)

        self.icon_label = QLabel()
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.icon_label, 0, Qt.AlignmentFlag.AlignCenter)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("emptytitle")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setWordWrap(True)
        layout.addWidget(self.title_label)

        self.hint_label = QLabel(hint)
        self.hint_label.setObjectName("emptyhint")
        self.hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hint_label.setWordWrap(True)
        layout.addWidget(self.hint_label)

        self.set_content(title, hint)

    def set_content(
        self,
        title: str,
        hint: str = "",
        icon=None,
    ) -> None:
        self.title_label.setText(title)
        self.hint_label.setText(hint)
        self.hint_label.setVisible(bool(hint))
        if icon is None:
            icon = icons.file_icon(self._icon_size, "#98a2b3")
        self.icon_label.setPixmap(icon)


class Toast(QFrame):
    """A small overlay card shown above the status bar."""

    def __init__(
        self,
        title: str,
        body: str = "",
        kind: str = "info",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("toast")
        self.setAttribute(
            Qt.WidgetAttribute.WA_ShowWithoutActivating, True
        )

        colors = {"ok": "#22c55e", "error": "#ef4444", "info": "#3b82f6"}
        accent = colors.get(kind, colors["info"])

        row = QHBoxLayout(self)
        row.setContentsMargins(12, 10, 16, 10)
        row.setSpacing(10)

        dot = QLabel()
        dot.setPixmap(icons.status_dot(10, {"ok": "ok", "error": "error"}.get(kind, "active")))
        row.addWidget(dot, 0, Qt.AlignmentFlag.AlignTop)

        texts = QVBoxLayout()
        texts.setSpacing(1)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("toasttitle")
        texts.addWidget(self.title_label)
        self.body_label: Optional[QLabel] = None
        if body:
            self.body_label = QLabel(body)
            self.body_label.setObjectName("toastbody")
            self.body_label.setWordWrap(True)
            texts.addWidget(self.body_label)
        row.addLayout(texts, 1)

        self._accent = accent
        self.adjustSize()


class ToastManager(QObject):
    """Owns the single visible toast on top of a host window."""

    def __init__(self, host: QWidget):
        super().__init__(host)
        self.host = host
        self._toast: Optional[Toast] = None
        self._dismiss_timer = QTimer(self)
        self._dismiss_timer.setSingleShot(True)
        self._dismiss_timer.timeout.connect(self.dismiss)

    @property
    def toast(self) -> Optional[Toast]:
        return self._toast

    def show(
        self,
        title: str,
        body: str = "",
        kind: str = "info",
        duration_ms: int = 4000,
    ) -> Toast:
        self.dismiss(immediate=True)
        toast = Toast(title, body, kind, self.host)
        self._toast = toast
        toast.adjustSize()
        self._place(toast)
        toast.show()
        toast.raise_()
        animations.fade_in(toast, duration=220)
        if duration_ms > 0:
            self._dismiss_timer.start(duration_ms)
        return toast

    def dismiss(self, immediate: bool = False) -> None:
        self._dismiss_timer.stop()
        toast = self._toast
        self._toast = None
        if toast is None:
            return
        if immediate:
            toast.hide()
            toast.deleteLater()
        else:
            animations.fade_out(
                toast,
                duration=180,
                on_finished=toast.deleteLater,
            )

    def _place(self, toast: Toast) -> None:
        toast.adjustSize()
        margin = 16
        bottom = self.host.height() - 48  # keep clear of the status bar
        x = max(margin, self.host.width() - toast.width() - margin)
        y = max(margin, bottom - toast.height())
        toast.move(QPoint(x, y))

    def reposition(self) -> None:
        if self._toast is not None:
            self._place(self._toast)
