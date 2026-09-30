"""virusShare - lightweight Qt animations.

All helpers are parent-owned (no leaked animations) and safe to call from
the GUI thread.  They return the animation object so tests - and callers
that need sequencing - can ``finish()`` or chain on it.
"""

from __future__ import annotations

from typing import Callable, Optional

from PySide6.QtCore import (
    QAbstractAnimation,
    QEasingCurve,
    QObject,
    QVariantAnimation,
    Qt,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QGraphicsOpacityEffect, QTableWidget, QWidget

import shiboken6

DEFAULT_DURATION = 240

_ACCENT = "#3b82f6"


def _opacity_effect(widget: QWidget) -> QGraphicsOpacityEffect:
    current = widget.graphicsEffect()
    if isinstance(current, QGraphicsOpacityEffect):
        return current
    effect = QGraphicsOpacityEffect(widget)
    effect.setOpacity(1.0)
    widget.setGraphicsEffect(effect)
    return effect


def _safe_opacity(effect: QGraphicsOpacityEffect, value: float) -> None:
    # a competing animation may have cleared the effect mid-flight
    try:
        effect.setOpacity(float(value))
    except RuntimeError:
        pass


def _clear_effect(widget: QWidget) -> None:
    """Drop our opacity effect so views paint natively again."""
    if isinstance(widget.graphicsEffect(), QGraphicsOpacityEffect):
        widget.setGraphicsEffect(None)


def fade_in(
    widget: QWidget,
    duration: int = DEFAULT_DURATION,
    *,
    start: float = 0.0,
    end: float = 1.0,
    on_finished: Optional[Callable[[], None]] = None,
) -> QVariantAnimation:
    """Show ``widget`` and fade it from ``start`` to ``end`` opacity."""
    effect = _opacity_effect(widget)
    effect.setOpacity(start)
    widget.show()

    anim = QVariantAnimation(widget)
    anim.setStartValue(start)
    anim.setEndValue(end)
    anim.setDuration(duration)
    anim.setEasingCurve(QEasingCurve.Type.OutCubic)
    anim.valueChanged.connect(lambda v: _safe_opacity(effect, v))
    if on_finished is not None:
        anim.finished.connect(on_finished)

    def _finish() -> None:
        _safe_opacity(effect, end)
        _clear_effect(widget)

    anim.finished.connect(_finish)
    anim.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
    return anim


def fade_out(
    widget: QWidget,
    duration: int = 200,
    *,
    hide: bool = True,
    on_finished: Optional[Callable[[], None]] = None,
) -> QVariantAnimation:
    """Fade ``widget`` out; optionally hide it when the animation ends."""
    effect = _opacity_effect(widget)
    start_opacity = effect.opacity()

    def _finish() -> None:
        _clear_effect(widget)
        if hide:
            widget.hide()
        if on_finished is not None:
            on_finished()

    anim = QVariantAnimation(widget)
    anim.setStartValue(start_opacity)
    anim.setEndValue(0.0)
    anim.setDuration(duration)
    anim.setEasingCurve(QEasingCurve.Type.InCubic)
    anim.valueChanged.connect(lambda v: _safe_opacity(effect, v))
    anim.finished.connect(_finish)
    anim.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
    return anim


def pulse(
    widget: QWidget,
    duration: int = 600,
    *,
    floor: float = 0.35,
) -> QVariantAnimation:
    """One attention pulse: full -> ``floor`` -> full opacity."""
    effect = _opacity_effect(widget)
    midpoint = max(duration // 2, 1)

    anim = QVariantAnimation(widget)
    anim.setStartValue(0)
    anim.setEndValue(1)
    anim.setDuration(duration)
    anim.setEasingCurve(QEasingCurve.Type.InOutSine)

    def _tick(_value) -> None:
        t = anim.currentTime()
        if t <= midpoint:
            f = t / midpoint
        else:
            f = (duration - t) / max(duration - midpoint, 1)
        _safe_opacity(effect, floor + (1.0 - floor) * f)

    anim.valueChanged.connect(_tick)

    def _finish() -> None:
        _clear_effect(widget)

    anim.finished.connect(_finish)
    anim.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
    return anim


def complete(anim: QAbstractAnimation) -> None:
    """Jump an animation to its end deterministically.

    PySide6 builds expose ``setCurrentTime`` but not ``QAbstractAnimation
    ::finish()``, and ``setCurrentTime(duration)`` emits ``finished`` just
    the same - tests and shutdown paths use this to settle instantly.
    """
    if anim.state() != QAbstractAnimation.State.Stopped:
        anim.setCurrentTime(anim.duration())


def animate_row_insert(
    table: QTableWidget,
    row: int,
    duration: int = 220,
) -> QVariantAnimation:
    """Grow a freshly inserted row from 1px to its natural height."""
    # QHeaderView enforces a minimum section size (~font height); lift it so
    # the row can actually collapse at the start of the animation.
    table.verticalHeader().setMinimumSectionSize(1)
    target = max(table.sizeHintForRow(row), 8)
    table.setRowHeight(row, 1)

    anim = QVariantAnimation(table)
    anim.setStartValue(1)
    anim.setEndValue(target)
    anim.setDuration(duration)
    anim.setEasingCurve(QEasingCurve.Type.OutCubic)
    anim.valueChanged.connect(lambda v: table.setRowHeight(row, int(v)))
    anim.finished.connect(lambda: table.resizeRowToContents(row))
    anim.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
    return anim


def flash_item_background(
    list_widget,
    item,
    color: str = _ACCENT,
    duration: int = 700,
    alpha: int = 110,
) -> QVariantAnimation:
    """Flash a list item's background (e.g. a newly discovered device)."""
    base = QColor(color)
    start = QColor(base.red(), base.green(), base.blue(), alpha)
    end = QColor(base.red(), base.green(), base.blue(), 0)

    anim = QVariantAnimation(list_widget)
    anim.setStartValue(start)
    anim.setEndValue(end)
    anim.setDuration(duration)
    anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def _tick(value: QColor) -> None:
        # the item may be deleted while the flash runs (list clear/remove);
        # skip and stop instead of raising on every frame (M9)
        if not shiboken6.isValid(item):
            anim.stop()
            return
        item.setBackground(value)

    def _reset() -> None:
        if shiboken6.isValid(item):
            item.setBackground(QColor())

    anim.valueChanged.connect(_tick)
    anim.finished.connect(_reset)
    anim.start(QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
    return anim


class TickDriver(QObject):
    """Shared ~30 FPS ticker for painters that need smooth interpolation.

    Consumers register a callback; the timer only runs while at least one
    callback is attached, so idle windows cost nothing.
    """

    def __init__(self, parent: Optional[QObject] = None, interval_ms: int = 33):
        super().__init__(parent)
        from PySide6.QtCore import QTimer

        self._callbacks: dict[str, Callable[[], None]] = {}
        self._timer = QTimer(self)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._tick)

    def add(self, key: str, callback: Callable[[], None]) -> None:
        self._callbacks[key] = callback
        if not self._timer.isActive():
            self._timer.start()

    def remove(self, key: str) -> None:
        self._callbacks.pop(key, None)
        if not self._callbacks and self._timer.isActive():
            self._timer.stop()

    def _tick(self) -> None:
        # copy: callbacks may unregister during iteration
        for callback in list(self._callbacks.values()):
            try:
                callback()
            except Exception:  # noqa: BLE001 - a painter bug must not kill Qt
                pass
