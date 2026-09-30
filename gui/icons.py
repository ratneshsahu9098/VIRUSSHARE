"""virusShare - programmatically drawn icons.

No hand-made binary assets: everything is painted with QPainter at the
requested pixel size, so the app works from a source checkout and from a
PyInstaller bundle alike.  ``write_ico`` packs the painted frames into a
Windows ``.ico`` for the exe resource (see ``scripts/make_release_assets.py``).
"""

from __future__ import annotations

import struct
from pathlib import Path

from PySide6.QtCore import QBuffer, QIODevice, QPoint, QRectF, Qt
from PySide6.QtGui import (
    QColor,
    QImage,
    QLinearGradient,
    QPainter,
    QPen,
    QPixmap,
)

_ACCENT = "#3b82f6"
_GREEN = "#22c55e"
_AMBER = "#f59e0b"
_RED = "#ef4444"
_SLATE = "#64748b"

#: sizes embedded in the generated ``.ico``
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)


def _painter(device) -> QPainter:
    p = QPainter(device)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    return p


def _draw_app_icon(p: QPainter, size: int) -> None:
    """Paint the app logo (rounded square with an arrow exchange glyph)."""
    grad = QLinearGradient(0, 0, size, size)
    grad.setColorAt(0.0, QColor(_ACCENT))
    grad.setColorAt(1.0, QColor("#1d4ed8"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(grad)
    p.drawRoundedRect(0, 0, size, size, size * 0.24, size * 0.24)

    pen = QPen(QColor("white"))
    pen.setWidthF(size * 0.09)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)

    # up-right arrow (send)
    m = size * 0.30
    p.drawLine(QPoint(int(m), int(size - m)), QPoint(int(size - m), int(m)))
    p.drawLine(QPoint(int(size * 0.58), int(m)), QPoint(int(size - m), int(m)))
    p.drawLine(QPoint(int(size - m), int(m)), QPoint(int(size - m), int(size * 0.42)))


def app_icon(size: int = 64) -> QPixmap:
    """App logo as a pixmap (needs a QApplication - use ``app_image`` headless)."""
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = _painter(pm)
    _draw_app_icon(p, size)
    p.end()
    return pm


def app_image(size: int = 64) -> QImage:
    """App logo as a QImage - works without any QApplication instance."""
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = _painter(img)
    _draw_app_icon(p, size)
    p.end()
    return img


def write_ico(path, sizes: tuple = ICO_SIZES) -> Path:
    """Render :func:`app_image` at ``sizes`` and pack them into a Windows
    ``.ico`` file (PNG-compressed entries, supported since Windows Vista).

    Returns the written path.
    """
    blobs = []
    for size in sizes:
        img = app_image(size)
        buf = QBuffer()
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        if not img.save(buf, "PNG"):
            raise RuntimeError(f"failed to PNG-encode icon frame {size}px")
        blobs.append((size, bytes(buf.data())))

    header = struct.pack("<HHH", 0, 1, len(blobs))  # reserved, type=icon, count
    offset = len(header) + 16 * len(blobs)
    entries = b""
    images = b""
    for size, data in blobs:
        dim = 0 if size >= 256 else size  # 0 encodes 256 in the entry byte
        entries += struct.pack(
            "<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset
        )
        offset += len(data)
        images += data

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(header + entries + images)
    return out


def file_icon(size: int = 16, color: str = _SLATE):
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = _painter(pm)
    p.setPen(QPen(QColor(color), 1.4))
    fold = size * 0.18
    p.drawRoundedRect(
        QRectF(size * 0.14, size * 0.22, size * 0.72, size * 0.60), fold, fold
    )
    p.drawLine(
        QPoint(int(size * 0.14), int(size * 0.40)), QPoint(int(size * 0.86), int(size * 0.40))
    )
    p.end()
    return pm


def device_icon(size: int = 18, color: str = _SLATE):
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = _painter(pm)
    p.setPen(QPen(QColor(color), 1.6))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawRoundedRect(
        QRectF(size * 0.10, size * 0.16, size * 0.80, size * 0.52), 2, 2
    )
    p.drawLine(
        QPoint(int(size * 0.35), int(size * 0.84)), QPoint(int(size * 0.65), int(size * 0.84))
    )
    p.drawLine(
        QPoint(int(size * 0.50), int(size * 0.68)), QPoint(int(size * 0.50), int(size * 0.84))
    )
    p.end()
    return pm


def direction_icon(up: bool, size: int = 16):
    color = _GREEN if up else _ACCENT
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = _painter(pm)
    pen = QPen(QColor(color))
    pen.setWidthF(size * 0.14)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    if up:  # send: arrow pointing up-right
        p.drawLine(QPoint(int(size * 0.25), int(size * 0.75)), QPoint(int(size * 0.75), int(size * 0.25)))
        p.drawLine(QPoint(int(size * 0.45), int(size * 0.25)), QPoint(int(size * 0.75), int(size * 0.25)))
        p.drawLine(QPoint(int(size * 0.75), int(size * 0.25)), QPoint(int(size * 0.75), int(size * 0.55)))
    else:  # receive: arrow pointing down-left
        p.drawLine(QPoint(int(size * 0.75), int(size * 0.25)), QPoint(int(size * 0.25), int(size * 0.75)))
        p.drawLine(QPoint(int(size * 0.25), int(size * 0.55)), QPoint(int(size * 0.25), int(size * 0.75)))
        p.drawLine(QPoint(int(size * 0.25), int(size * 0.75)), QPoint(int(size * 0.55), int(size * 0.75)))
    p.end()
    return pm


def status_dot(size: int = 10, state: str = "idle"):
    colors = {"idle": _SLATE, "active": _ACCENT, "ok": _GREEN, "warn": _AMBER, "error": _RED}
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = _painter(pm)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(colors.get(state, _SLATE)))
    p.drawEllipse(0, 0, size, size)
    p.end()
    return pm


def tray_icon(size: int = 64):
    return app_icon(size)
