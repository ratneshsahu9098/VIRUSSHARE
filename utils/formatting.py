"""virusShare - human-readable byte/time formatting."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def human_size(num_bytes: float, precision: int = 1) -> str:
    """1536 -> '1.5 KB'.  Works for negative/zero inputs too."""
    try:
        value = float(num_bytes)
    except (TypeError, ValueError):
        return "0 B"
    sign = "-" if value < 0 else ""
    value = abs(value)
    for unit in _UNITS:
        if value < 1024.0 or unit == _UNITS[-1]:
            if unit == "B":
                return f"{sign}{int(value)} B"
            return f"{sign}{value:.{precision}f} {unit}"
        value /= 1024.0
    return f"{sign}{value:.{precision}f} {_UNITS[-1]}"


def human_speed(bytes_per_second: Optional[float]) -> str:
    if not bytes_per_second or bytes_per_second <= 0:
        return "—"
    return f"{human_size(bytes_per_second)}/s"


def human_duration(seconds: Optional[float]) -> str:
    if seconds is None or seconds < 0:
        return "—"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {sec}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"


def human_eta(session) -> str:
    """ETA from a models.TransferSession (uses its speed/eta helpers)."""
    try:
        eta = session.get_eta()
    except Exception:  # noqa: BLE001 - display only
        return "—"
    return human_duration(eta)


def format_timestamp(value: Optional[object]) -> str:
    if value is None:
        return "—"
    if isinstance(value, (int, float)):  # epoch seconds (discovery last_seen)
        try:
            value = datetime.fromtimestamp(value)
        except (OverflowError, OSError, ValueError):
            return "—"
    if not isinstance(value, datetime):
        return "—"
    now = datetime.now()
    if value.date() == now.date():
        return value.strftime("%H:%M:%S")
    if value.year == now.year:
        return value.strftime("%b %d, %H:%M")
    return value.strftime("%Y-%m-%d %H:%M")


def short_hash(digest: str, keep: int = 8) -> str:
    if not digest:
        return "—"
    return f"{digest[:keep]}…"
