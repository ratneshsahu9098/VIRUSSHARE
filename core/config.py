"""virusShare - persistent settings (%APPDATA%\\virusShare\\settings.json)."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.constants import (
    DEFAULT_SETTINGS,
    DISCOVERY_PORT,
    MAX_SEND_CHUNK_SIZE,
    MIN_SEND_CHUNK_SIZE,
    TRANSFER_PORT,
    ensure_dirs,
    get_settings_path,
)

log = logging.getLogger(__name__)

_BOOL_KEYS = {
    "auto_accept_trusted",
    "enable_encryption",
    "verify_checksums",
    "minimize_to_tray",
    "show_notifications",
    "start_with_windows",
    "require_connection_approval",
}
_INT_KEYS = {
    "transfer_port": (1024, 65535),
    "discovery_port": (1024, 65535),
    "max_concurrent_transfers": (1, 16),
    "reconnect_attempts": (0, 10),
    "buffer_size": (16 * 1024, 8 * 1024 * 1024),
    "chunk_size": (MIN_SEND_CHUNK_SIZE, MAX_SEND_CHUNK_SIZE),
}
_STR_KEYS = {
    "theme": {"system", "light", "dark"},
    "language": {"en"},
    "save_received_files_to": None,  # validated separately
    "preferred_network_adapter": None,
}


class SettingsError(Exception):
    """Raised when a settings key or value is invalid."""


def _validate(key: str, value: Any) -> Any:
    if key in _BOOL_KEYS:
        if not isinstance(value, bool):
            raise SettingsError(f"{key} must be a boolean, got {type(value).__name__}")
        return value
    if key in _INT_KEYS:
        low, high = _INT_KEYS[key]
        if isinstance(value, bool) or not isinstance(value, int):
            raise SettingsError(f"{key} must be an integer")
        if not (low <= value <= high):
            raise SettingsError(f"{key} must be between {low} and {high}")
        return value
    if key in _STR_KEYS:
        allowed = _STR_KEYS[key]
        if not isinstance(value, str):
            raise SettingsError(f"{key} must be a string")
        if allowed is not None and value not in allowed:
            raise SettingsError(f"{key} must be one of {sorted(allowed)}")
        if key == "save_received_files_to":
            p = Path(value)
            if not p.is_absolute():
                raise SettingsError("save_received_files_to must be an absolute path")
            return str(p)
        return value
    if key == "trusted_devices":
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise SettingsError("trusted_devices must be a list of strings")
        return value
    # Unknown keys are preserved verbatim (forward compatibility).
    return value


class Settings:
    """Thread-safe settings with defaults, validation and atomic saves."""

    def __init__(self, path: Optional[Path] = None, create_dirs: bool = True):
        self.path = Path(path) if path else get_settings_path()
        self._lock = threading.RLock()
        self._data: Dict[str, Any] = dict(DEFAULT_SETTINGS)
        self._listeners: List[Callable[[str, Any], None]] = []
        self._dirty: set = set()
        self._unreadable = False
        if create_dirs:
            ensure_dirs()
        self.load()

    # -- persistence ------------------------------------------------------- #

    def _read_raw(self, attempts: int = 3):
        """Read and parse the settings file.

        Returns ``(raw, unreadable)``.  ``unreadable`` means a persistent
        OSError - the file exists but cannot be read (e.g. an antivirus lock):
        its real values must then be preserved, never overwritten by a later
        save (M28).  Transient failures are retried with a short backoff.
        """
        if not self.path.exists():
            return {}, False
        last_error: Optional[OSError] = None
        for attempt in range(attempts):
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                return (raw if isinstance(raw, dict) else {}), False
            except OSError as exc:
                last_error = exc
                if attempt + 1 < attempts:
                    time.sleep(0.05)
            except ValueError as exc:
                log.warning("settings file corrupt (%s); using defaults", exc)
                return {}, False
        log.warning(
            "settings file unreadable (%s); keeping in-memory settings",
            last_error,
        )
        return {}, True

    def load(self) -> None:
        with self._lock:
            raw, unreadable = self._read_raw()
            if unreadable:
                self._unreadable = True
                return
            self._unreadable = False
            merged = dict(DEFAULT_SETTINGS)
            for key, value in raw.items():
                try:
                    merged[key] = _validate(key, value)
                except SettingsError as exc:
                    log.warning("ignoring invalid setting %s: %s", key, exc)
            for key in self._dirty:
                if key in self._data:
                    merged[key] = self._data[key]
            self._data = merged

    def save(self) -> None:
        with self._lock:
            if self._unreadable:
                self.load()
                if self._unreadable:
                    log.error(
                        "settings not saved: %s is unreadable", self.path
                    )
                    return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)

    # -- API --------------------------------------------------------------- #

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(key, default)

    def set(self, key: str, value: Any, save: bool = True) -> Any:
        value = _validate(key, value)
        with self._lock:
            old = self._data.get(key)
            self._data[key] = value
            self._dirty.add(key)
            if save:
                self.save()
        if old != value:
            for callback in list(self._listeners):
                try:
                    callback(key, value)
                except Exception:  # pragma: no cover - listener bug must not break settings
                    log.exception("settings listener failed for %r", key)
        return value

    def as_dict(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._data)

    def reset(self) -> None:
        with self._lock:
            self._data = dict(DEFAULT_SETTINGS)
            self._dirty = set(DEFAULT_SETTINGS)
            self.save()

    def add_listener(self, callback: Callable[[str, Any], None]) -> None:
        self._listeners.append(callback)

    # -- convenience ------------------------------------------------------- #

    @property
    def receive_dir(self) -> Path:
        return Path(self.get("save_received_files_to"))

    @property
    def chunk_size(self) -> int:
        return int(self.get("chunk_size", MIN_SEND_CHUNK_SIZE))

    @property
    def max_concurrent_transfers(self) -> int:
        return int(self.get("max_concurrent_transfers", 3))

    @property
    def encryption_enabled(self) -> bool:
        return bool(self.get("enable_encryption", True))

    @property
    def require_connection_approval(self) -> bool:
        return bool(self.get("require_connection_approval", True))

    @property
    def verify_checksums(self) -> bool:
        return bool(self.get("verify_checksums", True))

    @property
    def discovery_port(self) -> int:
        return int(self.get("discovery_port", DISCOVERY_PORT))

    @property
    def transfer_port(self) -> int:
        return int(self.get("transfer_port", TRANSFER_PORT))


_default_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Process-wide settings singleton (created with directory setup)."""
    global _default_settings
    if _default_settings is None:
        _default_settings = Settings()
    return _default_settings
