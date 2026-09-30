"""virusShare - Windows integration helpers (all optional, all guarded).

Nothing here raises on non-Windows platforms: every function either does the
right thing or falls back to a cross-platform equivalent / no-op, so the app
and its tests can import this module anywhere.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Optional

IS_WINDOWS = sys.platform.startswith("win")

AUTOSTART_VALUE_NAME = "virusShare"


def resource_path(relative: str) -> Path:
    """Resolve a bundled resource for both dev and PyInstaller one-file mode.

    PyInstaller extracts the onefile archive to ``sys._MEIPASS``; keep this
    as the single place that knows about it.
    """
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / relative
    return Path(__file__).resolve().parent.parent / relative


# --------------------------------------------------------------------------- #
# shell integration
# --------------------------------------------------------------------------- #

def open_in_file_manager(path: Path, *, select: bool = True) -> bool:
    """Reveal ``path`` in Explorer (or the platform file manager)."""
    path = Path(path)
    try:
        if IS_WINDOWS:
            if select and path.exists():
                subprocess.Popen(["explorer", "/select,", str(path)])
            else:
                target = path if path.exists() else path.parent
                os.startfile(str(target))  # noqa: S606 - intentional shell open
            return True
        if path.is_dir():
            subprocess.Popen(["xdg-open", str(path)])
            return True
        subprocess.Popen(["xdg-open", str(path.parent)])
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def open_path(path: Path) -> bool:
    """Open a file with its default application (falls back to the folder)."""
    path = Path(path)
    try:
        if path.exists():
            os.startfile(str(path))  # noqa: S606
            return True
        return open_in_file_manager(path.parent if path.parent.exists() else Path.cwd())
    except OSError:
        return False


def copy_to_clipboard(text: str) -> bool:
    """Copy text via the Qt clipboard if available, else Windows clip."""
    try:
        from PySide6.QtWidgets import QApplication

        app = QApplication.instance()
        if app is not None:
            app.clipboard().setText(text)
            return True
    except (ImportError, RuntimeError):
        pass
    if IS_WINDOWS:
        try:
            proc = subprocess.run(
                ["clip"], input=text.encode("utf-16"), check=False
            )
            return proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
    return False


# --------------------------------------------------------------------------- #
# autostart (HKCU Run key - no admin rights required)
# --------------------------------------------------------------------------- #

def _run_key_path() -> str:
    return r"Software\Microsoft\Windows\CurrentVersion\Run"


def autostart_available() -> bool:
    return IS_WINDOWS


def is_autostart_enabled() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _run_key_path()
        ) as key:
            winreg.QueryValueEx(key, AUTOSTART_VALUE_NAME)
        return True
    except OSError:
        return False


def set_autostart(enabled: bool, *, executable: Optional[str] = None) -> bool:
    """Add/remove this app under HKCU\\...\\Run. Returns True on success."""
    if not IS_WINDOWS:
        return False
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _run_key_path(), 0, winreg.KEY_SET_VALUE
        ) as key:
            if enabled:
                winreg.SetValueEx(
                    key,
                    AUTOSTART_VALUE_NAME,
                    0,
                    winreg.REG_SZ,
                    _autostart_command(),
                )
            else:
                try:
                    winreg.DeleteValue(key, AUTOSTART_VALUE_NAME)
                except FileNotFoundError:
                    pass
        return True
    except OSError:
        return False


def _autostart_command() -> str:
    if getattr(sys, "frozen", False):  # PyInstaller build
        return f'"{sys.executable}" --minimized'
    app = Path(__file__).resolve().parent.parent / "app.py"
    return f'"{sys.executable}" "{app}" --minimized'


def remove_legacy_autostart() -> bool:
    """Delete the HKCU\\...\\Run entry created before the rename (best effort)."""
    if not IS_WINDOWS:
        return False
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _run_key_path(), 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.DeleteValue(key, "EtherTransfer")
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# session / window niceties
# --------------------------------------------------------------------------- #

def set_taskbar_progress(hwnd: int, fraction: float, *, state: str = "normal") -> bool:
    """Windows 7+ taskbar progress via ITaskbarList3. Best-effort no-op."""
    if not IS_WINDOWS or not hwnd:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8),
            ]

        # ITaskbarList3 {EA1AFB91-9E28-4B86-90E9-9E9F8A5EEFAF}
        iid = GUID(0xEA1AFB91, 0x9E28, 0x4B86,
                   (wintypes.BYTE * 8)(0x90, 0xE9, 0x9E, 0x9F, 0x8A, 0x5E, 0xEF, 0xAF))
        ole32 = ctypes.windll.ole32
        ctypes.windll.ole32.CoInitialize(None)

        # CLSID_TaskbarList
        clsid = GUID(0x56FDF344, 0xFD6D, 0x11D0,
                     (wintypes.BYTE * 8)(0x95, 0x8A, 0x00, 0x60, 0x97, 0xC9, 0xA0, 0x90))
        pbar = ctypes.c_void_p()
        hr = ole32.CoCreateInstance(
            ctypes.byref(clsid), None, 1,  # CLSCTX_INPROC_SERVER
            ctypes.byref(iid), ctypes.byref(pbar),
        )
        if hr != 0 or not pbar.value:
            return False

        vtbl = ctypes.POINTER(ctypes.c_void_p).from_address(pbar.value)
        # ITaskbarList3 methods beyond ITaskbarList (HrInit=4):
        # SetProgressValue = 8, SetProgressState = 9 (0-indexed after IUnknown)
        states = {"none": 0, "indeterminate": 1, "normal": 2, "error": 4, "paused": 8}
        state_id = states.get(state, 2)
        SetProgressState = ctypes.WINFUNCTYPE(
            ctypes.c_long, ctypes.c_void_p, ctypes.c_int
        )(vtbl[9])
        SetProgressValue = ctypes.WINFUNCTYPE(
            ctypes.c_long, ctypes.c_void_p, ctypes.c_int, ctypes.c_int
        )(vtbl[8])
        SetProgressState(pbar.value, state_id)
        if state_id == 2:
            SetProgressValue(pbar.value, 0, max(0, min(100, int(fraction * 100))))
        return True
    except Exception:  # noqa: BLE001 - cosmetic feature only
        return False


def clear_taskbar_progress(hwnd: int) -> bool:
    return set_taskbar_progress(hwnd, 0.0, state="none")


def machine_description() -> str:
    """Human-readable 'Windows 11 · DESKTOP-ABC' label for the UI."""
    system = platform.system() or "Unknown"
    release = platform.release() or ""
    host = platform.node() or "This PC"
    label = f"{system} {release}".strip()
    return f"{label} · {host}"
