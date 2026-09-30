# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build description for virusShare.

Build from the repository root:

    python -m PyInstaller --clean --noconfirm virusShare.spec

Produces the single-file executable ``dist\\virusShare.exe`` with a
branded icon and a Windows version resource (both generated from source by
``scripts/make_release_assets.py``).
"""

from PySide6.QtCore import __file__ as _qt_core_file  # noqa: F401  (ensures Qt present)
import os
import sys

block_cipher = None

_ROOT = os.path.dirname(os.path.abspath(SPEC))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from scripts.make_release_assets import ensure_assets  # noqa: E402

ICON_FILE, VERSION_FILE = ensure_assets(_ROOT)

# Qt modules that are never imported by virusShare; excluding them keeps
# the single-file bundle well below the full PySide6 footprint.
EXCLUDED_QT = [
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
    "PySide6.QtQuick",
    "PySide6.QtQuickWidgets",
    "PySide6.QtQml",
    "PySide6.Qt3DCore",
    "PySide6.Qt3DRender",
    "PySide6.Qt3DInput",
    "PySide6.QtCharts",
    "PySide6.QtDataVisualization",
    "PySide6.QtMultimedia",
    "PySide6.QtMultimediaWidgets",
    "PySide6.QtOpenGL",
    "PySide6.QtOpenGLWidgets",
    "PySide6.QtPdf",
    "PySide6.QtPdfWidgets",
    "PySide6.QtSql",
    "PySide6.QtTest",
    "tkinter",
]

datas = []
resources = os.path.join(os.path.dirname(os.path.abspath(SPEC)), "resources")  # noqa: F821
if os.path.isdir(resources):
    for name in os.listdir(resources):
        datas.append((os.path.join(resources, name), "resources"))

a = Analysis(
    ["app.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[
        # imported lazily inside functions; listed so a --clean build never
        # misses them even if the module graph gets conservative
        "gui.bridge",
        "gui.styles",
        "gui.icons",
        "gui.device_panel",
        "gui.transfer_queue",
        "gui.role_screen",
        "gui.sender_screen",
        "gui.receiver_screen",
        "gui.pairing_dialog",
        "gui.conflict_dialog",
        "gui.history_dialog",
        "gui.settings_dialog",
        "gui.tray",
        "gui.main_window",
        "database.history",
        "transfer.manager",
        "utils.windows",
        "utils.network",
        "utils.formatting",
        "utils.logger",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDED_QT,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="virusShare",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON_FILE,
    version=VERSION_FILE,
)
