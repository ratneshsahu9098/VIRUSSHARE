"""Generate the release assets consumed by ``virusShare.spec``.

* ``assets/virusShare.ico``  - multi-resolution Windows icon rendered from
  ``gui.icons.write_ico`` (the same artwork the window/tray use at runtime).
* ``assets/version_info.txt``  - ``VSVersionInfo`` text for the exe's
  Properties → Details resource, derived from ``core.constants.APP_VERSION``.

The spec file calls :func:`ensure_assets` before building, so a fresh clone
always produces a branded exe.  Run this module directly to refresh:

    python scripts/make_release_assets.py [--force]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ICO_FILE = ROOT / "assets" / "virusShare.ico"
VERSION_FILE = ROOT / "assets" / "version_info.txt"


def version_tuple(version: str) -> tuple:
    """``"1.2.3"`` -> ``(1, 2, 3, 0)`` (Windows wants four components)."""
    parts = [int(p) for p in str(version).split(".")]
    parts = (parts + [0, 0, 0, 0])[:4]
    return tuple(parts)


def render_version_info() -> str:
    """Build the eval-able ``VSVersionInfo`` text for the current version."""
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo,
        StringFileInfo,
        StringStruct,
        StringTable,
        VarFileInfo,
        VarStruct,
        VSVersionInfo,
    )

    from core.constants import APP_AUTHOR, APP_NAME, APP_VERSION

    filevers = version_tuple(APP_VERSION)
    info = VSVersionInfo(
        ffi=FixedFileInfo(
            filevers=filevers,
            prodvers=filevers,
            mask=0x3F,
            flags=0x0,
            OS=0x40004,  # VOS_NT_WINDOWS32
            fileType=0x1,  # VFT_APP
            subtype=0x0,
            date=(0, 0),
        ),
        kids=[
            StringFileInfo(
                [
                    StringTable(
                        "040904B0",  # en-US, Unicode
                        [
                            StringStruct("CompanyName", APP_AUTHOR),
                            StringStruct(
                                "FileDescription",
                                f"{APP_NAME} - peer-to-peer LAN file transfer",
                            ),
                            StringStruct("FileVersion", APP_VERSION),
                            StringStruct("InternalName", APP_NAME),
                            StringStruct("OriginalFilename", f"{APP_NAME}.exe"),
                            StringStruct("ProductName", APP_NAME),
                            StringStruct("ProductVersion", APP_VERSION),
                            StringStruct("LegalCopyright",
                                         f"Copyright (c) {APP_AUTHOR}"),
                        ],
                    )
                ]
            ),
            VarFileInfo([VarStruct("Translation", [1033, 1200])]),
        ],
    )
    return str(info)


def ensure_assets(force: bool = False) -> tuple:
    """Make sure both assets exist and are current; return their paths.

    The version file is rewritten whenever its content would change (e.g.
    after bumping ``APP_VERSION``); the icon only when missing or forced, so
    routine builds do not churn a binary blob.
    """
    ICO_FILE.parent.mkdir(parents=True, exist_ok=True)

    desired = render_version_info()
    if force or not VERSION_FILE.exists() or VERSION_FILE.read_text(encoding="utf-8") != desired:
        VERSION_FILE.write_text(desired, encoding="utf-8")

    if force or not ICO_FILE.exists():
        from gui.icons import write_ico

        write_ico(ICO_FILE)

    return str(ICO_FILE), str(VERSION_FILE)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="generate virusShare release assets")
    parser.add_argument("--force", action="store_true", help="regenerate everything")
    args = parser.parse_args(argv)
    ico, ver = ensure_assets(force=args.force)
    print(f"icon:    {ico}")
    print(f"version: {ver}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
