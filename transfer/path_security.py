"""virusShare - path security for received files.

Every path that arrives from the network is untrusted.  This module is the
single gate between a remote manifest and the local filesystem:

* only relative paths are accepted (no drives, no UNC, no leading slash)
* ``..`` components are rejected before joining
* the final canonicalized path must remain inside the destination directory
* Windows reserved device names, alternate data streams and trailing
  dots/spaces are rejected

Rejected input raises :class:`PathTraversalError`; nothing is ever written
outside the chosen receive directory.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath
from typing import Iterable, List

from core.constants import MAX_FILENAME_LENGTH, MAX_RELATIVE_PATH_LENGTH

# Windows reserves these basenames (with or without extension).
_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
}

_INVALID_CHARS = set('<>:"|?*')
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


class PathTraversalError(ValueError):
    """A remote path tried to escape the destination directory or is invalid."""


def _reject(reason: str, original: object = None) -> None:
    raise PathTraversalError(f"unsafe path {original!r}: {reason}")


def sanitize_relative_path(relpath: str) -> str:
    """Validate a remote relative path and return it in canonical form.

    Returns a forward-slash separated path with no ``.``/``..`` components.
    Raises :class:`PathTraversalError` for anything suspicious.
    """
    if not isinstance(relpath, str):
        _reject("not a string", relpath)
    if not relpath or not relpath.strip():
        _reject("empty", relpath)
    if len(relpath) > MAX_RELATIVE_PATH_LENGTH:
        _reject("too long", relpath)
    if "\x00" in relpath:
        _reject("NUL byte", relpath)
    for ch in relpath:
        if ord(ch) < 32:
            _reject(f"control character {ord(ch)}", relpath)

    # Windows separators become POSIX separators before splitting so that
    # "..\\..\\x" is inspected component-wise exactly like "../../x".
    normalized = relpath.replace("\\", "/")

    if normalized.startswith("/"):
        _reject("absolute path", relpath)
    if _DRIVE_RE.match(normalized):
        _reject("drive letter", relpath)
    if normalized.startswith("//"):
        _reject("UNC path", relpath)

    components: List[str] = []
    for part in normalized.split("/"):
        if part == "":
            _reject("empty path component", relpath)
        if part == ".":
            continue
        if part == "..":
            _reject("parent directory reference", relpath)
        if len(part) > MAX_FILENAME_LENGTH:
            _reject("component too long", relpath)
        if part != part.rstrip(". "):
            _reject("trailing dot or space", relpath)
        if part.startswith(". "):
            _reject("leading dot-space", relpath)
        if any(ch in _INVALID_CHARS for ch in part):
            _reject("invalid character for Windows", relpath)
        if part.endswith(":") or ":" in part:
            _reject("colon (alternate data stream?)", relpath)
        if part.lower().split(".")[0] in _RESERVED_NAMES:
            _reject("reserved Windows device name", relpath)
        if set(part) == {"."}:
            _reject("dot-only component", relpath)
        components.append(part)

    if not components:
        _reject("no usable components", relpath)

    return "/".join(components)


def is_safe_filename(name: str) -> bool:
    """True when a single filename is safe to create inside a directory."""
    try:
        return sanitize_relative_path(name) == name and "/" not in name
    except PathTraversalError:
        return False


def resolve_destination(dest_dir: Path, relpath: str) -> Path:
    """Join ``relpath`` under ``dest_dir`` and prove the result stays inside.

    The candidate path is canonicalized (``os.path.realpath`` resolves
    symlinks/junctions that already exist) and compared against the
    canonicalized destination root.
    """
    clean = sanitize_relative_path(relpath)
    root = os.path.realpath(str(dest_dir))
    candidate = os.path.realpath(os.path.join(root, *clean.split("/")))

    try:
        common = os.path.commonpath([root, candidate])
    except ValueError as exc:  # different drives
        raise PathTraversalError(f"path escapes destination: {relpath!r}") from exc

    if os.path.normcase(common) != os.path.normcase(root):
        raise PathTraversalError(f"path escapes destination: {relpath!r}")
    if os.path.normcase(candidate) == os.path.normcase(root):
        raise PathTraversalError(f"path resolves to the destination itself: {relpath!r}")
    return Path(candidate)


def ensure_parent(path: Path) -> None:
    """Create the parent directory chain for a destination file."""
    path.parent.mkdir(parents=True, exist_ok=True)


def unique_path(path: Path) -> Path:
    """Return ``path`` or ``name (1).ext``-style variant that does not exist yet."""
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    for index in range(1, 10_000):
        candidate = path.with_name(f"{stem} ({index}){suffix}")
        if not candidate.exists():
            return candidate
    raise FileExistsError(f"could not find a free name for {path}")


def sanitize_manifest(paths: Iterable[str]) -> "tuple[List[str], List[str]]":
    """Split manifest paths into (accepted, rejected)."""
    accepted: List[str] = []
    rejected: List[str] = []
    for raw in paths:
        try:
            accepted.append(sanitize_relative_path(raw))
        except PathTraversalError:
            rejected.append(raw)
    return accepted, rejected
