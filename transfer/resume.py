"""virusShare - partial-file state and resume validation.

Rules:

* in-progress data is written to ``<name>.etherpartial`` and only renamed to
  the final name after checksum verification
* a JSON sidecar (``<name>.etherpartial.json``) records what the partial was
  for: expected size, source mtime and the chunk size used
* a partial is only resumed when the sidecar matches the incoming manifest;
  otherwise it is discarded and the transfer restarts from zero
* the resume offset is aligned down to a chunk boundary and the partial is
  truncated to that offset, so a half-written chunk is never trusted
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from core.constants import PARTIAL_META_SUFFIX, PARTIAL_SUFFIX

log = logging.getLogger(__name__)


def partial_path(dest: Path) -> Path:
    return dest.with_name(dest.name + PARTIAL_SUFFIX)


def meta_path(dest: Path) -> Path:
    return dest.with_name(dest.name + PARTIAL_SUFFIX + ".json")


def read_meta(dest: Path) -> Optional[Dict[str, Any]]:
    path = meta_path(dest)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_meta(dest: Path, meta: Dict[str, Any]) -> None:
    path = meta_path(dest)
    try:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(meta), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:  # pragma: no cover - disk issues during tests
        log.warning("could not write resume metadata %s: %s", path, exc)


def remove_state(dest: Path) -> None:
    """Delete partial + sidecar (no error if absent)."""
    for path in (partial_path(dest), meta_path(dest)):
        try:
            path.unlink()
        except OSError:
            pass


def _meta_matches(meta: Optional[Dict[str, Any]], file_id: str, size: int,
                  mtime: Optional[float]) -> bool:
    if not meta:
        return False
    if meta.get("file_id") != file_id:
        return False
    if int(meta.get("size", -1)) != int(size):
        return False
    if mtime is not None and meta.get("mtime") is not None:
        try:
            if abs(float(meta["mtime"]) - float(mtime)) > 1e-6:
                return False
        except (TypeError, ValueError):
            return False
    return True


def prepare_partial(
    dest: Path,
    *,
    file_id: str,
    size: int,
    mtime: Optional[float],
    chunk_size: int,
) -> Tuple[Path, int]:
    """Validate/prepare ``dest.etherpartial`` for writing.

    Returns ``(partial_file_path, resume_offset)`` where ``resume_offset`` is
    chunk-aligned.  ``dest`` itself is never touched here - it is only
    replaced by :func:`commit` after verification.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    partial = partial_path(dest)
    meta = read_meta(dest)
    partial_size = partial.stat().st_size if partial.exists() else 0

    if not _meta_matches(meta, file_id, size, mtime):
        if partial.exists() or meta_path(dest).exists():
            log.info("discarding stale partial for %s", dest.name)
            remove_state(dest)
        partial_size = 0

    if partial_size > size:
        log.warning("partial for %s larger than expected file; restarting", dest.name)
        remove_state(dest)
        partial_size = 0

    offset = partial_size - (partial_size % chunk_size)
    if offset < 0:
        offset = 0

    if partial_size != offset:
        # discard the trailing partial chunk: its bytes are unverified
        try:
            with open(partial, "r+b") as fh:
                fh.truncate(offset)
        except OSError:
            remove_state(dest)
            offset = 0

    dest.parent.mkdir(parents=True, exist_ok=True)
    if not partial.exists():
        partial.touch()

    write_meta(
        dest,
        {
            "file_id": file_id,
            "size": size,
            "mtime": mtime,
            "chunk_size": chunk_size,
            "received": offset,
            "relpath": None,
        },
    )
    return partial, offset


def update_received(dest: Path, received: int) -> None:
    """Refresh the sidecar's received counter (best effort, throttled by caller)."""
    meta = read_meta(dest) or {}
    meta["received"] = received
    write_meta(dest, meta)


def commit(partial: Path, dest: Path) -> None:
    """Atomically rename a verified partial to its final name."""
    os.replace(partial, dest)
    try:
        meta_path(dest).unlink()
    except OSError:
        pass


def discard(partial: Path) -> None:
    """Delete a partial file (corrupt or cancelled permanently)."""
    try:
        partial.unlink()
    except OSError:
        pass
    # sidecar lives next to dest, derived from the partial name
    name = partial.name
    if name.endswith(PARTIAL_SUFFIX):
        dest_name = name[: -len(PARTIAL_SUFFIX)]
        try:
            (partial.parent / (dest_name + PARTIAL_META_SUFFIX)).unlink()
        except OSError:
            pass
