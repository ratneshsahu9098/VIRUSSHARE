"""virusShare - sending side: manifest building and chunked push driver."""

from __future__ import annotations

import logging
import os
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from core.constants import MESSAGE_TYPES
from network.protocol import FileInfo, Message, ProtocolError
from network.session import ConnectionSession
from transfer.checksum import StreamingHasher, hash_prefix_stream

log = logging.getLogger(__name__)

ProgressCallback = Callable[[str, str, int, int, int], None]
# (file_id, relpath, file_sent, file_size, total_sent)


# --------------------------------------------------------------------------- #
# manifest
# --------------------------------------------------------------------------- #

@dataclass
class SendEntry:
    source: Optional[Path]  # None for directories
    relpath: str            # forward-slash path; doubles as the file_id
    size: int
    mtime: float
    is_dir: bool = False

    @property
    def file_id(self) -> str:
        return self.relpath


def _unique_relpath(relpath: str, taken: set) -> str:
    if relpath not in taken:
        taken.add(relpath)
        return relpath
    parent, _, name = relpath.rpartition("/")
    stem, dot, ext = name.partition(".")
    base = stem if dot else name
    suffix = ext if dot else ""
    for index in range(1, 10_000):
        candidate = f"{base} ({index}){('.' + suffix) if suffix else ''}"
        if parent:
            candidate = f"{parent}/{candidate}"
        if candidate not in taken:
            taken.add(candidate)
            return candidate
    raise FileExistsError(f"cannot de-duplicate {relpath}")


def build_manifest(paths: Sequence[Path]) -> List[SendEntry]:
    """Enumerate selected files/folders into a relative-path manifest.

    * a selected file  -> ``filename.ext``
    * a selected folder -> ``folder/...`` (structure preserved, empty
      directories included, symlinks not followed)

    Absolute source paths never leave the machine.
    """
    entries: List[SendEntry] = []
    taken: set = set()

    for raw in paths:
        root = Path(raw)
        try:
            info = root.stat()
        except OSError as exc:
            log.warning("skipping %s: %s", root, exc)
            continue

        if stat.S_ISREG(info.st_mode):
            rel = _unique_relpath(root.name, taken)
            entries.append(
                SendEntry(source=root, relpath=rel, size=info.st_size,
                          mtime=info.st_mtime, is_dir=False)
            )
        elif stat.S_ISDIR(info.st_mode):
            base = root.parent
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                dirnames.sort()
                here = Path(dirpath)
                rel_dir = here.relative_to(base).as_posix()
                rel_dir = _unique_relpath(rel_dir, taken)
                entries.append(
                    SendEntry(source=None, relpath=rel_dir, size=0,
                              mtime=0.0, is_dir=True)
                )
                for name in sorted(filenames):
                    child = here / name
                    try:
                        cinfo = child.stat()
                    except OSError as exc:
                        log.warning("skipping %s: %s", child, exc)
                        continue
                    if not stat.S_ISREG(cinfo.st_mode):
                        continue
                    rel = child.relative_to(base).as_posix()
                    rel = _unique_relpath(rel, taken)
                    entries.append(
                        SendEntry(source=child, relpath=rel, size=cinfo.st_size,
                                  mtime=cinfo.st_mtime, is_dir=False)
                    )
        else:
            log.warning("skipping unsupported file type: %s", root)

    return entries


def manifest_to_file_infos(entries: Sequence[SendEntry]) -> List[FileInfo]:
    return [
        FileInfo(
            name=e.relpath.rsplit("/", 1)[-1],
            size=e.size,
            path=e.relpath,
            is_directory=e.is_dir,
            modified_time=e.mtime,
        )
        for e in entries
    ]


# --------------------------------------------------------------------------- #
# controls
# --------------------------------------------------------------------------- #

class TransferControls:
    """Thread-safe pause/cancel controls shared between GUI and transfer thread."""

    def __init__(self) -> None:
        self._resumed = threading.Event()
        self._resumed.set()
        self._cancelled = threading.Event()
        self._lock = threading.Lock()

    def pause(self) -> None:
        self._resumed.clear()

    def resume(self) -> None:
        self._resumed.set()

    def cancel(self) -> None:
        self._cancelled.set()
        self._resumed.set()  # unblock a paused sender so it can notice cancel

    @property
    def paused(self) -> bool:
        return not self._resumed.is_set()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def wait_while_paused(self, poll: float = 0.1) -> None:
        """Block while paused; returns early when cancelled."""
        while not self._resumed.is_set():
            if self._cancelled.is_set():
                return
            time.sleep(poll)

    def wait_interruptible(self, seconds: float, poll: float = 0.1) -> bool:
        """Sleep up to ``seconds``; returns True if cancelled meanwhile."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self._cancelled.is_set():
                return True
            time.sleep(min(poll, max(0.0, deadline - time.monotonic())))
        return self._cancelled.is_set()


# --------------------------------------------------------------------------- #
# results
# --------------------------------------------------------------------------- #

@dataclass
class FileResult:
    file_id: str
    relpath: str
    size: int
    sent: int = 0
    success: bool = False
    skipped: bool = False
    error: str = ""
    checksum: str = ""


@dataclass
class PushReport:
    results: List[FileResult] = field(default_factory=list)
    cancelled: bool = False
    error: str = ""

    @property
    def total_sent(self) -> int:
        return sum(r.sent for r in self.results)

    @property
    def success(self) -> bool:
        if self.cancelled or self.error:
            return False
        active = [r for r in self.results if not r.skipped]
        if not active:
            return not self.results
        return all(r.success for r in active)


# --------------------------------------------------------------------------- #
# push driver
# --------------------------------------------------------------------------- #

def push_files(
    session: ConnectionSession,
    entries: Sequence[SendEntry],
    *,
    chunk_size: int,
    controls: Optional[TransferControls] = None,
    progress: Optional[ProgressCallback] = None,
    verify: bool = True,
) -> PushReport:
    """Send a manifest and stream every accepted file with FILE_CHUNK.

    Blocking: call it from a worker thread.  Uses only the existing protocol
    framing (``session.send`` / ``session.expect``).
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    controls = controls or TransferControls()
    report = PushReport()
    files = [e for e in entries if not e.is_dir]
    total_sent = 0

    try:
        # 1. manifest ------------------------------------------------------
        session.send(Message.create_file_list(manifest_to_file_infos(entries)))
        reply = session.expect("FILE_LIST", "ERROR", "DISCONNECT")
        if reply.type_name == "DISCONNECT":
            report.error = "peer disconnected before accepting the transfer"
            return report
        if reply.type_name == "ERROR":
            code, text = reply.parse_error()
            report.error = text or f"peer refused the transfer (error 0x{code:02X})"
            if code == 0x08:
                report.cancelled = True
            return report

        accepted = {fi.path for fi in reply.parse_file_list()}
        log.info("peer accepted %d of %d manifest entries", len(accepted), len(entries))

        # 2. files ---------------------------------------------------------
        for entry in files:
            if controls.cancelled:
                report.cancelled = True
                session.send(Message.create_disconnect())
                return report
            if entry.relpath not in accepted:
                report.results.append(
                    FileResult(entry.file_id, entry.relpath, entry.size, skipped=True)
                )
                continue

            controls.wait_while_paused()
            if controls.cancelled:
                report.cancelled = True
                session.send(Message.create_disconnect())
                return report

            result = _send_one_file(
                session,
                entry,
                chunk_size=chunk_size,
                controls=controls,
                progress=progress,
                verify=verify,
                prior_total=total_sent,
            )
            total_sent += result.sent
            report.results.append(result)
            if result.error == "cancelled" or controls.cancelled:
                report.cancelled = True
                try:
                    session.send(Message.create_disconnect())
                except OSError:
                    pass
                return report
            if not result.success and result.error == "__abort__":
                report.error = "connection aborted during transfer"
                return report
            if report.cancelled:
                return report

        if report.results and all(r.skipped for r in report.results):
            report.error = "all files were skipped by the receiver"

        session.send(Message.create_disconnect())
        return report
    except (ProtocolError, OSError) as exc:
        report.error = str(exc)
        log.warning("push aborted: %s", exc)
        return report


def _send_one_file(
    session: ConnectionSession,
    entry: SendEntry,
    *,
    chunk_size: int,
    controls: TransferControls,
    progress: Optional[ProgressCallback],
    verify: bool,
    prior_total: int,
) -> FileResult:
    result = FileResult(entry.file_id, entry.relpath, entry.size)
    source = entry.source
    if source is None:
        result.error = "directory entries are not transferable"
        return result

    session.send(
        Message.create_file_request(
            entry.file_id,
            offset=0,
            metadata={
                "name": entry.relpath.rsplit("/", 1)[-1],
                "size": entry.size,
                "path": entry.relpath,
                "mtime": entry.mtime,
                "chunk_size": chunk_size,
            },
        )
    )

    reply = session.expect("FILE_RESUME", "ERROR", "DISCONNECT")
    if reply.type_name == "DISCONNECT":
        result.error = "__abort__"
        return result
    if reply.type_name == "ERROR":
        code, text = reply.parse_error()
        result.error = text or f"peer refused the file (error 0x{code:02X})"
        return result

    file_id, offset = _parse_resume(reply, entry, chunk_size)
    if file_id != entry.file_id:
        raise ProtocolError(f"FILE_RESUME for unexpected file {file_id!r}")

    hasher = StreamingHasher()
    try:
        with open(source, "rb") as fh:
            if offset:
                hash_prefix_stream(source, offset, hasher)
                fh.seek(offset)

            index = offset // chunk_size
            sent = 0
            remaining = entry.size - offset
            while remaining > 0:
                if controls.cancelled:
                    session.send(Message.create_file_cancel(entry.file_id))
                    _await_cancel_ack(session)
                    result.sent = sent
                    result.error = "cancelled"
                    return result
                controls.wait_while_paused()

                data = fh.read(min(chunk_size, remaining))
                if not data:
                    break

                session.send(Message.create_file_chunk(entry.file_id, index, data))
                hasher.update(data)
                sent += len(data)
                remaining -= len(data)
                index += 1
                if progress:
                    progress(entry.file_id, entry.relpath, sent, entry.size,
                             prior_total + sent)


            result.sent = sent
            result.checksum = hasher.hexdigest() if verify else ""
            session.send(
                Message.create_file_complete(
                    entry.file_id, True, checksum=result.checksum
                )
            )
    except OSError as exc:
        try:
            session.send(Message.create_error(0x03, f"Cannot read file: {exc}"))
        except OSError:
            pass
        result.error = f"cannot read source file: {exc}"
        return result

    ack = session.expect("FILE_COMPLETE", "ERROR", "DISCONNECT")
    if ack.type_name == "FILE_COMPLETE":
        _file_id, success, error = ack.parse_file_complete()
        result.success = bool(success)
        if not success:
            result.error = error or "peer reported failure"
    else:
        result.error = "peer aborted during verification"
    return result


def _parse_resume(reply: Message, entry: SendEntry, chunk_size: int):
    data = reply.parse_json_payload()
    file_id = data.get("file_id")
    offset = int(data.get("offset", 0))
    if offset < 0 or offset > entry.size:
        raise ProtocolError(f"invalid resume offset {offset} for {entry.relpath}")
    if offset % chunk_size != 0:
        raise ProtocolError(
            f"resume offset {offset} not aligned to chunk size {chunk_size}"
        )
    return file_id, offset


def _await_cancel_ack(session: ConnectionSession, timeout: float = 15.0) -> None:
    try:
        session.expect("FILE_COMPLETE", "ERROR", timeout=timeout)
    except (ProtocolError, OSError):
        pass
