"""virusShare - receiving side: manifest acceptance and chunk sink.

Runs inside the server's per-connection thread.  Never trusts the peer:

* every manifest path goes through :mod:`transfer.path_security`
* declared sizes are validated against the manifest before any write
* chunk indexes must match the exact expected offset
* data is written to ``*.etherpartial`` and renamed only after SHA-256
  verification (when checksum verification is enabled)
* existing destination files are never overwritten silently - the conflict
  callback decides (replace / keep both / skip / cancel)
"""

from __future__ import annotations

import logging
import math
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional

from core.constants import MAX_SEND_CHUNK_SIZE, MESSAGE_TYPES, MIN_SEND_CHUNK_SIZE
from network.protocol import FileInfo, Message, ProtocolError
from network.session import ConnectionSession
from transfer import resume as resume_mod
from transfer.checksum import StreamingHasher, hash_prefix_stream
from transfer.path_security import (
    PathTraversalError,
    resolve_destination,
    sanitize_relative_path,
    unique_path,
)

log = logging.getLogger(__name__)

MAX_MANIFEST_ENTRIES = 100_000
MAX_FILE_SIZE = 64 * 1024 * 1024 * 1024 * 1024  # 64 TiB


class ConnectionProblem(ProtocolError):
    """A socket-level failure while talking to the peer (never a disk error)."""


def _expect(session: ConnectionSession, *types: str) -> Message:
    try:
        return session.expect(*types)
    except OSError as exc:
        raise ConnectionProblem(f"connection error: {exc}") from exc


def _send(session: ConnectionSession, message: Message) -> None:
    try:
        session.send(message)
    except OSError as exc:
        raise ConnectionProblem(f"connection error: {exc}") from exc


class ConflictAction(Enum):
    REPLACE = "replace"
    KEEP_BOTH = "keep_both"
    SKIP = "skip"
    CANCEL = "cancel"


@dataclass
class ConflictRequest:
    relpath: str
    dest_path: Path
    incoming_size: int
    existing_size: int


@dataclass
class ConflictDecision:
    action: ConflictAction


ConflictCallback = Callable[[ConflictRequest], ConflictDecision]
ProgressCallback = Callable[[str, str, int, int], None]  # file_id, relpath, recv, total


@dataclass
class ReceiveContext:
    receive_dir: Path
    conflict_callback: Optional[ConflictCallback] = None
    progress: Optional[ProgressCallback] = None
    on_file_complete: Optional[Callable[[Path, str, int], None]] = None
    on_file_failed: Optional[Callable[[str, str], None]] = None
    verify: bool = True


@dataclass
class ReceivedFile:
    relpath: str
    path: Optional[Path]
    size: int
    received: int = 0
    success: bool = False
    skipped: bool = False
    checksum: str = ""
    error: str = ""


@dataclass
class ReceiveReport:
    files: List[ReceivedFile] = field(default_factory=list)
    rejected_paths: List[str] = field(default_factory=list)
    error: str = ""
    cancelled: bool = False
    completed: bool = False

    @property
    def success(self) -> bool:
        return self.completed and not self.error and not self.cancelled


def handle_incoming(session: ConnectionSession, ctx: ReceiveContext) -> ReceiveReport:
    """Drive one connected peer's push session to completion."""
    report = ReceiveReport()

    try:
        first = session.expect("FILE_LIST", "DISCONNECT", "ERROR")
        if first.type_name == "DISCONNECT":
            report.cancelled = True
            report.error = "peer disconnected before starting the transfer"
            return report
        if first.type_name == "ERROR":
            code, text = first.parse_error()
            report.error = text or f"peer aborted (error 0x{code:02X})"
            return report

        plan = _accept_manifest(first, ctx, report, session)
        if plan is None:
            return report  # cancelled or refused; reply already sent

        aborted = _receive_files(session, ctx, report, plan)
        if aborted:
            return report
        if report.cancelled:
            return report
        report.completed = True
        return report
    except (ProtocolError, OSError) as exc:
        report.error = str(exc)
        log.warning("receive session aborted: %s", exc)
        return report


# --------------------------------------------------------------------------- #
# manifest
# --------------------------------------------------------------------------- #

def _accept_manifest(
    message: Message, ctx: ReceiveContext, report: ReceiveReport,
    session: ConnectionSession,
) -> Optional[Dict[str, tuple]]:
    """Validate the manifest, resolve conflicts, reply with accepted entries.

    Returns ``{file_id: (FileInfo, dest_path, expected_state)}`` or ``None``
    when the job was cancelled/refused (an ERROR reply has already been sent).
    ``expected_state`` is what ``dest`` looked like when the conflict decision
    was taken (``None`` when it did not exist) - ``_finalize`` re-checks it
    right before commit (H9).
    """
    entries = message.parse_file_list()
    if len(entries) > MAX_MANIFEST_ENTRIES:
        session_error = f"manifest too large ({len(entries)} entries)"
        report.error = session_error
        # caller holds the session only indirectly; raise to abort cleanly
        raise ProtocolError(session_error)

    ctx.receive_dir.mkdir(parents=True, exist_ok=True)

    plan: Dict[str, tuple] = {}
    accepted: List[FileInfo] = []
    seen: set = set()

    for info in entries:
        try:
            relpath = sanitize_relative_path(info.path)
        except PathTraversalError as exc:
            log.warning("dropping manifest entry: %s", exc)
            report.rejected_paths.append(str(info.path))
            continue
        # H8: case-insensitive filesystems treat a.txt and A.txt as one
        # file - normcase (lowercases on Windows, identity on POSIX) keeps
        # both from sharing a partial and destroying each other at commit.
        key = os.path.normcase(relpath)
        if key in seen:
            report.rejected_paths.append(relpath)
            continue
        seen.add(key)

        if info.is_directory:
            dest = _safe_dest(ctx, relpath, report)
            if dest is None:
                continue
            if dest.exists() and not dest.is_dir():
                log.warning("directory path occupied by a file: %s", relpath)
                report.rejected_paths.append(relpath)
                continue
            try:
                dest.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                log.warning("cannot create directory %s: %s", dest, exc)
                report.rejected_paths.append(relpath)
                continue
            accepted.append(info)
            continue

        # --- file entry ---------------------------------------------------
        size = info.size
        if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > MAX_FILE_SIZE:
            log.warning("dropping entry with invalid size %r for %r", size, info.path)
            report.rejected_paths.append(relpath)
            continue

        dest = _safe_dest(ctx, relpath, report)
        if dest is None:
            continue

        if dest.exists():
            if dest.is_dir():
                log.warning("file path occupied by a directory: %s", relpath)
                report.rejected_paths.append(relpath)
                continue
            decision = _resolve_conflict(ctx, relpath, dest, size)
            if decision is None or decision is ConflictAction.CANCEL:
                report.cancelled = True
                report.error = "transfer cancelled at conflict prompt"
                session.send(Message.create_error(0x08, "Transfer cancelled by user"))
                return None
            if decision is ConflictAction.SKIP:
                report.files.append(
                    ReceivedFile(relpath, dest, size, skipped=True, error="exists")
                )
                continue
            if decision is ConflictAction.KEEP_BOTH:
                try:
                    dest = unique_path(dest)
                except FileExistsError:
                    report.files.append(
                        ReceivedFile(relpath, dest, size, skipped=True, error="exists")
                    )
                    continue
            # REPLACE falls through: the partial may still be resumable and the
            # final name is only overwritten by commit() after verification.

        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            log.warning("cannot create parent for %s: %s", dest, exc)
            report.rejected_paths.append(relpath)
            continue

        plan[info.path] = (info, dest, _dest_state(dest))
        accepted.append(info)

    # tell the sender which entries will proceed
    session.send(Message.create_file_list(accepted))
    return plan


def _safe_dest(ctx: ReceiveContext, relpath: str, report: ReceiveReport) -> Optional[Path]:
    try:
        return resolve_destination(ctx.receive_dir, relpath)
    except PathTraversalError as exc:
        log.warning("dropping manifest entry: %s", exc)
        report.rejected_paths.append(relpath)
        return None


def _dest_state(dest: Path):
    """(mtime_ns, size) of ``dest`` or ``None`` when it does not exist."""
    try:
        st = dest.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def _dest_changed(dest: Path, expected) -> bool:
    """H9: True when dest no longer matches the state recorded at manifest."""
    return _dest_state(dest) != expected


def _resolve_conflict(
    ctx: ReceiveContext, relpath: str, dest: Path, incoming_size: int
) -> Optional[ConflictAction]:
    if ctx.conflict_callback is None:
        # never overwrite silently
        log.info("file exists, skipping (no conflict handler): %s", relpath)
        return ConflictAction.SKIP
    try:
        existing_size = dest.stat().st_size
    except OSError:
        existing_size = 0
    try:
        decision = ctx.conflict_callback(
            ConflictRequest(relpath, dest, incoming_size, existing_size)
        )
    except Exception:
        log.exception("conflict handler failed; skipping %s", relpath)
        return ConflictAction.SKIP
    return decision.action


# --------------------------------------------------------------------------- #
# file receive loop
# --------------------------------------------------------------------------- #

def _receive_files(
    session: ConnectionSession,
    ctx: ReceiveContext,
    report: ReceiveReport,
    plan: Dict[str, tuple],
) -> bool:
    """Receive every requested file.  Returns True when the job aborted."""
    requested: set = set()
    while True:
        message = session.expect("FILE_REQUEST", "DISCONNECT", "ERROR")
        if message.type_name == "DISCONNECT":
            if set(plan) - requested:
                report.cancelled = True
                if not report.error:
                    report.error = "peer cancelled the transfer"
                return True
            return False
        if message.type_name == "ERROR":
            code, text = message.parse_error()
            report.error = text or f"peer aborted (error 0x{code:02X})"
            report.cancelled = code == 0x08
            return True

        request = message.parse_file_request_full()
        file_id = str(request.get("file_id", ""))
        entry = plan.get(file_id)
        if entry is None:
            session.send(Message.create_error(0x02, f"Unknown file {file_id!r}"))
            continue
        requested.add(file_id)
        info, dest, expected = entry

        declared = request.get("size", info.size)
        if declared != info.size:
            raise ProtocolError(
                f"declared size {declared} differs from manifest {info.size}"
            )
        chunk_size = int(request.get("chunk_size", MIN_SEND_CHUNK_SIZE))
        if not (1024 <= chunk_size <= MAX_SEND_CHUNK_SIZE):
            raise ProtocolError(f"invalid chunk size {chunk_size}")

        aborted = _receive_one_file(
            session, ctx, report, file_id, info, dest, chunk_size, expected
        )
        if aborted:
            return True


def _receive_one_file(
    session: ConnectionSession,
    ctx: ReceiveContext,
    report: ReceiveReport,
    file_id: str,
    info: FileInfo,
    dest: Path,
    chunk_size: int,
    expected=None,
) -> bool:
    """Receive a single file.  True when the whole job must abort."""
    record = ReceivedFile(relpath=info.path, path=dest, size=info.size)
    report.files.append(record)

    partial, offset = resume_mod.prepare_partial(
        dest,
        file_id=file_id,
        size=info.size,
        mtime=info.modified_time,
        chunk_size=chunk_size,
    )

    hasher: Optional[StreamingHasher] = StreamingHasher() if ctx.verify else None
    if hasher is not None and offset:
        hash_prefix_stream(partial, offset, hasher)

    received = offset
    last_emit = 0.0
    pending_finalize = None  # (received, hasher, declared_checksum)

    try:
        _send(session, Message.create_file_resume(file_id, offset))
        mode = "r+b" if offset else "w+b"
        with open(partial, mode) as fh:
            if offset:
                fh.seek(offset)
            while True:
                message = _expect(
                    session,
                    "FILE_CHUNK", "FILE_COMPLETE", "FILE_CANCEL", "DISCONNECT",
                    "ERROR",
                )

                if message.type_name == "FILE_CHUNK":
                    chunk_id, index, data = message.parse_file_chunk()
                    if chunk_id != file_id:
                        raise ProtocolError(f"chunk for unexpected file {chunk_id!r}")
                    if not data or len(data) > chunk_size:
                        raise ProtocolError(
                            f"chunk length {len(data)} outside (0, {chunk_size}]"
                        )
                    if received % chunk_size != 0:
                        raise ProtocolError("receiver offset not chunk aligned")
                    if index != received // chunk_size:
                        raise ProtocolError(
                            f"unexpected chunk index {index} (expected {received // chunk_size})"
                        )
                    if received + len(data) > info.size:
                        raise ProtocolError(
                            f"file would exceed declared size {info.size}"
                        )
                    fh.write(data)
                    received += len(data)
                    if hasher is not None:
                        hasher.update(data)

                    now = time.monotonic()
                    if now - last_emit >= 0.1:
                        last_emit = now
                        _safe_progress(ctx, file_id, info.path, received, info.size)
                    continue

                if message.type_name == "FILE_COMPLETE":
                    data = message.parse_file_complete_data()
                    if data.get("file_id") != file_id:
                        raise ProtocolError("FILE_COMPLETE for unexpected file")
                    if received != info.size:
                        _send(
                            session,
                            Message.create_file_complete(
                                file_id, False, error="incomplete transfer"
                            ),
                        )
                        record.error = "incomplete transfer"
                        record.received = received
                        _safe_failed(ctx, info.path, "incomplete transfer")
                        return False
                    # flush and close before commit: Windows cannot rename an
                    # open file, so the rename happens after the with-block.
                    try:
                        fh.flush()
                        os.fsync(fh.fileno())
                    except (OSError, ValueError):
                        pass
                    pending_finalize = (received, hasher, data.get("checksum", ""))
                    break

                if message.type_name == "FILE_CANCEL":
                    record.received = received
                    record.error = "cancelled"
                    report.cancelled = True
                    if not report.error:
                        report.error = "peer cancelled the transfer"
                    _send(
                        session,
                        Message.create_file_complete(
                            file_id, False, error="Cancelled by user"
                        ),
                    )
                    _safe_progress(ctx, file_id, info.path, received, info.size)
                    _safe_failed(ctx, info.path, "cancelled")
                    return False  # keep partial for a later resume

                if message.type_name == "DISCONNECT":
                    record.received = received
                    record.error = "peer disconnected"
                    return True

                if message.type_name == "ERROR":
                    code, text = message.parse_error()
                    record.received = received
                    record.error = text or f"error 0x{code:02X}"
                    report.error = record.error
                    report.cancelled = code == 0x08
                    return True
    except ConnectionProblem as exc:
        record.received = received
        record.error = str(exc)
        log.warning("connection error receiving %s: %s", dest, exc)
        _safe_failed(ctx, info.path, record.error)
        raise
    except OSError as exc:
        record.error = f"disk error: {exc}"
        log.warning("disk error receiving %s: %s", dest, exc)
        _safe_failed(ctx, info.path, record.error)
        raise ProtocolError(record.error) from exc

    if pending_finalize is not None:
        received, hasher, declared = pending_finalize
        _finalize(
            session, ctx, record, file_id, dest, partial, received, hasher,
            declared, expected,
        )
    return False


def _finalize(
    session: ConnectionSession,
    ctx: ReceiveContext,
    record: ReceivedFile,
    file_id: str,
    dest: Path,
    partial: Path,
    received: int,
    hasher: Optional[StreamingHasher],
    declared_checksum: str,
    expected=None,
) -> None:
    """Verify, commit (rename), and acknowledge one finished file."""
    record.received = received
    computed = hasher.hexdigest() if hasher is not None else ""
    declared = (declared_checksum or "").strip()

    if hasher is not None and not declared:
        # H1: an empty declared checksum means the sender ran with
        # verification disabled - an opt-out, not a mismatch.  Never
        # discard a file for the peer's settings; accept it by size.
        log.info("sender disabled checksums; accepting %s by size", dest.name)
    elif hasher is not None and computed.lower() != declared.lower():
        resume_mod.discard(partial)
        record.success = False
        record.error = "Checksum mismatch"
        session.send(
            Message.create_file_complete(file_id, False, error="Checksum mismatch")
        )
        log.warning("checksum mismatch for %s", dest.name)
        _safe_failed(ctx, record.relpath, "Checksum mismatch")
        return

    if hasher is None:
        log.warning("checksum verification disabled; accepting %s by size", dest.name)

    if _dest_changed(dest, expected):
        # H9: the conflict decision was taken at manifest time; a file that
        # appeared (or changed) since then must not be silently overwritten.
        decision = _resolve_conflict(ctx, record.relpath, dest, record.size)
        if decision is ConflictAction.KEEP_BOTH:
            try:
                dest = unique_path(dest)
                record.path = dest
            except FileExistsError:
                decision = None
        if decision not in (ConflictAction.REPLACE, ConflictAction.KEEP_BOTH):
            # SKIP / CANCEL / no usable decision: keep the partial so the
            # next attempt resumes cheaply and re-runs the conflict flow.
            record.success = False
            record.error = "destination changed during transfer"
            session.send(
                Message.create_file_complete(
                    file_id, False, error="destination changed during transfer"
                )
            )
            log.warning(
                "%s appeared or changed during transfer; not overwriting",
                dest.name,
            )
            _safe_failed(ctx, record.relpath, record.error)
            return

    resume_mod.commit(partial, dest)
    record.success = True
    record.checksum = computed or declared_checksum
    session.send(Message.create_file_complete(file_id, True))
    _safe_progress(ctx, file_id, record.relpath, received, record.size)
    _safe_completed(ctx, dest, record.checksum, received)
    log.info("received %s (%d bytes) verified=%s", dest, received, bool(computed))


def _safe_progress(ctx, file_id, relpath, received, total) -> None:
    if ctx.progress is None:
        return
    try:
        ctx.progress(file_id, relpath, received, total)
    except Exception:  # pragma: no cover - callback bug must not kill the session
        log.exception("progress callback failed")


def _safe_completed(ctx, dest, checksum, size) -> None:
    if ctx.on_file_complete is None:
        return
    try:
        ctx.on_file_complete(dest, checksum, size)
    except Exception:  # pragma: no cover
        log.exception("completion callback failed")


def _safe_failed(ctx, relpath, error) -> None:
    if ctx.on_file_failed is None:
        return
    try:
        ctx.on_file_failed(relpath, error)
    except Exception:  # pragma: no cover
        log.exception("failure callback failed")
