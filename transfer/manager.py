"""virusShare - transfer orchestration.

``TransferManager`` bridges the transport layer (``transfer.sender`` /
``transfer.receiver``) and the domain models (``models.TransferSession``):

* one worker thread per outgoing job, with a FIFO concurrency limit
* pause / resume / cancel via :class:`transfer.sender.TransferControls`
* automatic reconnection with resume (partial files make retries cheap)
* event callbacks (``on_update`` / ``on_finished``) for the GUI

Callbacks fire on worker threads — a Qt caller must marshal them onto the
GUI thread (e.g. ``QMetaObject.invokeMethod`` or a signal emitter).
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set

from core.constants import (
    CONNECTION_TIMEOUT,
    CONTROL_MESSAGE_TIMEOUT,
    HANDSHAKE_TIMEOUT,
    SEND_CHUNK_SIZE,
)
from core.security import Identity, TrustStore
from models import TransferFile, TransferSession, TransferStatus
from network.protocol import DeviceInfo, ProtocolError
from network.session import ConnectionRejected, SecurityViolation
from network.tcp_client import TransferClient
from transfer.receiver import ReceiveContext, ReceiveReport
from transfer.sender import (
    PushReport,
    SendEntry,
    TransferControls,
    build_manifest,
    push_files,
)

log = logging.getLogger(__name__)

UpdateCallback = Callable[[TransferSession], None]
FinishedCallback = Callable[[TransferSession], None]

_RECONNECT_BACKOFF = 0.5  # seconds; grows linearly per attempt

# Failures that make a retry pointless (auth/policy), versus transient
# socket problems where a fresh connection + resume can succeed.
_PERMANENT_ERRORS = (ConnectionRejected, SecurityViolation)


class TransferManager:
    """Runs outgoing push jobs and tracks incoming ones as models."""

    def __init__(
        self,
        *,
        identity: Identity,
        trust_store: TrustStore,
        device_provider: Callable[[], DeviceInfo],
        approve_callback: Optional[Callable[..., bool]] = None,
        settings: Optional[Mapping[str, Any]] = None,
        on_update: Optional[UpdateCallback] = None,
        on_finished: Optional[FinishedCallback] = None,
        on_peer_trusted: Optional[Callable[[str], None]] = None,
        connect_timeout: float = CONNECTION_TIMEOUT,
    ) -> None:
        settings = dict(settings or {})
        self.identity = identity
        self.trust_store = trust_store
        self.device_provider = device_provider
        self.approve_callback = approve_callback
        self.on_update = on_update
        self.on_finished = on_finished
        self.on_peer_trusted = on_peer_trusted
        self.connect_timeout = connect_timeout

        self.max_concurrent = max(1, int(settings.get("max_concurrent_transfers", 3)))
        self.chunk_size = int(settings.get("chunk_size", SEND_CHUNK_SIZE))
        self.verify = bool(settings.get("verify_checksums", True))
        self.encryption = bool(settings.get("enable_encryption", True))
        self.reconnect_attempts = max(0, int(settings.get("reconnect_attempts", 3)))
        self.receive_dir = Path(
            settings.get("save_received_files_to") or Path.home() / "Downloads"
        )

        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        self._active = 0
        self._sessions: Dict[str, TransferSession] = {}
        self._controls: Dict[str, TransferControls] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._finalized: Set[str] = set()
        self._shutdown = False

    def apply_settings(self, settings: Optional[Mapping[str, Any]]) -> None:
        """Refresh tunables after the user edits Settings (H4).

        The constructor snapshots these once; without this, "Change Location"
        and the settings dialog only update the stored setting while every
        transfer keeps using the old values.
        """
        settings = dict(settings or {})

        def _int(key: str, current: int, minimum: Optional[int] = None) -> int:
            try:
                value = int(settings.get(key, current))
            except (TypeError, ValueError):
                log.warning("invalid %r in settings; keeping %d", key, current)
                return current
            return max(minimum, value) if minimum is not None else value

        def _bool(key: str, current: bool) -> bool:
            value = settings.get(key, current)
            return current if value is None else bool(value)

        with self._lock:
            self.max_concurrent = _int(
                "max_concurrent_transfers", self.max_concurrent, minimum=1
            )
            self.chunk_size = _int("chunk_size", self.chunk_size)
            self.verify = _bool("verify_checksums", self.verify)
            self.encryption = _bool("enable_encryption", self.encryption)
            self.reconnect_attempts = _int(
                "reconnect_attempts", self.reconnect_attempts, minimum=0
            )
            receive_dir = settings.get("save_received_files_to")
            if receive_dir:
                self.receive_dir = Path(receive_dir)
            log.info(
                "settings applied: dir=%s chunk=%d verify=%s concurrency=%d",
                self.receive_dir,
                self.chunk_size,
                self.verify,
                self.max_concurrent,
            )

    # ------------------------------------------------------------------ #
    # session registry / events
    # ------------------------------------------------------------------ #

    @property
    def sessions(self) -> List[TransferSession]:
        with self._lock:
            return list(self._sessions.values())

    def get(self, session_id: str) -> Optional[TransferSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def _emit_update(self, model: TransferSession) -> None:
        if self.on_update is not None:
            try:
                self.on_update(model)
            except Exception:  # noqa: BLE001 - a UI bug must not kill a worker
                log.exception("on_update callback failed")

    def _emit_finished(self, model: TransferSession) -> None:
        if self.on_finished is not None:
            try:
                self.on_finished(model)
            except Exception:  # noqa: BLE001
                log.exception("on_finished callback failed")

    # ------------------------------------------------------------------ #
    # concurrency slots
    # ------------------------------------------------------------------ #

    def _acquire_slot(self, controls: TransferControls) -> bool:
        with self._cond:
            while True:
                if self._shutdown or controls.cancelled:
                    return False
                if self._active < self.max_concurrent:
                    self._active += 1
                    return True
                self._cond.wait(0.25)

    def _release_slot(self) -> None:
        with self._cond:
            self._active = max(0, self._active - 1)
            self._cond.notify_all()

    # ------------------------------------------------------------------ #
    # outgoing jobs
    # ------------------------------------------------------------------ #

    def send_files(
        self,
        target: DeviceInfo,
        paths: Sequence[Path],
        *,
        title: Optional[str] = None,
    ) -> TransferSession:
        """Queue a push of ``paths`` to ``target``. Returns immediately."""
        entries = build_manifest([Path(p) for p in paths])
        if not entries:
            raise ValueError("nothing to send")

        model = TransferSession(
            id=str(uuid.uuid4()),
            computer_id=target.device_id,
            computer_name=target.name,
            status=TransferStatus.PENDING,
            start_time=_now(),
            direction="send",
        )
        model.current_file = title or ""
        for entry in entries:
            if not entry.is_dir:
                model.add_file(
                    TransferFile(
                        id=entry.file_id,
                        name=Path(entry.relpath).name,
                        path=str(entry.source),
                        size=entry.size,
                    )
                )
        controls = TransferControls()

        with self._lock:
            self._sessions[model.id] = model
            self._controls[model.id] = controls
            thread = threading.Thread(
                target=self._run_send,
                args=(model, target, entries, controls),
                name=f"send-{model.id[:8]}",
                daemon=True,
            )
            self._threads[model.id] = thread
        thread.start()
        self._emit_update(model)
        return model

    def _run_send(
        self,
        model: TransferSession,
        target: DeviceInfo,
        entries: List[SendEntry],
        controls: TransferControls,
    ) -> None:
        acquired = False
        try:
            if not self._acquire_slot(controls):
                self._finalize(
                    model,
                    TransferStatus.CANCELLED
                    if controls.cancelled
                    else TransferStatus.FAILED,
                    error="" if controls.cancelled else "manager is shutting down",
                )
                return
            acquired = True
            if controls.cancelled:
                self._finalize(model, TransferStatus.CANCELLED)
                return

            model.status = TransferStatus.ACTIVE
            model.start_time = _now()
            self._emit_update(model)

            client = TransferClient(
                device_provider=self.device_provider,
                identity=self.identity,
                trust_store=self.trust_store,
                encryption=self.encryption,
                approve_callback=self.approve_callback,
            )

            completed_bytes = 0
            last_error = ""
            attempt = 0
            while True:
                attempt += 1
                report = PushReport()
                try:
                    conn = client.connect(
                        target.ip,
                        target.port,
                        timeout=self.connect_timeout,
                    )
                    # fingerprint was verified against the trust store during
                    # the handshake — report it so the GUI badge never has to
                    # trust a self-asserted discovery packet (H7)
                    if conn.result.trusted and self.on_peer_trusted is not None:
                        try:
                            self.on_peer_trusted(conn.result.device.device_id)
                        except Exception:  # noqa: BLE001
                            log.exception("on_peer_trusted callback failed")
                    try:
                        conn.sock.settimeout(CONTROL_MESSAGE_TIMEOUT)
                        report = push_files(
                            conn,
                            entries,
                            chunk_size=self.chunk_size,
                            controls=controls,
                            progress=self._progress_fn(model, completed_bytes),
                            verify=self.verify,
                        )
                    finally:
                        conn.close()
                except _PERMANENT_ERRORS as exc:
                    self._finalize(model, TransferStatus.FAILED, error=str(exc))
                    return
                except (OSError, ProtocolError) as exc:
                    report = PushReport(error=str(exc))
                    log.warning(
                        "send attempt %d to %s failed: %s",
                        attempt,
                        target.name,
                        exc,
                    )

                if controls.cancelled or report.cancelled:
                    self._finalize(model, TransferStatus.CANCELLED, error=report.error)
                    return
                if report.success:
                    model.transferred_size = report.total_sent
                    self._finalize(model, TransferStatus.COMPLETED)
                    return

                last_error = _report_error(report)
                completed_bytes += sum(
                    r.sent for r in report.results if r.success
                )
                if report.results and all(r.skipped for r in report.results):
                    break
                if attempt > self.reconnect_attempts:
                    break
                log.info(
                    "reconnecting to %s (attempt %d/%d): %s",
                    target.name,
                    attempt + 1,
                    self.reconnect_attempts + 1,
                    last_error,
                )
                if controls.wait_interruptible(_RECONNECT_BACKOFF * attempt):
                    self._finalize(model, TransferStatus.CANCELLED)
                    return

            self._finalize(model, TransferStatus.FAILED, error=last_error)
        except Exception as exc:  # noqa: BLE001 - worker must never leak
            log.exception("send worker crashed")
            self._finalize(model, TransferStatus.FAILED, error=str(exc))
        finally:
            if acquired:
                self._release_slot()
            with self._cond:
                self._controls.pop(model.id, None)
                self._threads.pop(model.id, None)

    def _progress_fn(self, model: TransferSession, completed_bytes: int):
        def progress(file_id: str, relpath: str, sent: int, size: int, total: int) -> None:
            model.current_file = relpath
            model.current_file_progress = sent
            model.current_file_size = size
            model.transferred_size = completed_bytes + total
            self._emit_update(model)

        return progress

    # ------------------------------------------------------------------ #
    # pause / resume / cancel
    # ------------------------------------------------------------------ #

    def pause(self, session_id: str) -> bool:
        controls = self._controls_for(session_id)
        if controls is None:
            return False
        controls.pause()
        with self._lock:
            model = self._sessions.get(session_id)
            if model is None:
                return True
            status = model.status
            if (
                status is TransferStatus.ACTIVE
                and session_id not in self._finalized
            ):
                model.status = TransferStatus.PAUSED
                emit = model
            else:
                emit = None
        if emit is not None:
            self._emit_update(emit)
        return True

    def resume(self, session_id: str) -> bool:
        controls = self._controls_for(session_id)
        if controls is None:
            return False
        controls.resume()
        with self._lock:
            model = self._sessions.get(session_id)
            if model is None:
                return True
            status = model.status
            if (
                status is TransferStatus.PAUSED
                and session_id not in self._finalized
            ):
                model.status = TransferStatus.ACTIVE
                emit = model
            else:
                emit = None
        if emit is not None:
            self._emit_update(emit)
        return True

    def cancel(self, session_id: str) -> bool:
        controls = self._controls_for(session_id)
        if controls is None:
            return False
        controls.cancel()
        with self._lock:
            model = self._sessions.get(session_id)
            if model is None:
                return True
            status = model.status
            if (
                status in (
                    TransferStatus.PENDING,
                    TransferStatus.ACTIVE,
                    TransferStatus.PAUSED,
                )
                and session_id not in self._finalized
            ):
                model.status = TransferStatus.CANCELLED
                model.end_time = _now()
                emit = model
            else:
                emit = None
        if emit is not None:
            self._emit_update(emit)
        return True

    def _controls_for(self, session_id: str) -> Optional[TransferControls]:
        with self._lock:
            return self._controls.get(session_id)

    # ------------------------------------------------------------------ #
    # incoming jobs
    # ------------------------------------------------------------------ #

    def begin_receive(self, peer: DeviceInfo) -> TransferSession:
        """Register an incoming transfer (called when a peer connects)."""
        model = TransferSession(
            id=str(uuid.uuid4()),
            computer_id=peer.device_id,
            computer_name=peer.name,
            status=TransferStatus.ACTIVE,
            start_time=_now(),
            direction="receive",
        )
        with self._lock:
            self._sessions[model.id] = model
        self._emit_update(model)
        return model

    def receive_context(
        self,
        model: TransferSession,
        *,
        conflict_callback=None,
        progress=None,
        on_file_complete=None,
        on_file_failed=None,
    ) -> ReceiveContext:
        """Build a :class:`ReceiveContext` that mirrors progress into ``model``."""

        # ``received`` from the progress callback is per-file; keep a running
        # total of finished files so the session-wide number never rewinds.
        completed_bytes = {"done": 0}

        def _progress(file_id: str, relpath: str, received: int, total: int) -> None:
            model.current_file = relpath
            model.current_file_progress = received
            model.current_file_size = total
            model.transferred_size = completed_bytes["done"] + received
            self._emit_update(model)
            if progress is not None:
                progress(file_id, relpath, received, total)

        def _file_complete(dest, checksum: str, size: int) -> None:
            completed_bytes["done"] += int(size)
            if on_file_complete is not None:
                on_file_complete(dest, checksum, size)

        return ReceiveContext(
            receive_dir=self.receive_dir,
            conflict_callback=conflict_callback,
            progress=_progress,
            on_file_complete=_file_complete,
            on_file_failed=on_file_failed,
            verify=self.verify,
        )

    def finish_receive(self, model: TransferSession, report: ReceiveReport) -> None:
        """Apply a :class:`ReceiveReport` to ``model`` and emit the finish."""
        for f in report.files:
            model.add_file(
                TransferFile(
                    id=f.relpath,
                    name=Path(f.relpath).name,
                    path=str(f.path) if f.path else "",
                    size=f.size,
                    checksum=f.checksum,
                )
            )
        model.transferred_size = sum(f.received for f in report.files)
        # M33: the receive model is ACTIVE while files arrive, so add_file
        # does not accumulate totals (mid-transfer it would rewrite the
        # denominator).  Set the final total explicitly from the report.
        model.total_size = sum(f.size for f in report.files)
        if report.cancelled:
            status = TransferStatus.CANCELLED
        elif report.success:
            status = TransferStatus.COMPLETED
        else:
            status = TransferStatus.FAILED
        self._finalize(model, status, error=report.error)

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #

    def _finalize(
        self,
        model: TransferSession,
        status: TransferStatus,
        error: str = "",
    ) -> None:
        """Terminal transition. Emits update + finished exactly once per id."""
        with self._lock:
            if model.id in self._finalized:
                return
            self._finalized.add(model.id)
            # a user cancel() may have set the status already; keep it
            if model.status not in (
                TransferStatus.COMPLETED,
                TransferStatus.FAILED,
                TransferStatus.CANCELLED,
            ):
                model.status = status
                if error:
                    model.error_message = error
            elif error and not model.error_message:
                model.error_message = error
            if model.end_time is None:
                model.end_time = _now()
            if model.status is TransferStatus.COMPLETED and model.current_file_size:
                model.current_file_progress = model.current_file_size
        self._emit_update(model)
        self._emit_finished(model)

    def wait(self, session_id: str, timeout: Optional[float] = None) -> bool:
        """Block until the worker for ``session_id`` exits (tests/shutdown)."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._lock:
                thread = self._threads.get(session_id)
            if thread is None:
                return True
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                return False
            thread.join(timeout=0.1 if remaining is None else min(0.1, remaining))

    def wait_all(self, timeout: Optional[float] = None) -> bool:
        """Block until every worker has exited (tests/shutdown)."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._lock:
                pending = list(self._threads)
            if not pending:
                return True
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                return False
            for sid in pending:
                self.wait(sid, timeout=0.1)

    def shutdown(
        self,
        timeout: float = 10.0,
        on_wait: Optional[Callable[[], None]] = None,
    ) -> None:
        """Cancel all jobs and wait for workers to exit.

        ``on_wait`` is invoked after every 0.1 s wait slice so a GUI caller
        can keep processing events instead of freezing while workers wind
        down (M27).
        """
        with self._lock:
            self._shutdown = True
            ids = list(self._controls)
        for sid in ids:
            self.cancel(sid)
        with self._cond:
            self._cond.notify_all()
        if on_wait is None:
            self.wait_all(timeout=timeout)
        else:
            deadline = time.monotonic() + timeout
            while True:
                finished = self.wait_all(timeout=0.1)
                try:
                    on_wait()
                except Exception:  # noqa: BLE001
                    log.exception("shutdown wait hook failed")
                if finished or time.monotonic() >= deadline:
                    break
        with self._lock:
            live = {
                sid
                for sid, thread in self._threads.items()
                if thread.is_alive()
            }
            for sid in list(self._threads):
                if sid not in live:
                    self._threads.pop(sid, None)
            for sid in list(self._sessions):
                if sid not in live:
                    self._sessions.pop(sid, None)
            for sid in list(self._controls):
                if sid not in live:
                    self._controls.pop(sid, None)


def _report_error(report: PushReport) -> str:
    """Session-level error, else the first file-level failure (M21).

    ``report.error`` only carries protocol/session failures; a per-file
    rejection like "Checksum mismatch" lives on the FileResult and would
    otherwise surface to the user as the useless "transfer failed".
    """
    if report.error:
        return report.error
    for result in report.results:
        if not result.success and not result.skipped and result.error:
            return f"{result.relpath}: {result.error}"
    return "transfer failed"


def _now() -> datetime:
    return datetime.now()
