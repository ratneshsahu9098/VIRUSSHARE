"""virusShare - Qt bridge for worker-thread callbacks.

Worker threads (handshake, transfer, discovery) must not touch widgets.
This module gives them two safe mechanisms:

* ``ThreadBridge`` — a QObject whose signals are emitted from worker threads
  and delivered on the GUI thread (Qt queued connections do the hop).
* ``request_*`` helpers — synchronous round-trips: the worker blocks on a
  ``concurrent.futures.Future`` while the GUI thread shows a modal dialog
  and sets the result.  Timeouts fall back to a safe default (reject/skip)
  so a hidden window can never wedge a network thread forever.
"""

from __future__ import annotations

import logging
import uuid
from concurrent.futures import Future
from typing import Any, Callable, Dict, Optional

from PySide6.QtCore import QObject, Signal

from core.constants import CONTROL_MESSAGE_TIMEOUT

log = logging.getLogger(__name__)

# how long a worker waits for the user to answer a modal prompt; must expire
# strictly before the peer's control-message socket wait gives up on us
PROMPT_MARGIN = 5.0
APPROVAL_TIMEOUT = CONTROL_MESSAGE_TIMEOUT - PROMPT_MARGIN
CONFLICT_TIMEOUT = CONTROL_MESSAGE_TIMEOUT - PROMPT_MARGIN


class ThreadBridge(QObject):
    """Signals emitted from any thread, handled on the GUI thread."""

    deviceFound = Signal(object)      # DiscoveredDevice
    deviceLost = Signal(str)          # device_id
    deviceTrusted = Signal(str, bool)  # device_id, trusted (fp-verified handshake or user toggle)
    sessionUpdate = Signal(object)    # models.TransferSession
    sessionFinished = Signal(object)  # models.TransferSession
    approvalRequested = Signal(str, object)  # request id, payload
    conflictRequested = Signal(str, object)  # request id, payload
    logMessage = Signal(str)

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._pending: Dict[str, Future] = {}

    # -- futures ------------------------------------------------------- #

    def _new_request(self) -> str:
        request_id = uuid.uuid4().hex
        future: Future = Future()
        self._pending[request_id] = future
        return request_id

    def _resolve(self, request_id: str, value: Any) -> None:
        future = self._pending.get(request_id)
        if future is not None and not future.done():
            future.set_result(value)

    def _wait(self, request_id: str, timeout: float, default: Any) -> Any:
        # Keep the future in _pending while waiting: the GUI resolves through
        # _pending, and popping it here would discard every answer that lands
        # after the emit (the normal queued-signal case).
        future = self._pending.get(request_id)
        if future is None:
            return default
        try:
            return future.result(timeout=timeout)
        except Exception:  # noqa: BLE001 - timeout or GUI gone
            log.warning("prompt %s timed out; using default %r", request_id, default)
            return default
        finally:
            self._pending.pop(request_id, None)

    # -- worker-side entry points --------------------------------------- #

    def request_approval(
        self,
        payload: Dict[str, Any],
        *,
        default: bool = False,
        timeout: float = APPROVAL_TIMEOUT,
    ) -> bool:
        """Ask the GUI whether to accept/pair with a peer. Blocks the caller."""
        request_id = self._new_request()
        self.approvalRequested.emit(request_id, payload)
        return bool(self._wait(request_id, timeout, default))

    def request_conflict(
        self,
        payload: Dict[str, Any],
        *,
        default: str = "skip",
        timeout: float = CONFLICT_TIMEOUT,
        scope: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Ask the GUI how to resolve a file conflict. Blocks the caller.

        ``scope`` is the per-session dict owned by one ``make_conflict_callback``
        closure; an "apply to all" answer is stored there and never escapes
        into the next session (M19).
        """
        request_id = self._new_request()
        self.conflictRequested.emit(request_id, payload)
        value = self._wait(request_id, timeout, None)
        if isinstance(value, tuple):
            action, apply_all = value
            if apply_all and scope is not None:
                scope["override"] = action
        else:
            action = value
        if action not in ("replace", "keep_both", "skip", "cancel"):
            return default
        return action

    def cancel_all_prompts(self) -> None:
        """Called on shutdown so blocked workers wake up immediately."""
        for request_id in list(self._pending):
            self._resolve(request_id, None)

    def is_prompt_pending(self, request_id: str) -> bool:
        """GUI-side: is this prompt still waiting for an answer?"""
        future = self._pending.get(request_id)
        return future is not None and not future.done()

    # -- GUI-side handlers (connected in MainWindow) --------------------- #

    def resolve_approval(self, request_id: str, accepted: bool) -> None:
        self._resolve(request_id, bool(accepted))

    def resolve_conflict(
        self, request_id: str, action: str, apply_all: bool = False
    ) -> None:
        self._resolve(request_id, (action, apply_all))


def make_approval_callback(
    bridge: ThreadBridge,
    auto_accept: Callable[[], bool],
    trust_store: Optional[Any] = None,
) -> Callable[..., bool]:
    """Adapter used as TransferServer/TransferClient approve_callback.

    ``auto_accept`` is the "accept trusted devices without asking" setting.
    It may only skip the prompt for a fingerprint that is *already* trusted —
    never for an unknown peer (that would auto-pair anyone on the LAN).
    """

    def approve(peer_device, peer_fp, our_fp, code) -> bool:
        if (
            auto_accept()
            and trust_store is not None
            and trust_store.is_trusted(
                getattr(peer_device, "device_id", ""), peer_fp
            )
        ):
            return True
        payload = {
            "kind": "approval",
            "name": getattr(peer_device, "name", "?"),
            "ip": getattr(peer_device, "ip", ""),
            "device_id": getattr(peer_device, "device_id", ""),
            "fingerprint": peer_fp,
            "code": getattr(code, "short", None) or str(code),
            "code_full": getattr(code, "canonical", "") or str(code),
        }
        return bridge.request_approval(payload, default=False)

    return approve


def make_conflict_callback(bridge: ThreadBridge) -> Callable[..., Any]:
    """Adapter used as ReceiveContext.conflict_callback (maps str -> enum).

    Each callback owns a fresh scope dict, so "apply to all" is reused for
    the rest of this session only (M19).
    """
    from transfer.receiver import ConflictAction, ConflictDecision

    scope: Dict[str, Any] = {}

    def decision(action: str) -> ConflictDecision:
        try:
            return ConflictDecision(ConflictAction(action))
        except ValueError:
            return ConflictDecision(ConflictAction.SKIP)

    def resolve(request) -> ConflictDecision:
        override = scope.get("override")
        if override:
            return decision(override)
        payload = {
            "kind": "conflict",
            "relpath": request.relpath,
            "dest_path": str(request.dest_path),
            "incoming_size": request.incoming_size,
            "existing_size": request.existing_size,
        }
        action = bridge.request_conflict(payload, default="skip", scope=scope)
        return decision(action)

    return resolve
