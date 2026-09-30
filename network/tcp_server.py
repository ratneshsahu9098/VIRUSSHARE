"""virusShare - TCP transfer server (accept loop on TRANSFER_PORT).

The server never blocks the GUI: ``start()`` launches one daemon thread for
the accept loop and one daemon thread per connection.  All user-visible
decisions (pairing dialogs, file conflicts, progress) flow through the
callbacks supplied by the transfer manager.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
from typing import Callable, List, Optional, Set, Tuple

from core.constants import CONNECTION_TIMEOUT, TRANSFER_PORT
from core.security import Identity, TrustStore
from network.protocol import DeviceInfo, ProtocolError, recv_message
from network.session import (
    ApproveCallback,
    ConnectionRejected,
    ConnectionSession,
    HandshakeError,
    SecurityViolation,
    server_handshake,
)

log = logging.getLogger(__name__)

SessionHandler = Callable[[ConnectionSession], None]


class TransferServer:
    """Accepts incoming transfer connections and hands them to a handler."""

    def __init__(
        self,
        device_provider: Callable[[], DeviceInfo],
        identity: Identity,
        trust_store: TrustStore,
        *,
        host: str = "",
        port: int = TRANSFER_PORT,
        encryption: bool = True,
        require_approval: bool = True,
        approve_callback: Optional[ApproveCallback] = None,
        session_handler: Optional[SessionHandler] = None,
        accept_timeout: float = 1.0,
    ):
        self.device_provider = device_provider
        self.identity = identity
        self.trust_store = trust_store
        self.host = host
        self.port = port
        self.encryption = encryption
        self.require_approval = require_approval
        self.approve_callback = approve_callback
        self.session_handler = session_handler
        self.accept_timeout = accept_timeout

        self._listener: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._conn_threads: Set[threading.Thread] = set()
        self._sockets: Set[socket.socket] = set()
        self._lock = threading.Lock()
        self._running = False

    # -- lifecycle --------------------------------------------------------- #

    @property
    def running(self) -> bool:
        return self._running

    @property
    def bound_port(self) -> int:
        if self._listener is None:
            return self.port
        try:
            return self._listener.getsockname()[1]
        except OSError:
            return self.port

    def start(self) -> int:
        if self._running:
            return self.bound_port

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name != "nt":
            # Windows: SO_REUSEADDR would let a second instance silently
            # hijack a port another process already bound; let the bind
            # fail there so start() raises (H3).
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self.host, self.port))
        except OSError as exc:
            listener.close()
            raise RuntimeError(
                f"Cannot bind TCP transfer port {self.port}: {exc}"
            ) from exc
        listener.listen(16)
        listener.settimeout(self.accept_timeout)

        self._listener = listener
        self._running = True
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="transfer-accept", daemon=True
        )
        self._accept_thread.start()
        log.info("transfer server listening on TCP %s", self.bound_port)
        return self.bound_port

    def stop(self) -> None:
        self._running = False
        with self._lock:
            sockets = list(self._sockets)
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None
        accept_thread = self._accept_thread
        if accept_thread is not None and accept_thread is not threading.current_thread():
            accept_thread.join(timeout=3.0)
        for thread in list(self._conn_threads):
            if thread is not threading.current_thread():
                thread.join(timeout=3.0)
        with self._lock:
            for thread in list(self._conn_threads):
                if not thread.is_alive():
                    self._conn_threads.discard(thread)
        log.info("transfer server stopped")

    # -- accept loop ------------------------------------------------------- #

    def _accept_loop(self) -> None:
        while self._running:
            listener = self._listener
            if listener is None:
                return
            try:
                conn, addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    log.warning("accept loop socket error", exc_info=True)
                return

            if not self._running:
                try:
                    conn.close()
                except OSError:
                    pass
                return
            with self._lock:
                self._sockets.add(conn)
            thread = threading.Thread(
                target=self._handle_connection,
                args=(conn, addr),
                name=f"conn-{addr[0]}:{addr[1]}",
                daemon=True,
            )
            with self._lock:
                self._conn_threads.add(thread)
            thread.start()

    def _handle_connection(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        session: Optional[ConnectionSession] = None
        wrapped: List[socket.socket] = []

        def on_wrapped(sock: socket.socket) -> None:
            wrapped.append(sock)
            with self._lock:
                self._sockets.add(sock)

        try:
            if not self._running:
                return
            session, result = server_handshake(
                conn,
                self.device_provider(),
                self.identity,
                self.trust_store,
                encryption=self.encryption,
                require_approval=self.require_approval,
                approve_callback=self.approve_callback,
                on_wrapped=on_wrapped,
            )
            log.info(
                "connection from %s (%s) trusted=%s encrypted=%s",
                result.device.name,
                addr[0],
                result.trusted,
                result.encryption,
            )
            with self._lock:
                self._sockets.add(session.sock)

            if not self._running:
                return
            if self.session_handler is not None:
                self.session_handler(session)
            else:
                self._idle_until_disconnect(session)
        except ConnectionRejected as exc:
            log.info("connection %s:%s rejected: %s", addr[0], addr[1], exc)
        except SecurityViolation as exc:
            log.warning("connection %s:%s failed authentication: %s", addr[0], addr[1], exc)
        except (HandshakeError, ProtocolError) as exc:
            log.warning("connection %s:%s handshake failed: %s", addr[0], addr[1], exc)
        except OSError as exc:
            log.info("connection %s:%s dropped: %s", addr[0], addr[1], exc)
        except Exception:
            log.exception("unexpected error handling connection %s:%s", addr[0], addr[1])
        finally:
            if session is not None:
                session.close()
            else:
                try:
                    conn.close()
                except OSError:
                    pass
            with self._lock:
                for sock in wrapped:
                    self._sockets.discard(sock)
                if session is not None:
                    self._sockets.discard(session.sock)
                self._sockets.discard(conn)
                self._conn_threads.discard(threading.current_thread())

    def _idle_until_disconnect(self, session: ConnectionSession) -> None:
        """Default handler: wait until the client disconnects."""
        while True:
            try:
                message = session.recv(timeout=300.0)
            except (OSError, ProtocolError):
                return
            if message.type_name == "DISCONNECT":
                return
