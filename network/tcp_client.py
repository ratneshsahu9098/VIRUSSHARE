"""virusShare - TCP transfer client (connect + handshake to a peer)."""

from __future__ import annotations

import logging
import socket
from typing import Callable, Optional

from core.constants import CONNECTION_TIMEOUT
from core.security import Identity, TrustStore
from network.protocol import DeviceInfo
from network.session import (
    ApproveCallback,
    ConnectionSession,
    client_handshake,
)

log = logging.getLogger(__name__)


class TransferClient:
    """Opens authenticated transfer sessions to discovered peers."""

    def __init__(
        self,
        device_provider: Callable[[], DeviceInfo],
        identity: Identity,
        trust_store: TrustStore,
        *,
        encryption: bool = True,
        approve_callback: Optional[ApproveCallback] = None,
    ):
        self.device_provider = device_provider
        self.identity = identity
        self.trust_store = trust_store
        self.encryption = encryption
        self.approve_callback = approve_callback

    def connect(
        self,
        host: str,
        port: int,
        timeout: float = CONNECTION_TIMEOUT,
    ) -> ConnectionSession:
        """Connect to ``host:port`` and run the client handshake.

        Raises ConnectionRejected / SecurityViolation / OSError on failure.
        """
        log.info("connecting to %s:%s (encryption=%s)", host, port, self.encryption)
        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            session, result = client_handshake(
                raw,
                self.device_provider(),
                self.identity,
                self.trust_store,
                encryption=self.encryption,
                approve_callback=self.approve_callback,
            )
        except BaseException:
            try:
                raw.close()
            except OSError:
                pass
            raise
        log.info(
            "connected to %s [%s] trusted=%s",
            result.device.name,
            result.fingerprint[:12],
            result.trusted,
        )
        return session
