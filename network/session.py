"""virusShare - connection sessions and the authenticated handshake.

Handshake flow (encryption on):

    client                                     server
      │  TCP connect + TLS handshake             │
      ├─────────────────────────────────────────►│
      │                                          │  generate nonce_s
      │        SESSION_CHALLENGE {device,        │  sign(server||nonce_s)
      │        cert_s, nonce_s, sig_s}           │
      ├─────────────────────────────────────────►│
      │  verify sig_s against cert_s             │
      │  cross-check cert_s == TLS certificate   │
      │  generate nonce_c                        │
      │  sign(client||nonce_s||nonce_c)          │
      │  CONNECT_REQUEST {device, cert_c,        │
      │                   nonce_c, sig_c}        │
      ├─────────────────────────────────────────►│
      │                                          │  verify sig_c
      │                                          │  pair / trust / approve
      │        CONNECT_RESPONSE {accepted,       │
      │        device, paired}                   │
      ├─────────────────────────────────────────◄│
      │  [if paired: both sides compare the      │
      │   pairing code shown to the user]        │
      │  PAIR_CONFIRM {code}  ──────────────────►│
      │  PAIR_CONFIRM {code}  ◄──────────────────┤
      │                                          │
      ready                                      ready

Authentication never relies on device_id, MAC or IP: the server proves
possession of its certificate private key inside the TLS handshake, the
client proves possession with an ECDSA signature over a server-chosen
nonce, and first-time pairing is confirmed by comparing a code derived
from both certificate fingerprints on both screens.
"""

from __future__ import annotations

import logging
import secrets
import socket
import ssl
import threading
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple

from core.constants import (
    CONNECTION_TIMEOUT,
    CONTROL_MESSAGE_TIMEOUT,
    HANDSHAKE_TIMEOUT,
    MESSAGE_TYPES,
)
from core.security import (
    Identity,
    PairingCode,
    SecurityError,
    TrustStore,
    client_challenge_data,
    compute_pairing_code,
    fingerprint_cert,
    server_challenge_data,
    verify_signature,
)
from network.protocol import (
    DeviceInfo,
    Message,
    ProtocolError,
    expect_message_type,
    recv_message,
    send_message,
)

log = logging.getLogger(__name__)

ApproveCallback = Callable[[DeviceInfo, str, str, PairingCode], bool]


class HandshakeError(Exception):
    """Base class for handshake failures."""


class ConnectionRejected(HandshakeError):
    """The peer refused the connection (user rejected, policy, or shutdown)."""


class SecurityViolation(HandshakeError):
    """The peer failed authentication or presented an unexpected identity."""


@dataclass
class HandshakeResult:
    device: DeviceInfo
    fingerprint: str
    trusted: bool
    paired: bool
    encryption: bool
    remote_address: str = ""


class ConnectionSession:
    """One authenticated peer connection with framing helpers."""

    def __init__(
        self,
        sock: socket.socket,
        local_device: DeviceInfo,
        is_server: bool,
        encryption: bool,
        identity: Identity,
        result: HandshakeResult,
    ):
        self.sock = sock
        self.local_device = local_device
        self.is_server = is_server
        self.encryption = encryption
        self.identity = identity
        self.result = result
        self._seq = 0
        self._lock = threading.Lock()
        self._closed = False

    # -- metadata ---------------------------------------------------------- #

    @property
    def peer_device(self) -> DeviceInfo:
        return self.result.device

    @property
    def peer_fingerprint(self) -> str:
        return self.result.fingerprint

    @property
    def peer_address(self) -> str:
        try:
            addr = self.sock.getpeername()
            return f"{addr[0]}:{addr[1]}"
        except OSError:
            return self.result.remote_address

    @property
    def closed(self) -> bool:
        return self._closed

    # -- messaging --------------------------------------------------------- #

    def next_sequence(self) -> int:
        with self._lock:
            seq = self._seq
            self._seq = (self._seq + 1) & 0xFFFF
            return seq

    def send(self, message: Message) -> None:
        if message.sequence == 0:
            message.sequence = self.next_sequence()
        send_message(self.sock, message)

    def recv(self, timeout: Optional[float] = None) -> Message:
        """Receive one message; ``timeout`` applies only for this call."""
        if timeout is None:
            return recv_message(self.sock)
        old = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        try:
            return recv_message(self.sock)
        finally:
            try:
                self.sock.settimeout(old)
            except OSError:
                pass

    def expect(self, *type_names: str, timeout: Optional[float] = None) -> Message:
        """Receive one message and validate its type before any parser runs."""
        message = self.recv(timeout=timeout)
        return expect_message_type(message, *type_names)

    def send_error(self, code: int, text: str) -> None:
        try:
            self.send(Message.create_error(code, text))
        except OSError:
            pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.sock.close()
        except OSError:
            pass

    def shutdown_gracefully(self) -> None:
        """Send DISCONNECT (best effort) then close."""
        if not self._closed:
            try:
                self.send(Message.create_disconnect())
            except OSError:
                pass
        self.close()

    def __enter__(self) -> "ConnectionSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# --------------------------------------------------------------------------- #
# transport helpers
# --------------------------------------------------------------------------- #

def build_server_ssl_context(identity: Identity) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if not identity.path:  # pragma: no cover - identity always has a path in practice
        raise SecurityError("identity has no backing file for TLS")
    ctx.load_cert_chain(str(identity.path))
    return ctx


def build_client_ssl_context() -> ssl.SSLContext:
    # Peer certificates are self-signed; authenticity is established by the
    # application-layer fingerprint/pairing handshake, not a CA chain.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def tune_socket(sock: socket.socket) -> None:
    """TCP_NODELAY + aggressive keepalive so paused transfers detect dead peers."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    if hasattr(socket, "SIO_KEEPALIVE_VALS"):  # Windows
        try:
            sock.ioctl(
                socket.SIO_KEEPALIVE_VALS,
                struct_keepalive(10_000, 3_000),  # type: ignore[name-defined]
            )
        except OSError:
            pass


def struct_keepalive(time_ms: int, interval_ms: int) -> Tuple[int, int, int]:
    return (1, time_ms, interval_ms)


# --------------------------------------------------------------------------- #
# handshake - server side
# --------------------------------------------------------------------------- #

def server_handshake(
    sock: socket.socket,
    local_device: DeviceInfo,
    identity: Identity,
    trust_store: TrustStore,
    *,
    encryption: bool = True,
    require_approval: bool = True,
    approve_callback: Optional[ApproveCallback] = None,
    handshake_timeout: float = HANDSHAKE_TIMEOUT,
    control_timeout: float = CONTROL_MESSAGE_TIMEOUT,
    on_wrapped: Optional[Callable[[socket.socket], None]] = None,
) -> Tuple[ConnectionSession, HandshakeResult]:
    """Run the server side of the handshake on an accepted socket."""
    remote = _remote_label(sock)
    sock.settimeout(handshake_timeout)
    tune_socket(sock)

    try:
        if encryption:
            ctx = build_server_ssl_context(identity)
            sock = ctx.wrap_socket(sock, server_side=True)
            sock.settimeout(handshake_timeout)
            if on_wrapped is not None:
                on_wrapped(sock)

        our_fp = identity.fingerprint

        # 1. server hello: certificate + fresh nonce, proves key possession.
        nonce_s = secrets.token_bytes(32)
        challenge = Message.create_session_challenge(
            local_device, identity.cert_der, nonce_s, identity.sign(server_challenge_data(nonce_s))
        )
        sock.sendall(challenge.encode())

        # 2. client request, bound to our nonce.
        request = recv_message(sock)
        expect_message_type(request, "CONNECT_REQUEST")
        peer_device, cert_c, nonce_c, signature = request.parse_connect_request_ex()
        if not verify_signature(cert_c, client_challenge_data(nonce_s, nonce_c), signature):
            raise SecurityViolation(f"client {peer_device.name!r} failed possession proof")

        peer_fp = fingerprint_cert(cert_c)

        # 3. trust decision.
        known = trust_store.get(peer_device.device_id)
        trusted = trust_store.is_trusted(peer_device.device_id, peer_fp)
        if known and not trusted:
            log.warning(
                "identity change for %s (stored %s..., presented %s...)",
                peer_device.name,
                known.get("fingerprint", "")[:12],
                peer_fp[:12],
            )

        paired = False
        if not trusted:
            if require_approval:
                code = compute_pairing_code(our_fp, peer_fp)
                accepted = False
                if approve_callback is not None:
                    accepted = bool(
                        approve_callback(peer_device, peer_fp, our_fp, code)
                    )
                if not accepted:
                    _send_rejected(sock, local_device, "Connection rejected")
                    raise ConnectionRejected(
                        f"rejected connection from {peer_device.name}"
                    )
                paired = True
            else:
                log.info(
                    "auto-accepting unpaired connection from %s (approval disabled)",
                    peer_device.name,
                )

        response = Message.create_connect_response(
            True, local_device, paired=paired
        )
        sock.sendall(response.encode())

        # 4. pairing confirmation.
        if paired:
            sock.settimeout(control_timeout)
            confirm = recv_message(sock)
            if confirm.msg_type == MESSAGE_TYPES["ERROR"]:
                try:
                    _, text = confirm.parse_error()
                except ProtocolError:
                    text = "rejected"
                raise ConnectionRejected(f"peer declined pairing: {text}")
            expect_message_type(confirm, "PAIR_CONFIRM")
            code = confirm.parse_pair_confirm()
            ours = compute_pairing_code(our_fp, peer_fp)
            if not secrets.compare_digest(code, ours.canonical):
                sock.sendall(
                    Message.create_error(0x06, "Pairing code mismatch").encode()
                )
                raise SecurityViolation("pairing code mismatch during confirmation")
            trust_store.add(peer_device.device_id, peer_device.name, peer_fp)
            sock.sendall(Message.create_pair_confirm(ours.canonical).encode())
            log.info("paired with %s (%s)", peer_device.name, peer_fp[:12])

        result = HandshakeResult(
            device=peer_device,
            fingerprint=peer_fp,
            trusted=trust_store.is_trusted(peer_device.device_id, peer_fp),
            paired=paired,
            encryption=encryption,
            remote_address=remote,
        )
        session = ConnectionSession(sock, local_device, True, encryption, identity, result)
        sock.settimeout(None)  # transfer phase: blocking reads, keepalive for dead peers
        return session, result
    except (ProtocolError, SecurityError) as exc:
        _safe_close(sock)
        raise SecurityViolation(str(exc)) from exc
    except HandshakeError:
        _safe_close(sock)
        raise
    except (OSError, ssl.SSLError) as exc:
        _safe_close(sock)
        raise ConnectionRejected(f"handshake transport error: {exc}") from exc
    except Exception:
        _safe_close(sock)
        raise


# --------------------------------------------------------------------------- #
# handshake - client side
# --------------------------------------------------------------------------- #

def client_handshake(
    sock: socket.socket,
    local_device: DeviceInfo,
    identity: Identity,
    trust_store: TrustStore,
    *,
    encryption: bool = True,
    approve_callback: Optional[ApproveCallback] = None,
    handshake_timeout: float = HANDSHAKE_TIMEOUT,
    control_timeout: float = CONTROL_MESSAGE_TIMEOUT,
) -> Tuple[ConnectionSession, HandshakeResult]:
    """Run the client side of the handshake on a connected socket."""
    remote = _remote_label(sock)
    sock.settimeout(handshake_timeout)
    tune_socket(sock)

    try:
        tls_cert_der: Optional[bytes] = None
        if encryption:
            ctx = build_client_ssl_context()
            sock = ctx.wrap_socket(sock, server_hostname=None)
            sock.settimeout(handshake_timeout)
            tls_cert_der = sock.getpeercert(binary_form=True)
            if not tls_cert_der:
                raise SecurityViolation("TLS peer did not present a certificate")

        our_fp = identity.fingerprint

        # 1. server hello.
        challenge = recv_message(sock)
        expect_message_type(challenge, "SESSION_CHALLENGE")
        server_device, cert_s, nonce_s, signature = challenge.parse_session_challenge()
        if not verify_signature(cert_s, server_challenge_data(nonce_s), signature):
            raise SecurityViolation(f"server {server_device.name!r} failed possession proof")
        server_fp = fingerprint_cert(cert_s)

        if encryption and tls_cert_der and fingerprint_cert(tls_cert_der) != server_fp:
            raise SecurityViolation(
                "application certificate differs from the TLS certificate (possible intercept)"
            )

        # 2. our request, bound to the server nonce.
        nonce_c = secrets.token_bytes(32)
        signature_c = identity.sign(client_challenge_data(nonce_s, nonce_c))
        sock.sendall(
            Message.create_connect_request_ex(
                local_device, identity.cert_der, nonce_c, signature_c
            ).encode()
        )

        # 3. response (the peer may be waiting for a user approval dialog).
        sock.settimeout(control_timeout)
        response = recv_message(sock)
        expect_message_type(response, "CONNECT_RESPONSE")
        accepted, server_device, paired = response.parse_connect_response_ex()
        if not accepted:
            raise ConnectionRejected(f"{server_device.name} rejected the connection")

        trusted = trust_store.is_trusted(server_device.device_id, server_fp)
        known = trust_store.get(server_device.device_id)
        if known and not trusted:
            log.warning(
                "identity change for %s (stored %s..., presented %s...)",
                server_device.name,
                known.get("fingerprint", "")[:12],
                server_fp[:12],
            )

        # 4. user confirmation for untrusted peers.
        code = compute_pairing_code(our_fp, server_fp)
        wants_pair = paired
        if not trusted:
            accepted_by_user = False
            if approve_callback is not None:
                accepted_by_user = bool(
                    approve_callback(server_device, server_fp, our_fp, code)
                )
            if not accepted_by_user:
                sock.sendall(Message.create_error(0x01, "User declined connection").encode())
                raise ConnectionRejected(f"declined connection to {server_device.name}")
        if wants_pair:
            # The server asked for pairing confirmation (either the user just
            # approved us, or it already trusted us and just wants the code).
            sock.sendall(Message.create_pair_confirm(code.canonical).encode())
            sock.settimeout(control_timeout)
            confirm = recv_message(sock)
            if confirm.msg_type == MESSAGE_TYPES["ERROR"]:
                try:
                    _, text = confirm.parse_error()
                except ProtocolError:
                    text = "rejected"
                raise ConnectionRejected(f"pairing failed: {text}")
            expect_message_type(confirm, "PAIR_CONFIRM")
            if not secrets.compare_digest(confirm.parse_pair_confirm(), code.canonical):
                raise SecurityViolation("pairing code mismatch during confirmation")
            if not trust_store.is_trusted(server_device.device_id, server_fp):
                trust_store.add(server_device.device_id, server_device.name, server_fp)
                log.info("paired with %s (%s)", server_device.name, server_fp[:12])
        elif not trusted:
            log.info(
                "connected to unpaired peer %s (peer did not request pairing)",
                server_device.name,
            )

        result = HandshakeResult(
            device=server_device,
            fingerprint=server_fp,
            trusted=trust_store.is_trusted(server_device.device_id, server_fp),
            paired=paired,
            encryption=encryption,
            remote_address=remote,
        )
        session = ConnectionSession(sock, local_device, False, encryption, identity, result)
        sock.settimeout(None)  # transfer phase: blocking reads, keepalive for dead peers
        return session, result
    except (ProtocolError, SecurityError) as exc:
        _safe_close(sock)
        raise SecurityViolation(str(exc)) from exc
    except HandshakeError:
        _safe_close(sock)
        raise
    except (OSError, ssl.SSLError) as exc:
        _safe_close(sock)
        raise ConnectionRejected(f"handshake transport error: {exc}") from exc
    except Exception:
        _safe_close(sock)
        raise


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _send_rejected(sock: socket.socket, local_device: DeviceInfo, reason: str) -> None:
    try:
        sock.sendall(
            Message.create_connect_response(False, local_device, reason=reason).encode()
        )
    except OSError:
        pass


def _safe_close(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass


def _remote_label(sock: socket.socket) -> str:
    try:
        addr = sock.getpeername()
        return f"{addr[0]}:{addr[1]}"
    except OSError:
        return ""
