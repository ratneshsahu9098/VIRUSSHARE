"""virusShare - TCP server/client, handshake and authentication tests."""

import json
import socket
import threading
import time

import pytest

from core.security import (
    Identity,
    SecurityError,
    TrustStore,
    compute_pairing_code,
    fingerprint_cert,
    load_identity,
    verify_signature,
)
from network.protocol import DeviceInfo, Message, ProtocolError, send_message, recv_message
from network.session import (
    ConnectionRejected,
    SecurityViolation,
    client_handshake,
    server_handshake,
)
from network.tcp_client import TransferClient
from network.tcp_server import TransferServer
from core.constants import MESSAGE_TYPES


def make_device(name="DESKTOP-TEST", ip="127.0.0.1", device_id="dev-test"):
    return DeviceInfo(
        name=name,
        ip=ip,
        port=54322,
        device_id=device_id,
        os_version="Windows 11",
        app_version="1.0.0",
        capabilities=["file_transfer", "resume", "checksum"],
    )


@pytest.fixture
def identity(tmp_path):
    return load_identity(tmp_path / "identity.pem")


@pytest.fixture
def other_identity(tmp_path):
    return load_identity(tmp_path / "identity2.pem")


@pytest.fixture
def trust(tmp_path):
    return TrustStore(tmp_path / "trust.json")


@pytest.fixture
def other_trust(tmp_path):
    return TrustStore(tmp_path / "trust2.json")


def start_server(identity, trust, **kwargs):
    server = TransferServer(
        device_provider=lambda: make_device("SERVER-PC", device_id="dev-server"),
        identity=identity,
        trust_store=trust,
        host="127.0.0.1",
        port=0,
        **kwargs,
    )
    port = server.start()
    return server, port


def pair_callbacks(log=None):
    """Approve callbacks that record invocations."""
    calls = []

    def make(label):
        def cb(peer, peer_fp, our_fp, code):
            calls.append((label, peer.name, code.short))
            return True

        return cb

    return make("server"), make("client"), calls


# --------------------------------------------------------------------------- #
# server lifecycle
# --------------------------------------------------------------------------- #

def test_server_starts_and_reports_bound_port(identity, trust):
    server, port = start_server(identity, trust, encryption=False)
    try:
        assert server.running
        assert port != 0
        assert server.bound_port == port
    finally:
        server.stop()
    assert not server.running


def test_server_rejects_port_conflict(identity, trust):
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    server = TransferServer(
        device_provider=lambda: make_device(),
        identity=identity,
        trust_store=trust,
        host="127.0.0.1",
        port=port,
        encryption=False,
    )
    try:
        with pytest.raises(RuntimeError, match="Cannot bind"):
            server.start()
    finally:
        blocker.close()


def test_server_stop_is_idempotent(identity, trust):
    server, _ = start_server(identity, trust, encryption=False)
    server.stop()
    server.stop()


# --------------------------------------------------------------------------- #
# successful handshake (encrypted + plaintext)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("encryption", [True, False])
def test_handshake_and_pairing_stores_trust_both_sides(
    identity, other_identity, trust, other_trust, encryption
):
    s_cb, c_cb, calls = pair_callbacks()
    server, port = start_server(
        identity,
        trust,
        encryption=encryption,
        require_approval=True,
        approve_callback=s_cb,
    )
    client = TransferClient(
        device_provider=lambda: make_device("CLIENT-PC", device_id="dev-client"),
        identity=other_identity,
        trust_store=other_trust,
        encryption=encryption,
        approve_callback=c_cb,
    )
    try:
        session = client.connect("127.0.0.1", port, timeout=5)
        assert session.peer_device.name == "SERVER-PC"
        assert session.peer_fingerprint == identity.fingerprint
        session.send(Message.create_disconnect())
        session.close()

        # both sides stored trust after pairing confirmation
        deadline = time.time() + 3
        while time.time() < deadline:
            if trust.is_trusted("dev-client") and other_trust.is_trusted("dev-server"):
                break
            time.sleep(0.05)
        assert trust.is_trusted("dev-client", other_identity.fingerprint)
        assert other_trust.is_trusted("dev-server", identity.fingerprint)
        assert [c[0] for c in calls].count("server") == 1
        assert [c[0] for c in calls].count("client") == 1
        # pairing codes shown to both sides were the same 6-digit code
        server_codes = [c[2] for c in calls if c[0] == "server"]
        client_codes = [c[2] for c in calls if c[0] == "client"]
        assert server_codes == client_codes
    finally:
        server.stop()


def test_trusted_peer_connects_without_dialog(
    identity, other_identity, trust, other_trust
):
    trust.add("dev-client", "CLIENT-PC", other_identity.fingerprint)
    other_trust.add("dev-server", "SERVER-PC", identity.fingerprint)
    s_cb, c_cb, calls = pair_callbacks()
    server, port = start_server(
        identity, trust, encryption=False, approve_callback=s_cb
    )
    client = TransferClient(
        device_provider=lambda: make_device("CLIENT-PC", device_id="dev-client"),
        identity=other_identity,
        trust_store=other_trust,
        encryption=False,
        approve_callback=c_cb,
    )
    try:
        session = client.connect("127.0.0.1", port, timeout=5)
        assert session.result.trusted is True
        session.send(Message.create_disconnect())
        session.close()
        time.sleep(0.2)
        assert calls == []  # no dialogs for trusted peers
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# rejection paths
# --------------------------------------------------------------------------- #

def test_server_user_rejection_disconnects_client(
    identity, other_identity, trust, other_trust
):
    server, port = start_server(
        identity,
        trust,
        encryption=False,
        require_approval=True,
        approve_callback=lambda *a: False,
    )
    client = TransferClient(
        device_provider=lambda: make_device("CLIENT-PC", device_id="dev-client"),
        identity=other_identity,
        trust_store=other_trust,
        encryption=False,
        approve_callback=lambda *a: True,
    )
    try:
        with pytest.raises(ConnectionRejected, match="rejected"):
            client.connect("127.0.0.1", port, timeout=5)
        assert not trust.is_trusted("dev-client")
        assert not other_trust.is_trusted("dev-server")
    finally:
        server.stop()


def test_client_decline_disconnects(
    identity, other_identity, trust, other_trust
):
    server, port = start_server(
        identity,
        trust,
        encryption=False,
        require_approval=True,
        approve_callback=lambda *a: True,
    )
    client = TransferClient(
        device_provider=lambda: make_device("CLIENT-PC", device_id="dev-client"),
        identity=other_identity,
        trust_store=other_trust,
        encryption=False,
        approve_callback=lambda *a: False,
    )
    try:
        with pytest.raises(ConnectionRejected):
            client.connect("127.0.0.1", port, timeout=5)
        # server must not have stored trust for the declined peer
        time.sleep(0.3)
        assert not trust.is_trusted("dev-client")
    finally:
        server.stop()


def test_missing_approval_callback_defaults_to_reject(
    identity, other_identity, trust, other_trust
):
    server, port = start_server(
        identity, trust, encryption=False, require_approval=True, approve_callback=None
    )
    client = TransferClient(
        device_provider=lambda: make_device("CLIENT-PC", device_id="dev-client"),
        identity=other_identity,
        trust_store=other_trust,
        encryption=False,
        approve_callback=None,
    )
    try:
        with pytest.raises(ConnectionRejected):
            client.connect("127.0.0.1", port, timeout=5)
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# hostile peers
# --------------------------------------------------------------------------- #

def _rogue_client_after_challenge(raw, identity, *, bad_signature=False, wrong_type=False):
    """Manually performs the client half of the handshake with a deliberate flaw."""
    challenge = recv_message(raw)
    assert challenge.type_name == "SESSION_CHALLENGE"
    device, cert, nonce, _sig = challenge.parse_session_challenge()

    import secrets as _secrets
    from core.security import client_challenge_data

    nonce_c = _secrets.token_bytes(32)
    if wrong_type:
        raw.sendall(Message.create_discovery(make_device()).encode())
        return
    sig = (
        b"\x00" * 64
        if bad_signature
        else identity.sign(client_challenge_data(nonce, nonce_c))
    )
    raw.sendall(
        Message.create_connect_request_ex(
            make_device("ROGUE", device_id="dev-rogue"),
            identity.cert_der,
            nonce_c,
            sig,
        ).encode()
    )
    # whatever comes back, keep reading until close
    try:
        recv_message(raw)
    except (OSError, ProtocolError):
        pass


def test_server_rejects_bad_signature(identity, trust):
    server, port = start_server(identity, trust, encryption=False)
    rogue = load_identity(trust.path.parent / "rogue.pem")
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        _rogue_client_after_challenge(raw, rogue, bad_signature=True)
        raw.close()
        time.sleep(0.4)
        assert not trust.is_trusted("dev-rogue")
    finally:
        server.stop()


def test_server_rejects_wrong_message_type(identity, trust):
    server, port = start_server(identity, trust, encryption=False)
    rogue = load_identity(trust.path.parent / "rogue.pem")
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        _rogue_client_after_challenge(raw, rogue, wrong_type=True)
        raw.close()
        time.sleep(0.4)
        assert not trust.is_trusted("dev-rogue")
    finally:
        server.stop()


def test_server_rejects_garbage_first_message(identity, trust):
    server, port = start_server(identity, trust, encryption=False)
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        raw.sendall(b"NOT A PROTOCOL MESSAGE AT ALL!!!!")
        raw.close()
        time.sleep(0.4)
        assert not trust.is_trusted("dev-rogue")
        assert server.running
    finally:
        server.stop()


def test_server_rejects_client_without_certificate(identity, trust):
    """A CONNECT_REQUEST lacking the certificate block is a protocol error."""
    server, port = start_server(identity, trust, encryption=False)
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        challenge = recv_message(raw)
        assert challenge.type_name == "SESSION_CHALLENGE"
        raw.sendall(Message.create_connect_request(make_device("LEGACY")).encode())
        with pytest.raises((OSError, ProtocolError)):
            recv_message(raw)
        raw.close()
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# TLS certificate binding
# --------------------------------------------------------------------------- #

def test_tls_certificate_must_match_application_certificate(
    identity, other_identity, trust, other_trust, monkeypatch
):
    """A relay that terminates TLS with a different certificate must be caught."""
    import network.session as session_mod

    real_build = session_mod.build_server_ssl_context

    def mismatched(identity_arg):
        return real_build(other_identity)  # TLS cert from the *other* identity

    monkeypatch.setattr(session_mod, "build_server_ssl_context", mismatched)

    server, port = start_server(identity, trust, encryption=True)
    client = TransferClient(
        device_provider=lambda: make_device("CLIENT-PC", device_id="dev-client"),
        identity=other_identity,
        trust_store=other_trust,
        encryption=True,
        approve_callback=lambda *a: True,
    )
    try:
        with pytest.raises(SecurityViolation, match="TLS certificate"):
            client.connect("127.0.0.1", port, timeout=5)
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# signature primitives
# --------------------------------------------------------------------------- #

def test_signature_roundtrip_and_tamper_detection(identity):
    data = b"some challenge bytes"
    sig = identity.sign(data)
    assert verify_signature(identity.cert_der, data, sig)
    assert not verify_signature(identity.cert_der, b"different", sig)
    assert not verify_signature(identity.cert_der, data, sig[:-1] + bytes([sig[-1] ^ 1]))


def test_pairing_code_is_order_independent():
    a = "aa" * 32
    b = "bb" * 32
    assert compute_pairing_code(a, b).canonical == compute_pairing_code(b, a).canonical
    assert compute_pairing_code(a, b).short != compute_pairing_code(a, "cc" * 32).short
    assert len(compute_pairing_code(a, b).short) == 6


def test_fingerprint_changes_when_certificate_changes(identity, other_identity):
    assert identity.fingerprint != other_identity.fingerprint
    assert fingerprint_cert(identity.cert_der) == identity.fingerprint


# --------------------------------------------------------------------------- #
# session helpers
# --------------------------------------------------------------------------- #

def test_session_expect_validates_message_type(identity, other_identity, trust, other_trust):
    server, port = start_server(
        identity, trust, encryption=False, approve_callback=lambda *a: True
    )
    client = TransferClient(
        device_provider=lambda: make_device("CLIENT-PC", device_id="dev-client"),
        identity=other_identity,
        trust_store=other_trust,
        encryption=False,
        approve_callback=lambda *a: True,
    )
    try:
        session = client.connect("127.0.0.1", port, timeout=5)
        session.send(Message.create_disconnect())
        # expect something that will never arrive on an idle server
        with pytest.raises((ProtocolError, OSError, AssertionError)):
            session.expect("FILE_LIST", timeout=2)
        session.close()
    finally:
        server.stop()


def test_identity_persists_across_loads(tmp_path):
    path = tmp_path / "id.pem"
    first = load_identity(path)
    second = load_identity(path)
    assert first.fingerprint == second.fingerprint
    assert first.cert_der == second.cert_der


def test_corrupt_identity_file_raises_security_error(tmp_path):
    path = tmp_path / "id.pem"
    path.write_bytes(b"not a pem file")
    with pytest.raises(SecurityError):
        load_identity(path)


# --------------------------------------------------------------------------- #
# H3 - port conflict surfaces as RuntimeError
# --------------------------------------------------------------------------- #

def test_second_server_on_same_port_raises(identity, trust, tmp_path):
    """A port already in use must surface as RuntimeError (the binding site
    wraps OSError), and on Windows a second instance must not silently
    double-bind the taken port via SO_REUSEADDR."""
    server, port = start_server(identity, trust)
    other = TransferServer(
        device_provider=lambda: make_device("SERVER-2", device_id="dev-server-2"),
        identity=load_identity(tmp_path / "identity3.pem"),
        trust_store=TrustStore(tmp_path / "trust3.json"),
        host="127.0.0.1",
        port=port,
    )
    try:
        with pytest.raises(RuntimeError):
            other.start()
    finally:
        other.stop()
        server.stop()


# --------------------------------------------------------------------------- #
# M25 - malformed handshake surfaces as SecurityViolation and closes the
# raw socket instead of leaking it
# --------------------------------------------------------------------------- #

MALFORMED_CHALLENGES = [
    pytest.param(
        {"device": make_device("BAD", device_id="dev-bad").to_dict()},
        id="missing-cert",
    ),
    pytest.param(
        {"device": {"name": "EVIL"}, "cert": "", "nonce": "", "signature": ""},
        id="incomplete-device",
    ),
]


def _client_against_malformed_challenge(payload, monkeypatch, identity, trust):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    challenge = Message(
        MESSAGE_TYPES["SESSION_CHALLENGE"], json.dumps(payload).encode("utf-8")
    )

    def serve():
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        try:
            conn.sendall(challenge.encode())
            time.sleep(0.5)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    threading.Thread(target=serve, daemon=True).start()

    real_create = socket.create_connection
    captured = {}

    def spy(address, *args, **kwargs):
        sock = real_create(address, *args, **kwargs)
        captured["sock"] = sock
        return sock

    monkeypatch.setattr(socket, "create_connection", spy)
    client = TransferClient(
        device_provider=lambda: make_device("CLIENT-PC", device_id="dev-client"),
        identity=identity,
        trust_store=trust,
        encryption=False,
    )
    return client, captured, listener, port


@pytest.mark.parametrize("payload", MALFORMED_CHALLENGES)
def test_malformed_session_challenge_raises_security_violation(
    payload, monkeypatch, other_identity, other_trust
):
    client, _captured, listener, port = _client_against_malformed_challenge(
        payload, monkeypatch, other_identity, other_trust
    )
    try:
        with pytest.raises(SecurityViolation):
            client.connect("127.0.0.1", port, timeout=5)
    finally:
        listener.close()


@pytest.mark.parametrize("payload", MALFORMED_CHALLENGES)
def test_malformed_session_challenge_does_not_leak_socket(
    payload, monkeypatch, other_identity, other_trust
):
    client, captured, listener, port = _client_against_malformed_challenge(
        payload, monkeypatch, other_identity, other_trust
    )
    try:
        with pytest.raises(Exception):
            client.connect("127.0.0.1", port, timeout=5)
        assert captured["sock"].fileno() == -1, (
            "raw socket leaked after malformed handshake"
        )
    finally:
        listener.close()


def test_connect_closes_socket_when_device_provider_raises(
    monkeypatch, identity, trust
):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    real_create = socket.create_connection
    captured = {}

    def spy(address, *args, **kwargs):
        sock = real_create(address, *args, **kwargs)
        captured["sock"] = sock
        return sock

    monkeypatch.setattr(socket, "create_connection", spy)

    def boom():
        raise RuntimeError("device info unavailable")

    client = TransferClient(
        device_provider=boom, identity=identity, trust_store=trust, encryption=False
    )
    try:
        with pytest.raises(RuntimeError, match="device info"):
            client.connect("127.0.0.1", port, timeout=5)
        assert captured["sock"].fileno() == -1, (
            "raw socket leaked when device_provider raised"
        )
    finally:
        listener.close()


# --------------------------------------------------------------------------- #
# M23 - stop() vs approval dialog, live survivors and accept thread
# --------------------------------------------------------------------------- #

def test_stop_drops_peer_blocked_in_approval_dialog(
    identity, other_identity, trust, other_trust
):
    """M23: stop() must disconnect a peer stuck in the approval dialog (the
    TLS-wrapped socket is detached from the raw conn by wrap_socket) and the
    session handler must never run after stopping."""
    entered = threading.Event()
    release = threading.Event()
    handled = []

    def approve(peer, peer_fp, our_fp, code):
        entered.set()
        release.wait(10.0)
        return True

    server, port = start_server(
        identity,
        trust,
        encryption=True,
        require_approval=True,
        approve_callback=approve,
        session_handler=handled.append,
    )
    client = TransferClient(
        device_provider=lambda: make_device("CLIENT-PC", device_id="dev-client"),
        identity=other_identity,
        trust_store=other_trust,
        encryption=True,
        approve_callback=lambda *a: True,
    )
    outcome = {}

    def run_client():
        try:
            outcome["session"] = client.connect("127.0.0.1", port, timeout=5)
        except Exception as exc:
            outcome["error"] = exc

    worker = threading.Thread(target=run_client, daemon=True)
    try:
        worker.start()
        assert entered.wait(5.0), "approval dialog never opened"
        server.stop()
        worker.join(timeout=5.0)
        assert not worker.is_alive(), "peer still blocked in the handshake after stop()"
        assert "error" in outcome, "peer survived stop() with a live session"
        release.set()
        deadline = time.time() + 5.0
        while time.time() < deadline and any(
            thread.is_alive() for thread in server._conn_threads
        ):
            time.sleep(0.05)
        assert handled == [], "session handler ran after stop()"
    finally:
        release.set()
        server.stop()
        worker.join(timeout=5.0)


def test_stop_keeps_live_conn_thread_visible(
    identity, other_identity, trust, other_trust
):
    """M23: a join-timeout must not clear() live connection threads."""
    entered = threading.Event()
    release = threading.Event()

    def approve(peer, peer_fp, our_fp, code):
        entered.set()
        release.wait(10.0)
        return True

    server, port = start_server(
        identity,
        trust,
        encryption=False,
        require_approval=True,
        approve_callback=approve,
    )
    client = TransferClient(
        device_provider=lambda: make_device("CLIENT-PC", device_id="dev-client"),
        identity=other_identity,
        trust_store=other_trust,
        encryption=False,
        approve_callback=lambda *a: True,
    )

    def run_client():
        try:
            client.connect("127.0.0.1", port, timeout=5)
        except Exception:
            pass

    worker = threading.Thread(target=run_client, daemon=True)
    try:
        worker.start()
        assert entered.wait(5.0), "approval dialog never opened"
        server.stop()
        survivors = [thread for thread in server._conn_threads if thread.is_alive()]
        assert survivors, "stop() hid the live connection thread"
    finally:
        release.set()
        server.stop()
        worker.join(timeout=5.0)


def test_stop_joins_the_accept_thread(identity, trust):
    """M23: stop() must join the accept thread before returning."""
    server, _ = start_server(identity, trust, encryption=False)
    real_thread = server._accept_thread

    class JoinSpy:
        def __init__(self, target):
            self._target = target
            self.joined = False

        def __getattr__(self, name):
            return getattr(self._target, name)

        def join(self, *args, **kwargs):
            self.joined = True
            return self._target.join(*args, **kwargs)

    server._accept_thread = JoinSpy(real_thread)
    try:
        server.stop()
        assert server._accept_thread.joined, "stop() never joined the accept thread"
    finally:
        server.stop()
