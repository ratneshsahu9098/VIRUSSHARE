"""virusShare - protocol serialization and TCP framing tests."""

import json
import socket
import struct
import threading

import pytest

from core.constants import (
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    MESSAGE_TYPES,
    TRANSFER_CHUNK_SIZE,
    CHECKSUM_CHUNK_SIZE,
)
from network.protocol import (
    HEADER_FORMAT,
    HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
    DeviceInfo,
    FileInfo,
    IncompleteMessage,
    Message,
    ProtocolError,
    calculate_checksum,
    decode_header,
    get_broadcast_address,
    get_local_ip,
    recv_message,
    send_message,
)


def sample_device(name="DESKTOP-ABC", ip="192.168.10.1", port=50000, device_id="dev-abc"):
    return DeviceInfo(
        name=name,
        ip=ip,
        port=port,
        device_id=device_id,
        os_version="Windows 11",
        app_version="1.0.0",
        capabilities=["file_transfer", "resume", "checksum"],
    )


def sample_files():
    return [
        FileInfo(name="a.txt", size=10, path="C:/a.txt", is_directory=False, modified_time=1.0),
        FileInfo(name="docs", size=0, path="C:/docs", is_directory=True, modified_time=2.0),
    ]


class FragmentedSocket:
    """Socket stand-in that returns at most `step` bytes per recv()."""

    def __init__(self, data: bytes, step: int = 1):
        self._data = data
        self._pos = 0
        self._step = step
        self.closed = False

    def recv(self, n: int) -> bytes:
        if self._pos >= len(self._data):
            self.closed = True
            return b""
        take = min(n, self._step, len(self._data) - self._pos)
        chunk = self._data[self._pos : self._pos + take]
        self._pos += take
        return chunk


# --------------------------------------------------------------------------- #
# Header / framing
# --------------------------------------------------------------------------- #

def test_header_layout_is_fixed_size():
    assert struct.calcsize(HEADER_FORMAT) == HEADER_SIZE
    assert HEADER_SIZE == 16


def test_magic_and_version():
    msg = Message(MESSAGE_TYPES["DISCOVERY"], b"{}")
    raw = msg.encode()

    magic, version, msg_type, sequence, flags, payload_len = struct.unpack(
        HEADER_FORMAT, raw[:HEADER_SIZE]
    )
    assert magic == MAGIC_BYTES
    assert version == PROTOCOL_VERSION
    assert msg_type == MESSAGE_TYPES["DISCOVERY"]
    assert sequence == 0
    assert flags == 0
    assert payload_len == 2
    assert len(raw) == HEADER_SIZE + 2


def test_type_name_lookup():
    assert Message(MESSAGE_TYPES["DISCOVERY"]).type_name == "DISCOVERY"
    assert Message(0x7F).type_name == "UNKNOWN_0x7F"


def test_decode_reports_consumed_bytes():
    one = Message(MESSAGE_TYPES["DISCONNECT"], b"", sequence=1).encode()
    two = Message(MESSAGE_TYPES["ERROR"], b'{"code":1}', sequence=2).encode()

    msg, consumed = Message.decode(one + two)
    assert consumed == len(one)
    assert msg.sequence == 1

    msg, consumed = Message.decode(two)
    assert msg.sequence == 2
    assert msg.parse_json_payload() == {"code": 1}


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

def test_incomplete_header_raises_incomplete_message():
    raw = Message(MESSAGE_TYPES["DISCOVERY"], b'{"a":1}').encode()
    with pytest.raises(IncompleteMessage):
        Message.decode(raw[: HEADER_SIZE - 1])


def test_incomplete_payload_raises_incomplete_message():
    raw = Message(MESSAGE_TYPES["DISCOVERY"], b'{"a":1}').encode()
    with pytest.raises(IncompleteMessage):
        Message.decode(raw[:-1])


def test_incomplete_message_is_protocol_error():
    with pytest.raises(ProtocolError):
        Message.decode(b"ETHR")


def test_bad_magic_rejected():
    raw = bytearray(Message(MESSAGE_TYPES["DISCOVERY"], b"{}").encode())
    raw[0:4] = b"XXXX"
    with pytest.raises(ProtocolError, match="magic"):
        Message.decode(bytes(raw))


def test_bad_version_rejected():
    raw = bytearray(Message(MESSAGE_TYPES["DISCOVERY"], b"{}").encode())
    raw[4] = PROTOCOL_VERSION + 1
    with pytest.raises(ProtocolError, match="version"):
        Message.decode(bytes(raw))


def test_oversized_payload_rejected_on_encode():
    msg = Message(MESSAGE_TYPES["FILE_DATA"], b"x" * (MAX_PAYLOAD_SIZE + 1))
    with pytest.raises(ProtocolError, match="too large"):
        msg.encode()


def test_oversized_payload_rejected_on_decode():
    header = struct.pack(
        HEADER_FORMAT, MAGIC_BYTES, PROTOCOL_VERSION, 0x22, 0, 0, MAX_PAYLOAD_SIZE + 1
    )
    with pytest.raises(ProtocolError, match="too large"):
        decode_header(header)


# --------------------------------------------------------------------------- #
# Message round trips
# --------------------------------------------------------------------------- #

def test_discovery_payload_shape():
    msg = Message.create_discovery(sample_device())
    msg2, _ = Message.decode(msg.encode())

    payload = msg2.parse_json_payload()
    assert payload["name"] == "DESKTOP-ABC"
    assert payload["ip"] == "192.168.10.1"
    assert payload["port"] == 50000
    assert payload["device_id"] == "dev-abc"
    assert payload["capabilities"] == ["file_transfer", "resume", "checksum"]
    assert msg2.parse_device_info() == sample_device()


def test_connect_request_and_response_roundtrip():
    msg = Message.create_connect_request(sample_device())
    decoded, _ = Message.decode(msg.encode())
    assert decoded.msg_type == MESSAGE_TYPES["CONNECT_REQUEST"]
    assert decoded.parse_device_info().name == "DESKTOP-ABC"

    msg = Message.create_connect_response(True, sample_device(name="DESKTOP-XYZ"))
    decoded, _ = Message.decode(msg.encode())
    accepted, device = decoded.parse_connect_response()
    assert accepted is True
    assert device.name == "DESKTOP-XYZ"

    msg = Message.create_connect_response(False, sample_device(), sequence=7)
    decoded, _ = Message.decode(msg.encode())
    accepted, _ = decoded.parse_connect_response()
    assert accepted is False
    assert decoded.sequence == 7


def test_file_list_roundtrip():
    files = sample_files()
    msg = Message.create_file_list(files)
    decoded, _ = Message.decode(msg.encode())

    parsed = decoded.parse_file_list()
    assert [f.name for f in parsed] == ["a.txt", "docs"]
    assert parsed[1].is_directory is True


def test_file_request_and_complete_roundtrip():
    msg = Message.create_file_request("f-1", offset=4096, sequence=3)
    decoded, _ = Message.decode(msg.encode())
    assert decoded.parse_file_request() == ("f-1", 4096)
    assert decoded.sequence == 3

    msg = Message.create_file_complete("f-1", True, sequence=4)
    decoded, _ = Message.decode(msg.encode())
    assert decoded.parse_file_complete() == ("f-1", True, "")


def test_checksum_and_error_roundtrip():
    msg = Message.create_checksum_request("f-1", algorithm="sha256")
    decoded, _ = Message.decode(msg.encode())
    assert decoded.parse_checksum_request() == ("f-1", "sha256")

    msg = Message.create_checksum_response("f-1", "abc123")
    decoded, _ = Message.decode(msg.encode())
    assert decoded.parse_checksum_response() == ("f-1", "abc123")

    msg = Message.create_error(0x05, "Checksum mismatch")
    decoded, _ = Message.decode(msg.encode())
    assert decoded.parse_error() == (0x05, "Checksum mismatch")


@pytest.mark.parametrize(
    "msg_type",
    [
        MESSAGE_TYPES["DISCOVERY"],
        MESSAGE_TYPES["DISCOVERY_RESPONSE"],
        MESSAGE_TYPES["CONNECT_REQUEST"],
        MESSAGE_TYPES["CONNECT_RESPONSE"],
        MESSAGE_TYPES["DISCONNECT"],
        MESSAGE_TYPES["FILE_LIST"],
        MESSAGE_TYPES["FILE_REQUEST"],
        MESSAGE_TYPES["FILE_DATA"],
        MESSAGE_TYPES["FILE_CHUNK"],
        MESSAGE_TYPES["FILE_COMPLETE"],
        MESSAGE_TYPES["FILE_CANCEL"],
        MESSAGE_TYPES["FILE_RESUME"],
        MESSAGE_TYPES["CHECKSUM_REQUEST"],
        MESSAGE_TYPES["CHECKSUM_RESPONSE"],
        MESSAGE_TYPES["ERROR"],
    ],
)
def test_every_message_type_roundtrips(msg_type):
    payload = bytes(range(256)) * 3
    original = Message(msg_type, payload, sequence=42, flags=7)
    decoded, consumed = Message.decode(original.encode())

    assert consumed == len(original.encode())
    assert decoded.msg_type == msg_type
    assert decoded.payload == payload
    assert decoded.sequence == 42
    assert decoded.flags == 7


def test_binary_file_chunk_roundtrip():
    blob = b"\x00\x01\xff\xfe" * 1024
    msg = Message.create_file_chunk("file-9", 17, blob, sequence=5)
    decoded, _ = Message.decode(msg.encode())

    file_id, chunk_index, data = decoded.parse_file_chunk()
    assert file_id == "file-9"
    assert chunk_index == 17
    assert data == blob


def test_file_chunk_with_unicode_file_id_roundtrip():
    """Regression: the id length prefix must be UTF-8 bytes, not char count."""
    file_id = "tree/sub/don\u2019t (test) \u2014 caf\u00e9.txt"
    assert len(file_id.encode("utf-8")) > len(file_id)  # multibyte premise
    blob = b"payload" * 100

    msg = Message.create_file_chunk(file_id, 3, blob)
    decoded, _ = Message.decode(msg.encode())
    got_id, index, data = decoded.parse_file_chunk()

    assert got_id == file_id
    assert index == 3
    assert data == blob


def test_file_data_with_unicode_file_id_roundtrip():
    file_id = "na\u00efve/r\u00e9sum\u00e9.bin"
    blob = bytes(range(256)) * 4

    msg = Message.create_file_data(file_id, blob)
    decoded, _ = Message.decode(msg.encode())
    got_id, data = decoded.parse_file_data()

    assert got_id == file_id
    assert data == blob


# --------------------------------------------------------------------------- #
# TCP framing
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("step", [1, 3, 16, 64, 1024])
def test_recv_handles_fragmented_stream(step):
    msg = Message.create_discovery(sample_device())
    sock = FragmentedSocket(msg.encode(), step=step)

    decoded = recv_message(sock)
    assert decoded.parse_device_info() == sample_device()


def test_recv_handles_multiple_messages_in_one_buffer():
    msgs = [
        Message.create_discovery(sample_device(device_id=f"dev-{i}"), sequence=i)
        for i in range(5)
    ]
    sock = FragmentedSocket(b"".join(m.encode() for m in msgs), step=4096)

    for expected in msgs:
        decoded = recv_message(sock)
        assert decoded.sequence == expected.sequence
        assert decoded.payload == expected.payload


def test_recv_raises_when_stream_ends_mid_message():
    msg = Message.create_discovery(sample_device())
    with pytest.raises(ConnectionError):
        recv_message(FragmentedSocket(msg.encode()[:-5], step=2))


def test_recv_raises_on_empty_stream():
    with pytest.raises(ConnectionError):
        recv_message(FragmentedSocket(b"", step=1))


def test_large_payload_over_tcp():
    blob = b"\xde\xad\xbe\xef" * (TRANSFER_CHUNK_SIZE * 4)
    msg = Message.create_file_data("big-file", blob, sequence=99)
    sender, receiver = socket.socketpair()
    try:
        send_message(sender, msg)
        decoded = recv_message(receiver)
    finally:
        sender.close()
        receiver.close()

    file_id, data = decoded.parse_file_data()
    assert file_id == "big-file"
    assert data == blob
    assert decoded.sequence == 99


def test_tcp_socketpair_many_messages_in_order():
    sender, receiver = socket.socketpair()
    sent = [Message.create_discovery(sample_device(device_id=f"d{i}"), sequence=i) for i in range(50)]
    sent.append(Message.create_disconnect(sequence=50))

    errors = []

    def reader():
        try:
            for expected in sent:
                got = recv_message(receiver)
                assert got.sequence == expected.sequence
                assert got.payload == expected.payload
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    try:
        for msg in sent:
            send_message(sender, msg)
        thread.join(timeout=10)
    finally:
        sender.close()
        receiver.close()

    assert not thread.is_alive()
    assert not errors


def test_empty_payload_message_roundtrip():
    msg = Message.create_disconnect(sequence=1)
    decoded, _ = Message.decode(msg.encode())
    assert decoded.msg_type == MESSAGE_TYPES["DISCONNECT"]
    assert decoded.payload == b""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def test_get_local_ip_is_ipv4():
    ip = get_local_ip()
    assert ip.count(".") == 3
    assert all(part.isdigit() for part in ip.split("."))


def test_get_local_ip_prefers_lan_interface_without_default_route(monkeypatch):
    """M31: with no default route the announced IP must be the LAN address -
    127.0.0.1 makes every peer try to connect to itself."""
    import network.protocol as proto
    from utils.network import InterfaceInfo

    monkeypatch.setattr(proto, "_default_route_ip", lambda: None)
    monkeypatch.setattr(
        proto,
        "list_ipv4_interfaces",
        lambda: [
            InterfaceInfo(
                name="Ethernet", ip="192.168.1.50", netmask="255.255.255.0"
            )
        ],
    )
    assert proto.get_local_ip() == "192.168.1.50"


def test_get_broadcast_address():
    assert get_broadcast_address("192.168.10.1", "255.255.255.0") == "192.168.10.255"
    assert get_broadcast_address("10.0.5.9", "255.255.0.0") == "10.0.255.255"


def test_calculate_checksum(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"virusshare")

    digest = calculate_checksum(target, chunk_size=4)
    assert len(digest) == 64
    assert digest == calculate_checksum(target, chunk_size=1024)
    assert CHECKSUM_CHUNK_SIZE > 0


# --------------------------------------------------------------------------- #
# M25 - malformed payload fields surface as ProtocolError, never raw
# KeyError/TypeError (handshake parsers)
# --------------------------------------------------------------------------- #

def test_session_challenge_missing_cert_raises_protocol_error():
    payload = json.dumps({"device": sample_device().to_dict()}).encode("utf-8")
    msg = Message(MESSAGE_TYPES["SESSION_CHALLENGE"], payload)
    with pytest.raises(ProtocolError):
        msg.parse_session_challenge()


def test_session_challenge_non_object_payload_raises_protocol_error():
    msg = Message(MESSAGE_TYPES["SESSION_CHALLENGE"], b"5")
    with pytest.raises(ProtocolError):
        msg.parse_session_challenge()


def test_session_challenge_incomplete_device_block_raises_protocol_error():
    payload = json.dumps(
        {"device": {"name": "EVIL"}, "cert": "", "nonce": "", "signature": ""}
    ).encode("utf-8")
    msg = Message(MESSAGE_TYPES["SESSION_CHALLENGE"], payload)
    with pytest.raises(ProtocolError):
        msg.parse_session_challenge()


def test_connect_request_missing_cert_raises_protocol_error():
    payload = json.dumps({"device": sample_device().to_dict()}).encode("utf-8")
    msg = Message(MESSAGE_TYPES["CONNECT_REQUEST"], payload)
    with pytest.raises(ProtocolError):
        msg.parse_connect_request_ex()


def test_connect_response_non_object_payload_raises_protocol_error():
    msg = Message(MESSAGE_TYPES["CONNECT_RESPONSE"], b"5")
    with pytest.raises(ProtocolError):
        msg.parse_connect_response_ex()


def test_device_info_incomplete_block_raises_protocol_error():
    payload = json.dumps({"name": "EVIL"}).encode("utf-8")
    msg = Message(MESSAGE_TYPES["DISCOVERY"], payload)
    with pytest.raises(ProtocolError):
        msg.parse_device_info()


def test_error_missing_fields_raises_protocol_error():
    msg = Message(MESSAGE_TYPES["ERROR"], b"{}")
    with pytest.raises(ProtocolError):
        msg.parse_error()
