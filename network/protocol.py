"""virusShare - Network Protocol Implementation"""

import base64
import ipaddress
import struct
import json
import socket
import hashlib
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass, asdict
from pathlib import Path

from core.constants import (
    MAGIC_BYTES,
    PROTOCOL_VERSION,
    MESSAGE_TYPES,
    CHECKSUM_CHUNK_SIZE,
)
from utils.network import list_ipv4_interfaces

HEADER_FORMAT = "!4sBBHII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_PAYLOAD_SIZE = 32 * 1024 * 1024


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    if not isinstance(text, str):
        raise ProtocolError("expected base64 string")
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:
        raise ProtocolError(f"invalid base64 field: {exc}") from exc



@dataclass
class DeviceInfo:
    name: str
    ip: str
    port: int
    device_id: str
    os_version: str
    app_version: str
    capabilities: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeviceInfo":
        if not isinstance(data, dict):
            raise ProtocolError("device block must be a JSON object")
        try:
            return cls(**data)
        except TypeError as exc:
            raise ProtocolError(f"invalid device block: {exc}") from exc


@dataclass
class FileInfo:
    name: str
    size: int
    path: str
    is_directory: bool
    modified_time: float
    checksum: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileInfo":
        return cls(**data)


@dataclass
class TransferProgress:
    file_id: str
    file_name: str
    total_size: int
    transferred: int
    speed: float
    status: str
    error: Optional[str] = None


class ProtocolError(Exception):
    pass


class IncompleteMessage(ProtocolError):
    """Raised when not enough bytes are available to decode a full message."""


def decode_header(data: bytes) -> Tuple[int, int, int, int]:
    if len(data) < HEADER_SIZE:
        raise IncompleteMessage(f"Need {HEADER_SIZE} header bytes, got {len(data)}")

    magic, version, msg_type, sequence, flags, payload_len = struct.unpack(
        HEADER_FORMAT, data[:HEADER_SIZE]
    )

    if magic != MAGIC_BYTES:
        raise ProtocolError(f"Invalid magic bytes: {magic!r}")

    if version != PROTOCOL_VERSION:
        raise ProtocolError(f"Unsupported protocol version: {version}")

    if payload_len > MAX_PAYLOAD_SIZE:
        raise ProtocolError(f"Payload too large: {payload_len}")

    return msg_type, sequence, flags, payload_len


class Message:
    def __init__(
        self,
        msg_type: int,
        payload: bytes = b"",
        sequence: int = 0,
        flags: int = 0,
    ):
        self.msg_type = msg_type
        self.payload = payload
        self.sequence = sequence
        self.flags = flags

    @property
    def type_name(self) -> str:
        for name, value in MESSAGE_TYPES.items():
            if value == self.msg_type:
                return name
        return f"UNKNOWN_0x{self.msg_type:02X}"

    def encode(self) -> bytes:
        if len(self.payload) > MAX_PAYLOAD_SIZE:
            raise ProtocolError(f"Payload too large: {len(self.payload)}")
        header = struct.pack(
            HEADER_FORMAT,
            MAGIC_BYTES,
            PROTOCOL_VERSION,
            self.msg_type,
            self.sequence,
            self.flags,
            len(self.payload),
        )
        return header + self.payload

    @classmethod
    def decode(cls, data: bytes) -> Tuple["Message", int]:
        msg_type, sequence, flags, payload_len = decode_header(data)

        end = HEADER_SIZE + payload_len
        if len(data) < end:
            raise IncompleteMessage(f"Need {end} bytes, got {len(data)}")

        return cls(msg_type, data[HEADER_SIZE:end], sequence, flags), end

    @classmethod
    def create_discovery(cls, device_info: DeviceInfo, sequence: int = 0) -> "Message":
        payload = json.dumps(device_info.to_dict()).encode("utf-8")
        return cls(MESSAGE_TYPES["DISCOVERY"], payload, sequence)

    @classmethod
    def create_discovery_response(cls, device_info: DeviceInfo, sequence: int = 0) -> "Message":
        payload = json.dumps(device_info.to_dict()).encode("utf-8")
        return cls(MESSAGE_TYPES["DISCOVERY_RESPONSE"], payload, sequence)

    @classmethod
    def create_connect_request(cls, device_info: DeviceInfo, sequence: int = 0) -> "Message":
        payload = json.dumps(device_info.to_dict()).encode("utf-8")
        return cls(MESSAGE_TYPES["CONNECT_REQUEST"], payload, sequence)

    @classmethod
    def create_connect_request_ex(
        cls,
        device_info: DeviceInfo,
        cert_der: bytes,
        nonce: bytes,
        signature: bytes,
        sequence: int = 0,
    ) -> "Message":
        """CONNECT_REQUEST with device certificate and nonce-bound signature."""
        data = {
            "device": device_info.to_dict(),
            "cert": _b64(cert_der),
            "nonce": _b64(nonce),
            "signature": _b64(signature),
        }
        payload = json.dumps(data).encode("utf-8")
        return cls(MESSAGE_TYPES["CONNECT_REQUEST"], payload, sequence)

    @classmethod
    def create_session_challenge(
        cls,
        device_info: DeviceInfo,
        cert_der: bytes,
        nonce: bytes,
        signature: bytes,
        sequence: int = 0,
    ) -> "Message":
        """SESSION_CHALLENGE: server hello with certificate + nonce-bound signature."""
        data = {
            "device": device_info.to_dict(),
            "cert": _b64(cert_der),
            "nonce": _b64(nonce),
            "signature": _b64(signature),
        }
        payload = json.dumps(data).encode("utf-8")
        return cls(MESSAGE_TYPES["SESSION_CHALLENGE"], payload, sequence)


    @classmethod
    def create_pair_confirm(cls, code: str, sequence: int = 0) -> "Message":
        payload = json.dumps({"code": code}).encode("utf-8")
        return cls(MESSAGE_TYPES["PAIR_CONFIRM"], payload, sequence)

    @classmethod
    def create_connect_response(
        cls,
        accepted: bool,
        device_info: DeviceInfo,
        sequence: int = 0,
        paired: bool = False,
        reason: str = "",
    ) -> "Message":
        data: Dict[str, Any] = {
            "accepted": accepted,
            "device": device_info.to_dict(),
            "paired": paired,
        }
        if reason:
            data["reason"] = reason
        payload = json.dumps(data).encode("utf-8")
        return cls(MESSAGE_TYPES["CONNECT_RESPONSE"], payload, sequence)


    @classmethod
    def create_disconnect(cls, sequence: int = 0) -> "Message":
        return cls(MESSAGE_TYPES["DISCONNECT"], b"", sequence)

    @classmethod
    def create_file_list(cls, files: List[FileInfo], sequence: int = 0) -> "Message":
        payload = json.dumps([f.to_dict() for f in files]).encode("utf-8")
        return cls(MESSAGE_TYPES["FILE_LIST"], payload, sequence)

    @classmethod
    def create_file_request(
        cls,
        file_id: str,
        offset: int = 0,
        sequence: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "Message":
        data: Dict[str, Any] = {"file_id": file_id, "offset": offset}
        if metadata:
            data.update(metadata)
        payload = json.dumps(data).encode("utf-8")
        return cls(MESSAGE_TYPES["FILE_REQUEST"], payload, sequence)


    @classmethod
    def create_file_data(cls, file_id: str, data: bytes, sequence: int = 0) -> "Message":
        encoded = file_id.encode("utf-8")
        payload = struct.pack("!I", len(encoded)) + encoded + data
        return cls(MESSAGE_TYPES["FILE_DATA"], payload, sequence)

    @classmethod
    def create_file_chunk(cls, file_id: str, chunk_index: int, data: bytes, sequence: int = 0) -> "Message":
        encoded = file_id.encode("utf-8")
        payload = struct.pack("!II", len(encoded), chunk_index)
        payload += encoded + data
        return cls(MESSAGE_TYPES["FILE_CHUNK"], payload, sequence)

    @classmethod
    def create_file_complete(
        cls,
        file_id: str,
        success: bool,
        error: str = "",
        sequence: int = 0,
        checksum: str = "",
    ) -> "Message":
        data: Dict[str, Any] = {"file_id": file_id, "success": success, "error": error}
        if checksum:
            data["checksum"] = checksum
        payload = json.dumps(data).encode("utf-8")
        return cls(MESSAGE_TYPES["FILE_COMPLETE"], payload, sequence)


    @classmethod
    def create_file_cancel(cls, file_id: str, sequence: int = 0) -> "Message":
        payload = file_id.encode("utf-8")
        return cls(MESSAGE_TYPES["FILE_CANCEL"], payload, sequence)

    @classmethod
    def create_file_resume(cls, file_id: str, offset: int, sequence: int = 0) -> "Message":
        data = {"file_id": file_id, "offset": offset}
        payload = json.dumps(data).encode("utf-8")
        return cls(MESSAGE_TYPES["FILE_RESUME"], payload, sequence)

    @classmethod
    def create_checksum_request(cls, file_id: str, algorithm: str = "sha256", sequence: int = 0) -> "Message":
        data = {"file_id": file_id, "algorithm": algorithm}
        payload = json.dumps(data).encode("utf-8")
        return cls(MESSAGE_TYPES["CHECKSUM_REQUEST"], payload, sequence)

    @classmethod
    def create_checksum_response(cls, file_id: str, checksum: str, sequence: int = 0) -> "Message":
        data = {"file_id": file_id, "checksum": checksum}
        payload = json.dumps(data).encode("utf-8")
        return cls(MESSAGE_TYPES["CHECKSUM_RESPONSE"], payload, sequence)

    @classmethod
    def create_error(cls, code: int, message: str, sequence: int = 0) -> "Message":
        data = {"code": code, "message": message}
        payload = json.dumps(data).encode("utf-8")
        return cls(MESSAGE_TYPES["ERROR"], payload, sequence)

    def parse_json_payload(self) -> Dict[str, Any]:
        try:
            data = json.loads(self.payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ProtocolError(f"invalid JSON payload: {exc}") from exc
        return data


    def parse_device_info(self) -> DeviceInfo:
        return DeviceInfo.from_dict(self.parse_json_payload())

    def parse_session_challenge(self) -> Tuple[DeviceInfo, bytes, bytes, bytes]:
        data = self.parse_json_payload()
        if not isinstance(data, dict) or "device" not in data:
            raise ProtocolError("SESSION_CHALLENGE missing device block")
        missing = [key for key in ("cert", "nonce", "signature") if key not in data]
        if missing:
            raise ProtocolError(f"SESSION_CHALLENGE missing {', '.join(missing)}")
        return (
            DeviceInfo.from_dict(data["device"]),
            _unb64(data["cert"]),
            _unb64(data["nonce"]),
            _unb64(data["signature"]),
        )

    def parse_connect_request_ex(self) -> Tuple[DeviceInfo, bytes, bytes, bytes]:
        data = self.parse_json_payload()
        if not isinstance(data, dict) or "device" not in data:
            raise ProtocolError("CONNECT_REQUEST missing device block")
        missing = [key for key in ("cert", "nonce", "signature") if key not in data]
        if missing:
            raise ProtocolError(f"CONNECT_REQUEST missing {', '.join(missing)}")
        return (
            DeviceInfo.from_dict(data["device"]),
            _unb64(data["cert"]),
            _unb64(data["nonce"]),
            _unb64(data["signature"]),
        )

    def parse_pair_confirm(self) -> str:
        code = self.parse_json_payload().get("code")
        if not isinstance(code, str) or not code:
            raise ProtocolError("PAIR_CONFIRM missing code")
        return code

    def parse_connect_response_ex(self) -> Tuple[bool, DeviceInfo, bool]:
        data = self.parse_json_payload()
        if (
            not isinstance(data, dict)
            or "accepted" not in data
            or "device" not in data
        ):
            raise ProtocolError("CONNECT_RESPONSE missing fields")
        return (
            bool(data["accepted"]),
            DeviceInfo.from_dict(data["device"]),
            bool(data.get("paired", False)),
        )


    def parse_file_list(self) -> List[FileInfo]:
        return [FileInfo.from_dict(f) for f in self.parse_json_payload()]

    def parse_connect_response(self) -> Tuple[bool, DeviceInfo]:
        data = self.parse_json_payload()
        return data["accepted"], DeviceInfo.from_dict(data["device"])

    def parse_file_request(self) -> Tuple[str, int]:
        data = self.parse_json_payload()
        return data["file_id"], data.get("offset", 0)

    def parse_file_request_full(self) -> Dict[str, Any]:
        """FILE_REQUEST payload including optional metadata (name/size/path/chunk_size)."""
        data = self.parse_json_payload()
        if "file_id" not in data:
            raise ProtocolError("FILE_REQUEST missing file_id")
        return data

    def parse_file_data(self) -> Tuple[str, bytes]:
        if len(self.payload) < 4:
            raise ProtocolError("FILE_DATA payload too short")
        name_len = struct.unpack("!I", self.payload[:4])[0]
        if name_len > len(self.payload) - 4:
            raise ProtocolError("FILE_DATA file_id length out of bounds")
        file_id = self.payload[4 : 4 + name_len].decode("utf-8")
        data = self.payload[4 + name_len :]
        return file_id, data

    def parse_file_chunk(self) -> Tuple[str, int, bytes]:
        if len(self.payload) < 8:
            raise ProtocolError("FILE_CHUNK payload too short")
        name_len, chunk_index = struct.unpack("!II", self.payload[:8])
        if name_len > len(self.payload) - 8:
            raise ProtocolError("FILE_CHUNK file_id length out of bounds")
        file_id = self.payload[8 : 8 + name_len].decode("utf-8")
        data = self.payload[8 + name_len :]
        return file_id, chunk_index, data

    def parse_file_complete(self) -> Tuple[str, bool, str]:
        data = self.parse_json_payload()
        return data["file_id"], data["success"], data.get("error", "")

    def parse_file_complete_data(self) -> Dict[str, Any]:
        """FILE_COMPLETE payload including the optional ``checksum`` field."""
        data = self.parse_json_payload()
        if "file_id" not in data or "success" not in data:
            raise ProtocolError("FILE_COMPLETE missing fields")
        return data


    def parse_checksum_request(self) -> Tuple[str, str]:
        data = self.parse_json_payload()
        return data["file_id"], data.get("algorithm", "sha256")

    def parse_checksum_response(self) -> Tuple[str, str]:
        data = self.parse_json_payload()
        return data["file_id"], data["checksum"]

    def parse_error(self) -> Tuple[int, str]:
        data = self.parse_json_payload()
        if not isinstance(data, dict) or "code" not in data or "message" not in data:
            raise ProtocolError("ERROR payload missing fields")
        return data["code"], data["message"]


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly `size` bytes from a stream socket."""
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("Connection closed while reading message")
        chunks.extend(chunk)
    return bytes(chunks)


def send_message(sock: socket.socket, message: Message) -> None:
    """Frame and send one complete message over a TCP stream."""
    sock.sendall(message.encode())


def recv_message(sock: socket.socket) -> Message:
    """Read exactly one framed message from a TCP stream.

    Handles arbitrary fragmentation: the header and payload are each read
    until complete, regardless of how the peer's send() calls were split.
    """
    header = _recv_exact(sock, HEADER_SIZE)
    msg_type, sequence, flags, payload_len = decode_header(header)
    payload = _recv_exact(sock, payload_len) if payload_len else b""
    return Message(msg_type, payload, sequence, flags)


def expect_message_type(message: Message, *type_names: str) -> Message:
    """Validate a message's type *before* calling a payload parser.

    Parsers assume the payload layout matches their message type; feeding a
    message of the wrong type into them raises KeyError/struct errors.
    This helper turns that mistake into a clean ProtocolError.
    """
    if not type_names:
        raise ValueError("at least one expected type name is required")
    expected = set()
    for name in type_names:
        if name not in MESSAGE_TYPES:
            raise ValueError(f"unknown message type name: {name}")
        expected.add(MESSAGE_TYPES[name])
    if message.msg_type not in expected:
        wanted = ", ".join(type_names)
        raise ProtocolError(f"expected {wanted}, got {message.type_name}")
    return message



def calculate_checksum(file_path: Path, algorithm: str = "sha256", chunk_size: int = CHECKSUM_CHUNK_SIZE) -> str:
    """Calculate file checksum."""
    hasher = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_checksum(file_path: Path, expected: str, algorithm: str = "sha256") -> bool:
    """Verify file checksum."""
    return calculate_checksum(file_path, algorithm) == expected


def _default_route_ip() -> Optional[str]:
    """Kernel's egress guess; None when there is no default route.

    The UDP connect sends no packet - it only makes the routing table pick
    an egress address.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def _usable_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        return not ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def get_local_ip() -> str:
    """Local IP announced to peers - never loopback while a LAN IP exists (M31).

    On a LAN without a default route the egress guess fails or points at
    127.0.0.1; announcing that would make every peer connect to itself.
    Falls back to the first real interface, then the hostname, then
    127.0.0.1 as a true last resort.
    """
    ip = _default_route_ip()
    if _usable_ip(ip):
        return str(ip)
    for info in list_ipv4_interfaces():
        if _usable_ip(info.ip):
            return info.ip
    try:
        hostname_ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        hostname_ip = None
    if _usable_ip(hostname_ip):
        return str(hostname_ip)
    return "127.0.0.1"


def get_broadcast_address(ip: str, netmask: str = "255.255.255.0") -> str:
    """Calculate broadcast address from IP and netmask."""
    ip_parts = [int(x) for x in ip.split(".")]
    mask_parts = [int(x) for x in netmask.split(".")]
    broadcast = [ip_parts[i] | (~mask_parts[i] & 0xFF) for i in range(4)]
    return ".".join(str(x) for x in broadcast)


if __name__ == "__main__":
    print("virusShare Protocol Test")
    print("---------------------------\n")

    device = DeviceInfo(
        name="DESKTOP-ABC",
        ip=get_local_ip(),
        port=50000,
        device_id="f47ac10b-58cc-4372-a567-0e02b2c3d479",
        os_version="Windows 11",
        app_version="1.0.0",
        capabilities=["file_transfer", "resume", "checksum"],
    )

    discovery = Message.create_discovery(device, sequence=1)
    raw = discovery.encode()

    magic, version, msg_type, sequence, flags, payload_len = struct.unpack(
        HEADER_FORMAT, raw[:HEADER_SIZE]
    )
    print(f"[1] DISCOVERY message ({len(raw)} bytes total)")
    print(f"    Header : {HEADER_SIZE} bytes -> magic={magic!r} version={version} "
          f"type=0x{msg_type:02X} seq={sequence} flags={flags} payload_len={payload_len}")
    print(f"    Payload: {raw[HEADER_SIZE:].decode('utf-8')}\n")

    decoded, consumed = Message.decode(raw)
    print(f"[2] Decoded as {decoded.type_name}, consumed {consumed} bytes")
    print(f"    Round trip equal: {decoded.parse_device_info() == device}\n")

    request = Message.create_connect_request(device, sequence=2)
    decoded, _ = Message.decode(request.encode())
    print(f"[3] {decoded.type_name}: name={decoded.parse_device_info().name} "
          f"port={decoded.parse_device_info().port}\n")

    print("[4] TCP framing over a real socket pair")
    sender, receiver = socket.socketpair()
    try:
        stream = b"".join(
            Message.create_discovery(device, sequence=i).encode() for i in range(3)
        )
        print(f"    Sending 3 messages in one write ({len(stream)} bytes)")
        sender.sendall(stream)

        for i in range(3):
            got = recv_message(receiver)
            print(f"    Recv -> {got.type_name} seq={got.sequence} "
                  f"payload={len(got.payload)} bytes")
    finally:
        sender.close()
        receiver.close()

    print("\nAll protocol checks passed.")