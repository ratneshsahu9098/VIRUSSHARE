"""virusShare - Network Discovery Service"""

import platform
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional

from core.constants import (
    APP_VERSION,
    BROADCAST_INTERVAL,
    DISCOVERY_PORT,
    DISCOVERY_TIMEOUT,
    MESSAGE_TYPES,
    TRANSFER_PORT,
)
from models import Computer, ConnectionStatus
from network.protocol import (
    DeviceInfo,
    Message,
    get_broadcast_address,
    get_local_ip,
)

LIMITED_BROADCAST = "255.255.255.255"


@dataclass
class DiscoveredDevice:
    info: DeviceInfo
    last_seen: float = field(default_factory=time.time)
    is_trusted: bool = False

    @property
    def is_alive(self) -> bool:
        return (time.time() - self.last_seen) <= DISCOVERY_TIMEOUT

    @property
    def status_text(self) -> str:
        return "Available" if self.is_alive else "Stale"

    def to_computer(self) -> Computer:
        return Computer(
            id=self.info.device_id,
            name=self.info.name,
            ip=self.info.ip,
            port=self.info.port,
            last_seen=datetime.fromtimestamp(self.last_seen),
            is_trusted=self.is_trusted,
            status=ConnectionStatus.DISCONNECTED,
        )


def get_stable_device_id() -> str:
    """Derive a device id that stays the same across restarts (MAC based)."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"virusshare-{uuid.getnode()}"))


class DiscoveryService:
    def __init__(
        self,
        device_name: str,
        device_id: str,
        port: int = DISCOVERY_PORT,
        transfer_port: int = TRANSFER_PORT,
        on_device_found: Optional[Callable[[DiscoveredDevice], None]] = None,
        on_device_lost: Optional[Callable[[str], None]] = None,
        device_timeout: float = DISCOVERY_TIMEOUT,
        broadcast_interval: float = BROADCAST_INTERVAL,
    ):
        self.device_name = device_name
        self.device_id = device_id
        self.port = port
        self.transfer_port = transfer_port
        self.on_device_found = on_device_found
        self.on_device_lost = on_device_lost
        self.device_timeout = device_timeout
        self.broadcast_interval = broadcast_interval

        self._socket: Optional[socket.socket] = None
        self._running = False
        self._threads: List[threading.Thread] = []
        self._stop_event = threading.Event()

        self._devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.RLock()

        self._device_info = self._create_device_info()

    # ------------------------------------------------------------------ #
    # setup
    # ------------------------------------------------------------------ #

    def _create_device_info(self) -> DeviceInfo:
        caps = ["file_transfer", "resume", "checksum"]
        try:
            import cryptography  # noqa: F401

            caps.append("encryption")
        except ImportError:
            pass

        return DeviceInfo(
            name=self.device_name,
            ip=get_local_ip(),
            port=self.transfer_port,
            device_id=self.device_id,
            os_version=f"{platform.system()} {platform.release()}",
            app_version=APP_VERSION,
            capabilities=caps,
        )

    @property
    def device_info(self) -> DeviceInfo:
        return self._device_info

    @property
    def running(self) -> bool:
        return self._running

    def start(self):
        if self._running:
            return

        self._stop_event.clear()
        for thread in self._threads:
            if thread.is_alive():
                thread.join(timeout=2.0)
        survivors = [thread for thread in self._threads if thread.is_alive()]

        self._device_info = self._create_device_info()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", self.port))
        except OSError as exc:
            sock.close()
            raise RuntimeError(
                f"Cannot bind UDP discovery port {self.port}: {exc}"
            ) from exc
        sock.settimeout(1.0)

        self._socket = sock
        self._running = True

        new_threads = [
            threading.Thread(target=self._broadcast_loop, daemon=True),
            threading.Thread(target=self._listen_loop, daemon=True),
            threading.Thread(target=self._cleanup_loop, daemon=True),
        ]
        self._threads = survivors + new_threads
        for thread in new_threads:
            thread.start()

    def stop(self):
        self._running = False
        self._stop_event.set()

        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

        for thread in self._threads:
            if thread.is_alive():
                thread.join(timeout=2.0)
        self._threads = [thread for thread in self._threads if thread.is_alive()]

        with self._lock:
            self._devices.clear()

    # ------------------------------------------------------------------ #
    # broadcast / listen
    # ------------------------------------------------------------------ #

    def _broadcast_targets(self) -> List[str]:
        targets = [LIMITED_BROADCAST]
        try:
            subnet = get_broadcast_address(get_local_ip())
            if subnet not in targets:
                targets.append(subnet)
        except Exception:
            pass
        return targets

    def _broadcast_loop(self):
        while self._running:
            sock = self._socket
            if sock is None:
                return
            try:
                self._device_info.ip = get_local_ip()
                data = Message.create_discovery(self._device_info).encode()
                for target in self._broadcast_targets():
                    sock.sendto(data, (target, self.port))
            except OSError:
                if not self._running:
                    return
            if self._stop_event.wait(self.broadcast_interval):
                return

    def _listen_loop(self):
        while self._running:
            sock = self._socket
            if sock is None:
                return
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self._handle_packet(data, addr)

    def _handle_packet(self, data: bytes, addr: tuple):
        try:
            msg, _ = Message.decode(data)
        except Exception:
            return

        if msg.msg_type == MESSAGE_TYPES["DISCOVERY"]:
            try:
                info = msg.parse_device_info()
            except Exception:
                return
            if info.device_id == self.device_id:
                return

            is_new = self._add_or_update_device(info)

            if is_new:
                try:
                    response = Message.create_discovery_response(self._device_info)
                    if self._socket is not None:
                        self._socket.sendto(response.encode(), addr)
                except OSError:
                    pass
            # re-notify on every beacon: cleared GUI lists repopulate within
            # one broadcast interval instead of waiting for a timeout (M2)
            self._notify_found(info.device_id)

        elif msg.msg_type == MESSAGE_TYPES["DISCOVERY_RESPONSE"]:
            try:
                info = msg.parse_device_info()
            except Exception:
                return
            if info.device_id == self.device_id:
                return

            self._add_or_update_device(info)
            self._notify_found(info.device_id)

    # ------------------------------------------------------------------ #
    # device bookkeeping
    # ------------------------------------------------------------------ #

    def _add_or_update_device(self, info: DeviceInfo) -> bool:
        with self._lock:
            known = info.device_id in self._devices
            trusted = self._devices[info.device_id].is_trusted if known else False
            self._devices[info.device_id] = DiscoveredDevice(
                info=info,
                last_seen=time.time(),
                is_trusted=trusted,
            )
            return not known

    def _notify_found(self, device_id: str):
        if not self.on_device_found:
            return
        device = self.get_device(device_id)
        if device is None:
            return
        try:
            self.on_device_found(device)
        except Exception:
            pass

    def _cleanup_once(self, now: Optional[float] = None) -> List[str]:
        now = time.time() if now is None else now
        lost: List[str] = []
        with self._lock:
            stale = [
                dev_id
                for dev_id, dev in self._devices.items()
                if now - dev.last_seen > self.device_timeout
            ]
            for dev_id in stale:
                del self._devices[dev_id]
                lost.append(dev_id)

        for dev_id in lost:
            if self.on_device_lost:
                try:
                    self.on_device_lost(dev_id)
                except Exception:
                    pass
        return lost

    def _cleanup_loop(self):
        while self._running:
            if self._stop_event.wait(1.0):
                return
            self._cleanup_once()

    # ------------------------------------------------------------------ #
    # public API
    # ------------------------------------------------------------------ #

    def get_devices(self) -> List[DiscoveredDevice]:
        with self._lock:
            return sorted(self._devices.values(), key=lambda d: d.info.name.lower())

    def get_device(self, device_id: str) -> Optional[DiscoveredDevice]:
        with self._lock:
            return self._devices.get(device_id)

    def set_trusted(self, device_id: str, trusted: bool):
        with self._lock:
            if device_id in self._devices:
                self._devices[device_id].is_trusted = trusted

    def update_device_info(self, device_name: Optional[str] = None):
        if device_name:
            self.device_name = device_name
        self._device_info = self._create_device_info()


def _print_device_list(devices: List[DiscoveredDevice]):
    if not devices:
        print("  (none yet)")
        return
    for device in devices:
        print(f"  {device.info.name}")
        print(f"    IP: {device.info.ip}")
        print(f"    Port: {device.info.port}")
        print(f"    Status: {device.status_text}")


def main() -> int:
    device_name = platform.node() or "UNKNOWN-PC"
    device_id = get_stable_device_id()

    print("virusShare Discovery")
    print("-----------------------")
    print(f"Local PC:   {device_name}")
    print(f"IP:         {get_local_ip()}")
    print(f"Device ID:  {device_id}")
    print(f"Discovery:  UDP {DISCOVERY_PORT}")
    print(f"Transfer:   TCP {TRANSFER_PORT}")
    print()

    def on_found(device: DiscoveredDevice):
        print(f"  [+] {device.info.name}  {device.info.ip}:{device.info.port}  "
              f"({device.status_text})")
        print()
        print("Found:")
        _print_device_list(service.get_devices())
        print()

    def on_lost(device_id: str):
        print(f"  [-] {device_id} went offline")
        print()

    service = DiscoveryService(
        device_name=device_name,
        device_id=device_id,
        on_device_found=on_found,
        on_device_lost=on_lost,
    )
    service.start()

    print("Searching for computers... (Ctrl+C to stop)")
    print()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        service.stop()

    print("Stopped.")
    print()
    print("Found:")
    _print_device_list(service.get_devices())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
