"""virusShare - LAN/network helpers built on psutil + stdlib sockets.

Everything here is defensive: adapters disappear mid-iteration, firewalls
hide connection tables, and offline machines have no default route.  Any
failure degrades to an empty result rather than an exception.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import List, Optional

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a hard requirement
    psutil = None  # type: ignore[assignment]

LIMITED_BROADCAST = "255.255.255.255"


@dataclass(frozen=True)
class InterfaceInfo:
    """One address-bearing network interface."""

    name: str          # friendly name, e.g. "Ethernet" / "Wi-Fi"
    ip: str            # dotted quad
    netmask: Optional[str] = None

    @property
    def is_loopback(self) -> bool:
        return self.ip.startswith("127.")

    @property
    def is_ipv4(self) -> bool:
        try:
            return ipaddress.ip_address(self.ip).version == 4
        except ValueError:
            return False

    @property
    def broadcast(self) -> Optional[str]:
        if not self.netmask or not self.is_ipv4:
            return None
        return broadcast_address(self.ip, self.netmask)

    @property
    def label(self) -> str:
        return f"{self.name} ({self.ip})"


def list_ipv4_interfaces() -> List[InterfaceInfo]:
    """All up, non-loopback IPv4 interfaces with their netmasks."""
    results: List[InterfaceInfo] = []
    if psutil is None:
        return results
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except (OSError, RuntimeError):
        return results

    for name, entries in addrs.items():
        try:
            if not stats.get(name) or not stats[name].isup:
                continue
        except (KeyError, AttributeError, IndexError):
            continue
        for entry in entries:
            family = getattr(socket, "AF_INET", object())
            if entry.family != family:
                continue
            ip = entry.address.split("%")[0]
            try:
                if ipaddress.ip_address(ip).is_loopback:
                    continue
            except ValueError:
                continue
            results.append(InterfaceInfo(name=name, ip=ip, netmask=entry.netmask))
    return results


def _non_loopback(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        return not ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def primary_ip() -> str:
    """Best-effort local IP of the interface facing the LAN (127.0.0.1 offline).

    A loopback egress guess (route via the loopback device) must never beat
    the real LAN address the hostname resolves to (M31).
    """
    for info in list_ipv4_interfaces():
        if not info.is_loopback:
            return info.ip
    # fallback: kernel's egress guess (no packet is sent for UDP connect)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        egress = sock.getsockname()[0]
    except OSError:
        egress = None
    finally:
        sock.close()
    if _non_loopback(egress):
        return egress
    # egress is loopback or missing: the hostname often resolves to the LAN IP
    try:
        hostname_ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        hostname_ip = None
    if _non_loopback(hostname_ip):
        return hostname_ip
    return "127.0.0.1"


def primary_interface() -> Optional[InterfaceInfo]:
    """The interface that faces the LAN, or None when offline."""
    interfaces = list_ipv4_interfaces()
    if not interfaces:
        return None
    ip = primary_ip()
    for info in interfaces:
        if info.ip == ip:
            return info
    return interfaces[0]


def interface_speed_mbps(name: str) -> Optional[int]:
    """Link speed of ``name`` in Mbps (None when unknown / not reported)."""
    if psutil is None or not name:
        return None
    try:
        stats = psutil.net_if_stats().get(name)
        speed = int(getattr(stats, "speed", 0) or 0)
    except (OSError, RuntimeError, ValueError, AttributeError):
        return None
    return speed if speed > 0 else None


def format_link(name: str) -> str:
    """``('Ethernet', 1000)`` -> ``'Ethernet • 1 Gbps'`` (defensive)."""
    speed = interface_speed_mbps(name)
    if speed is None:
        return name
    if speed >= 1000 and speed % 1000 == 0:
        return f"{name} \u2022 {speed // 1000} Gbps"
    return f"{name} \u2022 {speed} Mbps"


def broadcast_address(ip: str, netmask: str = "255.255.255.0") -> str:
    """ip OR ~mask for IPv4 dotted quads."""
    a = [int(o) for o in ip.split(".")]
    m = [int(o) for o in netmask.split(".")]
    if len(a) != 4 or len(m) != 4:
        raise ValueError("expected dotted-quad IPv4 addresses")
    return ".".join(str(a[i] | (255 - m[i])) for i in range(4))


def broadcast_targets() -> List[str]:
    """Every address a discovery broadcast should be sent to, deduplicated."""
    targets = [LIMITED_BROADCAST]
    for info in list_ipv4_interfaces():
        bcast = info.broadcast
        if bcast and bcast not in targets:
            targets.append(bcast)
    return targets


def is_private_ip(ip: str) -> bool:
    """True for RFC1918/link-local/loopback addresses (and False on junk)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_port_available(host: str, port: int) -> bool:
    """True when we could bind (i.e. nothing else owns) host:port."""
    if not (0 < int(port) < 65536):
        return False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def find_free_port(host: str = "127.0.0.1") -> int:
    """Ask the OS for an unused TCP port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def is_port_listening(host: str, port: int, timeout: float = 0.5) -> bool:
    """True when a TCP connect to host:port succeeds within ``timeout``."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False
