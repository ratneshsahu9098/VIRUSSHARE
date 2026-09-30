"""virusShare - utils.network and utils.windows helper tests."""

import socket
import sys
from pathlib import Path

import pytest

from utils import network as net
from utils import windows as win


# --------------------------------------------------------------------------- #
# utils.network
# --------------------------------------------------------------------------- #

def test_broadcast_address_24():
    assert net.broadcast_address("192.168.10.1", "255.255.255.0") == "192.168.10.255"


def test_broadcast_address_16():
    assert net.broadcast_address("10.0.5.9", "255.255.0.0") == "10.0.255.255"


def test_broadcast_address_rejects_junk():
    with pytest.raises(ValueError):
        net.broadcast_address("not-an-ip", "255.255.255.0")
    with pytest.raises(ValueError):
        net.broadcast_address("10.0.0.1", "mask")


def test_is_private_ip():
    assert net.is_private_ip("192.168.1.10")
    assert net.is_private_ip("10.1.2.3")
    assert net.is_private_ip("172.16.0.1")
    assert net.is_private_ip("127.0.0.1")
    assert not net.is_private_ip("8.8.8.8")
    assert not net.is_private_ip("banana")


def test_list_ipv4_interfaces_shape():
    interfaces = net.list_ipv4_interfaces()
    assert isinstance(interfaces, list)
    for info in interfaces:
        assert not info.is_loopback
        assert info.is_ipv4
        assert info.name
        assert "." in info.ip
        assert info.label == f"{info.name} ({info.ip})"


def test_primary_ip_is_a_dotted_quad():
    ip = net.primary_ip()
    parts = ip.split(".")
    assert len(parts) == 4
    assert all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def test_primary_ip_skips_loopback_egress(monkeypatch):
    """M31: an egress guess of 127.0.0.1 (route via loopback) must not beat
    the real LAN address the hostname resolves to."""

    class LoopbackEgress:
        def __init__(self, *args, **kwargs):
            pass

        def connect(self, addr):
            return None

        def getsockname(self):
            return ("127.0.0.1", 0)

        def close(self):
            return None

    monkeypatch.setattr(net, "list_ipv4_interfaces", lambda: [])
    monkeypatch.setattr(net.socket, "socket", LoopbackEgress)
    monkeypatch.setattr(net.socket, "gethostbyname", lambda host: "192.168.1.50")
    assert net.primary_ip() == "192.168.1.50"


def test_broadcast_targets_contains_limited_broadcast_and_is_unique():
    targets = net.broadcast_targets()
    assert net.LIMITED_BROADCAST in targets
    assert len(targets) == len(set(targets))
    assert all("." in t for t in targets)


def test_is_port_available_free_and_taken():
    assert net.is_port_available("127.0.0.1", net.find_free_port()) is True

    port = net.find_free_port()
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        blocker.bind(("127.0.0.1", port))
        blocker.listen(1)
        assert net.is_port_available("127.0.0.1", port) is False
    finally:
        blocker.close()


def test_is_port_available_rejects_bad_ports():
    assert net.is_port_available("127.0.0.1", 0) is False
    assert net.is_port_available("127.0.0.1", 70000) is False
    assert net.is_port_available("127.0.0.1", -1) is False


def test_find_free_port_in_range():
    port = net.find_free_port()
    assert 0 < port < 65536


def test_is_port_listening():
    port = net.find_free_port()
    assert net.is_port_listening("127.0.0.1", port) is False

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", port))
        server.listen(1)
        assert net.is_port_listening("127.0.0.1", port) is True
    finally:
        server.close()


def test_interface_info_broadcast_property():
    info = net.InterfaceInfo(name="Wi-Fi", ip="172.16.4.9", netmask="255.255.0.0")
    assert info.broadcast == "172.16.255.255"
    no_mask = net.InterfaceInfo(name="X", ip="10.0.0.2")
    assert no_mask.broadcast is None
    loopback = net.InterfaceInfo(name="lo", ip="127.0.0.1", netmask="255.0.0.0")
    assert loopback.is_loopback is True
    assert loopback.broadcast == "127.255.255.255"


# --------------------------------------------------------------------------- #
# utils.windows
# --------------------------------------------------------------------------- #

def test_is_windows_flag_matches_platform():
    assert win.IS_WINDOWS == sys.platform.startswith("win")


def test_resource_path_dev_mode_points_at_repo_root(monkeypatch):
    monkeypatch.delattr(sys, "_MEIPASS", raising=False)
    p = win.resource_path("README.md")
    assert p == Path(__file__).resolve().parent.parent / "README.md"
    assert p.exists()


def test_resource_path_pyinstaller_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert win.resource_path("assets/icon.ico") == tmp_path / "assets/icon.ico"


def test_machine_description_mentions_host():
    import platform

    label = win.machine_description()
    assert platform.node() in label
    assert platform.system() in label


def test_autostart_queries_do_not_raise():
    assert win.autostart_available() is win.IS_WINDOWS
    assert isinstance(win.is_autostart_enabled(), bool)


def test_set_autostart_without_windows_is_noop(monkeypatch):
    monkeypatch.setattr(win, "IS_WINDOWS", False)
    # never touches the registry when disabled
    assert win.set_autostart(True) is False
    assert win.is_autostart_enabled() is False


def test_autostart_command_is_quoted(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", r"C:\Program Files\Ether\virusShare.exe")
    cmd = win._autostart_command()
    assert cmd.startswith('"C:\\Program Files\\Ether\\virusShare.exe"')
    assert "--minimized" in cmd

    monkeypatch.setattr(sys, "frozen", False, raising=False)
    dev_cmd = win._autostart_command()
    assert "app.py" in dev_cmd
    assert "--minimized" in dev_cmd


def test_taskbar_progress_is_guarded():
    # with a bogus/non-Windows hwnd it must not raise
    assert win.set_taskbar_progress(0, 0.5) is False
    assert win.clear_taskbar_progress(0) is False


def test_remove_legacy_autostart():
    if not win.IS_WINDOWS:
        pytest.skip("windows registry only")
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, win._run_key_path(), 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, "EtherTransfer", 0, winreg.REG_SZ, "C:\\old.exe")

    try:
        assert win.remove_legacy_autostart() is True
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, win._run_key_path()) as key:
            with pytest.raises(FileNotFoundError):
                winreg.QueryValueEx(key, "EtherTransfer")
    finally:
        win.remove_legacy_autostart()

    # absent value -> no-op returning False
    assert win.remove_legacy_autostart() is False


# --------------------------------------------------------------------------- #
# utils.logger
# --------------------------------------------------------------------------- #

def test_log_formatter_escapes_newlines_in_message():
    """M32: a peer-supplied device name containing \\n must not forge an
    extra log record in the log file."""
    import logging

    from utils.logger import SingleLineFormatter

    fmt = SingleLineFormatter("%(levelname)s %(message)s")
    forged = "PC-1\n2026-01-01 00:00:00 CRITICAL forged record"
    record = logging.LogRecord(
        "network.session",
        logging.INFO,
        "session.py",
        10,
        "peer %s connected",
        (forged,),
        None,
    )
    out = fmt.format(record)
    assert "\n" not in out, "newline in a device name forged a log line (M32)"
    assert "CRITICAL forged" in out, "message content was dropped"
    assert "\\n" in out, "newline was not visibly escaped"
