"""virusShare - UDP discovery service tests.

Two services on one host find each other over loopback/subnet broadcast
(``SO_REUSEADDR`` allows sharing the port, same trick as ``_exp.py``).
Broadcast intervals are shortened so the whole module stays under ~10 s.
"""

import socket
import time

import pytest

from core.constants import TRANSFER_PORT
from network.discovery import DiscoveryService, get_stable_device_id

TEST_PORT = 54391  # away from the production 54321 to avoid clashing


def make_service(name, device_id, found, lost, **kwargs):
    defaults = dict(
        port=TEST_PORT,
        transfer_port=TRANSFER_PORT,
        broadcast_interval=0.3,
        device_timeout=2.0,
        on_device_found=found.append,
        on_device_lost=lambda device_id: lost.append(device_id),
    )
    defaults.update(kwargs)
    return DiscoveryService(name, device_id, **defaults)


def wait_for(predicate, timeout=8.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


@pytest.fixture
def services():
    """Start a pair of services; returns (svc_a, svc_b, found_a, found_b, ...)."""
    found_a, found_b, lost_a, lost_b = [], [], [], []
    a = make_service("PC-A", "id-AAA", found_a, lost_a)
    b = make_service("PC-B", "id-BBB", found_b, lost_b)
    a.start()
    b.start()
    ns = type("NS", (), {})()
    ns.a, ns.b = a, b
    ns.found_a, ns.found_b = found_a, found_b
    ns.lost_a, ns.lost_b = lost_a, lost_b
    yield ns
    a.stop()
    b.stop()


def test_services_find_each_other(services):
    assert wait_for(lambda: len(services.found_a) >= 1), "A never saw B"
    assert wait_for(lambda: len(services.found_b) >= 1), "B never saw A"

    seen_by_a = services.a.get_device("id-BBB")
    seen_by_b = services.b.get_device("id-AAA")
    assert seen_by_a is not None
    assert seen_by_b is not None
    assert seen_by_a.info.name == "PC-B"
    assert seen_by_b.info.name == "PC-A"
    assert seen_by_a.info.port == TRANSFER_PORT


def test_own_echo_is_ignored(services):
    wait_for(lambda: services.found_a and services.found_b, timeout=6)
    assert services.a.get_device("id-AAA") is None  # never lists itself
    assert services.b.get_device("id-BBB") is None
    assert len(services.a.get_devices()) == 1
    assert len(services.b.get_devices()) == 1


def test_found_refires_on_each_beacon(services):
    # M2: cleared views (View->Refresh, manual-connect) must repopulate on
    # the next beacon instead of waiting for the peer to time out (~10-12 s).
    wait_for(lambda: services.found_a, timeout=6)
    services.found_a.clear()
    assert wait_for(lambda: len(services.found_a) >= 1, timeout=3.0), (
        "discovery did not re-emit deviceFound for a live peer"
    )


def test_device_lost_fires_after_timeout(services):
    wait_for(lambda: services.a.get_device("id-BBB"), timeout=6)
    services.b.stop()
    assert wait_for(lambda: "id-BBB" in services.lost_a, timeout=8), (
        "A never expired B"
    )
    assert services.a.get_device("id-BBB") is None
    # restart b so the fixture's stop() is still safe (stop is idempotent)
    services.b.start()


def test_trust_flag_survives_refresh(services):
    wait_for(lambda: services.a.get_device("id-BBB"), timeout=6)
    services.a.set_trusted("id-BBB", True)

    time.sleep(1.0)  # several broadcasts pass through
    device = services.a.get_device("id-BBB")
    assert device is not None
    assert device.is_trusted is True
    services.a.set_trusted("id-BBB", False)
    time.sleep(1.0)
    assert services.a.get_device("id-BBB").is_trusted is False


def test_to_computer_conversion(services):
    wait_for(lambda: services.a.get_device("id-BBB"), timeout=6)
    computer = services.a.get_device("id-BBB").to_computer()
    assert computer.name == "PC-B"
    assert computer.id == "id-BBB"
    assert computer.port == TRANSFER_PORT
    assert computer.status.value in ("disconnected", "connected")


def test_update_device_info_changes_advertised_name(services):
    services.a.update_device_info(device_name="RENAMED-A")
    assert services.a.device_info.name == "RENAMED-A"
    # within a couple of broadcasts the peer sees the new name
    wait_for(
        lambda: any(
            d.info.name == "RENAMED-A" for d in services.b.get_devices()
        ),
        timeout=6,
    )


def test_stable_device_id_is_deterministic():
    first = get_stable_device_id()
    second = get_stable_device_id()
    assert first == second
    assert len(first) == 36  # uuid string
    assert first.count("-") == 4


def test_stop_is_idempotent_and_clears_registry(services):
    wait_for(lambda: services.a.get_device("id-BBB"), timeout=6)
    services.a.stop()
    services.a.stop()  # second stop must not raise
    assert services.a.running is False
    assert services.a.get_devices() == []


def test_running_flag_and_restart(services):
    services.a.stop()
    assert services.a.running is False
    services.a.start()
    assert services.a.running is True
    # and it still finds the peer after a restart
    services.found_a.clear()
    assert wait_for(lambda: services.a.get_device("id-BBB"), timeout=6)


def test_garbage_datagram_does_not_kill_listener(services):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for payload in (b"", b"ETHR", b"\x00" * 4, b"not json at all"):
            sock.sendto(payload, ("127.0.0.1", TEST_PORT))
        time.sleep(0.3)
        assert services.a.running is True
        assert wait_for(lambda: services.a.get_device("id-BBB"), timeout=6)
    finally:
        sock.close()


def test_stop_joins_broadcast_thread_and_restart_does_not_leak():
    """M35: stop() joins worker threads with a fixed 2.0 s timeout while the
    broadcast loop sleeps for broadcast_interval; an interval longer than the
    join timeout lets stop() return with a live broadcast thread that a later
    start() then duplicates."""
    found, lost = [], []
    svc = make_service("PC-X", "id-XXX", found, lost, broadcast_interval=3.0)
    svc.start()
    time.sleep(0.5)
    first_cycle = list(svc._threads)
    svc.stop()
    for thread in first_cycle:
        thread.join(timeout=0.2)
        assert not thread.is_alive(), "stop() returned with a live discovery thread"

    svc.start()
    second_cycle = list(svc._threads)
    svc.stop()
    for thread in second_cycle:
        thread.join(timeout=0.2)
        assert not thread.is_alive(), (
            "stop() returned with a live discovery thread after restart"
        )

    leaked = [t for t in first_cycle + second_cycle if t.is_alive()]
    assert not leaked, "restart accumulated duplicate discovery threads"
