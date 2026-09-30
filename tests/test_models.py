"""virusShare - domain model tests (models.py)."""

import os
from datetime import datetime
from pathlib import Path

import pytest

from models import (
    Computer,
    ConnectionStatus,
    TransferFile,
    TransferSession,
    TransferStatus,
)


# --------------------------------------------------------------------------- #
# Computer
# --------------------------------------------------------------------------- #

def test_computer_equality_and_hash_use_id_only():
    now = datetime(2026, 1, 1)
    a = Computer(id="same", name="A", ip="10.0.0.1", last_seen=now)
    b = Computer(id="same", name="B", ip="10.0.0.2", last_seen=now)
    c = Computer(id="other", name="A", ip="10.0.0.1", last_seen=now)

    assert a == b
    assert a != c
    assert len({a, b, c}) == 2
    assert hash(a) == hash(b)
    assert a != "not-a-computer"


def test_computer_dict_roundtrip():
    comp = Computer(
        id="dev-1",
        name="OFFICE-PC",
        ip="192.168.1.50",
        port=54322,
        mac="00:11:22:33:44:55",
        interface="Ethernet",
        is_trusted=True,
        status=ConnectionStatus.CONNECTED,
    )
    data = comp.to_dict()
    assert data["status"] == "connected"
    assert data["is_trusted"] is True

    restored = Computer.from_dict(data)
    assert restored.id == comp.id
    assert restored.name == comp.name
    assert restored.ip == comp.ip
    assert restored.port == comp.port
    assert restored.mac == comp.mac
    assert restored.is_trusted is True
    assert restored.status is ConnectionStatus.CONNECTED
    assert restored.last_seen == comp.last_seen


def test_computer_from_dict_minimal():
    comp = Computer.from_dict({"name": "X"})
    assert comp.name == "X"
    assert comp.status is ConnectionStatus.DISCONNECTED
    assert comp.id  # generated
    assert isinstance(comp.last_seen, datetime)


def test_connection_status_values():
    assert {s.value for s in ConnectionStatus} == {
        "disconnected",
        "connecting",
        "connected",
        "transferring",
    }


# --------------------------------------------------------------------------- #
# TransferFile
# --------------------------------------------------------------------------- #

def test_transfer_file_from_path(tmp_path):
    f = tmp_path / "report.pdf"
    f.write_bytes(b"x" * 4096)
    tf = TransferFile.from_path(f, parent_id="root")
    assert tf.name == "report.pdf"
    assert tf.path == str(f)
    assert tf.size == 4096
    assert tf.is_directory is False
    assert tf.parent_id == "root"
    assert tf.checksum == ""


def test_transfer_file_from_path_directory(tmp_path):
    d = tmp_path / "folder"
    d.mkdir()
    tf = TransferFile.from_path(d)
    assert tf.is_directory is True
    assert tf.size == 0


def test_transfer_file_dict_roundtrip():
    tf = TransferFile(
        id="f-1", name="a.bin", path="/x/a.bin", size=10,
        checksum="cd" * 32, parent_id="p",
    )
    restored = TransferFile.from_dict(tf.to_dict())
    assert restored == tf


# --------------------------------------------------------------------------- #
# TransferSession
# --------------------------------------------------------------------------- #

def make_session(total=1000, transferred=250, started=True):
    session = TransferSession(direction="send")
    if started:
        session.start_time = datetime(2026, 1, 1, 10, 0, 0)
    session.total_size = total
    session.transferred_size = transferred
    return session


def test_add_file_accumulates_total():
    session = TransferSession()
    session.add_file(TransferFile(size=100))
    session.add_file(TransferFile(size=250))
    assert len(session.files) == 2
    assert session.total_size == 350


def test_progress_guarded_against_zero_total():
    session = TransferSession()
    assert session.get_progress() == 0.0
    session.total_size = 0
    session.transferred_size = 99
    assert session.get_progress() == 0.0


def test_progress_percentage():
    session = make_session(total=400, transferred=100)
    assert session.get_progress() == pytest.approx(25.0)


def test_speed_and_eta():
    session = make_session(total=1_000_000, transferred=500_000)
    # start_time is fixed in the past; speed = transferred / elapsed
    elapsed = (datetime.now() - session.start_time).total_seconds()
    expected_speed = 500_000 / elapsed
    assert session.get_speed() == pytest.approx(expected_speed, rel=0.01)
    eta = session.get_eta()
    assert eta is not None
    assert eta > 0
    remaining = session.total_size - session.transferred_size
    assert eta == pytest.approx(remaining / session.get_speed(), rel=0.1)


def test_speed_and_eta_without_start():
    session = TransferSession(total_size=100, transferred_size=10)
    assert session.get_speed() == 0.0
    assert session.get_eta() is None


def test_eta_none_at_zero_speed():
    session = TransferSession()
    session.start_time = datetime.now()
    session.transferred_size = 0
    assert session.get_speed() == 0.0
    assert session.get_eta() is None


# --------------------------------------------------------------------------- #
# M33 - clamped progress / ETA, stable totals mid-transfer
# --------------------------------------------------------------------------- #

def test_progress_clamped_to_100_percent():
    session = make_session(total=100, transferred=250)
    assert session.get_progress() == 100.0, "progress exceeded 100% (M33)"


def test_eta_never_negative_when_over_transferred():
    session = make_session(total=100, transferred=250)
    eta = session.get_eta()
    assert eta is not None, "ETA missing for a running session (M33)"
    assert eta >= 0.0, f"negative ETA {eta}s (M33)"


def test_add_file_during_active_transfer_does_not_change_total():
    """A file added while the session is in flight must not rewrite the
    denominator the progress bar is dividing by (M33)."""
    session = TransferSession(
        status=TransferStatus.ACTIVE, total_size=100, transferred_size=50
    )
    session.add_file(TransferFile(size=1000))
    assert len(session.files) == 1, "file was not recorded"
    assert session.total_size == 100, (
        f"total_size mutated mid-transfer: {session.total_size} (M33)"
    )


def test_session_to_dict():
    session = TransferSession(
        computer_id="peer", computer_name="PC", direction="receive"
    )
    session.add_file(TransferFile(id="f1", name="a", path="/a", size=5))
    session.status = TransferStatus.ACTIVE
    data = session.to_dict()

    assert data["direction"] == "receive"
    assert data["status"] == "active"
    assert data["computer_name"] == "PC"
    assert len(data["files"]) == 1
    assert data["files"][0]["id"] == "f1"
    assert data["total_size"] == 5
    assert data["start_time"] is None  # never started


def test_transfer_status_values():
    assert {s.value for s in TransferStatus} == {
        "pending",
        "active",
        "paused",
        "completed",
        "failed",
        "cancelled",
    }
