"""virusShare - transfer history database tests."""

import threading
from datetime import datetime, timedelta

import pytest

from database.history import HistoryDB, HistoryEntry
from models import TransferFile, TransferSession, TransferStatus


def make_session(
    sid="s-1",
    direction="send",
    peer_id="peer-1",
    peer_name="PC-ONE",
    status=TransferStatus.COMPLETED,
    files=1,
    error="",
):
    now = datetime(2026, 1, 1, 12, 0, 0)
    session = TransferSession(
        id=sid,
        computer_id=peer_id,
        computer_name=peer_name,
        status=status,
        start_time=now,
        end_time=now + timedelta(seconds=5),
        direction=direction,
        error_message=error,
    )
    for i in range(files):
        session.add_file(
            TransferFile(
                id=f"f{i}",
                name=f"file{i}.bin",
                path=f"C:/data/file{i}.bin",
                size=1000 * (i + 1),
                checksum="ab" * 32,
            )
        )
    session.transferred_size = session.total_size
    return session


@pytest.fixture
def db(tmp_path):
    store = HistoryDB(tmp_path / "history.db")
    yield store
    store.close()


def test_record_and_recent_roundtrip(db):
    session = make_session()
    row_id = db.record(session)
    assert row_id == 1

    entries = db.recent()
    assert len(entries) == 1
    e = entries[0]
    assert e.id == 1
    assert e.session_id == "s-1"
    assert e.direction == "send"
    assert e.peer_id == "peer-1"
    assert e.peer_name == "PC-ONE"
    assert e.status == "completed"
    assert e.success is True
    assert e.error == ""
    assert e.total_size == 1000
    assert e.transferred_size == 1000
    assert e.file_count == 1
    assert e.files[0]["name"] == "file0.bin"
    assert e.files[0]["checksum"] == "ab" * 32
    assert e.started_at == datetime(2026, 1, 1, 12, 0, 0)
    assert e.finished_at == datetime(2026, 1, 1, 12, 0, 5)


def test_recent_is_newest_first_with_limit(db):
    for i in range(10):
        s = make_session(sid=f"s-{i}")
        s.start_time = datetime(2026, 1, 1) + timedelta(minutes=i)
        db.record(s)

    entries = db.recent(limit=3)
    assert [e.session_id for e in entries] == ["s-9", "s-8", "s-7"]
    assert db.count() == 10


def test_direction_and_peer_filters(db):
    db.record(make_session(sid="a", direction="send", peer_id="p1"))
    db.record(make_session(sid="b", direction="receive", peer_id="p1"))
    db.record(make_session(sid="c", direction="send", peer_id="p2"))

    assert [e.session_id for e in db.recent(direction="send")] == ["c", "a"]
    assert [e.session_id for e in db.recent(direction="receive")] == ["b"]
    assert [e.session_id for e in db.recent(peer_id="p1")] == ["b", "a"]
    assert db.recent(direction="send", peer_id="p1")[0].session_id == "a"


def test_failure_recorded(db):
    session = make_session(
        status=TransferStatus.FAILED, error="connection reset", files=2
    )
    db.record(session)
    e = db.recent()[0]
    assert e.status == "failed"
    assert e.success is False
    assert e.error == "connection reset"
    assert e.file_count == 2


def test_get_by_id(db):
    rid = db.record(make_session())
    assert db.get(rid).session_id == "s-1"
    assert db.get(999) is None


def test_search_matches_peer_and_file_names(db):
    db.record(make_session(peer_name="LAPTOP-GAMING", files=1))
    db.record(make_session(sid="s-2", peer_name="OFFICE-PC", files=2))

    assert len(db.search("gaming")) == 1
    assert len(db.search("file1.bin")) == 1
    assert len(db.search("no-match")) == 0


def test_clear(db):
    db.record(make_session())
    db.record(make_session(sid="s-2"))
    removed = db.clear()
    assert removed == 2
    assert db.count() == 0
    assert db.recent() == []


def test_prune_keeps_newest(db):
    for i in range(10):
        db.record(make_session(sid=f"s-{i}"))

    removed = db.prune(max_entries=4)
    assert removed == 6
    assert db.count() == 4
    assert [e.session_id for e in db.recent()] == ["s-9", "s-8", "s-7", "s-6"]


def test_persistence_across_reopen(tmp_path):
    path = tmp_path / "history.db"
    with HistoryDB(path) as db:
        db.record(make_session())

    with HistoryDB(path) as db2:
        assert db2.count() == 1
        assert db2.recent()[0].peer_name == "PC-ONE"


def test_corrupt_files_json_becomes_empty_list(tmp_path):
    path = tmp_path / "history.db"
    db = HistoryDB(path)
    db.record(make_session())
    with db._lock:  # noqa: SLF001 - deliberate corruption for resilience check
        db._require().execute(
            "UPDATE history SET files_json = 'not-json'"
        )
        db._require().commit()
    e = db.recent()[0]
    assert e.files == []
    db.close()


def test_closed_db_raises(tmp_path):
    db = HistoryDB(tmp_path / "h.db")
    db.close()
    with pytest.raises(RuntimeError):
        db.count()


def test_concurrent_writes(tmp_path):
    db = HistoryDB(tmp_path / "history.db")
    errors = []

    def worker(n):
        try:
            for i in range(10):
                db.record(make_session(sid=f"w{n}-{i}"))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        assert not errors
        assert db.count() == 80
    finally:
        db.close()


def test_unicode_paths_survive(db):
    session = make_session(peer_name="Ünïcødé-PC")
    session.files[0].name = "отчёт-2026 — final.pdf"
    db.record(session)
    e = db.recent()[0]
    assert e.peer_name == "Ünïcødé-PC"
    assert e.files[0]["name"] == "отчёт-2026 — final.pdf"


def test_entry_to_dict(db):
    rid = db.record(make_session())
    d = db.recent()[0].to_dict()
    assert d["id"] == rid
    assert d["session_id"] == "s-1"
    assert d["started_at"] == "2026-01-01T12:00:00"
    assert isinstance(d["files"], list)


# --------------------------------------------------------------------------- #
# M26 - cap, corruption quarantine, close resilience
# --------------------------------------------------------------------------- #

def test_prune_runs_after_every_record(tmp_path):
    """M26: prune() existed but was never called; history grew forever."""
    path = tmp_path / "history.db"
    db = HistoryDB(path, max_entries=3)
    try:
        for i in range(5):
            db.record(make_session(sid=f"s-{i}"))
        assert db.count() == 3, "history exceeded its cap after record()"
        assert [e.session_id for e in db.recent()] == ["s-4", "s-3", "s-2"]
    finally:
        db.close()


def test_prune_on_open_trims_legacy_growth(tmp_path):
    """M26: a pre-existing oversized DB must be trimmed when opened."""
    path = tmp_path / "history.db"
    db1 = HistoryDB(path)
    for i in range(5):
        db1.record(make_session(sid=f"s-{i}"))
    assert db1.count() == 5
    db1.close()

    db2 = HistoryDB(path, max_entries=3)
    try:
        assert db2.count() == 3, "oversized legacy history not pruned on open"
    finally:
        db2.close()


def test_corrupt_db_is_quarantined_not_fatal(tmp_path, caplog):
    """M26: a corrupt history.db must not brick startup."""
    import logging as logging_mod

    path = tmp_path / "history.db"
    original = b"definitely not a sqlite database " * 32
    path.write_bytes(original)

    with caplog.at_level(logging_mod.ERROR, logger="database.history"):
        db = HistoryDB(path)
    try:
        assert db.count() == 0, "fresh history not opened after quarantine"
        backups = list(tmp_path.glob("history.db.corrupt-*"))
        assert backups, "corrupt db file was not quarantined"
        assert path.exists(), "db path missing after quarantine"
        assert path.read_bytes() != original, "corrupt file was not replaced"
        assert any("corrupt" in r.message.lower() for r in caplog.records), (
            "quarantine was not logged as an error"
        )
    finally:
        db.close()


def test_close_survives_commit_failure(tmp_path):
    """M26: a failed commit on close must still close the connection."""
    import sqlite3

    db = HistoryDB(tmp_path / "history.db")
    real = db._conn

    class BrokenCommit:
        def commit(self):
            raise sqlite3.OperationalError("disk I/O error")

        def __getattr__(self, name):
            return getattr(real, name)

    db._conn = BrokenCommit()
    db.close()  # must not raise
    assert db._conn is None, "closed db still holds a connection"
    with pytest.raises(sqlite3.ProgrammingError):
        real.execute("SELECT 1")
