"""virusShare - path traversal, malicious metadata and trust-store tests."""

import os
from pathlib import Path

import pytest

from core.constants import MAX_FILENAME_LENGTH, MAX_RELATIVE_PATH_LENGTH
from core.security import TrustStore, load_identity
from network.protocol import DeviceInfo, FileInfo, Message
from network.tcp_client import TransferClient
from network.tcp_server import TransferServer
from transfer.path_security import (
    PathTraversalError,
    is_safe_filename,
    resolve_destination,
    sanitize_relative_path,
    unique_path,
)
from transfer.receiver import ReceiveContext, handle_incoming

CHUNK = 8192


def device(name, device_id):
    return DeviceInfo(
        name=name, ip="127.0.0.1", port=54322, device_id=device_id,
        os_version="Windows 11", app_version="1.0.0", capabilities=[],
    )


# --------------------------------------------------------------------------- #
# sanitize_relative_path
# --------------------------------------------------------------------------- #

TRAVERSAL_INPUTS = [
    r"..\..\file.txt",
    "../../file.txt",
    "..\\..\\file.txt",
    "foo/../../bar.txt",
    r"foo\..\..\bar.txt",
    "..",
    "../",
    r"..",
    "a/b/../../../c.txt",
    "./../x.txt",
]

ABSOLUTE_INPUTS = [
    "/etc/passwd",
    "\\Windows\\System32\\evil.dll",
    r"C:\Windows\file.txt",
    "C:/Windows/file.txt",
    "d:/temp/x.bin",
    "D:\\data\\x.bin",
    r"\\server\share\file.txt",
    "//server/share/file.txt",
    "\\\\server\\share\\file.txt",
    "C:file.txt",
]


@pytest.mark.parametrize("raw", TRAVERSAL_INPUTS)
def test_traversal_paths_rejected(raw):
    with pytest.raises(PathTraversalError):
        sanitize_relative_path(raw)


@pytest.mark.parametrize("raw", ABSOLUTE_INPUTS)
def test_absolute_and_unc_paths_rejected(raw):
    with pytest.raises(PathTraversalError):
        sanitize_relative_path(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "CON",
        "con.txt",
        "NUL",
        "nul.dat",
        "COM1",
        "com1.log",
        "LPT9",
        "lpt9.txt",
        "PRN",
        "AUX",
    ],
)
def test_reserved_windows_names_rejected(raw):
    with pytest.raises(PathTraversalError):
        sanitize_relative_path(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "file.txt.",          # trailing dot
        "file.txt ",          # trailing space
        "dir /file.txt",      # component with trailing space
        "file:stream.txt",    # alternate data stream
        "a:b",
        "file*.txt",
        "file?.txt",
        "file<name>.txt",
        "file>name.txt",
        "file|pipe.txt",
        'quote".txt',
        "null\x00byte.txt",
        "bell\x07.txt",
        "newline\nfile.txt",
        "a//b.txt",           # empty component
        "folder/",            # trailing separator
        ".",                  # dot only
        "...",
        "",
        "   ",
    ],
)
def test_invalid_windows_paths_rejected(raw):
    with pytest.raises(PathTraversalError):
        sanitize_relative_path(raw)


def test_overlong_paths_rejected():
    with pytest.raises(PathTraversalError):
        sanitize_relative_path("a" * (MAX_RELATIVE_PATH_LENGTH + 1) + "/x")
    with pytest.raises(PathTraversalError):
        sanitize_relative_path("a" * (MAX_FILENAME_LENGTH + 1))


def test_non_string_rejected():
    with pytest.raises(PathTraversalError):
        sanitize_relative_path(None)
    with pytest.raises(PathTraversalError):
        sanitize_relative_path(123)


def test_valid_relative_paths_pass_through():
    cases = {
        "file.txt": "file.txt",
        "project/README.md": "project/README.md",
        "a/b/c/d.bin": "a/b/c/d.bin",
        "file with spaces.txt": "file with spaces.txt",
        "café/naïve.txt": "café/naïve.txt",
        "archive.tar.gz": "archive.tar.gz",
        ".hidden": ".hidden",
        "..hidden": "..hidden",
    }
    for raw, expected in cases.items():
        assert sanitize_relative_path(raw) == expected


def test_windows_separator_traversal_normalized_then_rejected():
    # backslashes are treated as separators so this cannot sneak through
    with pytest.raises(PathTraversalError):
        sanitize_relative_path("ok\\..\\..\\evil")


def test_is_safe_filename():
    assert is_safe_filename("plain.txt")
    assert not is_safe_filename("../plain.txt")
    assert not is_safe_filename("sub/plain.txt")
    assert not is_safe_filename("CON")
    assert not is_safe_filename("a:b")


# --------------------------------------------------------------------------- #
# resolve_destination
# --------------------------------------------------------------------------- #

def test_resolve_destination_confined(tmp_path):
    dest = resolve_destination(tmp_path, "sub/file.txt")
    assert str(dest).startswith(str(tmp_path.resolve()))
    assert dest.name == "file.txt"


def test_resolve_destination_rejects_escape(tmp_path):
    with pytest.raises(PathTraversalError):
        resolve_destination(tmp_path, "../../escape.txt")
    with pytest.raises(PathTraversalError):
        resolve_destination(tmp_path, r"..\..\escape.txt")


def test_resolve_destination_rejects_symlink_escape(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    link = root / "link"
    try:
        os.symlink(str(outside), str(link), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation requires privileges on this host")

    with pytest.raises(PathTraversalError):
        resolve_destination(root, "link/evil.txt")


def test_unique_path_returns_free_sibling(tmp_path):
    target = tmp_path / "report.txt"
    assert unique_path(target) == target
    target.write_text("x", encoding="utf-8")
    second = unique_path(target)
    assert second == tmp_path / "report (1).txt"
    second.write_text("y", encoding="utf-8")
    assert unique_path(target) == tmp_path / "report (2).txt"


# --------------------------------------------------------------------------- #
# receiver-side integration
# --------------------------------------------------------------------------- #

@pytest.fixture
def env(tmp_path):
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    reports = []

    def handler(session):
        reports.append(
            handle_incoming(session, ReceiveContext(receive_dir=incoming, verify=True))
        )

    server = TransferServer(
        device_provider=lambda: device("S", "srv"),
        identity=load_identity(tmp_path / "server.pem"),
        trust_store=TrustStore(tmp_path / "server_trust.json"),
        host="127.0.0.1",
        port=0,
        encryption=False,
        approve_callback=lambda *a: True,
        session_handler=handler,
    )
    port = server.start()
    client = TransferClient(
        device_provider=lambda: device("C", "cli"),
        identity=load_identity(tmp_path / "client.pem"),
        trust_store=TrustStore(tmp_path / "client_trust.json"),
        encryption=False,
        approve_callback=lambda *a: True,
    )
    e = type("Env", (), {})()
    e.incoming = incoming
    e.tmp = tmp_path
    e.server = server
    e.client = client
    e.port = port
    e.reports = reports
    yield e
    server.stop()


def connect(env):
    session = env.client.connect("127.0.0.1", env.port, timeout=5)
    session.sock.settimeout(30)
    return session


def test_malicious_manifest_paths_are_dropped(env):
    session = connect(env)
    evil = [
        FileInfo(name="file.txt", size=5, path="../../evil.txt",
                 is_directory=False, modified_time=1.0),
        FileInfo(name="file.txt", size=5, path=r"..\..\evil2.txt",
                 is_directory=False, modified_time=1.0),
        FileInfo(name="file.txt", size=5, path=r"C:\Windows\evil.txt",
                 is_directory=False, modified_time=1.0),
        FileInfo(name="file.txt", size=5, path=r"\\server\share\evil.txt",
                 is_directory=False, modified_time=1.0),
        FileInfo(name="evil.txt", size=5, path="/evil.txt",
                 is_directory=False, modified_time=1.0),
        FileInfo(name="ok.txt", size=2, path="ok.txt",
                 is_directory=False, modified_time=1.0),
    ]
    try:
        session.send(Message.create_file_list(evil))
        reply = session.expect("FILE_LIST")
        accepted = [fi.path for fi in reply.parse_file_list()]
        assert accepted == ["ok.txt"]  # only the safe entry survives
        session.send(Message.create_disconnect())
    finally:
        session.close()

    # nothing was created outside (or even beside) the receive directory
    for name in ("evil.txt", "evil2.txt"):
        assert not (env.tmp / name).exists()
        assert not (env.incoming / name).exists()
        assert not (env.incoming.parent / name).exists()
    assert not (env.incoming / "ok.txt").exists()  # accepted but never requested


def test_chunk_beyond_declared_size_aborts(env):
    session = connect(env)
    try:
        session.send(
            Message.create_file_list(
                [FileInfo(name="f.bin", size=100, path="f.bin",
                          is_directory=False, modified_time=1.0)]
            )
        )
        session.expect("FILE_LIST")
        session.send(
            Message.create_file_request(
                "f.bin", 0,
                metadata={"name": "f.bin", "size": 100, "path": "f.bin",
                          "mtime": 1.0, "chunk_size": CHUNK},
            )
        )
        session.expect("FILE_RESUME")
        # 200 bytes for a file declared as 100 bytes
        session.send(Message.create_file_chunk("f.bin", 0, b"x" * 200))
        # receiver must abort rather than write past the declared size
        with pytest.raises((OSError, Exception)):
            # the receiver closes the connection / errors out; reading fails
            session.recv(timeout=5)
    finally:
        session.close()

    assert not (env.incoming / "f.bin").exists()
    # the 200-byte chunk is rejected before any write: no out-of-bounds data
    partial = env.incoming / "f.bin.etherpartial"
    assert not partial.exists() or partial.stat().st_size == 0


def test_wrong_chunk_index_aborts(env):
    session = connect(env)
    try:
        session.send(
            Message.create_file_list(
                [FileInfo(name="g.bin", size=10_000, path="g.bin",
                          is_directory=False, modified_time=1.0)]
            )
        )
        session.expect("FILE_LIST")
        session.send(
            Message.create_file_request(
                "g.bin", 0,
                metadata={"name": "g.bin", "size": 10_000, "path": "g.bin",
                          "mtime": 1.0, "chunk_size": CHUNK},
            )
        )
        session.expect("FILE_RESUME")
        session.send(Message.create_file_chunk("g.bin", 7, b"y" * 100))  # expected 0
        with pytest.raises((OSError, Exception)):
            session.recv(timeout=5)
    finally:
        session.close()

    assert not (env.incoming / "g.bin").exists()


def test_size_mismatch_between_manifest_and_request_aborts(env):
    session = connect(env)
    try:
        session.send(
            Message.create_file_list(
                [FileInfo(name="h.bin", size=100, path="h.bin",
                          is_directory=False, modified_time=1.0)]
            )
        )
        session.expect("FILE_LIST")
        session.send(
            Message.create_file_request(
                "h.bin", 0,
                metadata={"name": "h.bin", "size": 999_999, "path": "h.bin",
                          "mtime": 1.0, "chunk_size": CHUNK},
            )
        )
        with pytest.raises((OSError, Exception)):
            session.recv(timeout=5)
    finally:
        session.close()

    assert not (env.incoming / "h.bin").exists()


@pytest.mark.parametrize("bad_chunk", [100, 1023 * 1024 * 1024, -1, 0])
def test_invalid_declared_chunk_size_aborts(env, bad_chunk):
    session = connect(env)
    try:
        session.send(
            Message.create_file_list(
                [FileInfo(name="i.bin", size=1000, path="i.bin",
                          is_directory=False, modified_time=1.0)]
            )
        )
        session.expect("FILE_LIST")
        session.send(
            Message.create_file_request(
                "i.bin", 0,
                metadata={"name": "i.bin", "size": 1000, "path": "i.bin",
                          "mtime": 1.0, "chunk_size": bad_chunk},
            )
        )
        with pytest.raises((OSError, Exception)):
            session.recv(timeout=5)
    finally:
        session.close()

    assert not (env.incoming / "i.bin").exists()


def test_oversized_declared_file_dropped(env):
    session = connect(env)
    try:
        session.send(
            Message.create_file_list(
                [
                    FileInfo(name="huge.bin", size=2**62, path="huge.bin",
                             is_directory=False, modified_time=1.0),
                    FileInfo(name="ok.txt", size=2, path="ok.txt",
                             is_directory=False, modified_time=1.0),
                ]
            )
        )
        reply = session.expect("FILE_LIST")
        accepted = [fi.path for fi in reply.parse_file_list()]
        assert accepted == ["ok.txt"]
        session.send(Message.create_disconnect())
    finally:
        session.close()


def test_receiver_never_commits_unverified_data(env, monkeypatch):
    """Even if a file arrives byte-perfect, a failed digest blocks commit."""
    import hashlib
    from transfer import receiver as receiver_mod

    class Lying(receiver_mod.StreamingHasher):
        def hexdigest(self):
            return "f" * 64

    monkeypatch.setattr(receiver_mod, "StreamingHasher", Lying)

    session = connect(env)
    payload = b"payload-data" * 100
    try:
        session.send(
            Message.create_file_list(
                [FileInfo(name="v.bin", size=len(payload), path="v.bin",
                          is_directory=False, modified_time=1.0)]
            )
        )
        session.expect("FILE_LIST")
        session.send(
            Message.create_file_request(
                "v.bin", 0,
                metadata={"name": "v.bin", "size": len(payload), "path": "v.bin",
                          "mtime": 1.0, "chunk_size": CHUNK},
            )
        )
        session.expect("FILE_RESUME")
        session.send(Message.create_file_chunk("v.bin", 0, payload))
        session.send(
            Message.create_file_complete(
                "v.bin", True, checksum=hashlib.sha256(payload).hexdigest()
            )
        )
        ack = session.expect("FILE_COMPLETE")
        _, success, error = ack.parse_file_complete()
        assert success is False
        assert "Checksum mismatch" in error
        session.send(Message.create_disconnect())
    finally:
        session.close()

    assert not (env.incoming / "v.bin").exists()
    assert not (env.incoming / "v.bin.etherpartial").exists()


# --------------------------------------------------------------------------- #
# trust store
# --------------------------------------------------------------------------- #

def test_trust_store_persists_across_restart(tmp_path):
    path = tmp_path / "trust.json"
    store = TrustStore(path)
    store.add("dev-1", "PC-ONE", "ab" * 32)
    store.add("dev-2", "PC-TWO", "cd" * 32)

    reloaded = TrustStore(path)
    assert reloaded.is_trusted("dev-1")
    assert reloaded.is_trusted("dev-1", "AB" * 32)  # case-insensitive
    assert reloaded.is_trusted("dev-2", "cd" * 32)
    assert not reloaded.is_trusted("dev-2", "ab" * 32)  # fingerprint mismatch
    assert not reloaded.is_trusted("dev-3")
    names = {d["device_id"]: d["name"] for d in reloaded.list()}
    assert names == {"dev-1": "PC-ONE", "dev-2": "PC-TWO"}


def test_trust_store_remove(tmp_path):
    store = TrustStore(tmp_path / "t.json")
    store.add("dev", "PC", "aa" * 32)
    assert store.remove("dev") is True
    assert store.remove("dev") is False
    assert not store.is_trusted("dev")
    assert TrustStore(tmp_path / "t.json").is_trusted("dev") is False


def test_trust_store_survives_corrupt_file(tmp_path):
    path = tmp_path / "t.json"
    path.write_text("{not json", encoding="utf-8")
    store = TrustStore(path)
    assert store.list() == []


def test_malformed_trust_records_are_not_trusted(tmp_path):
    """M34: trust records must be schema-validated on load - a string or
    list where a record belongs must never be treated as a trusted device."""
    import json as json_mod

    path = tmp_path / "t.json"
    path.write_text(
        json_mod.dumps(
            {
                "devices": {
                    "good": {
                        "name": "PC-GOOD",
                        "fingerprint": "ab" * 32,
                        "added_at": "2026-01-01",
                    },
                    "str-value": "not-a-record",
                    "list-value": ["x"],
                    "int-name": {"name": 7, "fingerprint": "cd" * 32},
                }
            }
        ),
        encoding="utf-8",
    )

    store = TrustStore(path)
    assert store.is_trusted("good", "AB" * 32) is True
    assert store.is_trusted("str-value") is False, (
        "malformed record treated as trusted (M34)"
    )
    assert store.is_trusted("list-value") is False, (
        "list record treated as trusted (M34)"
    )
    assert store.get("str-value") is None, "malformed record returned (M34)"
    assert [d["device_id"] for d in store.list()] == ["good"], (
        "malformed records kept in the trust list (M34)"
    )


def test_non_string_fingerprint_does_not_crash_is_trusted(tmp_path):
    """M34: record.get('fingerprint').lower() inside the handshake must not
    raise AttributeError when the JSON value has the wrong type."""
    import json as json_mod

    path = tmp_path / "t.json"
    path.write_text(
        json_mod.dumps(
            {"devices": {"bad-fp": {"name": "PC", "fingerprint": 12345}}}
        ),
        encoding="utf-8",
    )

    store = TrustStore(path)
    assert store.is_trusted("bad-fp", "12345") is False, (
        "non-string fingerprint was not rejected (M34)"
    )


def test_identity_change_for_trusted_peer_prompts_reapproval(env, tmp_path):
    """A stored fingerprint that no longer matches is treated as untrusted."""
    store = env.server.trust_store
    store.add("cli", "CLIENT-PC", "00" * 32)  # stale fingerprint

    prompted = []

    def approve(peer, peer_fp, our_fp, code):
        prompted.append(peer_fp)
        return True

    env.server.approve_callback = approve

    session = connect(env)
    try:
        assert session.peer_device.name == "S"
        session.send(Message.create_disconnect())
    finally:
        session.close()

    # the approval dialog fired because the fingerprint did not match,
    # and pairing replaced the stale fingerprint with the new one
    assert prompted
    assert env.server.trust_store.is_trusted("cli")
    assert not env.server.trust_store.is_trusted("cli", "00" * 32)


def test_pairing_short_code_uses_full_entropy():
    """C3: the displayed 6-digit code must not be a 16-bit value.

    ``int(digest[:4], 16) % 1_000_000`` caps every code at 065535 (leading
    zero always), giving an attacker only 2**16 certificate grinds to make
    both screens agree.  The short code must draw from >= 20 bits.
    """
    from core.security import compute_pairing_code

    import hashlib

    values = []
    for i in range(64):
        a = hashlib.sha256(f"peer-a-{i}".encode()).hexdigest()
        b = hashlib.sha256(f"peer-b-{i}".encode()).hexdigest()
        code = compute_pairing_code(a, b)
        assert len(code.short) == 6
        values.append(int(code.short))

    assert max(values) > 65535, "short code stuck in the 16-bit range"
    assert any(not str(v).zfill(6).startswith("0") for v in values)


def test_corrupt_trust_store_is_backed_up_not_wiped(tmp_path, caplog):
    """H5: a damaged trusted_devices.json must not be silently replaced by an
    empty store on the next save - log it, keep the bytes, start empty."""
    import logging

    path = tmp_path / "trusted_devices.json"
    path.write_text("{ this is not json", encoding="utf-8")

    with caplog.at_level(logging.ERROR):
        store = TrustStore(path)

    assert store.list() == []
    assert any("trust" in r.message.lower() for r in caplog.records), (
        "corruption was not logged"
    )
    backups = list(tmp_path.glob("trusted_devices.json.corrupt-*"))
    assert backups, "damaged file was not preserved as a backup"
    assert backups[0].read_text(encoding="utf-8") == "{ this is not json"

    store.add("dev", "DEV", "ab" * 32)
    assert store.is_trusted("dev")
    assert backups[0].exists(), "backup must survive later saves"


def test_trust_store_save_fsyncs_before_replace(tmp_path, monkeypatch):
    """H5: a crash between write_text and os.replace can tear the store."""
    import os as os_mod

    synced = []
    real_fsync = os_mod.fsync

    def spy(fd):
        synced.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(os_mod, "fsync", spy)
    store = TrustStore(tmp_path / "t.json")
    store.add("dev", "DEV", "ab" * 32)
    assert synced, "save() did not fsync before os.replace"
