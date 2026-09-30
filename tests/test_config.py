"""virusShare - settings persistence tests (core.config)."""

import json

import pytest

from core.config import Settings, SettingsError, get_settings
from core.constants import DEFAULT_SETTINGS


@pytest.fixture
def settings(tmp_path):
    return Settings(path=tmp_path / "settings.json", create_dirs=False)


def test_defaults_loaded(settings):
    for key, value in DEFAULT_SETTINGS.items():
        assert settings.get(key) == value


def test_set_and_get_roundtrip(settings):
    settings.set("theme", "dark")
    assert settings.get("theme") == "dark"
    settings.set("max_concurrent_transfers", 7)
    assert settings.max_concurrent_transfers == 7


def test_persisted_across_reload(tmp_path):
    path = tmp_path / "settings.json"
    s1 = Settings(path=path, create_dirs=False)
    s1.set("theme", "light")
    s1.set("chunk_size", 256 * 1024)

    s2 = Settings(path=path, create_dirs=False)
    assert s2.get("theme") == "light"
    assert s2.chunk_size == 256 * 1024


def test_invalid_bool_rejected(settings):
    with pytest.raises(SettingsError):
        settings.set("verify_checksums", "yes")


def test_invalid_int_range_rejected(settings):
    with pytest.raises(SettingsError):
        settings.set("max_concurrent_transfers", 0)
    with pytest.raises(SettingsError):
        settings.set("transfer_port", 70000)
    with pytest.raises(SettingsError):
        settings.set("chunk_size", 10)  # below MIN_SEND_CHUNK_SIZE


def test_invalid_theme_rejected(settings):
    with pytest.raises(SettingsError):
        settings.set("theme", "neon")


def test_relative_receive_dir_rejected(settings):
    with pytest.raises(SettingsError):
        settings.set("save_received_files_to", "relative/path")


def test_invalid_trusted_devices_rejected(settings):
    with pytest.raises(SettingsError):
        settings.set("trusted_devices", "not-a-list")
    with pytest.raises(SettingsError):
        settings.set("trusted_devices", [1, 2, 3])


def test_unknown_keys_preserved(settings):
    settings.set("future_feature", {"enabled": True})
    assert settings.get("future_feature") == {"enabled": True}


def test_corrupt_file_falls_back_to_defaults(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{ this is not json", encoding="utf-8")
    s = Settings(path=path, create_dirs=False)
    assert s.get("theme") == DEFAULT_SETTINGS["theme"]


def test_invalid_values_in_file_are_ignored(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps(
            {
                "theme": "dark",
                "max_concurrent_transfers": "lots",  # invalid
                "discovery_port": 999999,            # out of range
            }
        ),
        encoding="utf-8",
    )
    s = Settings(path=path, create_dirs=False)
    assert s.get("theme") == "dark"                      # valid value kept
    assert s.max_concurrent_transfers == DEFAULT_SETTINGS["max_concurrent_transfers"]
    assert s.discovery_port == DEFAULT_SETTINGS["discovery_port"]


def test_listeners_fire_on_change(settings):
    seen = []
    settings.add_listener(lambda key, value: seen.append((key, value)))
    settings.set("theme", "dark", save=False)
    settings.set("theme", "dark", save=False)  # unchanged -> no event
    assert seen == [("theme", "dark")]


def test_listener_exception_does_not_break_set(settings):
    def boom(key, value):
        raise RuntimeError("listener bug")

    settings.add_listener(boom)
    settings.set("theme", "dark", save=False)
    assert settings.get("theme") == "dark"


def test_reset_restores_defaults(settings):
    settings.set("theme", "dark", save=False)
    settings.set("max_concurrent_transfers", 9, save=False)
    settings.reset()
    assert settings.get("theme") == DEFAULT_SETTINGS["theme"]
    assert settings.max_concurrent_transfers == DEFAULT_SETTINGS["max_concurrent_transfers"]


def test_convenience_properties(settings):
    from pathlib import Path

    assert settings.receive_dir == Path(DEFAULT_SETTINGS["save_received_files_to"])
    assert isinstance(settings.chunk_size, int)
    assert settings.encryption_enabled is True
    assert settings.require_connection_approval is True
    assert settings.verify_checksums is True
    assert 1024 <= settings.discovery_port <= 65535
    assert 1024 <= settings.transfer_port <= 65535


def test_get_settings_singleton():
    first = get_settings()
    second = get_settings()
    assert first is second


def test_save_creates_parent_dirs(tmp_path):
    nested = tmp_path / "a" / "b" / "settings.json"
    s = Settings(path=nested, create_dirs=False)
    s.set("theme", "dark")
    assert nested.exists()
    on_disk = json.loads(nested.read_text(encoding="utf-8"))
    assert on_disk["theme"] == "dark"


def test_migrate_legacy_data_dir(tmp_path, monkeypatch):
    from core.constants import LEGACY_APP_NAME, migrate_legacy_data_dir

    old = tmp_path / LEGACY_APP_NAME
    old.mkdir(parents=True)
    (old / "settings.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("APPDATA", str(tmp_path))

    migrate_legacy_data_dir()

    assert not old.exists()
    assert (tmp_path / "virusShare" / "settings.json").exists()

    # second run is a no-op (target already exists)
    marker = tmp_path / "virusShare" / "keep.txt"
    marker.write_text("x", encoding="utf-8")
    migrate_legacy_data_dir()
    assert marker.exists()


def test_migrate_legacy_data_dir_target_exists(tmp_path, monkeypatch):
    from core.constants import LEGACY_APP_NAME, migrate_legacy_data_dir

    old = tmp_path / LEGACY_APP_NAME
    new = tmp_path / "virusShare"
    old.mkdir(parents=True)
    new.mkdir(parents=True)
    (old / "a.txt").write_text("old", encoding="utf-8")
    (new / "b.txt").write_text("new", encoding="utf-8")
    monkeypatch.setenv("APPDATA", str(tmp_path))

    migrate_legacy_data_dir()  # must not raise or clobber

    assert (old / "a.txt").exists()
    assert (new / "b.txt").exists()


# --------------------------------------------------------------------------- #
# M28 / M29 - settings durability and legacy migration
# --------------------------------------------------------------------------- #

def test_transient_settings_read_failure_recovers(tmp_path, monkeypatch):
    """M28: an AV-locked settings file must be retried, not replaced by
    defaults (the next save would then destroy the real file)."""
    from pathlib import Path

    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")

    real_read = Path.read_text
    attempts = {"n": 0}

    def flaky_read(self, *args, **kwargs):
        if self == path:
            attempts["n"] += 1
            if attempts["n"] <= 2:
                raise OSError(13, "file locked by antivirus")
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", flaky_read)
    settings = Settings(path=path, create_dirs=False)

    assert attempts["n"] >= 3, "load() did not retry the transient failure"
    assert settings.get("theme") == "dark", (
        "transient read failure reset settings to defaults (M28)"
    )


def test_unreadable_settings_file_not_clobbered_by_save(tmp_path, monkeypatch):
    """M28: while the real file is unreadable, saves must not overwrite it;
    once readable again, the user's changes and the file's values merge."""
    from pathlib import Path

    path = tmp_path / "settings.json"
    original = json.dumps(
        {"theme": "dark", "auto_accept_trusted": True}, sort_keys=True
    )
    path.write_text(original, encoding="utf-8")

    blocked = {"on": True}
    real_read = Path.read_text

    def blocked_read(self, *args, **kwargs):
        if blocked["on"] and self == path:
            raise OSError(13, "file locked by antivirus")
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", blocked_read)

    settings = Settings(path=path, create_dirs=False)
    settings.set("transfer_port", 5555, save=True)
    assert real_read(path, encoding="utf-8") == original, (
        "unreadable settings file was clobbered by a later save (M28)"
    )

    blocked["on"] = False
    settings.set("theme", "light", save=True)
    data = json.loads(real_read(path, encoding="utf-8"))
    assert data.get("auto_accept_trusted") is True, "real settings lost (M28)"
    assert data.get("theme") == "light", "user change lost on recovery (M28)"
    assert data.get("transfer_port") == 5555, "change during outage lost (M28)"


def test_migrate_legacy_data_dir_copy_fallback(tmp_path, monkeypatch, caplog):
    """M29: a rename failure must not orphan the legacy identity - the next
    mkdir would make new.exists() and migration would never run again."""
    import logging as logging_mod
    from pathlib import Path

    from core.constants import (
        LEGACY_APP_NAME,
        get_app_data_dir,
        migrate_legacy_data_dir,
    )

    old = tmp_path / LEGACY_APP_NAME
    old.mkdir(parents=True)
    (old / "identity.pem").write_text("OLD-IDENTITY", encoding="utf-8")
    monkeypatch.setenv("APPDATA", str(tmp_path))

    def failing_rename(self, target):
        raise PermissionError("locked by antivirus")

    monkeypatch.setattr(Path, "rename", failing_rename)

    with caplog.at_level(logging_mod.ERROR, logger="core.constants"):
        migrate_legacy_data_dir()

    new = get_app_data_dir()
    assert (new / "identity.pem").exists(), (
        "legacy identity orphaned after rename failure (M29)"
    )
    assert (new / "identity.pem").read_text(encoding="utf-8") == "OLD-IDENTITY"
    assert any("legacy" in r.message.lower() for r in caplog.records), (
        "rename failure was swallowed silently (M29)"
    )
