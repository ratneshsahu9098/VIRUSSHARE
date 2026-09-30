"""virusShare - Core Constants and Configuration"""

import logging
import os
import shutil
import time
from pathlib import Path

log = logging.getLogger(__name__)

APP_NAME = "virusShare"
APP_VERSION = "1.0.0"
APP_AUTHOR = "virusShare"

# Data directory used before the rename; migrated once by
# ``migrate_legacy_data_dir`` so existing identities/trust/history survive.
LEGACY_APP_NAME = "EtherTransfer"

DISCOVERY_PORT = 54321
TRANSFER_PORT = 54322
CONTROL_PORT = 54323

BROADCAST_INTERVAL = 2.0
DISCOVERY_TIMEOUT = 10.0
CONNECTION_TIMEOUT = 15.0
TRANSFER_CHUNK_SIZE = 64 * 1024
CHECKSUM_CHUNK_SIZE = 1024 * 1024

MAGIC_BYTES = b"ETHR"
PROTOCOL_VERSION = 1

# --------------------------------------------------------------------------- #
# Transfer tuning
# --------------------------------------------------------------------------- #

# Chunk size used by the sender for FILE_CHUNK messages.  1 MiB balances
# syscall overhead against memory use on 1..10 Gbps links and stays far
# below the 32 MiB protocol payload cap.  Configurable via settings.
SEND_CHUNK_SIZE = 1024 * 1024
MIN_SEND_CHUNK_SIZE = 64 * 1024
MAX_SEND_CHUNK_SIZE = 8 * 1024 * 1024

# Sockets block on control messages (manifest approval, pairing dialogs) for
# at most this long before the peer is considered dead.
CONTROL_MESSAGE_TIMEOUT = 180.0
HANDSHAKE_TIMEOUT = 30.0
PAIRING_TIMEOUT = 60.0

# Partial (incomplete) files are never written under their final name.
PARTIAL_SUFFIX = ".etherpartial"
PARTIAL_META_SUFFIX = ".etherpartial.json"

MAX_FILENAME_LENGTH = 200
MAX_RELATIVE_PATH_LENGTH = 400

MESSAGE_TYPES = {
    "DISCOVERY": 0x01,
    "DISCOVERY_RESPONSE": 0x02,
    "CONNECT_REQUEST": 0x10,
    "CONNECT_RESPONSE": 0x11,
    "DISCONNECT": 0x12,
    "SESSION_CHALLENGE": 0x13,
    "PAIR_CONFIRM": 0x14,
    "FILE_LIST": 0x20,
    "FILE_REQUEST": 0x21,
    "FILE_DATA": 0x22,
    "FILE_CHUNK": 0x23,
    "FILE_COMPLETE": 0x24,
    "FILE_CANCEL": 0x25,
    "FILE_RESUME": 0x26,
    "CHECKSUM_REQUEST": 0x30,
    "CHECKSUM_RESPONSE": 0x31,
    "ERROR": 0xFF,
}

ERROR_CODES = {
    0x01: "Connection refused",
    0x02: "File not found",
    0x03: "Permission denied",
    0x04: "Disk full",
    0x05: "Checksum mismatch",
    0x06: "Protocol error",
    0x07: "Timeout",
    0x08: "Cancelled by user",
    0x09: "Encryption error",
}

DEFAULT_SETTINGS = {
    "auto_accept_trusted": False,
    "enable_encryption": True,
    "transfer_port": TRANSFER_PORT,
    "discovery_port": DISCOVERY_PORT,
    "max_concurrent_transfers": 3,
    "reconnect_attempts": 3,
    "buffer_size": TRANSFER_CHUNK_SIZE,
    "verify_checksums": True,
    "save_received_files_to": str(Path.home() / "Downloads" / APP_NAME),
    "trusted_devices": [],
    "theme": "system",
    "language": "en",
    "minimize_to_tray": True,
    "show_notifications": True,
    "start_with_windows": False,
    "preferred_network_adapter": "auto",
    "require_connection_approval": True,
    "chunk_size": SEND_CHUNK_SIZE,
}

def get_app_data_dir() -> Path:
    """Get the application data directory."""
    app_data = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    return app_data / APP_NAME

def get_settings_path() -> Path:
    """Get the settings file path."""
    return get_app_data_dir() / "settings.json"

def get_logs_dir() -> Path:
    """Get the logs directory."""
    return get_app_data_dir() / "logs"

def get_trust_store_path() -> Path:
    """Get the trusted-device store path."""
    return get_app_data_dir() / "trusted_devices.json"

def get_history_db_path() -> Path:
    """Get the SQLite transfer-history database path."""
    return get_app_data_dir() / "history.db"

def get_identity_path() -> Path:
    """Get the long-term identity (certificate + private key) path."""
    return get_app_data_dir() / "identity.pem"

def migrate_legacy_data_dir() -> None:
    """One-time rename of the pre-rebrand data directory (best effort).

    A rename that fails (antivirus lock, transient permissions) must not be
    swallowed: ``ensure_dirs`` would create the new directory right after and
    the condition ``not new.exists()`` would then skip migration forever,
    orphaning the legacy identity/trust/history (M29).  Retries cover
    transient locks; a persistent failure falls back to copying the content.
    """
    try:
        app_data = Path(
            os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")
        )
        old = app_data / LEGACY_APP_NAME
        new = get_app_data_dir()
        if not old.is_dir() or new.exists():
            return
        for attempt in range(4):
            try:
                old.rename(new)
                return
            except OSError:
                if attempt == 3:
                    break
                time.sleep(0.05)
        shutil.copytree(old, new)
        log.error(
            "legacy data dir rename failed; copied %s -> %s instead",
            old,
            new,
        )
    except OSError:
        log.exception("legacy data dir migration failed")

def ensure_dirs():
    """Ensure all required directories exist."""
    migrate_legacy_data_dir()
    get_app_data_dir().mkdir(parents=True, exist_ok=True)
    get_logs_dir().mkdir(parents=True, exist_ok=True)
    Path(DEFAULT_SETTINGS["save_received_files_to"]).mkdir(parents=True, exist_ok=True)