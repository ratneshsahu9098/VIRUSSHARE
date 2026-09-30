"""virusShare - file logging setup.

Log file: %APPDATA%\\virusShare\\logs\\virusShare.log

Never logs passwords, private keys, file contents or pairing codes; callers
are responsible for not passing secrets into log records (see README).
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path
from typing import Optional

from core.constants import APP_NAME, APP_VERSION, get_logs_dir

LOG_FILENAME = "virusShare.log"
MAX_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 5

_configured = False


class SingleLineFormatter(logging.Formatter):
    """Keep every formatted message on a single line (M32).

    Peer-supplied strings (device names, file names) flow into log calls;
    a ``\\n`` inside them would forge an extra, perfectly-formatted log
    record.  CR/LF are escaped visibly in the interpolated message, while
    tracebacks from ``exc_info`` keep their natural multi-line shape.
    """

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        message = message.replace("\r", "\\r").replace("\n", "\\n")
        record.msg = message
        record.args = None
        return super().format(record)


def setup_logging(
    level: int = logging.INFO,
    log_dir: Optional[Path] = None,
    console: bool = False,
    force: bool = False,
) -> Path:
    """Configure rotating file logging; returns the log file path."""
    global _configured
    directory = Path(log_dir) if log_dir else get_logs_dir()
    directory.mkdir(parents=True, exist_ok=True)
    log_path = directory / LOG_FILENAME

    if _configured and not force:
        return log_path

    root = logging.getLogger()
    if force:
        for handler in list(root.handlers):
            root.removeHandler(handler)
            try:
                handler.close()
            except Exception:  # pragma: no cover
                pass

    root.setLevel(level)
    formatter = SingleLineFormatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        root.addHandler(stream)

    _configured = True
    logging.getLogger(__name__).info(
        "%s %s starting (log file: %s)", APP_NAME, APP_VERSION, log_path
    )
    return log_path
