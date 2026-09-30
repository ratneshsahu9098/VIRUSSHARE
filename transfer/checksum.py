"""virusShare - streaming SHA-256 helpers.

Wraps the existing ``network.protocol.calculate_checksum`` so the transfer
layer has one obvious entry point; hashing is always streaming and the
memory footprint does not depend on file size.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional

from core.constants import CHECKSUM_CHUNK_SIZE
from network.protocol import calculate_checksum, verify_checksum

ALGORITHM = "sha256"


class StreamingHasher:
    """Incremental SHA-256 used while sending or receiving a file."""

    __slots__ = ("_hasher", "_bytes_seen")

    def __init__(self, algorithm: str = ALGORITHM):
        self._hasher = hashlib.new(algorithm)
        self._bytes_seen = 0

    def update(self, data: bytes) -> None:
        self._hasher.update(data)
        self._bytes_seen += len(data)

    @property
    def bytes_seen(self) -> int:
        return self._bytes_seen

    def hexdigest(self) -> str:
        return self._hasher.hexdigest()


def hash_file(path: Path, chunk_size: int = CHECKSUM_CHUNK_SIZE) -> str:
    """Streaming file digest (constant memory)."""
    return calculate_checksum(Path(path), ALGORITHM, chunk_size)


def verify_file(path: Path, expected: str, chunk_size: int = CHECKSUM_CHUNK_SIZE) -> bool:
    """True when the file digest matches ``expected`` (case-insensitive)."""
    if not expected:
        return False
    return hash_file(path, chunk_size).lower() == expected.lower()


def hash_prefix(path: Path, length: int, chunk_size: int = CHECKSUM_CHUNK_SIZE) -> str:
    """Digest of the first ``length`` bytes of a file (resume support)."""
    hasher = StreamingHasher()
    remaining = length
    with open(path, "rb") as fh:
        while remaining > 0:
            data = fh.read(min(chunk_size, remaining))
            if not data:
                break
            hasher.update(data)
            remaining -= len(data)
    return hasher.hexdigest()


def hash_prefix_stream(path: Path, length: int, stream: StreamingHasher,
                       chunk_size: int = CHECKSUM_CHUNK_SIZE) -> StreamingHasher:
    """Feed the first ``length`` bytes of ``path`` into an existing hasher."""
    remaining = length
    with open(path, "rb") as fh:
        while remaining > 0:
            data = fh.read(min(chunk_size, remaining))
            if not data:
                break
            stream.update(data)
            remaining -= len(data)
    return stream
