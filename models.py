from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List
import uuid


class TransferStatus(Enum):
    PENDING = "pending"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ConnectionStatus(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    TRANSFERRING = "transferring"


@dataclass
class Computer:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    ip: str = ""
    port: int = 0
    mac: str = ""
    interface: str = ""
    last_seen: datetime = field(default_factory=datetime.now)
    is_trusted: bool = False
    status: ConnectionStatus = ConnectionStatus.DISCONNECTED

    def __eq__(self, other):
        if isinstance(other, Computer):
            return self.id == other.id
        return False

    def __hash__(self):
        return hash(self.id)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "ip": self.ip,
            "port": self.port,
            "mac": self.mac,
            "interface": self.interface,
            "last_seen": self.last_seen.isoformat(),
            "is_trusted": self.is_trusted,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Computer":
        computer = cls(
            id=data.get("id", str(uuid.uuid4())),
            name=data.get("name", ""),
            ip=data.get("ip", ""),
            port=data.get("port", 0),
            mac=data.get("mac", ""),
            interface=data.get("interface", ""),
            is_trusted=data.get("is_trusted", False),
            status=ConnectionStatus(data.get("status", "disconnected")),
        )
        if "last_seen" in data:
            computer.last_seen = datetime.fromisoformat(data["last_seen"])
        return computer


@dataclass
class TransferFile:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    path: str = ""
    size: int = 0
    checksum: str = ""
    is_directory: bool = False
    parent_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "path": self.path,
            "size": self.size,
            "checksum": self.checksum,
            "is_directory": self.is_directory,
            "parent_id": self.parent_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TransferFile":
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            name=data.get("name", ""),
            path=data.get("path", ""),
            size=data.get("size", 0),
            checksum=data.get("checksum", ""),
            is_directory=data.get("is_directory", False),
            parent_id=data.get("parent_id"),
        )

    @classmethod
    def from_path(cls, path: Path, parent_id: Optional[str] = None) -> "TransferFile":
        stat = path.stat()
        return cls(
            name=path.name,
            path=str(path),
            size=stat.st_size if path.is_file() else 0,
            is_directory=path.is_dir(),
            parent_id=parent_id,
        )


@dataclass
class TransferSession:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    computer_id: str = ""
    computer_name: str = ""
    files: List[TransferFile] = field(default_factory=list)
    total_size: int = 0
    transferred_size: int = 0
    status: TransferStatus = TransferStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_message: str = ""
    current_file: str = ""
    current_file_progress: int = 0
    current_file_size: int = 0
    direction: str = "send"

    def add_file(self, file: TransferFile):
        self.files.append(file)
        if self.status not in (TransferStatus.ACTIVE, TransferStatus.PAUSED):
            self.total_size += file.size

    def get_progress(self) -> float:
        if self.total_size == 0:
            return 0.0
        percent = (self.transferred_size / self.total_size) * 100
        return max(0.0, min(100.0, percent))

    def get_speed(self) -> float:
        if self.start_time is None:
            return 0.0
        elapsed = (datetime.now() - self.start_time).total_seconds()
        if elapsed == 0:
            return 0.0
        return self.transferred_size / elapsed

    def get_eta(self) -> Optional[float]:
        speed = self.get_speed()
        if speed == 0:
            return None
        remaining = max(0, self.total_size - self.transferred_size)
        return remaining / speed

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "computer_id": self.computer_id,
            "computer_name": self.computer_name,
            "files": [f.to_dict() for f in self.files],
            "total_size": self.total_size,
            "transferred_size": self.transferred_size,
            "status": self.status.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "error_message": self.error_message,
            "current_file": self.current_file,
            "current_file_progress": self.current_file_progress,
            "current_file_size": self.current_file_size,
            "direction": self.direction,
        }

if __name__ == "__main__":
    computer = Computer(
        name="Test-PC",
        ip="192.168.10.2",
        port=50000,
        mac="00:11:22:33:44:55",
        interface="Ethernet"
    )

    print("Computer created successfully!")
    print(computer)
    print("ID:", computer.id)
    print("Name:", computer.name)
    print("IP:", computer.ip)
    print("Port:", computer.port)
    print("Status:", computer.status)