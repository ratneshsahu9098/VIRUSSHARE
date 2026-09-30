"""virusShare - transfer history browser."""

from __future__ import annotations

from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from database.history import HistoryDB, HistoryEntry
from utils.formatting import (
    format_timestamp,
    human_size,
    short_hash,
)

_COLUMNS = ("When", "Direction", "Peer", "Files", "Size", "Result", "Detail")


class HistoryDialog(QDialog):
    def __init__(
        self,
        db: HistoryDB,
        parent=None,
        *,
        limit: int = 500,
    ) -> None:
        super().__init__(parent)
        self.db = db
        self.limit = limit
        self.setWindowTitle("Transfer history")
        self.setModal(True)
        # one dialog per open; never accumulate as a child (M8)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.resize(860, 480)

        root = QVBoxLayout(self)

        tools = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search peer or file name…")
        self.search.textChanged.connect(lambda *_: self.reload())
        tools.addWidget(self.search, 1)
        clear = QPushButton("Clear all")
        clear.setObjectName("danger")
        clear.clicked.connect(self._clear)
        tools.addWidget(clear)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        tools.addWidget(close)
        root.addLayout(tools)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(list(_COLUMNS))
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu
        )
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.table, 1)

        self.detail = QLabel("Select a transfer to see details")
        self.detail.setObjectName("muted")
        self.detail.setWordWrap(True)
        root.addWidget(self.detail)

        self.table.itemSelectionChanged.connect(self._refresh_detail)
        self.reload()

    # ------------------------------------------------------------------ #

    def reload(self) -> None:
        query = self.search.text().strip()
        try:
            if query:
                entries = self.db.search(query, limit=self.limit)
            else:
                entries = self.db.recent(limit=self.limit)
        except Exception as exc:  # noqa: BLE001 - history must not crash UI
            QMessageBox.warning(self, "History", f"Could not read history:\n{exc}")
            entries = []
        self._fill(entries)

    def _fill(self, entries: List[HistoryEntry]) -> None:
        self.table.setRowCount(0)
        self._entries = entries
        for entry in entries:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = (
                format_timestamp(entry.finished_at or entry.started_at),
                "Sent" if entry.direction == "send" else "Received",
                entry.peer_name or entry.peer_id or "—",
                str(entry.file_count),
                human_size(entry.transferred_size or entry.total_size),
                entry.status.title(),
                entry.error or _files_brief(entry),
            )
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, entry.id)
                self.table.setItem(row, col, item)

    def _selected(self) -> Optional[HistoryEntry]:
        row = self.table.currentRow()
        if 0 <= row < len(getattr(self, "_entries", [])):
            return self._entries[row]
        return None

    def _refresh_detail(self) -> None:
        entry = self._selected()
        if entry is None:
            self.detail.setText("Select a transfer to see details")
            return
        lines = [
            f"{entry.direction.title()} · {entry.peer_name} · {entry.status}",
            f"Started {format_timestamp(entry.started_at)} · "
            f"Finished {format_timestamp(entry.finished_at)}",
        ]
        for f in entry.files[:8]:
            digest = short_hash(f.get("checksum", ""))
            lines.append(
                f"  {f.get('name', '?')} — {human_size(f.get('size', 0))}"
                + (f" — {digest}" if digest != "—" else "")
            )
        if len(entry.files) > 8:
            lines.append(f"  … and {len(entry.files) - 8} more")
        if entry.error:
            lines.append(f"  Error: {entry.error}")
        self.detail.setText("\n".join(lines))

    def _clear(self) -> None:
        answer = QMessageBox.question(
            self,
            "Clear history",
            "Delete the entire transfer history?",
        )
        if answer == QMessageBox.StandardButton.Yes:
            try:
                self.db.clear()
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, "History", str(exc))
            self.reload()


def _files_brief(entry: HistoryEntry) -> str:
    if not entry.files:
        return "—"
    if len(entry.files) == 1:
        return str(entry.files[0].get("name", "—"))
    return f"{len(entry.files)} files"
