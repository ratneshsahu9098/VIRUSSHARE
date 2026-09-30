"""virusShare - active transfer queue (center of the main window)."""

from __future__ import annotations

from typing import Dict, Optional

from PySide6.QtCore import QRectF, Qt, QVariantAnimation, Signal
from PySide6.QtGui import QColor, QPainter, QPainterPath
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QPushButton,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui import animations, icons
from gui.styles import current_palette
from gui.widgets import EmptyState
from models import TransferSession, TransferStatus
from utils.formatting import (
    format_timestamp,
    human_eta,
    human_size,
    human_speed,
)

_STATUS_STATE = {
    TransferStatus.PENDING: "idle",
    TransferStatus.ACTIVE: "active",
    TransferStatus.PAUSED: "warn",
    TransferStatus.COMPLETED: "ok",
    TransferStatus.FAILED: "error",
    TransferStatus.CANCELLED: "idle",
}

_COLUMNS = ("", "Peer", "File / progress", "Size", "Speed", "ETA", "Status")

_BAR_HEIGHT = 5.0
_MIN_ROW_HEIGHT = 32

# statuses a finished row can hold (clear_finished + M11 guard + M14 open)
_TERMINAL_STATUSES = (
    TransferStatus.COMPLETED,
    TransferStatus.FAILED,
    TransferStatus.CANCELLED,
)


class ProgressDelegate(QStyledItemDelegate):
    """Paints a smooth, theme-aware progress bar under the file text.

    Displayed values interpolate toward their targets on a shared ~30 FPS
    tick, so percentage jumps glide instead of snapping; active transfers
    get a moving shimmer.
    """

    DRIVER_KEY = "queue-progress"

    def __init__(self, table: QTableWidget, parent=None) -> None:
        super().__init__(parent)
        self.table = table
        self.driver = animations.TickDriver(table)
        self._targets: Dict[str, float] = {}
        self._display: Dict[str, float] = {}
        self._states: Dict[str, str] = {}
        self._phase = 0.0

    # ------------------------------------------------------------------ #
    # state
    # ------------------------------------------------------------------ #

    def set_progress(
        self,
        session_id: str,
        pct: float,
        state: str,
        *,
        fresh: bool = False,
    ) -> None:
        self._targets[session_id] = max(0.0, min(100.0, float(pct)))
        self._states[session_id] = state
        if fresh or session_id not in self._display:
            self._display[session_id] = 0.0 if fresh else self._targets[session_id]
        self.driver.add(self.DRIVER_KEY, self._tick)
        self.table.viewport().update()

    def drop(self, session_id: str) -> None:
        self._targets.pop(session_id, None)
        self._display.pop(session_id, None)
        self._states.pop(session_id, None)
        if not self._targets:
            self.driver.remove(self.DRIVER_KEY)
        self.table.viewport().update()

    def value_for(self, session_id: str) -> float:
        return self._display.get(
            session_id, self._targets.get(session_id, 0.0)
        )

    def _tick(self) -> None:
        moving = False
        for sid, target in self._targets.items():
            current = self._display.get(sid, target)
            if abs(current - target) > 0.3:
                stepped = current + (target - current) * 0.3
                if abs(stepped - target) <= 0.3:
                    stepped = target
                self._display[sid] = stepped
                moving = True
            elif current != target:
                self._display[sid] = target
                moving = True

        shimmering = "active" in self._states.values()
        if moving or shimmering:
            self._phase = (self._phase + 0.07) % 1.0
            self.table.viewport().update()
        else:
            # everything settled: stop burning frames until something moves
            self.driver.remove(self.DRIVER_KEY)

    # ------------------------------------------------------------------ #
    # painting
    # ------------------------------------------------------------------ #

    def paint(
        self,
        painter: QPainter,
        option: QStyleOptionViewItem,
        index,
    ) -> None:
        super().paint(painter, option, index)

        session_id = index.sibling(index.row(), 0).data(
            Qt.ItemDataRole.UserRole
        )
        if not session_id or session_id not in self._targets:
            return

        rect = QRectF(option.rect).adjusted(8, 0, -8, -5)
        if rect.width() < 40:
            return

        palette = current_palette()
        state = self._states.get(session_id, "idle")
        colors = {
            "active": palette["accent"],
            "ok": palette["ok"],
            "error": palette["danger"],
            "warn": palette["warn"],
            "idle": palette["muted"],
        }
        fill_color = QColor(colors.get(state, palette["muted"]))

        track = QRectF(rect.left(), rect.bottom() - _BAR_HEIGHT,
                       rect.width(), _BAR_HEIGHT)
        pct = self._display.get(session_id, self._targets[session_id])
        fill_width = track.width() * (pct / 100.0)

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)

        painter.setBrush(QColor(128, 128, 128, 55))
        painter.drawRoundedRect(track, 2.5, 2.5)

        if fill_width >= 2.0:
            fill = QRectF(track.left(), track.top(), fill_width,
                          track.height())
            painter.setBrush(fill_color)
            painter.drawRoundedRect(fill, 2.5, 2.5)

            if state == "active":
                # moving highlight band (clipped to the rounded fill)
                path = QPainterPath()
                path.addRoundedRect(fill, 2.5, 2.5)
                painter.setClipPath(path)
                span = fill.width() + 48.0
                head = (self._phase * span) - 48.0
                band = QRectF(fill.left() + head, fill.top(), 24.0,
                              fill.height())
                painter.setBrush(QColor(255, 255, 255, 80))
                painter.drawRect(band)
        painter.restore()


class TransferQueue(QWidget):
    """Table of TransferSession models with per-row controls."""

    pauseRequested = Signal(str)
    resumeRequested = Signal(str)
    cancelRequested = Signal(str)
    openFolderRequested = Signal(object)   # TransferSession
    showHistoryRequested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: Dict[str, int] = {}
        self._ids: Dict[int, str] = {}
        self._row_anims: Dict[str, QVariantAnimation] = {}
        self._empty_shown: Optional[bool] = None
        # session ids the user explicitly cleared - late queued updates for
        # them must not resurrect the row (M11)
        self._cleared_ids: set = set()

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)

        header = QHBoxLayout()
        title = QLabel("Transfers")
        title.setObjectName("heading")
        header.addWidget(title)
        header.addStretch(1)
        history_btn = QPushButton("History")
        history_btn.clicked.connect(self.showHistoryRequested.emit)
        header.addWidget(history_btn)
        root.addLayout(header)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(list(_COLUMNS))
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu
        )
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.itemSelectionChanged.connect(self._refresh_buttons)
        self.delegate = ProgressDelegate(self.table, self.table)
        self.table.setItemDelegateForColumn(2, self.delegate)
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for col in (3, 4, 5, 6):
            header_view.setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
        self.table.setMinimumHeight(180)
        root.addWidget(self.table, 1)

        self.empty = EmptyState(
            title="No transfers yet",
            hint="Select a device and send files -\nprogress shows up here.",
        )
        root.addWidget(self.empty, 1)

        controls = QHBoxLayout()
        self.pause_btn = QPushButton("Pause")
        self.resume_btn = QPushButton("Resume")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("danger")
        self.open_btn = QPushButton("Open folder")
        self.pause_btn.setEnabled(False)
        self.resume_btn.setEnabled(False)
        self.cancel_btn.setEnabled(False)
        self.open_btn.setEnabled(False)

        self.pause_btn.clicked.connect(lambda: self._emit_control(self.pauseRequested))
        self.resume_btn.clicked.connect(lambda: self._emit_control(self.resumeRequested))
        self.cancel_btn.clicked.connect(lambda: self._emit_control(self.cancelRequested))
        self.open_btn.clicked.connect(lambda: self._emit_control(self.openFolderRequested))

        for button in (
            self.pause_btn,
            self.resume_btn,
            self.cancel_btn,
            self.open_btn,
        ):
            controls.addWidget(button)
        controls.addStretch(1)
        root.addLayout(controls)

        self._refresh_empty_state()
        self._refresh_buttons()

    # ------------------------------------------------------------------ #
    # model updates
    # ------------------------------------------------------------------ #

    def upsert_session(self, session: TransferSession) -> None:
        if session.id in self._cleared_ids:
            if session.status in _TERMINAL_STATUSES:
                return  # user cleared this row; keep it cleared (M11)
            self._cleared_ids.discard(session.id)
        row = self._rows.get(session.id)
        is_new = row is None
        if is_new:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self._rows[session.id] = row
            self._ids[row] = session.id
            for col in range(len(_COLUMNS)):
                self.table.setItem(row, col, QTableWidgetItem(""))
            self.table.item(row, 0).setData(
                Qt.ItemDataRole.UserRole, session.id
            )
        direction_up = session.direction == "send"
        self.table.item(row, 0).setIcon(
            icons.direction_icon(direction_up, 15)
        )
        self.table.item(row, 0).setToolTip(
            "Outgoing transfer" if direction_up else "Incoming transfer"
        )
        self.table.item(row, 1).setText(session.computer_name or "—")
        self.table.item(row, 1).setToolTip(
            f"{session.computer_name}\nstarted {format_timestamp(session.start_time)}"
        )

        self.table.item(row, 2).setText(
            session.current_file or _file_summary(session)
        )
        self.table.item(row, 2).setToolTip(_file_summary(session))

        self.table.item(row, 3).setText(
            f"{human_size(session.transferred_size)} / {human_size(session.total_size)}"
        )
        speed = session.get_speed() if session.status is TransferStatus.ACTIVE else 0
        self.table.item(row, 4).setText(
            human_speed(speed) if session.status is TransferStatus.ACTIVE else "—"
        )
        self.table.item(row, 5).setText(
            human_eta(session)
            if session.status in (TransferStatus.ACTIVE, TransferStatus.PAUSED)
            else "—"
        )

        status_item = self.table.item(row, 6)
        status_item.setText(_status_text(session))
        status_item.setData(Qt.ItemDataRole.UserRole, session.status)
        status_item.setIcon(
            icons.status_dot(9, _STATUS_STATE.get(session.status, "idle"))
        )
        status_item.setToolTip(session.error_message or "")

        self.delegate.set_progress(
            session.id,
            _session_percent(session),
            _STATUS_STATE.get(session.status, "idle"),
            fresh=is_new,
        )

        if is_new:
            self._animate_row_insert(session.id, row)
        elif session.id not in self._row_anims:
            self.table.resizeRowToContents(row)
            if self.table.rowHeight(row) < _MIN_ROW_HEIGHT:
                self.table.setRowHeight(row, _MIN_ROW_HEIGHT)
        self._refresh_empty_state()
        self._refresh_buttons()

    def remove_session(self, session_id: str) -> None:
        row = self._rows.pop(session_id, None)
        if row is not None:
            self._ids.pop(row, None)
        self._row_anims.pop(session_id, None)
        self.delegate.drop(session_id)
        if row is None:
            return
        self.table.removeRow(row)
        self._reindex()
        self._refresh_empty_state()
        self._refresh_buttons()

    def clear_finished(self) -> None:
        stale = [
            sid
            for sid, row in list(self._rows.items())
            if _session_status_from_row(self.table, row) in _TERMINAL_STATUSES
        ]
        self._cleared_ids.update(stale)
        while len(self._cleared_ids) > 256:
            self._cleared_ids.pop()
        for session_id in stale:
            self.remove_session(session_id)

    def _reindex(self) -> None:
        self._rows.clear()
        self._ids.clear()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            sid = item.data(Qt.ItemDataRole.UserRole) if item else None
            if sid:
                self._rows[sid] = row
                self._ids[row] = sid

    def selected_session_id(self) -> Optional[str]:
        row = self.table.currentRow()
        return self._ids.get(row)

    def session_count(self) -> int:
        return self.table.rowCount()

    # ------------------------------------------------------------------ #
    # internals
    # ------------------------------------------------------------------ #

    def _animate_row_insert(self, session_id: str, row: int) -> None:
        anim = animations.animate_row_insert(self.table, row)

        def _done(sid=session_id) -> None:
            self._row_anims.pop(sid, None)
            current = self._rows.get(sid)
            if current is not None and current < self.table.rowCount():
                self.table.resizeRowToContents(current)
                if self.table.rowHeight(current) < _MIN_ROW_HEIGHT:
                    self.table.setRowHeight(current, _MIN_ROW_HEIGHT)

        anim.finished.connect(_done)
        self._row_anims[session_id] = anim

    def _emit_control(self, signal: Signal) -> None:
        session_id = self.selected_session_id()
        if session_id:
            signal.emit(session_id)

    def _refresh_buttons(self) -> None:
        session_id = self.selected_session_id()
        status = self._status_of_selected()
        active = status in (TransferStatus.ACTIVE, TransferStatus.PENDING)
        paused = status is TransferStatus.PAUSED
        self.pause_btn.setEnabled(active and session_id is not None)
        self.resume_btn.setEnabled(paused and session_id is not None)
        self.cancel_btn.setEnabled(
            bool(session_id)
            and status
            in (
                TransferStatus.PENDING,
                TransferStatus.ACTIVE,
                TransferStatus.PAUSED,
            )
        )
        self.open_btn.setEnabled(
            bool(session_id) and self._can_open_folder(status)
        )

    @staticmethod
    def _can_open_folder(status) -> bool:
        # CANCELLED transfers keep their partials - the folder matters there
        # too (M14); clear_finished treats the same set as terminal.
        return status in (
            TransferStatus.COMPLETED,
            TransferStatus.FAILED,
            TransferStatus.CANCELLED,
        )

    def _status_of_selected(self):
        session_id = self.selected_session_id()
        if session_id is None:
            return None
        row = self._rows.get(session_id, -1)
        item = self.table.item(row, 6) if row >= 0 else None
        if item is None:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    def _context_menu(self, pos) -> None:
        session_id = self.selected_session_id()
        if session_id is None:
            return
        status = self._status_of_selected()
        menu = QMenu(self)
        if status in (TransferStatus.ACTIVE, TransferStatus.PENDING):
            menu.addAction(
                "Pause", lambda: self.pauseRequested.emit(session_id)
            )
        if status is TransferStatus.PAUSED:
            menu.addAction(
                "Resume", lambda: self.resumeRequested.emit(session_id)
            )
        if status in (
            TransferStatus.PENDING,
            TransferStatus.ACTIVE,
            TransferStatus.PAUSED,
        ):
            menu.addAction(
                "Cancel", lambda: self.cancelRequested.emit(session_id)
            )
        if self._can_open_folder(status):
            menu.addAction(
                "Open folder",
                lambda: self._emit_open_folder(session_id),
            )
        menu.addAction(
            "Clear finished", self.clear_finished
        )
        menu.exec(self.table.mapToGlobal(pos))

    def _emit_open_folder(self, session_id: str) -> None:
        self.openFolderRequested.emit(session_id)

    def _refresh_empty_state(self) -> None:
        empty = self.table.rowCount() == 0
        # plain visibility swap: opacity effects are unsafe on item views
        self.table.setVisible(not empty)
        self.empty.setVisible(empty)
        self._empty_shown = empty


def _session_status_from_row(table: QTableWidget, row: int):
    item = table.item(row, 6)
    return item.data(Qt.ItemDataRole.UserRole) if item else None


def _session_percent(session: TransferSession) -> float:
    if session.status is TransferStatus.COMPLETED:
        return 100.0
    if session.total_size:
        return min(100.0, 100.0 * session.transferred_size / session.total_size)
    if session.current_file and session.current_file_size:
        return min(
            100.0,
            100.0 * session.current_file_progress / session.current_file_size,
        )
    return 0.0


def _file_summary(session: TransferSession) -> str:
    count = len(session.files)
    if count == 0:
        return "—"
    if count == 1:
        return session.files[0].name
    return f"{count} files · {human_size(session.total_size)}"


def _status_text(session: TransferSession) -> str:
    if session.status is TransferStatus.FAILED and session.error_message:
        return f"Failed — {session.error_message[:40]}"
    if session.status is TransferStatus.PENDING:
        return "Queued"
    if session.status is TransferStatus.ACTIVE:
        return "Transferring"
    if session.status is TransferStatus.PAUSED:
        return "Paused"
    if session.status is TransferStatus.COMPLETED:
        return "Completed"
    if session.status is TransferStatus.CANCELLED:
        return "Cancelled"
    return session.status.value.title()
