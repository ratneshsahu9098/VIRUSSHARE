"""virusShare - incoming/outgoing connection approval dialog."""

from __future__ import annotations

from typing import Any, Dict, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGridLayout,
    QLabel,
    QVBoxLayout,
)


class ApprovalDialog(QDialog):
    """Ask the user whether to accept a connection / start pairing."""

    def __init__(self, payload: Dict[str, Any], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Connection request")
        self.setModal(True)
        # one dialog per connection request; never accumulate (M8)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setMinimumWidth(400)

        root = QVBoxLayout(self)
        root.setSpacing(12)

        header = QLabel("Accept connection from this device?")
        header.setObjectName("heading")
        root.addWidget(header)

        frame = QFrame()
        frame.setObjectName("panel")
        grid = QGridLayout(frame)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)

        fp = str(payload.get("fingerprint") or "")
        rows = [
            ("Device", str(payload.get("name") or "Unknown")),
            ("Address", str(payload.get("ip") or "—")),
            ("Pairing code", str(payload.get("code") or "—")),
            ("Fingerprint", f"{fp[:16]}…" if len(fp) > 16 else (fp or "—")),
        ]
        for i, (label, value) in enumerate(rows):
            key = QLabel(label)
            key.setObjectName("muted")
            val = QLabel(value)
            val.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            grid.addWidget(key, i, 0)
            grid.addWidget(val, i, 1)
        root.addWidget(frame)

        note = QLabel(
            "Only accept devices you trust. The pairing code must match on "
            "both screens."
        )
        note.setObjectName("muted")
        note.setWordWrap(True)
        root.addWidget(note)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Yes
            | QDialogButtonBox.StandardButton.No
        )
        buttons.button(QDialogButtonBox.StandardButton.Yes).setText("Accept")
        buttons.button(QDialogButtonBox.StandardButton.No).setText("Reject")
        buttons.button(QDialogButtonBox.StandardButton.Yes).setProperty(
            "class", "primary"
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

        header.setText(f"Accept connection from {rows[0][1]}?")

    @staticmethod
    def ask(payload: Dict[str, Any], parent=None) -> bool:
        dialog = ApprovalDialog(payload, parent)
        return dialog.exec() == QDialog.DialogCode.Accepted
