"""virusShare - file conflict resolution dialog."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGridLayout,
    QLabel,
    QVBoxLayout,
)

from utils.formatting import human_size


class ConflictDialog(QDialog):
    """Replace / keep both / skip / cancel when a destination already exists."""

    def __init__(self, payload: Dict[str, Any], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("File already exists")
        self.setModal(True)
        # one dialog per conflict; never accumulate as a child (M8)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setMinimumWidth(430)
        self.apply_all = False
        self.action = "skip"

        root = QVBoxLayout(self)
        root.setSpacing(12)

        heading = QLabel("A file with the same name already exists")
        heading.setObjectName("heading")
        root.addWidget(heading)

        frame = QFrame()
        frame.setObjectName("panel")
        grid = QGridLayout(frame)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)

        rows = [
            ("File", str(payload.get("relpath") or "—")),
            ("Incoming", human_size(payload.get("incoming_size", 0))),
            ("Existing", human_size(payload.get("existing_size", 0))),
            ("Location", str(payload.get("dest_path") or "—")),
        ]
        for i, (label, value) in enumerate(rows):
            key = QLabel(label)
            key.setObjectName("muted")
            val = QLabel(value)
            val.setWordWrap(True)
            grid.addWidget(key, i, 0)
            grid.addWidget(val, i, 1)
        root.addWidget(frame)

        self._apply_all = QCheckBox("Apply this choice to all remaining conflicts")
        root.addWidget(self._apply_all)

        buttons = QDialogButtonBox()
        replace = buttons.addButton(
            "Replace", QDialogButtonBox.ButtonRole.AcceptRole
        )
        keep = buttons.addButton(
            "Keep both", QDialogButtonBox.ButtonRole.AcceptRole
        )
        skip = buttons.addButton("Skip", QDialogButtonBox.ButtonRole.AcceptRole)
        cancel = buttons.addButton(
            "Cancel transfer", QDialogButtonBox.ButtonRole.DestructiveRole
        )
        replace.setProperty("class", "primary")
        skip.setDefault(True)

        replace.clicked.connect(lambda: self._choose("replace"))
        keep.clicked.connect(lambda: self._choose("keep_both"))
        skip.clicked.connect(lambda: self._choose("skip"))
        cancel.clicked.connect(lambda: self._choose("cancel"))
        root.addWidget(buttons)

    def _choose(self, action: str) -> None:
        self.action = action
        self.apply_all = self._apply_all.isChecked()
        self.accept()

    @staticmethod
    def ask(
        payload: Dict[str, Any], parent=None
    ) -> Tuple[str, bool]:
        """Returns ``(action, apply_to_all)``.

        Rejecting the dialog (Esc/X) maps to ``"skip"`` - the default
        button - rather than "cancel", so dismissing never aborts the
        whole transfer (M1).
        """
        dialog = ConflictDialog(payload, parent)
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        if not accepted:
            return "skip", False
        return dialog.action, dialog.apply_all
