"""virusShare - light/dark stylesheets.

Kept as plain QSS strings (no external .qss files) so PyInstaller needs no
data-file collection and the theme can respond to settings at runtime.
"""

from __future__ import annotations

import sys

_BASE = """
QWidget {
    font-size: 13px;
}
QMainWindow, QDialog {
    background: %(bg)s;
}
QLabel#heading {
    font-size: 15px;
    font-weight: 600;
}
QLabel#muted {
    color: %(muted)s;
}
QLabel#emptytitle {
    font-size: 14px;
    font-weight: 600;
    color: %(text)s;
}
QLabel#emptyhint {
    color: %(muted)s;
    font-size: 12px;
}
QFrame#panel {
    background: %(panel)s;
    border: 1px solid %(border)s;
    border-radius: 8px;
}
QFrame#toast {
    background: %(panel)s;
    border: 1px solid %(border)s;
    border-radius: 10px;
}
QLabel#toasttitle {
    font-size: 13px;
    font-weight: 600;
    color: %(text)s;
}
QLabel#toastbody {
    color: %(muted)s;
    font-size: 12px;
}
QPushButton {
    background: %(button)s;
    color: %(button_text)s;
    border: 1px solid %(border)s;
    border-radius: 6px;
    padding: 5px 14px;
    min-height: 22px;
}
QPushButton:hover {
    background: %(button_hover)s;
}
QPushButton:pressed {
    background: %(button_pressed)s;
}
QPushButton:focus {
    border-color: %(accent)s;
}
QPushButton:disabled {
    color: %(muted)s;
    background: %(bg)s;
}
QPushButton#primary {
    background: %(accent)s;
    color: white;
    border: 1px solid %(accent)s;
    font-weight: 600;
}
QPushButton#primary:hover {
    background: %(accent_hover)s;
}
QPushButton#primary:pressed {
    background: %(accent_hover)s;
}
QPushButton#primary:disabled {
    background: %(button)s;
    color: %(muted)s;
    border-color: %(border)s;
}
QPushButton#danger {
    color: %(danger)s;
    border-color: %(danger)s;
}
QPushButton#danger:hover {
    background: %(danger_bg)s;
}
QListWidget, QTableWidget, QTreeWidget, QTextEdit, QLineEdit, QSpinBox,
QComboBox {
    background: %(input)s;
    color: %(text)s;
    border: 1px solid %(border)s;
    border-radius: 6px;
    padding: 3px;
    selection-background-color: %(accent)s;
    selection-color: white;
}
QListWidget::item {
    padding: 7px 8px;
    margin: 1px;
    border-radius: 6px;
}
QListWidget::item:hover {
    background: %(hover)s;
}
QListWidget::item:selected {
    background: %(accent_bg)s;
    color: %(text)s;
    border: 1px solid %(accent)s;
}
QTableWidget {
    gridline-color: transparent;
    alternate-background-color: %(row_alt)s;
}
QHeaderView::section {
    background: %(panel)s;
    color: %(muted)s;
    border: none;
    border-bottom: 1px solid %(border)s;
    padding: 6px 5px;
    font-weight: 600;
}
QTableWidget::item, QTreeWidget::item {
    padding: 4px;
}
QTableWidget::item:selected, QTreeWidget::item:selected {
    background: %(accent)s;
    color: white;
}
QMenuBar {
    background: %(bg)s;
    color: %(text)s;
    padding: 2px 6px;
}
QMenuBar::item:selected {
    background: %(panel)s;
    border-radius: 4px;
}
QMenu {
    background: %(panel)s;
    color: %(text)s;
    border: 1px solid %(border)s;
    padding: 6px;
}
QMenu::item {
    padding: 6px 26px 6px 18px;
    border-radius: 4px;
    margin: 1px 0;
}
QMenu::item:selected {
    background: %(accent)s;
    color: white;
}
QMenu::separator {
    height: 1px;
    background: %(border)s;
    margin: 5px 8px;
}
QStatusBar {
    color: %(muted)s;
    border-top: 1px solid %(border)s;
}
QStatusBar::item {
    border: none;
}
QToolBar {
    background: %(panel)s;
    border: none;
    spacing: 6px;
    padding: 4px;
}
QProgressBar {
    background: %(bg)s;
    border: 1px solid %(border)s;
    border-radius: 5px;
    text-align: center;
    height: 14px;
    min-width: 90px;
}
QProgressBar::chunk {
    background: %(accent)s;
    border-radius: 4px;
}
QScrollBar:vertical {
    background: %(bg)s;
    width: 10px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: %(border)s;
    border-radius: 5px;
    min-height: 24px;
}
QScrollBar::handle:vertical:hover {
    background: %(muted)s;
}
QScrollBar:horizontal {
    background: %(bg)s;
    height: 10px;
    margin: 0;
}
QScrollBar::handle:horizontal {
    background: %(border)s;
    border-radius: 5px;
    min-width: 24px;
}
QScrollBar::handle:horizontal:hover {
    background: %(muted)s;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}
QCheckBox, QRadioButton {
    spacing: 6px;
}
QTabWidget::pane {
    border: 1px solid %(border)s;
    border-radius: 6px;
    top: -1px;
}
QTabBar::tab {
    background: %(panel)s;
    color: %(muted)s;
    padding: 6px 16px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    color: %(text)s;
    background: %(accent)s;
}
QToolTip {
    background: %(panel)s;
    color: %(text)s;
    border: 1px solid %(border)s;
    padding: 5px 8px;
    border-radius: 6px;
}
QLabel#roletitle {
    font-size: 26px;
    font-weight: 700;
    color: %(text)s;
}
QLabel#rolesubtitle {
    font-size: 13px;
    color: %(muted)s;
}
QLabel#rolequestion {
    font-size: 15px;
    font-weight: 600;
    color: %(text)s;
}
QFrame#rolecard {
    background: %(panel)s;
    border: 1px solid %(border)s;
    border-radius: 10px;
    min-width: 210px;
    max-width: 250px;
    min-height: 128px;
}
QFrame#rolecard:hover, QFrame#rolecard:focus {
    border-color: %(accent)s;
    background: %(hover)s;
}
QLabel#cardtitle {
    font-size: 15px;
    font-weight: 700;
    color: %(text)s;
}
QLabel#cardhint {
    font-size: 12px;
    color: %(muted)s;
}
QPushButton#link {
    background: transparent;
    border: none;
    color: %(muted)s;
    padding: 4px 10px;
}
QPushButton#link:hover {
    color: %(accent)s;
}
QPushButton#link:disabled {
    background: transparent;
    color: %(muted)s;
    border: none;
}
QLabel#screentitle {
    font-size: 16px;
    font-weight: 600;
    color: %(text)s;
}
QFrame#dropzone {
    background: %(panel)s;
    border: 2px dashed %(border)s;
    border-radius: 10px;
    min-height: 96px;
}
QFrame#dropzone[active="true"] {
    border-color: %(accent)s;
    background: %(accent_bg)s;
}
QFrame#devrow {
    background: %(panel)s;
    border: 1px solid %(border)s;
    border-radius: 8px;
}
QFrame#devrow[selected="true"] {
    border-color: %(accent)s;
    background: %(accent_bg)s;
}
QLabel#devname {
    font-size: 13px;
    font-weight: 600;
    color: %(text)s;
}
QLabel#devmeta {
    color: %(muted)s;
    font-size: 12px;
}
QLabel#pathlabel {
    color: %(text)s;
    font-size: 12px;
}
"""

_LIGHT = dict(
    bg="#f5f6f8",
    panel="#ffffff",
    border="#d8dbe0",
    text="#1c1e21",
    muted="#667085",
    input="#ffffff",
    button="#ffffff",
    button_text="#1c1e21",
    button_hover="#eef0f3",
    button_pressed="#e2e5ea",
    accent="#2563eb",
    accent_hover="#1d4ed8",
    accent_bg="#e8f0fe",
    danger="#dc2626",
    danger_bg="#fdeaea",
    hover="#eef1f5",
    row_alt="#fafbfc",
    ok="#16a34a",
    warn="#d97706",
)

_DARK = dict(
    bg="#15171c",
    panel="#1f232b",
    border="#333a45",
    text="#e6e8eb",
    muted="#98a2b3",
    input="#1a1e25",
    button="#262b34",
    button_text="#e6e8eb",
    button_hover="#2f3540",
    button_pressed="#39404c",
    accent="#3b82f6",
    accent_hover="#2563eb",
    accent_bg="#1e3a5f",
    danger="#f87171",
    danger_bg="#3b2226",
    hover="#262c35",
    row_alt="#1a1e25",
    ok="#4ade80",
    warn="#fbbf24",
)


def palette_for(theme: str) -> dict:
    if theme == "dark":
        return dict(_DARK)
    if theme == "light":
        return dict(_LIGHT)
    # system
    if sys.platform.startswith("win"):
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            ) as key:
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            return dict(_LIGHT) if value else dict(_DARK)
        except OSError:
            return dict(_LIGHT)
    return dict(_LIGHT)


# Palette most recently handed to :func:`apply_theme`; widgets that draw
# custom chrome (progress bars, flashes) read it so they follow the theme.
_APPLIED: dict = dict(_LIGHT)


def current_palette() -> dict:
    return dict(_APPLIED)


def stylesheet(theme: str = "system") -> str:
    return _BASE % palette_for(theme)


def apply_theme(app, theme: str) -> None:
    global _APPLIED
    _APPLIED = palette_for(theme)
    app.setStyleSheet(stylesheet(theme))
