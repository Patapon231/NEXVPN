"""NEXVPN visual design tokens, Inter font loader, and global Qt StyleSheet."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QColor, QFont, QFontDatabase
from PySide6.QtWidgets import QApplication


class Palette:
    """Official NEXVPN dark minimalist palette."""

    BACKGROUND = "#111318"
    SURFACE = "#1B1F27"
    SECONDARY = "#252B35"
    BORDER = "#2D3542"
    ACCENT = "#55B9F3"
    ACCENT_HOVER = "#6EC5F7"
    ACCENT_DIM = "#1E3A4F"
    TEXT = "#F4F6F8"
    MUTED = "#929BAA"
    SUCCESS = "#38C98B"
    ERROR = "#F16D76"
    WARNING = "#E9B75A"

    @staticmethod
    def qcolor(hex_code: str, alpha: int = 255) -> QColor:
        color = QColor(hex_code)
        color.setAlpha(alpha)
        return color


def load_inter_font(assets_dir: Path) -> str:
    """Load bundled Inter font files if present; fall back gracefully to Inter/Segoe UI."""
    fonts_dir = assets_dir / "fonts"
    loaded_family: str | None = None
    if fonts_dir.is_dir():
        for font_file in sorted(fonts_dir.glob("*.[to]tf")):
            font_id = QFontDatabase.addApplicationFont(str(font_file))
            if font_id != -1:
                families = QFontDatabase.applicationFontFamilies(font_id)
                if families and loaded_family is None:
                    loaded_family = families[0]

    if loaded_family:
        return loaded_family
    if "Inter" in QFontDatabase.families():
        return "Inter"
    return "Segoe UI"


def apply_app_theme(app: QApplication, assets_dir: Path) -> str:
    """Configure application-wide typography and dark minimalist stylesheet."""
    family = load_inter_font(assets_dir)
    base_font = QFont(family, 10)
    base_font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    app.setFont(base_font)
    app.setStyleSheet(build_stylesheet(family))
    return family


def build_stylesheet(font_family: str = "Inter") -> str:
    """Return unified QSS for all PySide6 widgets."""
    return f"""
    QWidget {{
        background-color: transparent;
        color: {Palette.TEXT};
        font-family: "{font_family}", "Inter", "Segoe UI", sans-serif;
        font-size: 13px;
    }}

    QMainWindow {{
        background-color: {Palette.BACKGROUND};
    }}

    QFrame#Sidebar {{
        background-color: {Palette.SURFACE};
        border-right: 1px solid {Palette.BORDER};
    }}

    QFrame#Card {{
        background-color: {Palette.SURFACE};
        border: 1px solid {Palette.BORDER};
        border-radius: 14px;
    }}

    QFrame#CardSelected {{
        background-color: {Palette.SURFACE};
        border: 1px solid {Palette.ACCENT};
        border-radius: 14px;
    }}

    QFrame#SubtlePanel {{
        background-color: {Palette.SECONDARY};
        border: 1px solid {Palette.BORDER};
        border-radius: 10px;
    }}

    QLabel#PageTitle {{
        font-size: 22px;
        font-weight: 700;
        color: {Palette.TEXT};
    }}

    QLabel#SectionTitle {{
        font-size: 14px;
        font-weight: 600;
        color: {Palette.TEXT};
    }}

    QLabel#MutedLabel {{
        color: {Palette.MUTED};
        font-size: 12px;
    }}

    QLabel#MetricValue {{
        color: {Palette.TEXT};
        font-size: 16px;
        font-weight: 600;
    }}

    QPushButton {{
        background-color: {Palette.SECONDARY};
        color: {Palette.TEXT};
        border: 1px solid {Palette.BORDER};
        border-radius: 9px;
        padding: 8px 15px;
        font-weight: 500;
    }}

    QPushButton:hover {{
        background-color: #2E3644;
        border-color: #3B4658;
    }}

    QPushButton:pressed {{
        background-color: #202630;
    }}

    QPushButton:disabled {{
        color: #596273;
        background-color: #181C23;
        border-color: #222832;
    }}

    QPushButton#PrimaryButton {{
        background-color: {Palette.ACCENT};
        color: #0B1117;
        border: none;
        font-weight: 600;
    }}

    QPushButton#PrimaryButton:hover {{
        background-color: {Palette.ACCENT_HOVER};
    }}

    QPushButton#PrimaryButton:disabled {{
        background-color: #274459;
        color: #6B8294;
    }}

    QPushButton#DangerButton {{
        background-color: rgba(241, 109, 118, 0.14);
        color: {Palette.ERROR};
        border: 1px solid rgba(241, 109, 118, 0.35);
        font-weight: 600;
    }}

    QPushButton#DangerButton:hover {{
        background-color: rgba(241, 109, 118, 0.25);
    }}

    QPushButton#NavButton {{
        background-color: transparent;
        color: {Palette.MUTED};
        border: 1px solid transparent;
        border-radius: 10px;
        padding: 10px 14px;
        text-align: left;
        font-size: 13px;
        font-weight: 500;
    }}

    QPushButton#NavButton:hover {{
        background-color: {Palette.SECONDARY};
        color: {Palette.TEXT};
    }}

    QPushButton#NavButton[active="true"] {{
        background-color: rgba(85, 185, 243, 0.14);
        color: {Palette.ACCENT};
        border: 1px solid rgba(85, 185, 243, 0.32);
        font-weight: 600;
    }}

    QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {{
        background-color: {Palette.SECONDARY};
        color: {Palette.TEXT};
        border: 1px solid {Palette.BORDER};
        border-radius: 9px;
        padding: 8px 12px;
        selection-background-color: {Palette.ACCENT};
        selection-color: #0B1117;
    }}

    QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus {{
        border: 1px solid {Palette.ACCENT};
    }}

    QComboBox::drop-down {{
        border: none;
        width: 24px;
    }}

    QComboBox QAbstractItemView {{
        background-color: {Palette.SURFACE};
        color: {Palette.TEXT};
        border: 1px solid {Palette.BORDER};
        selection-background-color: {Palette.SECONDARY};
        selection-color: {Palette.ACCENT};
        outline: 0;
    }}

    QScrollArea {{
        border: none;
        background-color: transparent;
    }}

    QScrollBar:vertical {{
        background: transparent;
        width: 8px;
        margin: 2px;
    }}

    QScrollBar::handle:vertical {{
        background: #2F3746;
        min-height: 28px;
        border-radius: 4px;
    }}

    QScrollBar::handle:vertical:hover {{
        background: #404B5E;
    }}

    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0px;
    }}

    QCheckBox {{
        spacing: 8px;
        color: {Palette.TEXT};
    }}

    QCheckBox::indicator {{
        width: 18px;
        height: 18px;
        border-radius: 5px;
        border: 1px solid {Palette.BORDER};
        background-color: {Palette.SECONDARY};
    }}

    QCheckBox::indicator:checked {{
        background-color: {Palette.ACCENT};
        border-color: {Palette.ACCENT};
    }}

    QMessageBox, QDialog {{
        background-color: {Palette.SURFACE};
        color: {Palette.TEXT};
    }}

    QToolTip {{
        background-color: {Palette.SECONDARY};
        color: {Palette.TEXT};
        border: 1px solid {Palette.BORDER};
        padding: 5px 8px;
        border-radius: 6px;
    }}
    """
