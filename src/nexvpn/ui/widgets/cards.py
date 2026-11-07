"""Reusable rounded card and status badge widgets."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from nexvpn.connection.states import ConnectionState
from nexvpn.ui.theme import Palette


class CardFrame(QFrame):
    """Rounded dark surface card with thin subtle border."""

    def __init__(self, parent: QWidget | None = None, selected: bool = False) -> None:
        super().__init__(parent)
        self.setObjectName("CardSelected" if selected else "Card")

    def set_selected(self, selected: bool) -> None:
        self.setObjectName("CardSelected" if selected else "Card")
        self.style().unpolish(self)
        self.style().polish(self)
        self.update()


class MetricCard(CardFrame):
    """Compact metric card showing a muted caption and bold primary value."""

    def __init__(self, title: str, initial_value: str = "—", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 13, 16, 13)
        layout.setSpacing(5)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("MutedLabel")

        self.value_label = QLabel(initial_value)
        self.value_label.setObjectName("MetricValue")

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)

    def set_title(self, title: str) -> None:
        self.title_label.setText(title)

    def set_value(self, value: str, color: str | None = None) -> None:
        self.value_label.setText(value)
        if color:
            self.value_label.setStyleSheet(f"color: {color}; font-size: 16px; font-weight: 600;")
        else:
            self.value_label.setStyleSheet("")


class StatusBadge(QFrame):
    """Pill-shaped status indicator with colored dot and label."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 6, 14, 6)
        layout.setSpacing(8)

        self._dot = QLabel("●")
        self._text = QLabel("Отключено")
        self._text.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        layout.addWidget(self._dot)
        layout.addWidget(self._text)
        self.set_state(ConnectionState.DISCONNECTED, "Отключено")

    def set_state(self, state: ConnectionState, text: str) -> None:
        self._text.setText(text)
        if state == ConnectionState.CONNECTED:
            fg = Palette.SUCCESS
            bg = "rgba(56, 201, 139, 0.13)"
            bd = "rgba(56, 201, 139, 0.35)"
        elif state in (
            ConnectionState.CONNECTING,
            ConnectionState.RECONNECTING,
            ConnectionState.DISCONNECTING,
        ):
            fg = Palette.WARNING
            bg = "rgba(233, 183, 90, 0.13)"
            bd = "rgba(233, 183, 90, 0.35)"
        elif state == ConnectionState.ERROR:
            fg = Palette.ERROR
            bg = "rgba(241, 109, 118, 0.14)"
            bd = "rgba(241, 109, 118, 0.36)"
        else:
            fg = Palette.MUTED
            bg = Palette.SECONDARY
            bd = Palette.BORDER

        self.setStyleSheet(
            f"QFrame {{ background-color: {bg}; border: 1px solid {bd}; border-radius: 15px; }}"
        )
        self._dot.setStyleSheet(f"color: {fg}; font-size: 11px; border: none; background: transparent;")
        self._text.setStyleSheet(
            f"color: {fg}; font-size: 12px; font-weight: 600; border: none; background: transparent;"
        )
