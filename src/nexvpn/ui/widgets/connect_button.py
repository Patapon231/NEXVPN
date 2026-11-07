"""Animated circular Connect button with state-driven ring and glow."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, QVariantAnimation, Signal
from PySide6.QtGui import (
    QColor,
    QCursor,
    QFont,
    QPainter,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import QWidget

from nexvpn.connection.states import ConnectionState
from nexvpn.ui.theme import Palette


class ConnectOrbButton(QWidget):
    """Large tactile circular Connect/Disconnect button with smooth animations."""

    clicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(196, 196)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))

        self._state: ConnectionState = ConnectionState.DISCONNECTED
        self._hovered: bool = False
        self._pressed: bool = False
        self._hover_progress: float = 0.0
        self._spin_angle: int = 0
        self._label_text: str = "Подключиться"

        self._hover_anim = QVariantAnimation(self)
        self._hover_anim.setDuration(180)
        self._hover_anim.valueChanged.connect(self._on_hover_anim)

        self._spin_timer = QTimer(self)
        self._spin_timer.setInterval(24)
        self._spin_timer.timeout.connect(self._advance_spin)

    def set_state(self, state: ConnectionState, action_label: str) -> None:
        self._state = state
        self._label_text = action_label
        if state in (
            ConnectionState.CONNECTING,
            ConnectionState.RECONNECTING,
            ConnectionState.DISCONNECTING,
        ):
            if not self._spin_timer.isActive():
                self._spin_timer.start()
        else:
            self._spin_timer.stop()
        self.update()

    def _on_hover_anim(self, value: object) -> None:
        self._hover_progress = float(value)  # type: ignore[arg-type]
        self.update()

    def _advance_spin(self) -> None:
        self._spin_angle = (self._spin_angle - 7) % 360
        self.update()

    def enterEvent(self, event: object) -> None:  # noqa: N802
        self._hovered = True
        self._hover_anim.stop()
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()

    def leaveEvent(self, event: object) -> None:  # noqa: N802
        self._hovered = False
        self._pressed = False
        self._hover_anim.stop()
        self._hover_anim.setStartValue(self._hover_progress)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()

    def mousePressEvent(self, event: object) -> None:  # noqa: N802
        if getattr(event, "button", lambda: None)() == Qt.MouseButton.LeftButton:
            self._pressed = True
            self.update()

    def mouseReleaseEvent(self, event: object) -> None:  # noqa: N802
        was_pressed = self._pressed
        self._pressed = False
        self.update()
        if was_pressed and self.rect().contains(getattr(event, "pos")()):
            self.clicked.emit()

    def _ring_color(self) -> QColor:
        if self._state == ConnectionState.CONNECTED:
            return QColor(Palette.SUCCESS)
        if self._state in (
            ConnectionState.CONNECTING,
            ConnectionState.RECONNECTING,
            ConnectionState.DISCONNECTING,
        ):
            return QColor(Palette.WARNING)
        if self._state == ConnectionState.ERROR:
            return QColor(Palette.ERROR)
        return QColor(Palette.ACCENT)

    def paintEvent(self, event: object) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        w = float(self.width())
        h = float(self.height())
        center = QPointF(w / 2.0, h / 2.0)
        ring_color = self._ring_color()

        # Soft radial ambient glow
        glow_alpha = int(34 + 36 * self._hover_progress)
        if self._state == ConnectionState.CONNECTED:
            glow_alpha = int(56 + 28 * self._hover_progress)
        glow = QRadialGradient(center, w * 0.49)
        c_inner = QColor(ring_color)
        c_inner.setAlpha(glow_alpha)
        c_outer = QColor(ring_color)
        c_outer.setAlpha(0)
        glow.setColorAt(0.45, c_inner)
        glow.setColorAt(1.0, c_outer)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(glow)
        p.drawEllipse(center, w * 0.48, h * 0.48)

        # Core disc
        scale = 0.96 if self._pressed else (1.0 + 0.018 * self._hover_progress)
        radius = 70.0 * scale

        disc_color = QColor(Palette.SURFACE)
        if self._state == ConnectionState.CONNECTED:
            disc_color = QColor("#162925")
        elif self._hovered:
            disc_color = QColor("#202631")

        p.setBrush(disc_color)
        border_pen = QPen(QColor(Palette.BORDER), 2.0)
        p.setPen(border_pen)
        p.drawEllipse(center, radius, radius)

        # Active outer ring or animated spinner arc
        arc_rect = QRectF(center.x() - radius, center.y() - radius, radius * 2, radius * 2)
        if self._state in (
            ConnectionState.CONNECTING,
            ConnectionState.RECONNECTING,
            ConnectionState.DISCONNECTING,
        ):
            track_pen = QPen(QColor(Palette.SECONDARY), 3.2)
            p.setPen(track_pen)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(arc_rect)

            spin_pen = QPen(ring_color, 3.5)
            spin_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            p.setPen(spin_pen)
            p.drawArc(arc_rect, self._spin_angle * 16, 110 * 16)
        else:
            ring_alpha = 235 if self._state == ConnectionState.CONNECTED else int(145 + 90 * self._hover_progress)
            rc = QColor(ring_color)
            rc.setAlpha(ring_alpha)
            ring_pen = QPen(rc, 3.0)
            p.setPen(ring_pen)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(arc_rect)

        # Power symbol inside orb
        icon_pen = QPen(ring_color, 2.8)
        icon_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(icon_pen)
        icon_r = 16.0
        icon_center_y = center.y() - 12.0
        icon_rect = QRectF(center.x() - icon_r, icon_center_y - icon_r, icon_r * 2, icon_r * 2)
        p.drawArc(icon_rect, 130 * 16, 280 * 16)
        p.drawLine(
            QPointF(center.x(), icon_center_y - icon_r - 2.0),
            QPointF(center.x(), icon_center_y + 1.0),
        )

        # Action caption under power glyph
        font = QFont(self.font())
        font.setPixelSize(13)
        font.setWeight(QFont.Weight.DemiBold)
        p.setFont(font)
        p.setPen(QColor(Palette.TEXT))
        text_rect = QRectF(center.x() - 62, center.y() + 14, 124, 24)
        p.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, self._label_text)

        p.end()
