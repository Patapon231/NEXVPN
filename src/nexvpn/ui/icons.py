"""Crisp vector icons rendered via QPainter (zero external icon-pack breakage)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QColor,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)

from nexvpn.ui.theme import Palette


def create_brand_pixmap(size: int = 64) -> QPixmap:
    """Render the NEXVPN shield + lightning/node emblem as a crisp QPixmap."""
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    pad = size * 0.08
    w = size - 2 * pad
    h = size - 2 * pad

    # Shield contour
    shield = QPainterPath()
    cx = size / 2.0
    top = pad
    bottom = size - pad
    shield.moveTo(cx, top)
    shield.lineTo(size - pad, top + h * 0.18)
    shield.quadTo(size - pad, top + h * 0.62, cx, bottom)
    shield.quadTo(pad, top + h * 0.62, pad, top + h * 0.18)
    shield.closeSubpath()

    grad = QLinearGradient(0, top, size, bottom)
    grad.setColorAt(0.0, QColor("#55B9F3"))
    grad.setColorAt(1.0, QColor("#2678B8"))
    painter.setPen(QPen(QColor("#82CEFA"), max(1.2, size * 0.03)))
    painter.setBrush(grad)
    painter.drawPath(shield)

    # Stylized 'N' / signal vector inside shield
    pen = QPen(QColor("#0D131A"), max(2.2, size * 0.085))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)

    nx1 = cx - w * 0.19
    nx2 = cx + w * 0.19
    ny1 = cx - h * 0.17
    ny2 = cx + h * 0.17
    n_path = QPainterPath()
    n_path.moveTo(nx1, ny2)
    n_path.lineTo(nx1, ny1)
    n_path.lineTo(nx2, ny2)
    n_path.lineTo(nx2, ny1)
    painter.drawPath(n_path)

    painter.end()
    return pix


def create_brand_icon() -> QIcon:
    """Create multi-resolution QIcon for window titlebar, taskbar, and tray."""
    icon = QIcon()
    for sz in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(create_brand_pixmap(sz))
    return icon


def save_brand_ico(ico_path: Path) -> None:
    """Export brand icon to .ico file for PyInstaller packaging."""
    ico_path.parent.mkdir(parents=True, exist_ok=True)
    pix = create_brand_pixmap(256)
    pix.save(str(ico_path), "ICO")


def make_nav_icon(kind: str, color_hex: str = Palette.MUTED, size: int = 20) -> QIcon:
    """Render minimal stroke icons for sidebar navigation and actions."""
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    pen = QPen(QColor(color_hex), 1.7)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)

    m = 3.0
    s = size - 2 * m

    if kind == "dashboard":
        # Power / gauge arc
        p.drawArc(QRectF(m, m, s, s), 30 * 16, 300 * 16)
        p.drawLine(QPointF(size / 2, m + 1), QPointF(size / 2, size / 2))
    elif kind == "servers":
        # Stacked server nodes
        p.drawRoundedRect(QRectF(m, m + 1, s, s * 0.38), 2.5, 2.5)
        p.drawRoundedRect(QRectF(m, m + s * 0.56, s, s * 0.38), 2.5, 2.5)
        p.drawPoint(QPointF(m + 3.5, m + 1 + s * 0.19))
        p.drawPoint(QPointF(m + 3.5, m + s * 0.75))
    elif kind == "subscriptions":
        # Link / cloud feed
        p.drawRoundedRect(QRectF(m, m + 2, s, s - 4), 4, 4)
        p.drawLine(QPointF(m + 4, size / 2), QPointF(size - m - 4, size / 2))
        p.drawLine(QPointF(size / 2, m + 5), QPointF(size / 2, size - m - 5))
    elif kind == "settings":
        # Sliders
        y1, y2, y3 = m + 3, size / 2, size - m - 3
        p.drawLine(QPointF(m, y1), QPointF(size - m, y1))
        p.drawLine(QPointF(m, y2), QPointF(size - m, y2))
        p.drawLine(QPointF(m, y3), QPointF(size - m, y3))
        p.setBrush(QColor(Palette.SURFACE))
        p.drawEllipse(QPointF(m + s * 0.3, y1), 2.2, 2.2)
        p.drawEllipse(QPointF(m + s * 0.7, y2), 2.2, 2.2)
        p.drawEllipse(QPointF(m + s * 0.45, y3), 2.2, 2.2)
    elif kind == "logs":
        # Terminal prompt >_
        p.drawRoundedRect(QRectF(m, m + 1, s, s - 2), 3, 3)
        path = QPainterPath()
        path.moveTo(m + 3.5, m + 5.5)
        path.lineTo(m + 7.0, size / 2)
        path.lineTo(m + 3.5, size - m - 5.5)
        p.drawPath(path)
        p.drawLine(QPointF(m + 9.0, size - m - 5.0), QPointF(size - m - 3.5, size - m - 5.0))
    elif kind == "power":
        arc_rect = QRectF(m + 1, m + 2, s - 2, s - 2)
        p.drawArc(arc_rect, 130 * 16, 280 * 16)
        p.drawLine(QPointF(size / 2, m), QPointF(size / 2, size * 0.52))

    p.end()
    return QIcon(pix)
