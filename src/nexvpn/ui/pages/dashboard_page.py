"""Dashboard screen: brand header, status pill, Connect orb, selected node, live metrics."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from nexvpn.connection.states import (
    ConnectionMode,
    ConnectionState,
    TrafficStats,
    format_speed,
)
from nexvpn.ui.i18n import tr
from nexvpn.ui.icons import create_brand_pixmap
from nexvpn.ui.theme import Palette
from nexvpn.ui.widgets.cards import CardFrame, MetricCard, StatusBadge
from nexvpn.ui.widgets.connect_button import ConnectOrbButton


class DashboardPage(QWidget):
    """Primary NEXVPN Dashboard screen."""

    connect_toggled = Signal()
    mode_changed = Signal(str)
    ping_requested = Signal()
    open_servers_requested = Signal()

    def __init__(self, lang: str = "ru", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._lang = lang
        self._state = ConnectionState.DISCONNECTED
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(18)

        # Top header bar: NEXVPN logo + status badge
        header = QHBoxLayout()
        brand_row = QHBoxLayout()
        brand_row.setSpacing(10)
        logo_lbl = QLabel()
        logo_lbl.setPixmap(create_brand_pixmap(32))
        title_lbl = QLabel("NEXVPN")
        title_lbl.setObjectName("PageTitle")
        brand_row.addWidget(logo_lbl)
        brand_row.addWidget(title_lbl)

        self.status_badge = StatusBadge()

        header.addLayout(brand_row)
        header.addStretch(1)
        header.addWidget(self.status_badge)
        root.addLayout(header)

        # Error / diagnostic banner (hidden unless error/warning present)
        self.alert_card = CardFrame()
        self.alert_card.setStyleSheet(
            f"QFrame {{ background-color: rgba(241, 109, 118, 0.12); "
            f"border: 1px solid rgba(241, 109, 118, 0.4); border-radius: 10px; }}"
        )
        alert_layout = QHBoxLayout(self.alert_card)
        alert_layout.setContentsMargins(14, 10, 14, 10)
        self.alert_label = QLabel("")
        self.alert_label.setWordWrap(True)
        self.alert_label.setStyleSheet(
            f"color: {Palette.ERROR}; font-size: 12px; border: none; background: transparent;"
        )
        alert_layout.addWidget(self.alert_label)
        self.alert_card.hide()
        root.addWidget(self.alert_card)

        # Center Connect Orb section
        root.addStretch(1)
        orb_row = QHBoxLayout()
        orb_row.addStretch(1)
        self.connect_btn = ConnectOrbButton()
        self.connect_btn.clicked.connect(self.connect_toggled.emit)
        orb_row.addWidget(self.connect_btn)
        orb_row.addStretch(1)
        root.addLayout(orb_row)
        root.addStretch(1)

        # Selected Server Card + Mode Selector
        self.server_card = CardFrame()
        srv_layout = QHBoxLayout(self.server_card)
        srv_layout.setContentsMargins(18, 14, 18, 14)
        srv_layout.setSpacing(14)

        srv_info_col = QVBoxLayout()
        srv_info_col.setSpacing(4)
        self.srv_caption_lbl = QLabel(tr("dash.selected_server", self._lang))
        self.srv_caption_lbl.setObjectName("MutedLabel")
        self.srv_name_lbl = QLabel(tr("dash.no_server", self._lang))
        self.srv_name_lbl.setObjectName("SectionTitle")
        self.srv_meta_lbl = QLabel("—")
        self.srv_meta_lbl.setObjectName("MutedLabel")
        srv_info_col.addWidget(self.srv_caption_lbl)
        srv_info_col.addWidget(self.srv_name_lbl)
        srv_info_col.addWidget(self.srv_meta_lbl)

        srv_actions_col = QHBoxLayout()
        srv_actions_col.setSpacing(8)

        self.mode_combo = QComboBox()
        self.mode_combo.addItem("System Proxy", ConnectionMode.SYSTEM_PROXY.value)
        self.mode_combo.addItem("TUN Mode", ConnectionMode.TUN.value)
        self.mode_combo.setMinimumWidth(145)
        self.mode_combo.currentIndexChanged.connect(self._emit_mode_changed)

        self.ping_btn = QPushButton(tr("dash.check_ping", self._lang))
        self.ping_btn.clicked.connect(self.ping_requested.emit)

        self.choose_srv_btn = QPushButton("→")
        self.choose_srv_btn.setToolTip("Выбрать сервер")
        self.choose_srv_btn.setFixedWidth(38)
        self.choose_srv_btn.clicked.connect(self.open_servers_requested.emit)

        srv_actions_col.addWidget(self.mode_combo)
        srv_actions_col.addWidget(self.ping_btn)
        srv_actions_col.addWidget(self.choose_srv_btn)

        srv_layout.addLayout(srv_info_col, stretch=1)
        srv_layout.addLayout(srv_actions_col)
        root.addWidget(self.server_card)

        # Metrics Grid: Latency | Session Uptime | Download | Upload
        grid = QGridLayout()
        grid.setSpacing(12)

        self.latency_card = MetricCard(tr("dash.latency", self._lang), "—")
        self.uptime_card = MetricCard(tr("dash.uptime", self._lang), "00:00:00")
        self.down_card = MetricCard(tr("dash.download", self._lang), "—")
        self.up_card = MetricCard(tr("dash.upload", self._lang), "—")

        for idx, card in enumerate(
            (self.latency_card, self.uptime_card, self.down_card, self.up_card)
        ):
            card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            grid.addWidget(card, 0, idx)

        root.addLayout(grid)
        self.set_connection_state(ConnectionState.DISCONNECTED)

    def _emit_mode_changed(self) -> None:
        val = self.mode_combo.currentData()
        if isinstance(val, str):
            self.mode_changed.emit(val)

    def set_mode_silently(self, mode: ConnectionMode) -> None:
        idx = self.mode_combo.findData(mode.value)
        if idx >= 0 and idx != self.mode_combo.currentIndex():
            self.mode_combo.blockSignals(True)
            self.mode_combo.setCurrentIndex(idx)
            self.mode_combo.blockSignals(False)

    def set_connection_state(self, state: ConnectionState, error_msg: str = "") -> None:
        self._state = state
        status_text = tr(f"state.{state.value}", self._lang)
        self.status_badge.set_state(state, status_text)

        if state == ConnectionState.CONNECTED:
            btn_label = tr("btn.disconnect", self._lang)
        elif state in (ConnectionState.CONNECTING, ConnectionState.RECONNECTING):
            btn_label = tr("btn.cancel", self._lang)
        elif state == ConnectionState.DISCONNECTING:
            btn_label = "..."
        else:
            btn_label = tr("btn.connect", self._lang)

        self.connect_btn.set_state(state, btn_label)
        self.mode_combo.setEnabled(state in (ConnectionState.DISCONNECTED, ConnectionState.ERROR))

        if error_msg:
            self.alert_label.setText(error_msg)
            self.alert_card.show()
        elif state != ConnectionState.ERROR:
            self.alert_card.hide()

        if state in (ConnectionState.DISCONNECTED, ConnectionState.ERROR):
            self.uptime_card.set_value("00:00:00")
            self.down_card.set_value("—")
            self.up_card.set_value("—")

    def set_selected_server_info(
        self,
        name: str | None,
        protocol: str = "",
        address: str = "",
        latency_ms: int | None = None,
    ) -> None:
        if not name:
            self.srv_name_lbl.setText(tr("dash.no_server", self._lang))
            self.srv_meta_lbl.setText("—")
            self.set_latency(None)
            return

        self.srv_name_lbl.setText(name)
        meta_parts = [p for p in (protocol.upper(), address) if p]
        self.srv_meta_lbl.setText("  •  ".join(meta_parts) if meta_parts else "—")
        self.set_latency(latency_ms)

    def set_latency(self, latency_ms: int | None) -> None:
        if latency_ms is None:
            self.latency_card.set_value("—")
        elif latency_ms < 0:
            self.latency_card.set_value("Timeout", Palette.ERROR)
        else:
            color = (
                Palette.SUCCESS
                if latency_ms < 150
                else (Palette.WARNING if latency_ms < 350 else Palette.ERROR)
            )
            self.latency_card.set_value(f"{latency_ms} ms", color)

    def set_uptime_seconds(self, total_seconds: int) -> None:
        hrs, rem = divmod(max(0, total_seconds), 3600)
        mins, secs = divmod(rem, 60)
        self.uptime_card.set_value(f"{hrs:02d}:{mins:02d}:{secs:02d}")

    def set_traffic_stats(self, stats: TrafficStats) -> None:
        if not stats.available:
            self.down_card.set_value("—")
            self.up_card.set_value("—")
            return
        self.down_card.set_value(f"↓ {format_speed(stats.download_bps)}", Palette.ACCENT)
        self.up_card.set_value(f"↑ {format_speed(stats.upload_bps)}", Palette.SUCCESS)

    def set_language(self, lang: str) -> None:
        self._lang = lang
        self.srv_caption_lbl.setText(tr("dash.selected_server", lang))
        self.ping_btn.setText(tr("dash.check_ping", lang))
        self.latency_card.set_title(tr("dash.latency", lang))
        self.uptime_card.set_title(tr("dash.uptime", lang))
        self.down_card.set_title(tr("dash.download", lang))
        self.up_card.set_title(tr("dash.upload", lang))
        self.set_connection_state(self._state, self.alert_label.text() if self.alert_card.isVisible() else "")
