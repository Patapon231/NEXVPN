"""Main NEXVPN application window with full orchestration of ConnectionManager, Subscriptions, Servers, Settings, and Logs."""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QSize, QThread, QTimer
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from nexvpn import __version__
from nexvpn.connection.manager import ConnectionManager
from nexvpn.connection.states import ConnectionMode, ConnectionState, TrafficStats
from nexvpn.core.locator import (
    CoreInfo,
    CoreNotFoundError,
    CoreVersionError,
    inspect_sing_box,
    locate_sing_box,
)
from nexvpn.database.repository import DatabaseRepository
from nexvpn.subscription.manager import SubscriptionError, SubscriptionManager
from nexvpn.ui.i18n import tr
from nexvpn.ui.icons import create_brand_icon, create_brand_pixmap, make_nav_icon
from nexvpn.ui.pages.dashboard_page import DashboardPage
from nexvpn.ui.pages.logs_page import LogsPage
from nexvpn.ui.pages.servers_page import ServersPage
from nexvpn.ui.pages.settings_page import SettingsPage
from nexvpn.ui.pages.subscriptions_page import SubscriptionsPage
from nexvpn.ui.theme import Palette
from nexvpn.utils.logger import InMemoryLogHandler, get_logger
from nexvpn.utils.paths import AppPaths

log = get_logger("ui.main_window")


class MainWindow(QMainWindow):
    """Top-level NEXVPN desktop window."""

    NAV_ITEMS = (
        ("dashboard", "nav.dashboard"),
        ("servers", "nav.servers"),
        ("subscriptions", "nav.subscriptions"),
        ("settings", "nav.settings"),
        ("logs", "nav.logs"),
    )

    def __init__(
        self,
        paths: AppPaths,
        log_handler: InMemoryLogHandler,
        repo: DatabaseRepository | None = None,
        connection_manager: ConnectionManager | None = None,
        lang: str | None = None,
        enable_autoconnect: bool = False,
    ) -> None:
        super().__init__()
        self.paths = paths
        self.log_handler = log_handler
        self._owns_repo = repo is None
        self.repo = repo or DatabaseRepository(paths.db_file)
        self.sub_manager = SubscriptionManager(self.repo)
        self.conn_manager = connection_manager or ConnectionManager(
            paths=paths, repo=self.repo, parent=self
        )
        self._lang = lang or self.repo.get_setting("language", "ru")
        self._nav_buttons: dict[str, QPushButton] = {}
        self._core_info: CoreInfo | None = None
        self._fade_anim: QPropertyAnimation | None = None
        self._auto_sub_thread: QThread | None = None
        self._shut_down = False

        self.setWindowTitle("NEXVPN")
        self.setWindowIcon(create_brand_icon())
        self.setMinimumSize(940, 620)
        self.resize(1060, 680)

        self._build_layout()
        self._wire_signals()
        self._detect_core()
        self._sync_mode_to_dashboard()
        self._sync_selected_server_to_dashboard()
        self._setup_auto_update_timer()
        self.switch_page("dashboard")

        if enable_autoconnect and self.repo.get_setting("autoconnect", "0") == "1":
            if self.repo.get_setting("selected_server_id", "").isdigit():
                QTimer.singleShot(400, self.conn_manager.connect_to_selected)

    def _build_layout(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)

        main_row = QHBoxLayout(central)
        main_row.setContentsMargins(0, 0, 0, 0)
        main_row.setSpacing(0)

        # Left Sidebar
        self.sidebar = QFrame()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(226)
        side_col = QVBoxLayout(self.sidebar)
        side_col.setContentsMargins(16, 22, 16, 18)
        side_col.setSpacing(6)

        brand_box = QHBoxLayout()
        brand_box.setContentsMargins(6, 0, 6, 16)
        brand_box.setSpacing(10)
        logo_lbl = QLabel()
        logo_lbl.setPixmap(create_brand_pixmap(28))
        brand_txt_col = QVBoxLayout()
        brand_txt_col.setSpacing(1)
        name_lbl = QLabel("NEXVPN")
        name_lbl.setStyleSheet("font-size: 16px; font-weight: 700; letter-spacing: 0.6px;")
        ver_lbl = QLabel(f"Desktop v{__version__}")
        ver_lbl.setObjectName("MutedLabel")
        brand_txt_col.addWidget(name_lbl)
        brand_txt_col.addWidget(ver_lbl)
        brand_box.addWidget(logo_lbl)
        brand_box.addLayout(brand_txt_col)
        brand_box.addStretch(1)
        side_col.addLayout(brand_box)

        for key, i18n_key in self.NAV_ITEMS:
            btn = QPushButton(tr(i18n_key, self._lang))
            btn.setObjectName("NavButton")
            btn.setIcon(make_nav_icon(key, Palette.MUTED))
            btn.setIconSize(QSize(18, 18))
            btn.clicked.connect(lambda _checked=False, k=key: self.switch_page(k))
            side_col.addWidget(btn)
            self._nav_buttons[key] = btn

        side_col.addStretch(1)

        core_panel = QFrame()
        core_panel.setObjectName("SubtlePanel")
        core_layout = QVBoxLayout(core_panel)
        core_layout.setContentsMargins(12, 10, 12, 10)
        core_layout.setSpacing(3)
        core_title = QLabel("VPN Engine")
        core_title.setObjectName("MutedLabel")
        self.core_status_lbl = QLabel("sing-box: проверка...")
        self.core_status_lbl.setStyleSheet("font-size: 12px; font-weight: 600;")
        core_layout.addWidget(core_title)
        core_layout.addWidget(self.core_status_lbl)
        side_col.addWidget(core_panel)

        # Right Content Stack
        self.stack = QStackedWidget()
        self.dashboard_page = DashboardPage(lang=self._lang)
        self.servers_page = ServersPage(
            repo=self.repo,
            sub_manager=self.sub_manager,
            lang=self._lang,
        )
        self.subscriptions_page = SubscriptionsPage(
            repo=self.repo,
            manager=self.sub_manager,
            lang=self._lang,
        )
        self.settings_page = SettingsPage(
            repo=self.repo,
            paths=self.paths,
            lang=self._lang,
        )
        self.logs_page = LogsPage(log_handler=self.log_handler, lang=self._lang)

        self._pages: dict[str, QWidget] = {
            "dashboard": self.dashboard_page,
            "servers": self.servers_page,
            "subscriptions": self.subscriptions_page,
            "settings": self.settings_page,
            "logs": self.logs_page,
        }
        for page in self._pages.values():
            self.stack.addWidget(page)

        main_row.addWidget(self.sidebar)
        main_row.addWidget(self.stack, stretch=1)

    def _wire_signals(self) -> None:
        # Dashboard actions
        self.dashboard_page.connect_toggled.connect(self.conn_manager.toggle_connection)
        self.dashboard_page.mode_changed.connect(self._on_dashboard_mode_changed)
        self.dashboard_page.ping_requested.connect(self.conn_manager.check_active_latency_async)
        self.dashboard_page.open_servers_requested.connect(lambda: self.switch_page("servers"))

        # ConnectionManager live telemetry -> UI
        self.conn_manager.state_changed.connect(self._on_connection_state_changed)
        self.conn_manager.uptime_updated.connect(self.dashboard_page.set_uptime_seconds)
        self.conn_manager.traffic_updated.connect(self._on_traffic_updated)
        self.conn_manager.latency_updated.connect(self._on_latency_updated)

        # Subscriptions / Servers / Settings sync
        self.subscriptions_page.subscriptions_changed.connect(self._on_data_changed)
        self.servers_page.server_selected.connect(self._on_server_selected)
        self.servers_page.servers_modified.connect(self._sync_selected_server_to_dashboard)
        self.settings_page.settings_saved.connect(self._on_settings_saved)
        self.settings_page.language_changed.connect(self.set_language)

    def _on_dashboard_mode_changed(self, mode_val: str) -> None:
        self.repo.set_setting("connection_mode", mode_val)
        self.settings_page.load_from_repo()

    def _on_connection_state_changed(self, state_obj: object, message: str) -> None:
        if isinstance(state_obj, ConnectionState):
            self.dashboard_page.set_connection_state(state_obj, message)
            self.settings_page.refresh_diagnostics()

    def _on_traffic_updated(self, stats_obj: object) -> None:
        if isinstance(stats_obj, TrafficStats):
            self.dashboard_page.set_traffic_stats(stats_obj)

    def _on_latency_updated(self, ms: int) -> None:
        self.dashboard_page.set_latency(ms)
        self.servers_page.reload_servers()

    def _on_server_selected(self, _server_id: int) -> None:
        self._sync_selected_server_to_dashboard()
        if self.conn_manager.state == ConnectionState.CONNECTED:
            self.conn_manager.reconnect()

    def _on_settings_saved(self) -> None:
        self._sync_mode_to_dashboard()

    def _sync_mode_to_dashboard(self) -> None:
        mode_raw = self.repo.get_setting("connection_mode", ConnectionMode.SYSTEM_PROXY.value)
        mode = (
            ConnectionMode.TUN
            if mode_raw == ConnectionMode.TUN.value
            else ConnectionMode.SYSTEM_PROXY
        )
        self.dashboard_page.set_mode_silently(mode)

    def _detect_core(self) -> None:
        try:
            bin_path = locate_sing_box(self.paths)
            self._core_info = inspect_sing_box(bin_path)
            self.core_status_lbl.setText(f"sing-box v{self._core_info.version}")
            self.core_status_lbl.setStyleSheet(
                f"color: {Palette.SUCCESS}; font-size: 12px; font-weight: 600;"
            )
        except (CoreNotFoundError, CoreVersionError) as exc:
            log.warning("Проблема с ядром sing-box: %s", exc)
            self.core_status_lbl.setText("sing-box не найден")
            self.core_status_lbl.setStyleSheet(
                f"color: {Palette.ERROR}; font-size: 12px; font-weight: 600;"
            )

    def switch_page(self, key: str) -> None:
        target = self._pages.get(key)
        if target is None:
            return

        if key == "settings":
            self.settings_page.refresh_diagnostics()

        for nav_key, btn in self._nav_buttons.items():
            is_active = nav_key == key
            btn.setProperty("active", "true" if is_active else "false")
            btn.setIcon(make_nav_icon(nav_key, Palette.ACCENT if is_active else Palette.MUTED))
            btn.style().unpolish(btn)
            btn.style().polish(btn)

        if self.stack.currentWidget() is not target:
            self.stack.setCurrentWidget(target)
            effect = QGraphicsOpacityEffect(target)
            target.setGraphicsEffect(effect)
            anim = QPropertyAnimation(effect, b"opacity", self)
            anim.setDuration(140)
            anim.setStartValue(0.35)
            anim.setEndValue(1.0)
            anim.setEasingCurve(QEasingCurve.Type.OutCubic)
            anim.finished.connect(lambda t=target: t.setGraphicsEffect(None))
            self._fade_anim = anim
            anim.start()

    def set_language(self, lang: str) -> None:
        self._lang = lang
        for nav_key, i18n_key in self.NAV_ITEMS:
            if nav_key in self._nav_buttons:
                self._nav_buttons[nav_key].setText(tr(i18n_key, lang))
        self.dashboard_page.set_language(lang)
        self.servers_page.set_language(lang)
        self.subscriptions_page.set_language(lang)
        self.settings_page.set_language(lang)
        self.logs_page.set_language(lang)
        self._sync_selected_server_to_dashboard()

    def _on_data_changed(self) -> None:
        self.servers_page.reload_servers()
        self._sync_selected_server_to_dashboard()

    def _sync_selected_server_to_dashboard(self) -> None:
        sel_raw = self.repo.get_setting("selected_server_id", "")
        srv = self.repo.get_server(int(sel_raw)) if sel_raw.isdigit() else None
        if srv is None:
            self.dashboard_page.set_selected_server_info(None)
        else:
            self.dashboard_page.set_selected_server_info(
                name=srv.display_name,
                protocol=srv.protocol_summary,
                address=srv.endpoint_label,
                latency_ms=srv.latency_ms,
            )

    def _setup_auto_update_timer(self) -> None:
        self._auto_timer = QTimer(self)
        self._auto_timer.setInterval(60_000)
        self._auto_timer.timeout.connect(self._check_due_subscriptions)
        self._auto_timer.start()

    def _check_due_subscriptions(self) -> None:
        if self.repo.get_setting("auto_update_subs", "1") != "1":
            return
        if self._auto_sub_thread is not None and self._auto_sub_thread.isRunning():
            return

        now = datetime.now(UTC)
        due_ids: list[int] = []
        for sub in self.repo.list_subscriptions():
            if sub.source_type != "url" or not sub.auto_update or not sub.url:
                continue
            if not sub.last_updated_at:
                due_ids.append(sub.id)
                continue
            try:
                last_dt = datetime.fromisoformat(sub.last_updated_at.replace("Z", "+00:00"))
                elapsed_min = (now - last_dt).total_seconds() / 60.0
                if elapsed_min >= sub.update_interval_min:
                    due_ids.append(sub.id)
            except ValueError:
                pass

        if not due_ids:
            return

        class _AutoUpdater(QThread):
            def __init__(self, mgr: SubscriptionManager, ids: list[int], parent: QWidget) -> None:
                super().__init__(parent)
                self.mgr = mgr
                self.ids = ids

            def run(self) -> None:
                for sid in self.ids:
                    try:
                        self.mgr.refresh_subscription(sid)
                    except SubscriptionError as exc:
                        log.warning("Автообновление подписки #%d не удалось: %s", sid, exc)

        worker = _AutoUpdater(self.sub_manager, due_ids, self)
        worker.finished.connect(self._on_auto_update_finished)
        self._auto_sub_thread = worker
        worker.start()

    def _on_auto_update_finished(self) -> None:
        self.subscriptions_page.reload_subscriptions()
        self._on_data_changed()

    def shutdown_cleanly(self) -> None:
        """Stop timers, background workers, VPN engine, and restore Windows network state."""
        if self._shut_down:
            return
        self._shut_down = True
        self._auto_timer.stop()
        self.servers_page.stop_background_tasks()
        if self._auto_sub_thread is not None and self._auto_sub_thread.isRunning():
            self._auto_sub_thread.wait(2000)
        self.conn_manager.shutdown()
        self.logs_page.detach_listener()
        if self._owns_repo:
            self.repo.close()

    def closeEvent(self, event: object) -> None:  # noqa: N802
        self.shutdown_cleanly()
        super().closeEvent(event)  # type: ignore[arg-type]
