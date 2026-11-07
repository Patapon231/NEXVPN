"""ConnectionManager: real state machine orchestrating sing-box, System Proxy, TUN, latency, and diagnostics."""

from __future__ import annotations

import secrets
import socket
import time

from PySide6.QtCore import QObject, QThread, QTimer, Signal

from nexvpn.connection.latency import (
    measure_node_tcp_rtt_ms,
    measure_proxy_roundtrip_ms,
    measure_server_tcp_rtt_ms,
)
from nexvpn.connection.states import (
    ConnectionMode,
    ConnectionState,
    DiagnosticInfo,
    TrafficStats,
)
from nexvpn.core.config_generator import (
    ConfigGenerationError,
    generate_sing_box_config,
    generate_xray_bridge_config,
    node_requires_xray,
)
from nexvpn.core.engine import CoreEngine, CoreEngineError
from nexvpn.core.locator import CoreNotFoundError, CoreVersionError
from nexvpn.database.repository import DatabaseRepository
from nexvpn.services.system_proxy import SystemProxyError, SystemProxyService
from nexvpn.services.traffic_monitor import TrafficMonitor
from nexvpn.services.tun_service import TunError, TunService
from nexvpn.subscription.models import ServerRecord
from nexvpn.utils.logger import get_logger
from nexvpn.utils.network import find_free_port, is_port_available
from nexvpn.utils.paths import AppPaths

log = get_logger("connection.manager")


def verify_socks5_inbound_ready(host: str, port: int, timeout: float = 0.6) -> bool:
    """Perform a real SOCKS5 greeting (0x05 0x01 0x00 -> 0x05 0x00) with local sing-box inbound."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"\x05\x01\x00")
            reply = sock.recv(2)
            return reply == b"\x05\x00"
    except OSError:
        return False


class _ReadinessProbeWorker(QThread):
    """Verifies real remote server reachability and local proxy/TUN readiness off the GUI thread."""

    ready = Signal(int)  # measured_latency_ms
    failed = Signal(str)

    def __init__(
        self,
        mode: ConnectionMode,
        server: ServerRecord,
        local_port: int | None,
        tun_cidr: str | None,
        tun_service: TunService,
        check_remote_tcp: bool = True,
        timeout_sec: float = 8.0,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.mode = mode
        self.server = server
        self.local_port = local_port
        self.tun_cidr = tun_cidr
        self.tun_service = tun_service
        self.check_remote_tcp = check_remote_tcp
        self.timeout_sec = timeout_sec
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        # Step 1: Verify local sing-box inbound or TUN interface is genuinely alive
        deadline = time.monotonic() + self.timeout_sec
        if self.mode == ConnectionMode.SYSTEM_PROXY:
            assert self.local_port is not None
            inbound_ok = False
            while time.monotonic() < deadline and not self._cancelled:
                if verify_socks5_inbound_ready("127.0.0.1", self.local_port, timeout=0.45):
                    inbound_ok = True
                    break
                time.sleep(0.12)
            if self._cancelled:
                return
            if not inbound_ok:
                self.failed.emit(
                    f"Локальный прокси sing-box (127.0.0.1:{self.local_port}) не ответил вовремя."
                )
                return
        else:
            assert self.tun_cidr is not None
            if not self.tun_service.wait_until_interface_up(
                self.tun_cidr, timeout_sec=self.timeout_sec
            ):
                if not self._cancelled:
                    self.failed.emit("Не удалось подтвердить готовность виртуального интерфейса TUN.")
                return

        if self._cancelled:
            return

        # Step 2: Check remote server reachability & measure real initial latency
        rtt_ms = -1
        if self.check_remote_tcp and self.server.protocol not in ("hysteria2", "tuic"):
            rtt_ms = measure_server_tcp_rtt_ms(
                self.server, timeout=min(4.0, self.timeout_sec)
            )
            if self._cancelled:
                return
            if rtt_ms < 0:
                self.failed.emit(
                    f"Удалённый сервер {self.server.endpoint_label} недоступен (тайм-аут или отказ в соединении)."
                )
                return
        elif self.check_remote_tcp:
            # QUIC protocols (Hysteria2 / TUIC): attempt non-fatal TCP RTT if port also listens TCP
            rtt_ms = measure_node_tcp_rtt_ms(self.server.host, self.server.port, timeout=1.5)

        self.ready.emit(rtt_ms)


class ConnectionManager(QObject):
    """Central connection state machine with strict readiness checks and automatic cleanup."""

    state_changed = Signal(object, str)  # (ConnectionState, error_or_info_msg)
    diagnostics_updated = Signal(object)  # DiagnosticInfo
    traffic_updated = Signal(object)  # TrafficStats
    uptime_updated = Signal(int)  # elapsed_seconds
    latency_updated = Signal(int)  # latency_ms

    def __init__(
        self,
        paths: AppPaths,
        repo: DatabaseRepository,
        engine: CoreEngine | None = None,
        proxy_service: SystemProxyService | None = None,
        tun_service: TunService | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.paths = paths
        self.repo = repo
        self.engine = engine or CoreEngine(paths=paths, parent=self)
        self.proxy_service = proxy_service or SystemProxyService(repo=repo)
        self.tun_service = tun_service or TunService()
        self.traffic_monitor = TrafficMonitor(parent=self)

        self._state = ConnectionState.DISCONNECTED
        self._busy_lock = False
        self._active_mode = ConnectionMode.SYSTEM_PROXY
        self._active_server: ServerRecord | None = None
        self._active_local_port: int | None = None
        self._active_tun_cidr: str | None = None
        self._active_history_id: int | None = None
        self._connected_since: float | None = None
        self._probe_worker: _ReadinessProbeWorker | None = None
        self._diag = DiagnosticInfo()

        self._uptime_timer = QTimer(self)
        self._uptime_timer.setInterval(1000)
        self._uptime_timer.timeout.connect(self._tick_uptime)

        self.engine.crashed.connect(self._on_engine_crashed)
        self.traffic_monitor.stats_updated.connect(self.traffic_updated.emit)

        # Recover Windows System Proxy if previous run terminated abnormally
        self.proxy_service.recover_if_dirty()

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def diagnostics(self) -> DiagnosticInfo:
        return self._diag

    @property
    def active_local_port(self) -> int | None:
        return self._active_local_port

    def _set_state(self, new_state: ConnectionState, message: str = "") -> None:
        self._state = new_state
        self._diag.state = new_state
        if new_state == ConnectionState.ERROR:
            self._diag.last_error = message
        elif new_state == ConnectionState.CONNECTED:
            self._diag.last_error = ""
        self.state_changed.emit(new_state, message)
        self.diagnostics_updated.emit(self._diag)

    def connect_to_selected(self, is_reconnect: bool = False) -> bool:
        """Start connection to the currently selected server in SQLite settings."""
        sel_raw = self.repo.get_setting("selected_server_id", "")
        if not sel_raw.isdigit():
            self._fail_transition("Сначала выберите сервер на вкладке «Серверы».")
            return False
        srv = self.repo.get_server(int(sel_raw))
        if srv is None:
            self._fail_transition("Выбранный сервер не найден. Пожалуйста, выберите другой сервер.")
            return False
        return self.connect_to_server(srv, is_reconnect=is_reconnect)

    def connect_to_server(
        self,
        server: ServerRecord,
        is_reconnect: bool = False,
        xray_send_through: str | None = None,
    ) -> bool:
        """Initiate non-blocking connection with full preflight validation."""
        if self._busy_lock or self._state in (
            ConnectionState.CONNECTING,
            ConnectionState.RECONNECTING,
            ConnectionState.DISCONNECTING,
        ):
            log.warning("Повторный запрос на подключение проигнорирован: операция уже выполняется.")
            return False

        if self._state == ConnectionState.CONNECTED and not is_reconnect:
            log.warning("Соединение уже активно.")
            return False

        self._busy_lock = True
        target_transition = (
            ConnectionState.RECONNECTING if is_reconnect else ConnectionState.CONNECTING
        )
        self._set_state(target_transition)

        try:
            mode_str = self.repo.get_setting("connection_mode", ConnectionMode.SYSTEM_PROXY.value)
            mode = (
                ConnectionMode.TUN
                if mode_str == ConnectionMode.TUN.value
                else ConnectionMode.SYSTEM_PROXY
            )
            self._active_mode = mode
            self._active_server = server
            self._diag.mode = mode
            self._diag.warnings.clear()

            core_info = self.engine.ensure_core_ready()
            self._diag.core_version = core_info.version

            if server.protocol in ("hysteria2", "tuic") and not core_info.supports_quic:
                raise CoreEngineError(
                    f"Текущая сборка sing-box ({core_info.version}) не поддерживает QUIC ({server.protocol})."
                )

            local_port: int | None = None
            tun_cidr: str | None = None

            if mode == ConnectionMode.SYSTEM_PROXY:
                if self.repo.get_setting("system_proxy_consent", "1") != "1":
                    raise SystemProxyError(
                        "Изменение системного прокси отключено пользователем в настройках NEXVPN."
                    )
                pref_port_raw = self.repo.get_setting("local_mixed_port", "10808")
                pref_port = int(pref_port_raw) if pref_port_raw.isdigit() else 10808
                if not is_port_available(pref_port):
                    raise SystemProxyError(
                        f"Локальный порт {pref_port} уже занят другим процессом. "
                        "Выберите другой порт в разделе «Настройки»."
                    )
                local_port = pref_port
                self._diag.local_proxy_port = local_port
                self._diag.tun_interface = None
            else:
                tun_cidr, tun_warns = self.tun_service.preflight_check(core_info)
                self._diag.warnings.extend(tun_warns)
                self._diag.local_proxy_port = None
                self._diag.tun_interface = self.tun_service.INTERFACE_NAME

            clash_port = find_free_port() if core_info.supports_clash_api else None
            clash_secret = secrets.token_hex(16) if clash_port else ""

            dns_remote = self.repo.get_setting("dns_remote", "https://1.1.1.1/dns-query")
            dns_direct = self.repo.get_setting("dns_direct", "1.1.1.1")
            bypass_lan = self.repo.get_setting("bypass_lan", "1") == "1"
            tun_stack = self.repo.get_setting("tun_stack", "system")
            tun_strict = self.repo.get_setting("tun_strict_route", "1") == "1"

            uses_xray = node_requires_xray(server.node)
            xray_socks_port: int | None = None
            xray_cfg: dict[str, object] | None = None
            if uses_xray:
                xray_socks_port = find_free_port()
                xray_cfg = generate_xray_bridge_config(
                    node=server.node,
                    socks_port=xray_socks_port,
                    send_through=xray_send_through,
                )

            cfg = generate_sing_box_config(
                node=server.node,
                mode=mode,
                local_mixed_port=local_port or 10808,
                dns_remote=dns_remote,
                dns_direct=dns_direct,
                bypass_lan=bypass_lan,
                tun_interface_name=self.tun_service.INTERFACE_NAME,
                tun_address=tun_cidr or "172.19.0.1/30",
                tun_stack=tun_stack,
                tun_strict_route=tun_strict,
                clash_api_port=clash_port,
                clash_api_secret=clash_secret,
                xray_socks_port=xray_socks_port,
            )

            self._active_local_port = local_port
            self._active_tun_cidr = tun_cidr
            self._active_history_id = self.repo.record_connection_start(
                server_id=server.id,
                server_name=server.display_name,
                protocol=server.protocol_summary,
                mode=mode.value,
            )

            self.engine.start(
                cfg,
                xray_config=xray_cfg,
                xray_socks_port=xray_socks_port,
            )

            # Launch asynchronous readiness probe BEFORE entering CONNECTED
            probe = _ReadinessProbeWorker(
                mode=mode,
                server=server,
                local_port=local_port,
                tun_cidr=tun_cidr,
                tun_service=self.tun_service,
                parent=self,
            )
            probe.ready.connect(
                lambda rtt, cp=clash_port, cs=clash_secret: self._on_probe_ready(rtt, cp, cs)
            )
            probe.failed.connect(self._on_probe_failed)
            self._probe_worker = probe
            probe.start()
            return True

        except (
            CoreNotFoundError,
            CoreVersionError,
            CoreEngineError,
            ConfigGenerationError,
            SystemProxyError,
            TunError,
        ) as exc:
            log.error("Ошибка при подготовке подключения: %s", exc)
            self._cleanup_resources()
            self._busy_lock = False
            self._fail_transition(str(exc))
            return False
        except Exception as exc:
            log.error("Непредвиденная ошибка подключения: %s", exc)
            self._cleanup_resources()
            self._busy_lock = False
            self._fail_transition(f"Внутренняя ошибка подключения: {exc}")
            return False

    def _on_probe_ready(
        self, rtt_ms: int, clash_port: int | None, clash_secret: str
    ) -> None:
        if not self.engine.is_running:
            self._busy_lock = False
            return

        try:
            if self._active_mode == ConnectionMode.SYSTEM_PROXY:
                assert self._active_local_port is not None
                bypass_lan = self.repo.get_setting("bypass_lan", "1") == "1"
                proxy_warns = self.proxy_service.enable(
                    "127.0.0.1", self._active_local_port, bypass_lan=bypass_lan
                )
                self._diag.warnings.extend(proxy_warns)

            if rtt_ms > 0 and self._active_server is not None:
                self._diag.latency_ms = rtt_ms
                self.repo.update_server_latency(self._active_server.id, rtt_ms)
                self.latency_updated.emit(rtt_ms)

            if clash_port:
                self.traffic_monitor.start(clash_port, clash_secret)

            self._connected_since = time.monotonic()
            self._uptime_timer.start()
            if self._active_history_id is not None:
                self.repo.update_connection_history(self._active_history_id, status="CONNECTED")

            self._busy_lock = False
            log.info(
                "Подключение установлено: %s (%s)",
                self._active_server.display_name if self._active_server else "Server",
                self._active_mode.value,
            )
            self._set_state(ConnectionState.CONNECTED)
        except SystemProxyError as exc:
            log.error("Не удалось активировать System Proxy: %s", exc)
            self._cleanup_resources()
            self._busy_lock = False
            self._fail_transition(str(exc))

    def _on_probe_failed(self, reason: str) -> None:
        diag_tail = self.engine.get_diagnostic_tail()
        if self._active_mode == ConnectionMode.TUN and diag_tail:
            reason = self.tun_service.analyze_failure(diag_tail)
        log.error("Проверка готовности соединения не пройдена: %s", reason)
        self._cleanup_resources()
        self._busy_lock = False
        self._fail_transition(reason)

    def disconnect_session(self) -> None:
        """Stop active or pending VPN connection and restore Windows network/proxy settings."""
        if self._state in (ConnectionState.DISCONNECTED, ConnectionState.DISCONNECTING):
            return

        self._busy_lock = True
        self._set_state(ConnectionState.DISCONNECTING)

        if self._probe_worker is not None and self._probe_worker.isRunning():
            self._probe_worker.cancel()
            self._probe_worker.wait(2000)

        stats = self.traffic_monitor.latest
        self._cleanup_resources()

        if self._active_history_id is not None:
            self.repo.update_connection_history(
                self._active_history_id,
                status="DISCONNECTED",
                bytes_up=stats.upload_total,
                bytes_down=stats.download_total,
                ended=True,
            )
            self._active_history_id = None

        self._busy_lock = False
        log.info("Соединение корректно отключено.")
        self._set_state(ConnectionState.DISCONNECTED)

    def reconnect(self) -> bool:
        """Cleanly tear down current session and reconnect to selected server."""
        if self._state in (
            ConnectionState.CONNECTED,
            ConnectionState.CONNECTING,
            ConnectionState.ERROR,
        ):
            self.disconnect_session()
        return self.connect_to_selected(is_reconnect=True)

    def toggle_connection(self) -> None:
        """UI helper for the primary Connect / Cancel / Disconnect button."""
        if self._state in (
            ConnectionState.CONNECTED,
            ConnectionState.CONNECTING,
            ConnectionState.RECONNECTING,
        ):
            self.disconnect_session()
        else:
            self.connect_to_selected(is_reconnect=False)

    def check_active_latency_async(self) -> None:
        """Measure real latency (via local proxy HTTP 204 if connected, else TCP RTT)."""
        sel_raw = self.repo.get_setting("selected_server_id", "")
        if not sel_raw.isdigit():
            return
        srv = self.repo.get_server(int(sel_raw))
        if srv is None:
            return

        use_proxy = (
            self._state == ConnectionState.CONNECTED
            and self._active_mode == ConnectionMode.SYSTEM_PROXY
            and self._active_local_port is not None
        )
        local_port = self._active_local_port

        class _SinglePing(QThread):
            done = Signal(int, int)

            def run(self) -> None:
                if use_proxy and local_port is not None:
                    ms = measure_proxy_roundtrip_ms(local_port)
                    if ms < 0:
                        ms = measure_server_tcp_rtt_ms(srv)
                else:
                    ms = measure_server_tcp_rtt_ms(srv)
                self.done.emit(srv.id, ms)

        worker = _SinglePing(self)
        worker.done.connect(self._on_single_ping_done)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _on_single_ping_done(self, server_id: int, ms: int) -> None:
        self.repo.update_server_latency(server_id, ms)
        self._diag.latency_ms = ms
        self.latency_updated.emit(ms)

    def _on_engine_crashed(self, exit_code: int, diagnostic_tail: str) -> None:
        if self._state == ConnectionState.DISCONNECTING:
            return
        if self._probe_worker is not None and self._probe_worker.isRunning():
            self._probe_worker.cancel()
            self._probe_worker.wait(1500)

        msg = (
            self.tun_service.analyze_failure(diagnostic_tail)
            if self._active_mode == ConnectionMode.TUN
            else f"Процесс sing-box аварийно завершился (код {exit_code}). {diagnostic_tail}"
        )
        self._cleanup_resources()
        self._busy_lock = False
        self._fail_transition(msg)

    def _fail_transition(self, error_msg: str) -> None:
        if self._active_history_id is not None:
            stats = self.traffic_monitor.latest
            self.repo.update_connection_history(
                self._active_history_id,
                status="ERROR",
                bytes_up=stats.upload_total,
                bytes_down=stats.download_total,
                error_message=error_msg[:500],
                ended=True,
            )
            self._active_history_id = None
        self._set_state(ConnectionState.ERROR, error_msg)

    def _cleanup_resources(self) -> None:
        self._uptime_timer.stop()
        self._connected_since = None
        self.traffic_monitor.stop()

        if self.proxy_service.is_active or (
            not self.repo.is_closed
            and self.repo.get_setting(SystemProxyService.BACKUP_SETTING_KEY, "")
        ):
            self.proxy_service.disable()

        self.engine.stop()

        if self._active_mode == ConnectionMode.TUN and self._active_tun_cidr:
            self.tun_service.verify_cleanup(self._active_tun_cidr)

        self._active_local_port = None
        self._active_tun_cidr = None

    def _tick_uptime(self) -> None:
        if self._connected_since is not None and self._state == ConnectionState.CONNECTED:
            elapsed = int(time.monotonic() - self._connected_since)
            self.uptime_updated.emit(elapsed)

    def shutdown(self) -> None:
        """Guaranteed cleanup hook called on application exit."""
        if self._state != ConnectionState.DISCONNECTED:
            self.disconnect_session()
        else:
            self._cleanup_resources()
