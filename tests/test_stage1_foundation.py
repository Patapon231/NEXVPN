"""Stage 1 foundation tests: paths, secret redaction, network port checks, core locator, UI window."""

from __future__ import annotations

import socket
from pathlib import Path

from nexvpn.core.locator import inspect_sing_box, locate_sing_box
from nexvpn.ui.main_window import MainWindow
from nexvpn.utils.logger import InMemoryLogHandler, redact_secrets, setup_logging
from nexvpn.utils.network import find_free_port, is_port_available, measure_tcp_latency_ms
from nexvpn.utils.paths import AppPaths, restrict_path_to_current_user
from nexvpn.utils.single_instance import SingleInstanceGuard


def test_app_paths_and_acl(tmp_path: Path) -> None:
    paths = AppPaths.resolve(tmp_path)
    paths.ensure_directories()
    assert paths.core_dir.is_dir()
    assert paths.data_dir.is_dir()
    assert paths.runtime_dir.is_dir()
    assert paths.logs_dir.is_dir()

    secret_cfg = paths.runtime_dir / "test_cfg.json"
    secret_cfg.write_text("{}", encoding="utf-8")
    assert restrict_path_to_current_user(secret_cfg) is True


def test_secret_redaction_filter() -> None:
    raw = (
        "Updating sub https://panel.example.org/api/v1/sub?token=abc999xyz "
        "node vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?security=tls#DE "
        'and {"password": "mySuperSecretPassword123"} uuid=123e4567-e89b-12d3-a456-426614174000'
    )
    cleaned = redact_secrets(raw)
    assert "abc999xyz" not in cleaned
    assert "b831381d-6324-4d53-ad4f-8cda48b30811" not in cleaned
    assert "mySuperSecretPassword123" not in cleaned
    assert "123e4567-e89b-12d3-a456-426614174000" not in cleaned
    assert "https://panel.example.org/<REDACTED_URL_PATH>" in cleaned
    assert "<REDACTED_PROXY_URI>" in cleaned


def test_port_availability_and_real_tcp_latency() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        busy_port = srv.getsockname()[1]

        assert is_port_available(busy_port) is False
        rtt = measure_tcp_latency_ms("127.0.0.1", busy_port, timeout=1.0)
        assert rtt is not None and rtt >= 1

        alt_port = find_free_port(preferred=busy_port)
        assert alt_port != busy_port
        assert is_port_available(alt_port) is True


def test_single_instance_mutex() -> None:
    name = "Local\\NEXVPN_UnitTest_Mutex_Stage1"
    g1 = SingleInstanceGuard(name)
    g2 = SingleInstanceGuard(name)
    try:
        assert g1.acquire() is True
        assert g2.acquire() is False
    finally:
        g1.release()
    assert g2.acquire() is True
    g2.release()


def test_sing_box_locator_and_version() -> None:
    bin_path = locate_sing_box()
    info = inspect_sing_box(bin_path)
    assert info.major >= 1
    assert info.minor >= 12
    assert info.supports_quic is True
    assert info.supports_clash_api is True


def test_main_window_navigation(qtbot, tmp_path: Path) -> None:
    paths = AppPaths.resolve(tmp_path)
    paths.ensure_directories()
    handler: InMemoryLogHandler = setup_logging(paths.log_file)
    win = MainWindow(paths=paths, log_handler=handler)
    qtbot.addWidget(win)

    for key in ("dashboard", "servers", "subscriptions", "settings", "logs"):
        win.switch_page(key)
        assert win.stack.currentWidget() is win._pages[key]

    win.set_language("en")
    assert win._nav_buttons["dashboard"].text() == "Dashboard"
    win.set_language("ru")
    assert win._nav_buttons["dashboard"].text() == "Панель"
