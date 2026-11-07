"""Stage 8 real end-to-end integration tests with local sing-box VPN server + local HTTP target server."""

from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import winreg

import httpx
import pytest

from nexvpn.connection.manager import ConnectionManager
from nexvpn.connection.states import ConnectionMode, ConnectionState
from nexvpn.core.engine import CoreEngine
from nexvpn.core.locator import locate_sing_box
from nexvpn.database.repository import DatabaseRepository
from nexvpn.services import tun_service
from nexvpn.services.system_proxy import SystemProxyService
from nexvpn.subscription.parsers import parse_proxy_uri
from nexvpn.utils.network import find_free_port, is_local_port_listening
from nexvpn.utils.paths import AppPaths

TEST_INT_PROXY_SUBKEY = r"Software\NEXVPN_Pytest_E2E_InternetSettings"


@pytest.fixture()
def clean_e2e_reg() -> object:
    if sys.platform == "win32":
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, TEST_INT_PROXY_SUBKEY)
        except FileNotFoundError:
            pass
    yield
    if sys.platform == "win32":
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, TEST_INT_PROXY_SUBKEY)
        except FileNotFoundError:
            pass


def _make_test_paths(tmp_path: Path) -> AppPaths:
    real = AppPaths.resolve()
    paths = AppPaths(
        root_dir=real.root_dir,
        bundle_dir=real.bundle_dir,
        core_dir=real.core_dir,
        data_dir=tmp_path / "data",
        runtime_dir=tmp_path / "data" / "runtime",
        logs_dir=tmp_path / "logs",
        assets_dir=real.assets_dir,
        db_file=tmp_path / "data" / "nexvpn.db",
        log_file=tmp_path / "logs" / "nexvpn.log",
    )
    paths.ensure_directories()
    return paths


def test_real_end_to_end_vpn_tunnel_reconnect_crash_and_edge_cases(
    qtbot, tmp_path: Path, clean_e2e_reg: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 1. Start local target HTTP server (origin)
    class _TargetHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = b"NEXVPN_REAL_TUNNEL_VERIFIED_200"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    origin_http = HTTPServer(("127.0.0.1", 0), _TargetHandler)
    origin_port = origin_http.server_port
    threading.Thread(target=origin_http.serve_forever, daemon=True).start()

    # 2. Start a REAL local sing-box VPN server (Shadowsocks 2022)
    ss_key = base64.b64encode(b"0123456789abcdef").decode("ascii")
    vpn_server_port = find_free_port()
    server_cfg = {
        "log": {"level": "error"},
        "inbounds": [
            {
                "type": "shadowsocks",
                "tag": "ss-in",
                "listen": "127.0.0.1",
                "listen_port": vpn_server_port,
                "method": "2022-blake3-aes-128-gcm",
                "password": ss_key,
            }
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    server_cfg_file = tmp_path / "local_vpn_server.json"
    server_cfg_file.write_text(json.dumps(server_cfg), encoding="utf-8")

    singbox_bin = locate_sing_box()
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    server_proc = subprocess.Popen(
        [str(singbox_bin), "run", "-c", str(server_cfg_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creationflags,
    )

    paths = _make_test_paths(tmp_path)
    repo = DatabaseRepository(paths.db_file)
    proxy_svc = SystemProxyService(
        repo=repo, registry_subkey=TEST_INT_PROXY_SUBKEY, notify_wininet=False
    )
    engine = CoreEngine(paths=paths, mutex_name="Local\\NEXVPN_E2E_Client_Mutex")
    conn_mgr = ConnectionManager(
        paths=paths, repo=repo, engine=engine, proxy_service=proxy_svc
    )

    try:
        # Wait until local sing-box VPN server is listening
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not is_local_port_listening(vpn_server_port):
            time.sleep(0.1)
        assert is_local_port_listening(vpn_server_port) is True

        # Add server to SQLite repository
        uri = f"ss://2022-blake3-aes-128-gcm:{ss_key}@127.0.0.1:{vpn_server_port}#Local-E2E-Server"
        node = parse_proxy_uri(uri)
        # Note: client config bypass_lan=False so 127.0.0.1 origin goes THROUGH proxy-out VPN tunnel!
        repo.set_setting("bypass_lan", "0")
        added = repo.add_standalone_servers([node])
        srv_rec = added[0]
        repo.set_setting("selected_server_id", str(srv_rec.id))

        # --- EDGE CASE A: Busy local port ---
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
            blocker.bind(("127.0.0.1", 0))
            blocker.listen(2)
            busy_port = blocker.getsockname()[1]
            repo.set_setting("local_mixed_port", str(busy_port))

            assert conn_mgr.connect_to_selected() is False
            assert conn_mgr.state == ConnectionState.ERROR
            assert str(busy_port) in conn_mgr.diagnostics.last_error
            assert proxy_svc.read_current_state().proxy_enable in (None, 0)

        # --- REAL CONNECTION OVER SYSTEM PROXY ---
        client_mixed_port = find_free_port()
        repo.set_setting("local_mixed_port", str(client_mixed_port))

        states_seen: list[ConnectionState] = []
        conn_mgr.state_changed.connect(lambda st, _m: states_seen.append(st))

        assert conn_mgr.connect_to_selected() is True
        qtbot.waitUntil(lambda: conn_mgr.state == ConnectionState.CONNECTED, timeout=8000)

        assert ConnectionState.CONNECTING in states_seen
        assert conn_mgr.state == ConnectionState.CONNECTED
        assert proxy_svc.read_current_state().proxy_enable == 1
        assert proxy_svc.read_current_state().proxy_server == f"127.0.0.1:{client_mixed_port}"

        # Send REAL HTTP traffic through both HTTP proxy and SOCKS5 proxy of sing-box!
        for proxy_scheme in ("http", "socks5"):
            with httpx.Client(
                proxy=f"{proxy_scheme}://127.0.0.1:{client_mixed_port}",
                timeout=5.0,
                trust_env=False,
            ) as client:
                r = client.get(f"http://127.0.0.1:{origin_port}/check")
                assert r.status_code == 200
                assert r.text == "NEXVPN_REAL_TUNNEL_VERIFIED_200"

        # --- EDGE CASE B: Reconnect (`RECONNECTING` -> `CONNECTED`) ---
        assert conn_mgr.reconnect() is True
        qtbot.waitUntil(lambda: conn_mgr.state == ConnectionState.CONNECTED, timeout=8000)
        assert ConnectionState.RECONNECTING in states_seen

        # Verify tunnel still works after reconnect
        with httpx.Client(
            proxy=f"http://127.0.0.1:{client_mixed_port}",
            timeout=5.0,
            trust_env=False,
        ) as client:
            r2 = client.get(f"http://127.0.0.1:{origin_port}/check")
            assert r2.text == "NEXVPN_REAL_TUNNEL_VERIFIED_200"

        # --- EDGE CASE C: Abnormal crash of sing-box mid-session ---
        assert engine._proc is not None
        engine._proc.kill()
        qtbot.waitUntil(lambda: conn_mgr.state == ConnectionState.ERROR, timeout=5000)
        # System proxy MUST be automatically disabled on crash!
        assert proxy_svc.read_current_state().proxy_enable == 0

        # --- EDGE CASE D: Offline / unreachable VPN server ---
        closed_port = find_free_port()
        dead_node = parse_proxy_uri(
            f"ss://2022-blake3-aes-128-gcm:{ss_key}@127.0.0.1:{closed_port}#OfflineServer"
        )
        dead_rec = repo.add_standalone_servers([dead_node])[0]
        repo.set_setting("selected_server_id", str(dead_rec.id))
        conn_mgr.connect_to_selected()
        qtbot.waitUntil(lambda: conn_mgr.state == ConnectionState.ERROR, timeout=8000)
        assert proxy_svc.read_current_state().proxy_enable == 0

        # --- EDGE CASE E: Insufficient privileges in TUN mode ---
        monkeypatch.setattr(tun_service, "is_running_as_admin", lambda: False)
        repo.set_setting("connection_mode", ConnectionMode.TUN.value)
        repo.set_setting("selected_server_id", str(srv_rec.id))
        assert conn_mgr.connect_to_selected() is False
        assert conn_mgr.state == ConnectionState.ERROR
        assert "администратора" in conn_mgr.diagnostics.last_error.lower()

        # Switch back to System Proxy, connect cleanly, then disconnect cleanly
        repo.set_setting("connection_mode", ConnectionMode.SYSTEM_PROXY.value)
        assert conn_mgr.connect_to_selected() is True
        qtbot.waitUntil(lambda: conn_mgr.state == ConnectionState.CONNECTED, timeout=8000)
        conn_mgr.disconnect_session()
        assert conn_mgr.state == ConnectionState.DISCONNECTED
        assert proxy_svc.read_current_state().proxy_enable == 0

        # Verify connection history recorded in SQLite
        history = repo.list_connection_history()
        assert len(history) >= 3
    finally:
        conn_mgr.shutdown()
        repo.close()
        server_proc.terminate()
        try:
            server_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server_proc.kill()
        origin_http.shutdown()
