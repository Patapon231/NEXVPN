"""Tests for XHTTP transport, Xray/Happ JSON subscriptions, cluster balancing, and real local XHTTP E2E tunnel."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
import winreg

import httpx
import pytest

from nexvpn.connection.manager import ConnectionManager
from nexvpn.connection.states import ConnectionMode, ConnectionState
from nexvpn.core.config_generator import (
    ConfigGenerationError,
    build_proxy_outbound,
    generate_sing_box_config,
    generate_xray_bridge_config,
    node_requires_xray,
)
from nexvpn.core.engine import CoreEngine
from nexvpn.core.locator import locate_sing_box, locate_xray
from nexvpn.database.repository import DatabaseRepository
from nexvpn.services.system_proxy import SystemProxyService
from nexvpn.subscription.parsers import parse_proxy_uri, parse_subscription_payload
from nexvpn.utils.network import find_free_port, is_local_port_listening
from nexvpn.utils.paths import AppPaths

TEST_XHTTP_PROXY_SUBKEY = r"Software\NEXVPN_Pytest_XHTTP_InternetSettings"


@pytest.fixture()
def clean_xhttp_reg() -> object:
    if sys.platform == "win32":
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, TEST_XHTTP_PROXY_SUBKEY)
        except FileNotFoundError:
            pass
    yield
    if sys.platform == "win32":
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, TEST_XHTTP_PROXY_SUBKEY)
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


def test_parse_vless_xhttp_tls_uri_and_never_substitute_reality() -> None:
    uri = (
        "vless://11111111-2222-3333-4444-555555555555@de-xhttp.example.com:8443"
        "?encryption=none&security=tls&sni=cdn.example.com&alpn=h2&fp=firefox"
        "&type=xhttp&path=%2Fvpnxhttp&mode=auto"
        "&extra=%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A%2216-32%22%7D%7D"
        "#DE%20XHTTP"
    )
    node = parse_proxy_uri(uri)
    assert node.protocol == "vless"
    assert node.name == "DE XHTTP"
    assert node.host == "de-xhttp.example.com"
    assert node.port == 8443
    assert node.transport.type == "xhttp"
    assert node.transport.path == "/vpnxhttp"
    assert node.transport.mode == "auto"
    assert node.transport.extra == {"xmux": {"maxConcurrency": "16-32"}}
    assert node.tls.enabled is True
    assert node.tls.reality_enabled is False
    assert node.tls.server_name == "cdn.example.com"
    assert node.tls.alpn == ["h2"]
    assert node.tls.utls_fingerprint == "firefox"
    assert node_requires_xray(node) is True

    # Calling sing-box direct outbound builder without Xray bridge must fail explicitly, never downgrade
    with pytest.raises(ConfigGenerationError):
        build_proxy_outbound(node)


def test_parse_xray_json_array_subscription_and_validate_configs(tmp_path: Path) -> None:
    sample_happ_json = json.dumps(
        [
            {
                "remarks": "🇩🇪 Germany XHTTP Cluster",
                "outbounds": [
                    {
                        "tag": "proxy",
                        "protocol": "vless",
                        "settings": {
                            "vnext": [
                                {
                                    "address": "de1.example.com",
                                    "port": 8443,
                                    "users": [
                                        {
                                            "id": "11111111-2222-3333-4444-555555555555",
                                            "encryption": "none",
                                        }
                                    ],
                                }
                            ]
                        },
                        "streamSettings": {
                            "network": "xhttp",
                            "security": "tls",
                            "tlsSettings": {
                                "serverName": "example.com",
                                "alpn": ["h2"],
                                "fingerprint": "firefox",
                            },
                            "xhttpSettings": {
                                "path": "/vpnxhttp",
                                "mode": "auto",
                            },
                        },
                    },
                    {
                        "tag": "proxy-2",
                        "protocol": "vless",
                        "settings": {
                            "vnext": [
                                {
                                    "address": "198.51.100.67",
                                    "port": 8443,
                                    "users": [
                                        {
                                            "id": "11111111-2222-3333-4444-555555555555",
                                            "encryption": "none",
                                        }
                                    ],
                                }
                            ]
                        },
                        "streamSettings": {
                            "network": "xhttp",
                            "security": "tls",
                            "tlsSettings": {
                                "serverName": "example.com",
                                "alpn": ["h2"],
                                "fingerprint": "firefox",
                            },
                            "xhttpSettings": {
                                "path": "/vpnxhttp",
                                "mode": "auto",
                            },
                        },
                    },
                    {
                        "tag": "RU",
                        "protocol": "socks",
                        "settings": {"servers": [{"address": "ru-helper.example.net", "port": 37001}]},
                    },
                    {"tag": "direct", "protocol": "freedom", "settings": {}},
                ],
            },
            {
                "remarks": "Direct-Only Placeholder",
                "outbounds": [
                    {"tag": "direct", "protocol": "freedom", "settings": {}},
                    {"tag": "block", "protocol": "blackhole", "settings": {}},
                ],
            },
        ]
    )

    nodes, warnings = parse_subscription_payload(sample_happ_json)
    assert len(nodes) == 1
    assert len(warnings) == 1  # placeholder skipped with warning

    de_node = nodes[0]
    assert de_node.name == "🇩🇪 Germany XHTTP Cluster"
    assert de_node.protocol == "vless"
    assert de_node.host == "de1.example.com"
    assert de_node.port == 8443
    assert de_node.transport.type == "xhttp"
    assert de_node.tls.enabled is True
    assert de_node.tls.reality_enabled is False
    assert len(de_node.additional_outbounds) == 1
    assert de_node.iter_cluster_nodes()[1].host == "198.51.100.67"

    # Persist & reload through SQLite DPAPI repository to verify roundtrip serialization + protocol_summary
    paths = _make_test_paths(tmp_path)
    repo = DatabaseRepository(paths.db_file)
    try:
        rec = repo.add_standalone_servers([de_node])[0]
        assert rec.protocol_summary == "VLESS / XHTTP / TLS"
        assert len(rec.node.additional_outbounds) == 1

        engine = CoreEngine(paths=paths, mutex_name="Local\\NEXVPN_XrayValidateTest")
        bridge_port = find_free_port()
        xray_cfg = generate_xray_bridge_config(rec.node, socks_port=bridge_port)
        engine.validate_xray_config(xray_cfg)

        for mode in (ConnectionMode.SYSTEM_PROXY, ConnectionMode.TUN):
            sb_cfg = generate_sing_box_config(
                node=rec.node,
                mode=mode,
                local_mixed_port=find_free_port(),
                xray_socks_port=bridge_port,
            )
            engine.validate_config(sb_cfg)
    finally:
        repo.close()


def test_real_local_vless_xhttp_tunnel_end_to_end(
    qtbot, tmp_path: Path, clean_xhttp_reg: object
) -> None:
    """Spin up a real local Xray VLESS+XHTTP server and verify NEXVPN routes HTTP traffic through it."""

    class _OriginHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = b"NEXVPN_XHTTP_TUNNEL_OK_DE"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    origin = HTTPServer(("127.0.0.1", 0), _OriginHandler)
    origin_port = origin.server_port
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    test_uuid = "a1b2c3d4-e5f6-4789-abcd-ef0123456789"
    relay_socks_port = find_free_port()
    xhttp_server_port = find_free_port()

    # Local sing-box SOCKS5 -> direct relay behind mock Xray server (avoids Xray v26 freedom loopback SSRF block)
    relay_cfg = {
        "log": {"level": "error"},
        "inbounds": [
            {
                "type": "socks",
                "tag": "relay-in",
                "listen": "127.0.0.1",
                "listen_port": relay_socks_port,
            }
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    relay_cfg_path = tmp_path / "local_relay.json"
    relay_cfg_path.write_text(json.dumps(relay_cfg), encoding="utf-8")

    server_cfg = {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "tag": "vless-xhttp-in",
                "listen": "127.0.0.1",
                "port": xhttp_server_port,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": test_uuid}],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "none",
                    "xhttpSettings": {
                        "path": "/vpnxhttp",
                        "mode": "auto",
                    },
                },
            }
        ],
        "outbounds": [
            {
                "protocol": "socks",
                "tag": "to-origin",
                "settings": {
                    "servers": [{"address": "127.0.0.1", "port": relay_socks_port}]
                },
            }
        ],
    }
    server_cfg_path = tmp_path / "local_xray_xhttp_server.json"
    server_cfg_path.write_text(json.dumps(server_cfg), encoding="utf-8")

    singbox_bin = locate_sing_box()
    xray_bin = locate_xray()
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    relay_proc = subprocess.Popen(
        [str(singbox_bin), "run", "-c", str(relay_cfg_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creationflags,
    )
    server_proc = subprocess.Popen(
        [str(xray_bin), "run", "-c", str(server_cfg_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creationflags,
    )

    paths = _make_test_paths(tmp_path)
    repo = DatabaseRepository(paths.db_file)
    proxy_svc = SystemProxyService(
        repo=repo, registry_subkey=TEST_XHTTP_PROXY_SUBKEY, notify_wininet=False
    )
    engine = CoreEngine(paths=paths, mutex_name="Local\\NEXVPN_XHTTP_E2E_Mutex")
    conn_mgr = ConnectionManager(
        paths=paths, repo=repo, engine=engine, proxy_service=proxy_svc
    )

    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not (
            is_local_port_listening(relay_socks_port) and is_local_port_listening(xhttp_server_port)
        ):
            time.sleep(0.1)
        assert is_local_port_listening(relay_socks_port) is True
        assert is_local_port_listening(xhttp_server_port) is True

        uri = (
            f"vless://{test_uuid}@127.0.0.1:{xhttp_server_port}"
            "?encryption=none&security=none&type=xhttp&path=%2Fvpnxhttp&mode=auto#Local-XHTTP"
        )
        node = parse_proxy_uri(uri)
        repo.set_setting("bypass_lan", "0")
        mixed_port = find_free_port()
        repo.set_setting("local_mixed_port", str(mixed_port))
        srv_rec = repo.add_standalone_servers([node])[0]
        repo.set_setting("selected_server_id", str(srv_rec.id))

        assert conn_mgr.connect_to_selected() is True
        qtbot.waitUntil(lambda: conn_mgr.state == ConnectionState.CONNECTED, timeout=8000)

        with httpx.Client(
            proxy=f"http://127.0.0.1:{mixed_port}",
            timeout=5.0,
            trust_env=False,
        ) as client:
            resp = client.get(f"http://127.0.0.1:{origin_port}/verify")
            assert resp.status_code == 200
            assert resp.text == "NEXVPN_XHTTP_TUNNEL_OK_DE"

        conn_mgr.disconnect_session()
        assert conn_mgr.state == ConnectionState.DISCONNECTED
        assert not (paths.runtime_dir / "active_config.json").exists()
        assert not (paths.runtime_dir / "active_xray.json").exists()
    finally:
        conn_mgr.shutdown()
        repo.close()
        for p in (server_proc, relay_proc):
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
        origin.shutdown()
