"""Stage 4 tests: sing-box v1.14 config generation + real `sing-box check -c` + QProcess engine lifecycle & crash detection."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from nexvpn.connection.states import ConnectionMode
from nexvpn.core.config_generator import generate_sing_box_config
from nexvpn.core.engine import (
    CoreAlreadyRunningError,
    CoreConfigInvalidError,
    CoreEngine,
)
from nexvpn.subscription.parsers import parse_proxy_uri
from nexvpn.utils.network import find_free_port
from nexvpn.utils.paths import AppPaths


SAMPLE_URIS = [
    # VLESS Reality ( requires valid 32-byte base64url public key and hex short_id for real `sing-box check`! )
    (
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@de.example.com:443"
        "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com"
        "&fp=chrome&pbk=mFX2p9G5_8vX2k9L4n6P8r0T2v4X6z8B0d2F4h6J8lA&sid=0123456789abcdef&type=tcp#VLESS-Reality"
    ),
    # VLESS WS TLS
    (
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@ws.example.com:443"
        "?security=tls&type=ws&host=ws.example.com&path=%2Fws#VLESS-WS"
    ),
    # VMess gRPC TLS
    "vmess://"
    + base64.b64encode(
        json.dumps(
            {
                "v": "2",
                "ps": "VMess-gRPC",
                "add": "vmess.example.com",
                "port": 443,
                "id": "27848739-7e62-4138-9fd3-098a63964b6b",
                "aid": 0,
                "scy": "auto",
                "net": "grpc",
                "path": "myGrpcSvc",
                "tls": "tls",
                "sni": "vmess.example.com",
            }
        ).encode("utf-8")
    ).decode("ascii"),
    # Trojan HTTPUpgrade TLS
    (
        "trojan://myTrojanSecret@tr.example.com:443"
        "?security=tls&type=httpupgrade&host=tr.example.com&path=%2Fupgrade#Trojan-Upgrade"
    ),
    # Shadowsocks 2022
    "ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw%3D%3D@ss.example.com:8388#SS-2022",
    # Hysteria2 with Salamander obfs
    (
        "hysteria2://hyPass123@hy.example.com:443"
        "?sni=hy.example.com&obfs=salamander&obfs-password=obfsSecret&upmbps=100&downmbps=300#HY2"
    ),
    # TUIC v5
    (
        "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:tuicSecret@tuic.example.com:443"
        "?congestion_control=bbr&udp_relay_mode=native&sni=tuic.example.com#TUIC"
    ),
]


@pytest.mark.parametrize("uri", SAMPLE_URIS)
@pytest.mark.parametrize("mode", [ConnectionMode.SYSTEM_PROXY, ConnectionMode.TUN])
def test_generated_configs_pass_real_sing_box_check(
    uri: str, mode: ConnectionMode, tmp_path: Path
) -> None:
    paths = AppPaths(
        root_dir=AppPaths.resolve().root_dir,
        bundle_dir=AppPaths.resolve().bundle_dir,
        core_dir=AppPaths.resolve().core_dir,
        data_dir=tmp_path / "data",
        runtime_dir=tmp_path / "data" / "runtime",
        logs_dir=tmp_path / "logs",
        assets_dir=AppPaths.resolve().assets_dir,
        db_file=tmp_path / "data" / "nexvpn.db",
        log_file=tmp_path / "logs" / "nexvpn.log",
    )
    paths.ensure_directories()

    node = parse_proxy_uri(uri)
    clash_port = find_free_port()
    mixed_port = find_free_port()
    cfg = generate_sing_box_config(
        node=node,
        mode=mode,
        local_mixed_port=mixed_port,
        dns_remote="https://cloudflare-dns.com/dns-query",
        dns_direct="1.1.1.1",
        clash_api_port=clash_port,
        clash_api_secret="test_secret_123",
    )

    engine = CoreEngine(paths=paths, mutex_name=f"Local\\NEXVPN_CfgCheck_{id(cfg)}")
    # Runs real `sing-box.exe check -c`!
    engine.validate_config(cfg)


def test_invalid_config_rejected_by_sing_box_check(tmp_path: Path) -> None:
    real_paths = AppPaths.resolve()
    paths = AppPaths(
        root_dir=real_paths.root_dir,
        bundle_dir=real_paths.bundle_dir,
        core_dir=real_paths.core_dir,
        data_dir=tmp_path / "data",
        runtime_dir=tmp_path / "data" / "runtime",
        logs_dir=tmp_path / "logs",
        assets_dir=real_paths.assets_dir,
        db_file=tmp_path / "data" / "nexvpn.db",
        log_file=tmp_path / "logs" / "nexvpn.log",
    )
    paths.ensure_directories()
    engine = CoreEngine(paths=paths, mutex_name="Local\\NEXVPN_InvalidCfgTest")
    with pytest.raises(CoreConfigInvalidError):
        engine.validate_config({"inbounds": [{"type": "nonexistent_inbound_xyz"}]})


def test_engine_start_duplicate_guard_crash_detection_and_stop(qtbot, tmp_path: Path) -> None:
    real_paths = AppPaths.resolve()
    paths = AppPaths(
        root_dir=real_paths.root_dir,
        bundle_dir=real_paths.bundle_dir,
        core_dir=real_paths.core_dir,
        data_dir=tmp_path / "data",
        runtime_dir=tmp_path / "data" / "runtime",
        logs_dir=tmp_path / "logs",
        assets_dir=real_paths.assets_dir,
        db_file=tmp_path / "data" / "nexvpn.db",
        log_file=tmp_path / "logs" / "nexvpn.log",
    )
    paths.ensure_directories()

    node = parse_proxy_uri(
        "ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw%3D%3D@127.0.0.1:19999#LocalTest"
    )
    port = find_free_port()
    cfg = generate_sing_box_config(node=node, mode=ConnectionMode.SYSTEM_PROXY, local_mixed_port=port)

    engine = CoreEngine(paths=paths, mutex_name="Local\\NEXVPN_EngineLifecycleTest")
    try:
        engine.start(cfg)
        assert engine.is_running is True
        assert engine.pid is not None

        # Duplicate start on same or second engine with same mutex must fail
        with pytest.raises(CoreAlreadyRunningError):
            engine.start(cfg)

        engine2 = CoreEngine(paths=paths, mutex_name="Local\\NEXVPN_EngineLifecycleTest")
        with pytest.raises(CoreAlreadyRunningError):
            engine2.start(cfg)

        # Simulate unexpected external kill/crash of sing-box process -> crashed signal MUST fire!
        crashed_events: list[tuple[int, str]] = []
        engine.crashed.connect(lambda code, tail: crashed_events.append((code, tail)))
        assert engine._proc is not None
        engine._proc.kill()
        qtbot.waitUntil(lambda: len(crashed_events) == 1, timeout=4000)
        assert engine.is_running is False

        # Restart and test clean graceful stop() -> stopped signal, NOT crashed!
        stopped_events: list[int] = []
        engine.stopped.connect(lambda code: stopped_events.append(code))
        engine.start(cfg)
        assert engine.is_running is True
        engine.stop()
        assert engine.is_running is False
        assert len(crashed_events) == 1  # did not increment on normal stop
        assert len(stopped_events) == 1
        # Config file with credentials must be wiped after stop
        assert not (paths.runtime_dir / "active_config.json").exists()
    finally:
        engine.stop()
