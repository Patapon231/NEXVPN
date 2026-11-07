"""Stage 3 tests: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC parsers, containers, and invalid inputs."""

from __future__ import annotations

import base64
import json

import pytest

from nexvpn.subscription.parsers import (
    ProtocolParseError,
    parse_proxy_uri,
    parse_subscription_payload,
)


def test_parse_vless_reality_and_ws() -> None:
    uri_reality = (
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@198.51.100.10:443"
        "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com"
        "&fp=chrome&pbk=9234567890abcdef_test_pbk&sid=a1b2c3d4&type=tcp#DE%20Reality"
    )
    node = parse_proxy_uri(uri_reality)
    assert node.protocol == "vless"
    assert node.name == "DE Reality"
    assert node.host == "198.51.100.10"
    assert node.port == 443
    assert node.uuid == "b831381d-6324-4d53-ad4f-8cda48b30811"
    assert node.flow == "xtls-rprx-vision"
    assert node.tls.enabled is True
    assert node.tls.reality_enabled is True
    assert node.tls.reality_public_key == "9234567890abcdef_test_pbk"
    assert node.tls.reality_short_id == "a1b2c3d4"
    assert node.tls.server_name == "www.microsoft.com"

    uri_ws = (
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@[2001:db8::1]:8443"
        "?security=tls&type=ws&host=cdn.example.com&path=%2Fws-stream&alpn=h2%2Chttp%2F1.1#IPv6-WS"
    )
    ws_node = parse_proxy_uri(uri_ws)
    assert ws_node.host == "2001:db8::1"
    assert ws_node.port == 8443
    assert ws_node.transport.type == "ws"
    assert ws_node.transport.path == "/ws-stream"
    assert ws_node.transport.host == "cdn.example.com"
    assert ws_node.tls.alpn == ["h2", "http/1.1"]


def test_parse_vmess_base64_json_and_uri() -> None:
    vmess_obj = {
        "v": "2",
        "ps": "Tokyo VMess WS",
        "add": "jp.example.net",
        "port": "443",
        "id": "27848739-7e62-4138-9fd3-098a63964b6b",
        "aid": "0",
        "scy": "chacha20-poly1305",
        "net": "ws",
        "type": "none",
        "host": "jp.example.net",
        "path": "/v2",
        "tls": "tls",
        "sni": "jp.example.net",
        "fp": "firefox",
    }
    b64 = base64.b64encode(json.dumps(vmess_obj).encode("utf-8")).decode("ascii")
    node = parse_proxy_uri(f"vmess://{b64}")
    assert node.protocol == "vmess"
    assert node.name == "Tokyo VMess WS"
    assert node.host == "jp.example.net"
    assert node.port == 443
    assert node.uuid == "27848739-7e62-4138-9fd3-098a63964b6b"
    assert node.method == "chacha20-poly1305"
    assert node.transport.type == "ws"
    assert node.transport.path == "/v2"
    assert node.tls.enabled is True
    assert node.tls.utls_fingerprint == "firefox"


def test_parse_trojan_grpc_with_special_password() -> None:
    uri = (
        "trojan://p%40ss%3Aw0rd!@tr.example.com:443"
        "?security=tls&type=grpc&serviceName=gunService&sni=tr.example.com#Trojan-gRPC"
    )
    node = parse_proxy_uri(uri)
    assert node.protocol == "trojan"
    assert node.password == "p@ss:w0rd!"
    assert node.transport.type == "grpc"
    assert node.transport.service_name == "gunService"
    assert node.tls.enabled is True


def test_parse_shadowsocks_sip002_ss2022_and_legacy() -> None:
    # SIP002 Base64 userinfo
    creds = base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:my-secret-pw").decode("ascii").rstrip("=")
    sip002 = f"ss://{creds}@ss1.example.com:8388#SS-SIP002"
    n1 = parse_proxy_uri(sip002)
    assert n1.protocol == "shadowsocks"
    assert n1.method == "chacha20-ietf-poly1305"
    assert n1.password == "my-secret-pw"
    assert n1.port == 8388

    # Plain SS-2022 userinfo with URL-encoded base64 key
    ss2022 = "ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw%3D%3D@ss2.example.com:9000#SS2022"
    n2 = parse_proxy_uri(ss2022)
    assert n2.method == "2022-blake3-aes-128-gcm"
    assert n2.password == "AAECAwQFBgcICQoLDA0ODw=="

    # Legacy full-Base64 format
    legacy_raw = base64.b64encode(b"aes-256-gcm:legacyPass@192.0.2.55:4433").decode("ascii")
    n3 = parse_proxy_uri(f"ss://{legacy_raw}#LegacySS")
    assert n3.host == "192.0.2.55"
    assert n3.port == 4433
    assert n3.password == "legacyPass"


def test_parse_hysteria2_and_tuic() -> None:
    hy2 = (
        "hy2://hySecretAuth@quic.example.com:443"
        "?sni=quic.example.com&obfs=salamander&obfs-password=obfsKey99&upmbps=50&downmbps=200#HY2-Node"
    )
    nh = parse_proxy_uri(hy2)
    assert nh.protocol == "hysteria2"
    assert nh.password == "hySecretAuth"
    assert nh.obfs_type == "salamander"
    assert nh.obfs_password == "obfsKey99"
    assert nh.up_mbps == 50
    assert nh.down_mbps == 200
    assert nh.tls.enabled is True

    tuic = (
        "tuic://11111111-2222-3333-4444-555555555555:tuicPass@tuic.example.com:8443"
        "?congestion_control=bbr&udp_relay_mode=native&sni=tuic.example.com#TUIC-Node"
    )
    nt = parse_proxy_uri(tuic)
    assert nt.protocol == "tuic"
    assert nt.uuid == "11111111-2222-3333-4444-555555555555"
    assert nt.password == "tuicPass"
    assert nt.congestion_control == "bbr"


def test_subscription_containers_and_malformed_data() -> None:
    plain_list = (
        "# Subscription comment\n"
        "trojan://pw1@a.example.com:443#NodeA\n"
        "invalid_garbage_line://foo\n"
        "vless://11111111-2222-3333-4444-555555555555@b.example.com:443?security=tls#NodeB\n"
    )
    nodes, warnings = parse_subscription_payload(plain_list)
    assert len(nodes) == 2
    assert len(warnings) == 1

    # URL-safe unpadded Base64 subscription
    b64_unpadded = base64.urlsafe_b64encode(plain_list.encode("utf-8")).decode("ascii").rstrip("=")
    nodes2, warnings2 = parse_subscription_payload(b64_unpadded)
    assert len(nodes2) == 2
    assert len(warnings2) == 1

    # Error cases
    for bad in (
        "",
        "   ",
        "<html>Error</html>",
        "vless://@example.com:443",  # missing uuid
        "vless://uuid@example.com:99999",  # invalid port
        "vless://uuid@example.com:443?security=reality",  # reality without pbk
        "ss://unknown-cipher:pw@example.com:443",  # invalid SS cipher
        "http://example.com/not-a-proxy",
    ):
        with pytest.raises(ProtocolParseError):
            if bad.startswith(("vless://", "ss://", "http://")):
                parse_proxy_uri(bad)
            else:
                parse_subscription_payload(bad)
