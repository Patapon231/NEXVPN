"""sing-box v1.14+ compliant configuration generator (zero deprecated 1.10/1.11 fields)."""

from __future__ import annotations

import ipaddress
import json
from typing import Any
from urllib.parse import urlsplit

from nexvpn.connection.states import ConnectionMode
from nexvpn.subscription.models import ServerNode, TLSOptions, TransportOptions


class ConfigGenerationError(ValueError):
    """Raised when a ServerNode or runtime option cannot produce a valid sing-box config."""


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _build_tls_block(tls: TLSOptions, default_sni: str) -> dict[str, Any] | None:
    if not tls.enabled:
        return None

    block: dict[str, Any] = {
        "enabled": True,
        "server_name": tls.server_name or default_sni,
        "insecure": bool(tls.insecure),
    }
    if tls.alpn:
        block["alpn"] = list(tls.alpn)

    if tls.reality_enabled:
        if not tls.reality_public_key:
            raise ConfigGenerationError("Reality включён, но отсутствует публичный ключ (pbk).")
        block["utls"] = {
            "enabled": True,
            "fingerprint": tls.utls_fingerprint or "chrome",
        }
        reality_cfg: dict[str, Any] = {
            "enabled": True,
            "public_key": tls.reality_public_key,
        }
        if tls.reality_short_id:
            reality_cfg["short_id"] = tls.reality_short_id
        block["reality"] = reality_cfg
    elif tls.utls_fingerprint:
        block["utls"] = {
            "enabled": True,
            "fingerprint": tls.utls_fingerprint,
        }

    return block


def _build_transport_block(tr: TransportOptions) -> dict[str, Any] | None:
    t = tr.type.lower().strip()
    if not t or t == "tcp":
        return None

    if t == "ws":
        ws_cfg: dict[str, Any] = {
            "type": "ws",
            "path": tr.path or "/",
        }
        headers = dict(tr.headers)
        if tr.host and "Host" not in headers:
            headers["Host"] = tr.host
        if headers:
            ws_cfg["headers"] = headers
        return ws_cfg

    if t == "grpc":
        grpc_cfg: dict[str, Any] = {"type": "grpc"}
        if tr.service_name:
            grpc_cfg["service_name"] = tr.service_name
        return grpc_cfg

    if t == "http":
        http_cfg: dict[str, Any] = {
            "type": "http",
            "path": tr.path or "/",
        }
        if tr.host:
            http_cfg["host"] = [h.strip() for h in tr.host.split(",") if h.strip()]
        return http_cfg

    if t == "httpupgrade":
        upg_cfg: dict[str, Any] = {
            "type": "httpupgrade",
            "path": tr.path or "/",
        }
        if tr.host:
            upg_cfg["host"] = tr.host
        return upg_cfg

    if t in ("xhttp", "splithttp"):
        raise ConfigGenerationError(
            "Транспорт XHTTP не поддерживается напрямую в sing-box и должен маршрутизироваться через локальный мост Xray."
        )

    raise ConfigGenerationError(f"Неподдерживаемый транспорт sing-box: {t}")


def node_requires_xray(node: ServerNode) -> bool:
    """Return True if the primary node or any cluster peer requires Xray (`xhttp` transport)."""
    return any(
        peer.transport.type.lower().strip() in ("xhttp", "splithttp")
        for peer in node.iter_cluster_nodes()
    )


def build_xray_outbound(
    node: ServerNode,
    tag: str = "proxy",
    send_through: str | None = None,
) -> dict[str, Any]:
    """Convert a ServerNode into an official Xray-core outbound preserving XHTTP/TLS/Reality semantics."""
    proto = node.protocol.lower().strip()
    host = node.host.strip("[]")
    if not host or not (1 <= node.port <= 65535):
        raise ConfigGenerationError("Некорректный адрес или порт сервера для Xray.")

    if proto == "vless":
        if not node.uuid:
            raise ConfigGenerationError("Отсутствует UUID для VLESS.")
        user: dict[str, Any] = {
            "id": node.uuid,
            "encryption": "none",
        }
        if node.flow:
            user["flow"] = node.flow
        settings: dict[str, Any] = {
            "vnext": [{"address": host, "port": node.port, "users": [user]}]
        }
    elif proto == "vmess":
        if not node.uuid:
            raise ConfigGenerationError("Отсутствует UUID для VMess.")
        user = {
            "id": node.uuid,
            "alterId": max(0, int(node.alter_id)),
            "security": node.method or "auto",
        }
        settings = {
            "vnext": [{"address": host, "port": node.port, "users": [user]}]
        }
    elif proto == "trojan":
        if not node.password:
            raise ConfigGenerationError("Отсутствует пароль для Trojan.")
        settings = {
            "servers": [{"address": host, "port": node.port, "password": node.password}]
        }
    elif proto == "shadowsocks":
        if not node.method:
            raise ConfigGenerationError("Отсутствует метод шифрования для Shadowsocks.")
        settings = {
            "servers": [
                {
                    "address": host,
                    "port": node.port,
                    "method": node.method,
                    "password": node.password,
                }
            ]
        }
    else:
        raise ConfigGenerationError(f"Протокол {proto} не поддерживается в мосте Xray.")

    tr = node.transport
    net = tr.type.lower().strip()
    stream: dict[str, Any] = {}
    if not net or net == "tcp":
        stream["network"] = "tcp"
    elif net == "ws":
        ws_cfg: dict[str, Any] = {"path": tr.path or "/"}
        if tr.host:
            ws_cfg["host"] = tr.host
        if tr.headers:
            ws_cfg["headers"] = dict(tr.headers)
        stream["network"] = "ws"
        stream["wsSettings"] = ws_cfg
    elif net == "grpc":
        stream["network"] = "grpc"
        stream["grpcSettings"] = {"serviceName": tr.service_name}
    elif net == "http":
        h2_cfg: dict[str, Any] = {"path": tr.path or "/"}
        if tr.host:
            h2_cfg["host"] = [h.strip() for h in tr.host.split(",") if h.strip()]
        stream["network"] = "http"
        stream["httpSettings"] = h2_cfg
    elif net == "httpupgrade":
        hu_cfg: dict[str, Any] = {"path": tr.path or "/"}
        if tr.host:
            hu_cfg["host"] = tr.host
        stream["network"] = "httpupgrade"
        stream["httpupgradeSettings"] = hu_cfg
    elif net in ("xhttp", "splithttp"):
        xh_cfg: dict[str, Any] = {
            "path": tr.path or "/",
            "mode": tr.mode or "auto",
        }
        if tr.host:
            xh_cfg["host"] = tr.host
        if tr.headers:
            xh_cfg["headers"] = dict(tr.headers)
        if tr.extra:
            xh_cfg["extra"] = dict(tr.extra)
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = xh_cfg
    else:
        raise ConfigGenerationError(f"Неподдерживаемый транспорт Xray: {net}")

    tls = node.tls
    if tls.enabled and tls.reality_enabled:
        if not tls.reality_public_key:
            raise ConfigGenerationError("Reality включён, но отсутствует публичный ключ (pbk).")
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": tls.server_name or host,
            "fingerprint": tls.utls_fingerprint or "chrome",
            "publicKey": tls.reality_public_key,
            "shortId": tls.reality_short_id,
        }
    elif tls.enabled:
        tls_cfg: dict[str, Any] = {
            "serverName": tls.server_name or host,
            "allowInsecure": bool(tls.insecure),
        }
        if tls.alpn:
            tls_cfg["alpn"] = list(tls.alpn)
        if tls.utls_fingerprint:
            tls_cfg["fingerprint"] = tls.utls_fingerprint
        stream["security"] = "tls"
        stream["tlsSettings"] = tls_cfg
    else:
        stream["security"] = "none"

    out: dict[str, Any] = {
        "tag": tag,
        "protocol": proto,
        "settings": settings,
        "streamSettings": stream,
    }
    if send_through:
        out["sendThrough"] = send_through
    return out


def generate_xray_bridge_config(
    node: ServerNode,
    socks_port: int,
    log_level: str = "warning",
    send_through: str | None = None,
) -> dict[str, Any]:
    """Generate a leak-proof local SOCKS5 Xray configuration for XHTTP (single or balanced cluster)."""
    if not (1 <= socks_port <= 65535):
        raise ConfigGenerationError(f"Некорректный порт локального моста Xray: {socks_port}")

    cluster_nodes = node.iter_cluster_nodes()
    outbounds: list[dict[str, Any]] = []
    for idx, peer in enumerate(cluster_nodes, start=1):
        tag = "proxy" if idx == 1 else f"proxy-{idx}"
        outbounds.append(build_xray_outbound(peer, tag=tag, send_through=send_through))

    cfg: dict[str, Any] = {
        "log": {"loglevel": log_level},
        "inbounds": [
            {
                "tag": "socks-in",
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            }
        ],
        "outbounds": outbounds,
    }

    if len(outbounds) > 1:
        cfg["burstObservatory"] = {
            "subjectSelector": ["proxy"],
            "pingConfig": {
                "destination": "http://cp.cloudflare.com/generate_204",
                "interval": "30s",
                "sampling": 2,
                "timeout": "3s",
            },
        }
        cfg["routing"] = {
            "domainStrategy": "AsIs",
            "balancers": [
                {
                    "tag": "auto_balancer",
                    "selector": ["proxy"],
                    "strategy": {
                        "type": "leastLoad",
                        "settings": {
                            "maxRTT": "2s",
                            "expected": 2,
                            "baselines": ["1s"],
                            "tolerance": 0.01,
                        },
                    },
                    "fallbackTag": "proxy",
                }
            ],
            "rules": [
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "balancerTag": "auto_balancer",
                }
            ],
        }

    return cfg


def build_proxy_outbound(node: ServerNode, tag: str = "proxy-out") -> dict[str, Any]:
    """Convert a normalized ServerNode into a sing-box v1.14 outbound dictionary."""
    proto = node.protocol.lower().strip()
    host = node.host.strip("[]")
    if not host or not (1 <= node.port <= 65535):
        raise ConfigGenerationError("Некорректный адрес или порт сервера.")

    if proto == "vless":
        if not node.uuid:
            raise ConfigGenerationError("Отсутствует UUID для VLESS.")
        out: dict[str, Any] = {
            "type": "vless",
            "tag": tag,
            "server": host,
            "server_port": node.port,
            "uuid": node.uuid,
        }
        if node.flow:
            out["flow"] = node.flow
        if node.packet_encoding:
            out["packet_encoding"] = node.packet_encoding
        tls_blk = _build_tls_block(node.tls, host)
        if tls_blk:
            out["tls"] = tls_blk
        tr_blk = _build_transport_block(node.transport)
        if tr_blk:
            out["transport"] = tr_blk
        return out

    if proto == "vmess":
        if not node.uuid:
            raise ConfigGenerationError("Отсутствует UUID для VMess.")
        out = {
            "type": "vmess",
            "tag": tag,
            "server": host,
            "server_port": node.port,
            "uuid": node.uuid,
            "security": node.method or "auto",
            "alter_id": max(0, int(node.alter_id)),
        }
        tls_blk = _build_tls_block(node.tls, host)
        if tls_blk:
            out["tls"] = tls_blk
        tr_blk = _build_transport_block(node.transport)
        if tr_blk:
            out["transport"] = tr_blk
        return out

    if proto == "trojan":
        if not node.password:
            raise ConfigGenerationError("Отсутствует пароль для Trojan.")
        out = {
            "type": "trojan",
            "tag": tag,
            "server": host,
            "server_port": node.port,
            "password": node.password,
        }
        tls_blk = _build_tls_block(node.tls, host)
        if tls_blk:
            out["tls"] = tls_blk
        tr_blk = _build_transport_block(node.transport)
        if tr_blk:
            out["transport"] = tr_blk
        return out

    if proto == "shadowsocks":
        if not node.method:
            raise ConfigGenerationError("Отсутствует метод шифрования для Shadowsocks.")
        out = {
            "type": "shadowsocks",
            "tag": tag,
            "server": host,
            "server_port": node.port,
            "method": node.method,
            "password": node.password,
        }
        if node.plugin:
            out["plugin"] = node.plugin
            if node.plugin_opts:
                out["plugin_opts"] = node.plugin_opts
        return out

    if proto == "hysteria2":
        if not node.password:
            raise ConfigGenerationError("Отсутствует пароль для Hysteria2.")
        out = {
            "type": "hysteria2",
            "tag": tag,
            "server": host,
            "server_port": node.port,
            "password": node.password,
        }
        if node.up_mbps:
            out["up_mbps"] = node.up_mbps
        if node.down_mbps:
            out["down_mbps"] = node.down_mbps
        if node.obfs_type == "salamander":
            out["obfs"] = {
                "type": "salamander",
                "password": node.obfs_password,
            }
        tls_blk = _build_tls_block(node.tls, host)
        if tls_blk:
            # Hysteria2 uses native QUIC TLS (no uTLS wrapper)
            tls_blk.pop("utls", None)
            tls_blk.pop("reality", None)
            out["tls"] = tls_blk
        return out

    if proto == "tuic":
        if not node.uuid:
            raise ConfigGenerationError("Отсутствует UUID для TUIC.")
        out = {
            "type": "tuic",
            "tag": tag,
            "server": host,
            "server_port": node.port,
            "uuid": node.uuid,
            "password": node.password,
            "congestion_control": node.congestion_control or "bbr",
            "udp_relay_mode": node.udp_relay_mode or "native",
            "zero_rtt_handshake": bool(node.zero_rtt_handshake),
        }
        tls_blk = _build_tls_block(node.tls, host)
        if tls_blk:
            tls_blk.pop("utls", None)
            tls_blk.pop("reality", None)
            out["tls"] = tls_blk
        return out

    raise ConfigGenerationError(f"Неподдерживаемый протокол: {proto}")


def _build_direct_dns_server(dns_direct: str) -> dict[str, Any]:
    cleaned = dns_direct.strip()
    if not cleaned or cleaned.lower() in ("local", "system"):
        return {"type": "local", "tag": "dns-direct"}

    if "://" not in cleaned:
        host = cleaned
        port = 53
        if ":" in cleaned and not _is_ip_literal(cleaned):
            h, p = cleaned.rsplit(":", 1)
            if p.isdigit():
                host, port = h, int(p)
        return {
            "type": "udp",
            "tag": "dns-direct",
            "server": host,
            "server_port": port,
        }

    parts = urlsplit(cleaned)
    scheme = parts.scheme.lower()
    host = parts.hostname or "1.1.1.1"
    if scheme == "https":
        return {
            "type": "https",
            "tag": "dns-direct",
            "server": host,
            "server_port": parts.port or 443,
            "path": parts.path or "/dns-query",
        }
    return {
        "type": "udp",
        "tag": "dns-direct",
        "server": host,
        "server_port": parts.port or 53,
    }


def _build_remote_dns_server(dns_remote: str) -> dict[str, Any]:
    cleaned = dns_remote.strip() or "https://1.1.1.1/dns-query"
    if "://" not in cleaned:
        srv: dict[str, Any] = {
            "type": "tcp",
            "tag": "dns-remote",
            "server": cleaned,
            "server_port": 53,
            "detour": "proxy-out",
        }
        if not _is_ip_literal(cleaned):
            srv["domain_resolver"] = "dns-direct"
        return srv

    parts = urlsplit(cleaned)
    scheme = parts.scheme.lower()
    host = parts.hostname or "1.1.1.1"

    if scheme == "https":
        srv = {
            "type": "https",
            "tag": "dns-remote",
            "server": host,
            "server_port": parts.port or 443,
            "path": parts.path or "/dns-query",
            "detour": "proxy-out",
        }
    elif scheme == "tls":
        srv = {
            "type": "tls",
            "tag": "dns-remote",
            "server": host,
            "server_port": parts.port or 853,
            "detour": "proxy-out",
        }
    elif scheme == "quic":
        srv = {
            "type": "quic",
            "tag": "dns-remote",
            "server": host,
            "server_port": parts.port or 853,
            "detour": "proxy-out",
        }
    else:
        srv = {
            "type": "tcp",
            "tag": "dns-remote",
            "server": host,
            "server_port": parts.port or 53,
            "detour": "proxy-out",
        }

    if not _is_ip_literal(host):
        srv["domain_resolver"] = "dns-direct"
    return srv


def generate_sing_box_config(
    node: ServerNode,
    mode: ConnectionMode = ConnectionMode.SYSTEM_PROXY,
    local_mixed_port: int = 10808,
    dns_remote: str = "https://1.1.1.1/dns-query",
    dns_direct: str = "1.1.1.1",
    bypass_lan: bool = True,
    tun_interface_name: str = "NEXVPN-TUN",
    tun_address: str = "172.19.0.1/30",
    tun_stack: str = "system",
    tun_strict_route: bool = True,
    clash_api_port: int | None = None,
    clash_api_secret: str = "",
    log_level: str = "info",
    xray_socks_port: int | None = None,
) -> dict[str, Any]:
    """Generate a complete, modern sing-box v1.14+ configuration dictionary."""
    outbounds: list[dict[str, Any]] = []
    if xray_socks_port is not None:
        if not (1 <= xray_socks_port <= 65535):
            raise ConfigGenerationError(f"Некорректный порт моста Xray: {xray_socks_port}")
        outbounds.append(
            {
                "type": "socks",
                "tag": "proxy-out",
                "server": "127.0.0.1",
                "server_port": xray_socks_port,
                "version": "5",
            }
        )
    else:
        cluster = node.iter_cluster_nodes()
        if len(cluster) > 1:
            peer_tags: list[str] = []
            peer_outbounds: list[dict[str, Any]] = []
            for idx, peer in enumerate(cluster, start=1):
                ptag = f"proxy-peer-{idx}"
                peer_tags.append(ptag)
                peer_outbounds.append(build_proxy_outbound(peer, tag=ptag))
            outbounds.append(
                {
                    "type": "urltest",
                    "tag": "proxy-out",
                    "outbounds": peer_tags,
                    "url": "https://cp.cloudflare.com/generate_204",
                    "interval": "1m",
                    "tolerance": 50,
                }
            )
            outbounds.extend(peer_outbounds)
        else:
            outbounds.append(build_proxy_outbound(node, tag="proxy-out"))

    outbounds.append({"type": "direct", "tag": "direct-out"})

    if mode == ConnectionMode.SYSTEM_PROXY:
        if not (1 <= local_mixed_port <= 65535):
            raise ConfigGenerationError(f"Некорректный локальный порт: {local_mixed_port}")
        inbounds: list[dict[str, Any]] = [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": local_mixed_port,
                "set_system_proxy": False,
            }
        ]
    elif mode == ConnectionMode.TUN:
        stack_val = tun_stack if tun_stack in ("system", "gvisor", "mixed") else "system"
        inbounds = [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": tun_interface_name,
                "address": [tun_address],
                "mtu": 9000,
                "auto_route": True,
                "strict_route": bool(tun_strict_route),
                "stack": stack_val,
            }
        ]
    else:
        raise ConfigGenerationError(f"Неизвестный режим подключения: {mode}")

    route_rules: list[dict[str, Any]] = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
    ]
    if mode == ConnectionMode.TUN and xray_socks_port is not None:
        # Prevent routing loop: xray.exe upstream connections must exit via direct-out
        route_rules.append({"process_name": ["xray.exe"], "outbound": "direct-out"})
    if bypass_lan:
        route_rules.append({"ip_is_private": True, "outbound": "direct-out"})

    route_block: dict[str, Any] = {
        "default_domain_resolver": "dns-direct",
        "rules": route_rules,
        "final": "proxy-out",
    }
    if mode == ConnectionMode.TUN:
        route_block["auto_detect_interface"] = True

    config: dict[str, Any] = {
        "log": {
            "disabled": False,
            "level": log_level,
            "timestamp": True,
        },
        "dns": {
            "servers": [
                _build_remote_dns_server(dns_remote),
                _build_direct_dns_server(dns_direct),
            ],
            "final": "dns-remote",
            "strategy": "prefer_ipv4",
            "independent_cache": True,
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route_block,
    }

    if clash_api_port and (1 <= clash_api_port <= 65535):
        clash_cfg: dict[str, Any] = {
            "external_controller": f"127.0.0.1:{clash_api_port}",
        }
        if clash_api_secret:
            clash_cfg["secret"] = clash_api_secret
        config["experimental"] = {"clash_api": clash_cfg}

    return config


def serialize_config(config: dict[str, Any]) -> str:
    """Serialize sing-box config dict to formatted UTF-8 JSON."""
    return json.dumps(config, ensure_ascii=False, indent=2)
