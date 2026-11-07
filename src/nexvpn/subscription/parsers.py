"""Strict protocol URI parsers (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC) and subscription decoder."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from nexvpn.subscription.models import ServerNode, TLSOptions, TransportOptions

SUPPORTED_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")

VALID_SS_METHODS = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
}


class ProtocolParseError(ValueError):
    """Raised when a proxy URI or subscription payload is invalid."""


def _decode_b64_flexible(data: str) -> bytes:
    """Decode standard or URL-safe Base64 with automatic padding normalization."""
    cleaned = "".join(data.strip().split())
    if not cleaned:
        raise ProtocolParseError("Пустая Base64-строка.")
    cleaned = cleaned.replace("-", "+").replace("_", "/")
    pad = (-len(cleaned)) % 4
    if pad:
        cleaned += "=" * pad
    try:
        return base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProtocolParseError("Некорректное кодирование Base64.") from exc


def _split_authority(authority: str) -> tuple[str, str, int]:
    """Safely split `[userinfo@]host:port` allowing special chars in userinfo and IPv6 hosts."""
    if "@" in authority:
        userinfo, hostport = authority.rsplit("@", 1)
    else:
        userinfo, hostport = "", authority

    hostport = hostport.strip()
    if not hostport:
        raise ProtocolParseError("Отсутствует адрес сервера.")

    if hostport.startswith("["):
        end_bracket = hostport.find("]")
        if end_bracket == -1:
            raise ProtocolParseError("Некорректный IPv6-адрес сервера.")
        host = hostport[1:end_bracket].strip()
        rest = hostport[end_bracket + 1 :]
        if not rest.startswith(":"):
            raise ProtocolParseError("Отсутствует порт сервера.")
        port_str = rest[1:]
    else:
        if ":" not in hostport:
            raise ProtocolParseError("Отсутствует порт сервера.")
        host, port_str = hostport.rsplit(":", 1)
        host = host.strip()

    if not host or any(ch.isspace() for ch in host):
        raise ProtocolParseError("Некорректное имя хоста или IP-адрес.")

    # Handle port ranges like 443-500 by taking first port if digits
    if "-" in port_str:
        port_str = port_str.split("-", 1)[0]

    try:
        port = int(port_str)
    except ValueError as exc:
        raise ProtocolParseError(f"Некорректный порт: {port_str!r}") from exc

    if not (1 <= port <= 65535):
        raise ProtocolParseError(f"Порт вне допустимого диапазона (1-65535): {port}")

    return userinfo, host, port


def _first_param(params: dict[str, list[str]], *keys: str, default: str = "") -> str:
    for k in keys:
        vals = params.get(k)
        if vals and vals[0] != "":
            return vals[0]
    return default


def _parse_bool(val: str) -> bool:
    return val.strip().lower() in ("1", "true", "yes", "on")


def _parse_common_tls(
    params: dict[str, list[str]],
    default_security: str = "none",
    fallback_sni: str = "",
) -> TLSOptions:
    security = _first_param(params, "security", default=default_security).lower()
    if security in ("none", "", "0", "false"):
        return TLSOptions(enabled=False)

    sni = _first_param(params, "sni", "peer", default=fallback_sni).strip()
    insecure = _parse_bool(_first_param(params, "allowInsecure", "insecure", "allow_insecure"))
    alpn_raw = _first_param(params, "alpn")
    alpn = [item.strip() for item in unquote(alpn_raw).split(",") if item.strip()] if alpn_raw else []
    fp = _first_param(params, "fp", "fingerprint").strip()

    if security == "reality":
        pbk = _first_param(params, "pbk", "publicKey").strip()
        if not pbk:
            raise ProtocolParseError("Для VLESS/Trojan Reality требуется публичный ключ (pbk).")
        sid = _first_param(params, "sid", "shortId").strip()
        return TLSOptions(
            enabled=True,
            server_name=sni,
            insecure=insecure,
            alpn=alpn,
            utls_fingerprint=fp or "chrome",
            reality_enabled=True,
            reality_public_key=pbk,
            reality_short_id=sid,
        )

    return TLSOptions(
        enabled=True,
        server_name=sni,
        insecure=insecure,
        alpn=alpn,
        utls_fingerprint=fp,
    )


def _parse_common_transport(params: dict[str, list[str]]) -> TransportOptions:
    net = _first_param(params, "type", "net", default="tcp").lower()
    if net in ("tcp", "none", "", "raw"):
        header_type = _first_param(params, "headerType", default="none").lower()
        if header_type == "http":
            return TransportOptions(
                type="http",
                path=_first_param(params, "path", default="/"),
                host=_first_param(params, "host"),
            )
        return TransportOptions(type="")

    if net == "ws":
        host_hdr = _first_param(params, "host").strip()
        headers = {"Host": host_hdr} if host_hdr else {}
        return TransportOptions(
            type="ws",
            path=_first_param(params, "path", default="/"),
            host=host_hdr,
            headers=headers,
        )

    if net == "grpc":
        svc = _first_param(params, "serviceName", "path").strip()
        return TransportOptions(type="grpc", service_name=svc)

    if net in ("http", "h2"):
        return TransportOptions(
            type="http",
            path=_first_param(params, "path", default="/"),
            host=_first_param(params, "host").strip(),
        )

    if net == "httpupgrade":
        return TransportOptions(
            type="httpupgrade",
            path=_first_param(params, "path", default="/"),
            host=_first_param(params, "host").strip(),
        )

    if net in ("xhttp", "splithttp"):
        extra_dict: dict[str, Any] = {}
        extra_raw = _first_param(params, "extra").strip()
        if extra_raw:
            parsed_extra: Any = None
            for candidate in (extra_raw, unquote(extra_raw)):
                try:
                    parsed_extra = json.loads(candidate)
                    break
                except json.JSONDecodeError:
                    continue
            if not isinstance(parsed_extra, dict):
                raise ProtocolParseError("Некорректный JSON в параметре XHTTP extra.")
            extra_dict = parsed_extra
        return TransportOptions(
            type="xhttp",
            path=_first_param(params, "path", default="/"),
            host=_first_param(params, "host").strip(),
            mode=_first_param(params, "mode", default="auto").strip() or "auto",
            extra=extra_dict,
        )

    raise ProtocolParseError(f"Неподдерживаемый тип транспорта: {net}")


def _split_custom_uri(uri: str, expected_scheme: str) -> tuple[str, dict[str, list[str]], str]:
    """Extract (authority, query_params, remark) without Python urlsplit choking on special userinfo."""
    prefix = f"{expected_scheme}://"
    body = uri[len(prefix) :]

    remark = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        remark = unquote(frag).strip()

    query_str = ""
    if "?" in body:
        body, query_str = body.split("?", 1)

    # Strip trailing slash on authority (e.g. host:port/?plugin=...)
    authority = body.rstrip("/")
    params = parse_qs(query_str, keep_blank_values=False)
    return authority, params, remark


def parse_vless_uri(uri: str) -> ServerNode:
    authority, params, remark = _split_custom_uri(uri.strip(), "vless")
    userinfo, host, port = _split_authority(authority)
    uuid = unquote(userinfo).strip()
    if not uuid:
        raise ProtocolParseError("В VLESS URI отсутствует UUID.")

    tls = _parse_common_tls(params, default_security="none", fallback_sni=host)
    transport = _parse_common_transport(params)
    flow = _first_param(params, "flow").strip()
    packet_encoding = _first_param(params, "packetEncoding", default="xudp").strip()

    return ServerNode(
        protocol="vless",
        name=remark or f"VLESS {host}:{port}",
        host=host,
        port=port,
        uuid=uuid,
        flow=flow,
        packet_encoding=packet_encoding,
        tls=tls,
        transport=transport,
    )


def parse_vmess_uri(uri: str) -> ServerNode:
    trimmed = uri.strip()
    body = trimmed[len("vmess://") :]

    # Standard v2rayN Base64 JSON format
    if "@" not in body.split("?", 1)[0]:
        frag_remark = ""
        if "#" in body:
            body, frag = body.split("#", 1)
            frag_remark = unquote(frag).strip()
        raw_bytes = _decode_b64_flexible(body)
        try:
            data = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolParseError("Некорректный JSON внутри VMess Base64.") from exc
        if not isinstance(data, dict):
            raise ProtocolParseError("Ожидался JSON-объект в конфигурации VMess.")

        host = str(data.get("add") or "").strip()
        if not host or any(c.isspace() for c in host):
            raise ProtocolParseError("В VMess отсутствует корректный адрес сервера (add).")
        try:
            port = int(data.get("port", 0))
        except (TypeError, ValueError) as exc:
            raise ProtocolParseError("Некорректный порт в VMess.") from exc
        if not (1 <= port <= 65535):
            raise ProtocolParseError(f"Порт VMess вне диапазона: {port}")

        uuid = str(data.get("id") or "").strip()
        if not uuid:
            raise ProtocolParseError("В VMess отсутствует UUID (id).")

        try:
            alter_id = int(data.get("aid") or 0)
        except (TypeError, ValueError):
            alter_id = 0

        cipher = str(data.get("scy") or data.get("cipher") or "auto").strip() or "auto"
        name = str(data.get("ps") or frag_remark or f"VMess {host}:{port}").strip()

        net = str(data.get("net") or "tcp").strip().lower()
        hdr_type = str(data.get("type") or "none").strip().lower()
        host_hdr = str(data.get("host") or "").strip()
        path = str(data.get("path") or "").strip()

        q_equiv: dict[str, list[str]] = {"type": [net]}
        if hdr_type and hdr_type != "none":
            q_equiv["headerType"] = [hdr_type]
            if net in ("xhttp", "splithttp"):
                q_equiv["mode"] = [hdr_type]
        if host_hdr:
            q_equiv["host"] = [host_hdr]
        if path:
            q_equiv["path"] = [path]
            q_equiv["serviceName"] = [path]
        transport = _parse_common_transport(q_equiv)

        tls_flag = str(data.get("tls") or "").strip().lower()
        tls_enabled = tls_flag in ("tls", "1", "true")
        sni = str(data.get("sni") or host_hdr or host).strip()
        alpn_str = str(data.get("alpn") or "").strip()
        alpn = [x.strip() for x in alpn_str.split(",") if x.strip()] if alpn_str else []
        fp = str(data.get("fp") or "").strip()
        insecure = _parse_bool(str(data.get("allowInsecure") or data.get("insecure") or ""))

        tls = (
            TLSOptions(
                enabled=True,
                server_name=sni,
                insecure=insecure,
                alpn=alpn,
                utls_fingerprint=fp,
            )
            if tls_enabled
            else TLSOptions(enabled=False)
        )

        return ServerNode(
            protocol="vmess",
            name=name,
            host=host,
            port=port,
            uuid=uuid,
            method=cipher,
            alter_id=max(0, alter_id),
            tls=tls,
            transport=transport,
        )

    # URI-style vmess://uuid@host:port?...#remark
    authority, params, remark = _split_custom_uri(trimmed, "vmess")
    userinfo, host, port = _split_authority(authority)
    uuid = unquote(userinfo).strip()
    if not uuid:
        raise ProtocolParseError("В VMess URI отсутствует UUID.")
    tls = _parse_common_tls(params, default_security="none", fallback_sni=host)
    transport = _parse_common_transport(params)
    cipher = _first_param(params, "encryption", "scy", default="auto")
    return ServerNode(
        protocol="vmess",
        name=remark or f"VMess {host}:{port}",
        host=host,
        port=port,
        uuid=uuid,
        method=cipher,
        tls=tls,
        transport=transport,
    )


def parse_trojan_uri(uri: str) -> ServerNode:
    authority, params, remark = _split_custom_uri(uri.strip(), "trojan")
    userinfo, host, port = _split_authority(authority)
    password = unquote(userinfo)
    if not password:
        raise ProtocolParseError("В Trojan URI отсутствует пароль.")

    tls = _parse_common_tls(params, default_security="tls", fallback_sni=host)
    transport = _parse_common_transport(params)
    return ServerNode(
        protocol="trojan",
        name=remark or f"Trojan {host}:{port}",
        host=host,
        port=port,
        password=password,
        tls=tls,
        transport=transport,
    )


def parse_shadowsocks_uri(uri: str) -> ServerNode:
    trimmed = uri.strip()
    body = trimmed[len("ss://") :]

    remark = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        remark = unquote(frag).strip()

    query_str = ""
    if "?" in body:
        body, query_str = body.split("?", 1)
    body = body.rstrip("/")
    params = parse_qs(query_str, keep_blank_values=False)

    if "@" not in body:
        # Legacy full-base64: ss://base64(method:password@host:port)
        decoded = _decode_b64_flexible(body).decode("utf-8", errors="strict")
        userinfo, host, port = _split_authority(decoded)
    else:
        userinfo, host, port = _split_authority(body)

    if ":" in userinfo:
        raw_method, raw_pass = userinfo.split(":", 1)
        method = unquote(raw_method).strip()
        password = unquote(raw_pass)
    else:
        decoded_ui = _decode_b64_flexible(unquote(userinfo)).decode("utf-8", errors="strict")
        if ":" not in decoded_ui:
            raise ProtocolParseError("В Shadowsocks URI отсутствует разделитель method:password.")
        method, password = decoded_ui.split(":", 1)
        method = method.strip()

    method_lower = method.lower()
    if method_lower not in VALID_SS_METHODS:
        raise ProtocolParseError(f"Неподдерживаемый метод шифрования Shadowsocks: {method}")
    if not password and method_lower != "none":
        raise ProtocolParseError("В Shadowsocks URI отсутствует пароль.")

    plugin_raw = _first_param(params, "plugin")
    plugin_name = ""
    plugin_opts = ""
    if plugin_raw:
        plugin_decoded = unquote(plugin_raw)
        if ";" in plugin_decoded:
            plugin_name, plugin_opts = plugin_decoded.split(";", 1)
        else:
            plugin_name = plugin_decoded
        if plugin_name == "obfs-local" or plugin_name == "simple-obfs":
            plugin_name = "obfs-local"

    return ServerNode(
        protocol="shadowsocks",
        name=remark or f"SS {host}:{port}",
        host=host,
        port=port,
        method=method_lower,
        password=password,
        plugin=plugin_name,
        plugin_opts=plugin_opts,
    )


def parse_hysteria2_uri(uri: str) -> ServerNode:
    trimmed = uri.strip()
    scheme = "hysteria2" if trimmed.lower().startswith("hysteria2://") else "hy2"
    authority, params, remark = _split_custom_uri(trimmed, scheme)
    userinfo, host, port = _split_authority(authority)
    password = unquote(userinfo) or _first_param(params, "auth")
    if not password:
        raise ProtocolParseError("В Hysteria2 URI отсутствует пароль авторизации.")

    sni = _first_param(params, "sni", "peer", default=host).strip()
    insecure = _parse_bool(_first_param(params, "insecure", "allowInsecure"))
    alpn_raw = _first_param(params, "alpn")
    alpn = [a.strip() for a in unquote(alpn_raw).split(",") if a.strip()] if alpn_raw else ["h3"]

    obfs_type = _first_param(params, "obfs").strip().lower()
    if obfs_type in ("none", ""):
        obfs_type = ""
    elif obfs_type != "salamander":
        raise ProtocolParseError(f"Неподдерживаемый тип обфускации Hysteria2: {obfs_type}")
    obfs_password = _first_param(params, "obfs-password").strip()

    up_raw = _first_param(params, "upmbps", "up")
    down_raw = _first_param(params, "downmbps", "down")
    up_mbps = int(up_raw) if up_raw.isdigit() and int(up_raw) > 0 else None
    down_mbps = int(down_raw) if down_raw.isdigit() and int(down_raw) > 0 else None

    return ServerNode(
        protocol="hysteria2",
        name=remark or f"Hysteria2 {host}:{port}",
        host=host,
        port=port,
        password=password,
        obfs_type=obfs_type,
        obfs_password=obfs_password,
        up_mbps=up_mbps,
        down_mbps=down_mbps,
        tls=TLSOptions(enabled=True, server_name=sni, insecure=insecure, alpn=alpn),
    )


def parse_tuic_uri(uri: str) -> ServerNode:
    authority, params, remark = _split_custom_uri(uri.strip(), "tuic")
    userinfo, host, port = _split_authority(authority)
    if ":" in userinfo:
        raw_uuid, raw_pass = userinfo.split(":", 1)
        uuid = unquote(raw_uuid).strip()
        password = unquote(raw_pass)
    else:
        uuid = unquote(userinfo).strip()
        password = _first_param(params, "password")

    if not uuid:
        raise ProtocolParseError("В TUIC URI отсутствует UUID.")

    sni = _first_param(params, "sni", default=host).strip()
    insecure = _parse_bool(_first_param(params, "allow_insecure", "insecure", "allowInsecure"))
    alpn_raw = _first_param(params, "alpn")
    alpn = [a.strip() for a in unquote(alpn_raw).split(",") if a.strip()] if alpn_raw else ["h3"]

    cc = _first_param(params, "congestion_control", default="bbr").lower()
    if cc not in ("bbr", "cubic", "new_reno"):
        cc = "bbr"
    udp_mode = _first_param(params, "udp_relay_mode", default="native").lower()
    if udp_mode not in ("native", "quic"):
        udp_mode = "native"
    zero_rtt = _parse_bool(_first_param(params, "reduce_rtt", "zero_rtt"))

    return ServerNode(
        protocol="tuic",
        name=remark or f"TUIC {host}:{port}",
        host=host,
        port=port,
        uuid=uuid,
        password=password,
        congestion_control=cc,
        udp_relay_mode=udp_mode,
        zero_rtt_handshake=zero_rtt,
        tls=TLSOptions(enabled=True, server_name=sni, insecure=insecure, alpn=alpn),
    )


def parse_proxy_uri(uri: str) -> ServerNode:
    """Parse a single proxy URI across all supported protocols."""
    line = uri.strip()
    if not line:
        raise ProtocolParseError("Пустая строка URI.")

    lower = line.lower()
    if lower.startswith("vless://"):
        return parse_vless_uri(line)
    if lower.startswith("vmess://"):
        return parse_vmess_uri(line)
    if lower.startswith("trojan://"):
        return parse_trojan_uri(line)
    if lower.startswith("ss://"):
        return parse_shadowsocks_uri(line)
    if lower.startswith(("hysteria2://", "hy2://")):
        return parse_hysteria2_uri(line)
    if lower.startswith("tuic://"):
        return parse_tuic_uri(line)

    scheme = urlsplit(line).scheme or "unknown"
    raise ProtocolParseError(f"Неподдерживаемый протокол или схема URI: {scheme}")


def _extract_uri_lines(text: str) -> list[str]:
    lines: list[str] = []
    for raw_line in text.splitlines():
        s = raw_line.strip()
        if not s or s.startswith("#") or s.startswith("//"):
            continue
        lines.append(s)
    return lines


def _looks_like_uri_list(lines: list[str]) -> bool:
    return any(line.lower().startswith(SUPPORTED_SCHEMES) for line in lines)


def _parse_xray_stream_settings(stream: dict[str, Any], fallback_host: str) -> tuple[TransportOptions, TLSOptions]:
    net = str(stream.get("network") or "tcp").strip().lower()
    if net in ("tcp", "raw", "", "none"):
        tcp_cfg = stream.get("tcpSettings") or stream.get("rawSettings") or {}
        header = tcp_cfg.get("header") if isinstance(tcp_cfg, dict) else None
        if isinstance(header, dict) and str(header.get("type") or "").lower() == "http":
            req = header.get("request") or {}
            paths = req.get("path") if isinstance(req, dict) else None
            path_val = str(paths[0]) if isinstance(paths, list) and paths else "/"
            hdrs = req.get("headers") if isinstance(req, dict) else None
            host_list = hdrs.get("Host") if isinstance(hdrs, dict) else None
            host_val = str(host_list[0]) if isinstance(host_list, list) and host_list else ""
            transport = TransportOptions(type="http", path=path_val, host=host_val)
        else:
            transport = TransportOptions(type="")
    elif net == "ws":
        ws = stream.get("wsSettings") or {}
        raw_hdrs = ws.get("headers") if isinstance(ws, dict) else None
        headers = {str(k): str(v) for k, v in raw_hdrs.items()} if isinstance(raw_hdrs, dict) else {}
        host_val = str(ws.get("host") or headers.get("Host") or headers.get("host") or "").strip()
        if host_val and "Host" not in headers:
            headers["Host"] = host_val
        transport = TransportOptions(
            type="ws",
            path=str(ws.get("path") or "/"),
            host=host_val,
            headers=headers,
        )
    elif net in ("grpc", "gun"):
        grpc = stream.get("grpcSettings") or {}
        svc = str(grpc.get("serviceName") or "").strip()
        transport = TransportOptions(type="grpc", service_name=svc)
    elif net in ("http", "h2"):
        h2 = stream.get("httpSettings") or {}
        raw_host = h2.get("host")
        if isinstance(raw_host, list):
            host_val = ",".join(str(x).strip() for x in raw_host if str(x).strip())
        else:
            host_val = str(raw_host or "").strip()
        transport = TransportOptions(
            type="http",
            path=str(h2.get("path") or "/"),
            host=host_val,
        )
    elif net == "httpupgrade":
        hu = stream.get("httpupgradeSettings") or {}
        transport = TransportOptions(
            type="httpupgrade",
            path=str(hu.get("path") or "/"),
            host=str(hu.get("host") or "").strip(),
        )
    elif net in ("xhttp", "splithttp"):
        xh = stream.get("xhttpSettings") or stream.get("splithttpSettings") or {}
        raw_hdrs = xh.get("headers") if isinstance(xh, dict) else None
        headers = {str(k): str(v) for k, v in raw_hdrs.items()} if isinstance(raw_hdrs, dict) else {}
        raw_extra = xh.get("extra") if isinstance(xh, dict) else None
        extra_dict: dict[str, Any] = {}
        if isinstance(raw_extra, dict):
            extra_dict = dict(raw_extra)
        elif isinstance(raw_extra, str) and raw_extra.strip():
            try:
                loaded = json.loads(raw_extra)
                if isinstance(loaded, dict):
                    extra_dict = loaded
            except json.JSONDecodeError:
                pass
        transport = TransportOptions(
            type="xhttp",
            path=str(xh.get("path") or "/"),
            host=str(xh.get("host") or "").strip(),
            headers=headers,
            mode=str(xh.get("mode") or "auto").strip() or "auto",
            extra=extra_dict,
        )
    else:
        raise ProtocolParseError(f"Неподдерживаемый тип транспорта в JSON: {net}")

    security = str(stream.get("security") or "none").strip().lower()
    if security in ("none", "", "0", "false"):
        tls = TLSOptions(enabled=False)
    elif security == "reality":
        rs = stream.get("realitySettings") or {}
        pbk = str(rs.get("publicKey") or rs.get("pbk") or "").strip()
        if not pbk:
            raise ProtocolParseError("В Reality JSON отсутствует publicKey.")
        sid = str(rs.get("shortId") or rs.get("sid") or "").strip()
        sni = str(rs.get("serverName") or fallback_host).strip()
        fp = str(rs.get("fingerprint") or "chrome").strip() or "chrome"
        tls = TLSOptions(
            enabled=True,
            server_name=sni,
            utls_fingerprint=fp,
            reality_enabled=True,
            reality_public_key=pbk,
            reality_short_id=sid,
        )
    elif security == "tls":
        ts = stream.get("tlsSettings") or {}
        sni = str(ts.get("serverName") or fallback_host).strip()
        insecure = bool(ts.get("allowInsecure", False))
        raw_alpn = ts.get("alpn")
        alpn = [str(a).strip() for a in raw_alpn if str(a).strip()] if isinstance(raw_alpn, list) else []
        fp = str(ts.get("fingerprint") or "").strip()
        tls = TLSOptions(
            enabled=True,
            server_name=sni,
            insecure=insecure,
            alpn=alpn,
            utls_fingerprint=fp,
        )
    else:
        raise ProtocolParseError(f"Неподдерживаемый режим безопасности в JSON: {security}")

    return transport, tls


def _parse_xray_outbound_dict(ob: dict[str, Any], default_name: str = "") -> ServerNode:
    proto = str(ob.get("protocol") or "").strip().lower()
    settings = ob.get("settings")
    if not isinstance(settings, dict):
        raise ProtocolParseError(f"Отсутствует секция settings в outbound ({proto}).")

    stream = ob.get("streamSettings")
    stream_dict = stream if isinstance(stream, dict) else {}

    if proto in ("vless", "vmess"):
        vnext = settings.get("vnext")
        if not isinstance(vnext, list) or not vnext or not isinstance(vnext[0], dict):
            raise ProtocolParseError(f"Отсутствует vnext в {proto.upper()} JSON.")
        vn = vnext[0]
        host = str(vn.get("address") or "").strip()
        try:
            port = int(vn.get("port", 0))
        except (TypeError, ValueError) as exc:
            raise ProtocolParseError(f"Некорректный порт в {proto.upper()} JSON.") from exc
        if not host or not (1 <= port <= 65535):
            raise ProtocolParseError(f"Некорректный адрес или порт в {proto.upper()} JSON.")

        users = vn.get("users")
        if not isinstance(users, list) or not users or not isinstance(users[0], dict):
            raise ProtocolParseError(f"Отсутствует список users в {proto.upper()} JSON.")
        user = users[0]
        uuid = str(user.get("id") or "").strip()
        if not uuid:
            raise ProtocolParseError(f"Отсутствует UUID в {proto.upper()} JSON.")

        transport, tls = _parse_xray_stream_settings(stream_dict, fallback_host=host)
        if proto == "vless":
            flow = str(user.get("flow") or "").strip()
            pkt = str(settings.get("packetEncoding") or user.get("packetEncoding") or "xudp").strip()
            return ServerNode(
                protocol="vless",
                name=default_name or f"VLESS {host}:{port}",
                host=host,
                port=port,
                uuid=uuid,
                flow=flow,
                packet_encoding=pkt,
                tls=tls,
                transport=transport,
            )
        cipher = str(user.get("security") or "auto").strip() or "auto"
        try:
            alter_id = max(0, int(user.get("alterId") or 0))
        except (TypeError, ValueError):
            alter_id = 0
        return ServerNode(
            protocol="vmess",
            name=default_name or f"VMess {host}:{port}",
            host=host,
            port=port,
            uuid=uuid,
            method=cipher,
            alter_id=alter_id,
            tls=tls,
            transport=transport,
        )

    if proto == "trojan":
        servers = settings.get("servers")
        if not isinstance(servers, list) or not servers or not isinstance(servers[0], dict):
            raise ProtocolParseError("Отсутствует servers в Trojan JSON.")
        sv = servers[0]
        host = str(sv.get("address") or "").strip()
        try:
            port = int(sv.get("port", 0))
        except (TypeError, ValueError) as exc:
            raise ProtocolParseError("Некорректный порт в Trojan JSON.") from exc
        password = str(sv.get("password") or "")
        if not host or not (1 <= port <= 65535) or not password:
            raise ProtocolParseError("Некорректные параметры сервера или пароль в Trojan JSON.")
        transport, tls = _parse_xray_stream_settings(stream_dict, fallback_host=host)
        return ServerNode(
            protocol="trojan",
            name=default_name or f"Trojan {host}:{port}",
            host=host,
            port=port,
            password=password,
            tls=tls,
            transport=transport,
        )

    if proto == "shadowsocks":
        servers = settings.get("servers")
        if not isinstance(servers, list) or not servers or not isinstance(servers[0], dict):
            raise ProtocolParseError("Отсутствует servers в Shadowsocks JSON.")
        sv = servers[0]
        host = str(sv.get("address") or "").strip()
        try:
            port = int(sv.get("port", 0))
        except (TypeError, ValueError) as exc:
            raise ProtocolParseError("Некорректный порт в Shadowsocks JSON.") from exc
        method = str(sv.get("method") or "").strip().lower()
        password = str(sv.get("password") or "")
        if not host or not (1 <= port <= 65535) or method not in VALID_SS_METHODS:
            raise ProtocolParseError("Некорректные параметры Shadowsocks JSON.")
        if not password and method != "none":
            raise ProtocolParseError("Отсутствует пароль в Shadowsocks JSON.")
        return ServerNode(
            protocol="shadowsocks",
            name=default_name or f"SS {host}:{port}",
            host=host,
            port=port,
            method=method,
            password=password,
        )

    raise ProtocolParseError(f"Неподдерживаемый протокол outbound в JSON: {proto}")


_XRAY_PROXY_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}
_XRAY_SKIP_TAGS = {"direct", "block", "dns", "dns-out", "ru", "torrent", "bypass"}


def parse_xray_json_subscription(raw_json_text: str) -> tuple[list[ServerNode], list[str]]:
    """Parse Xray/Happ JSON array `[ {...}, ... ]` or single Xray config object `{...}`."""
    try:
        parsed = json.loads(raw_json_text)
    except json.JSONDecodeError as exc:
        raise ProtocolParseError("Сервер подписки вернул некорректный JSON.") from exc

    if isinstance(parsed, dict):
        profiles = [parsed]
    elif isinstance(parsed, list):
        profiles = [item for item in parsed if isinstance(item, dict)]
    else:
        raise ProtocolParseError("Сервер подписки вернул HTML/JSON вместо списка VPN-конфигураций.")

    if not profiles or not any(isinstance(p.get("outbounds"), list) for p in profiles):
        raise ProtocolParseError("Сервер подписки вернул HTML/JSON вместо списка VPN-конфигураций.")

    nodes: list[ServerNode] = []
    warnings: list[str] = []

    for idx, prof in enumerate(profiles, start=1):
        outbounds_raw = prof.get("outbounds")
        remarks = str(prof.get("remarks") or prof.get("name") or "").strip()
        if not isinstance(outbounds_raw, list):
            warnings.append(f"Профиль #{idx} пропущен: отсутствует секция outbounds.")
            continue

        # Prefer explicit `proxy*` tagged VPN outbounds; otherwise take supported VPN protocols
        explicit_proxy_obs = [
            ob
            for ob in outbounds_raw
            if isinstance(ob, dict)
            and str(ob.get("tag") or "").strip().lower().startswith("proxy")
            and str(ob.get("protocol") or "").strip().lower() in _XRAY_PROXY_PROTOCOLS
        ]
        if explicit_proxy_obs:
            candidate_obs = explicit_proxy_obs
        else:
            candidate_obs = [
                ob
                for ob in outbounds_raw
                if isinstance(ob, dict)
                and str(ob.get("protocol") or "").strip().lower() in _XRAY_PROXY_PROTOCOLS
                and str(ob.get("tag") or "").strip().lower() not in _XRAY_SKIP_TAGS
            ]

        if not candidate_obs:
            label = f" ({remarks})" if remarks else ""
            warnings.append(f"Профиль #{idx}{label} пропущен: не содержит VPN-прокси узлов.")
            continue

        parsed_cluster: list[ServerNode] = []
        for ob_idx, ob_dict in enumerate(candidate_obs, start=1):
            try:
                parsed_cluster.append(_parse_xray_outbound_dict(ob_dict, default_name=remarks))
            except ProtocolParseError as exc:
                warnings.append(f"Профиль #{idx} узел #{ob_idx} отклонён: {exc}")

        if not parsed_cluster:
            continue

        primary = parsed_cluster[0]
        if remarks:
            primary.name = remarks
        if len(parsed_cluster) > 1:
            primary.additional_outbounds = [
                peer.to_dict(include_additional=False) for peer in parsed_cluster[1:]
            ]
        nodes.append(primary)

    if not nodes:
        detail = warnings[0] if warnings else "нет валидных серверов"
        raise ProtocolParseError(f"Ни один сервер из JSON-подписки не прошёл проверку ({detail}).")

    return nodes, warnings


def parse_subscription_payload(raw_text: str) -> tuple[list[ServerNode], list[str]]:
    """Decode JSON, Base64, or plain-text subscription content into validated ServerNodes.

    Returns (nodes, non_sensitive_warnings). Raises ProtocolParseError if empty or 0 valid nodes.
    """
    cleaned = raw_text.lstrip("\ufeff").strip()
    if not cleaned:
        raise ProtocolParseError("Ответ подписки пуст.")

    if cleaned.startswith(("[", "{")):
        return parse_xray_json_subscription(cleaned)

    candidate_lines = _extract_uri_lines(cleaned)
    if not _looks_like_uri_list(candidate_lines):
        # Attempt Base64 / URL-safe Base64 container decode
        try:
            decoded_bytes = _decode_b64_flexible(cleaned)
            decoded_text = decoded_bytes.decode("utf-8", errors="replace").lstrip("\ufeff").strip()
            if decoded_text.startswith(("[", "{")):
                return parse_xray_json_subscription(decoded_text)
            candidate_lines = _extract_uri_lines(decoded_text)
        except ProtocolParseError:
            pass

    if not _looks_like_uri_list(candidate_lines):
        if cleaned.lstrip().startswith(("<html", "<!DOCTYPE", "{")):
            raise ProtocolParseError(
                "Сервер подписки вернул HTML/JSON вместо списка VPN-конфигураций."
            )
        raise ProtocolParseError(
            "Не найдено поддерживаемых конфигураций (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC)."
        )

    nodes: list[ServerNode] = []
    warnings: list[str] = []
    for idx, line in enumerate(candidate_lines, start=1):
        if not line.lower().startswith(SUPPORTED_SCHEMES):
            warnings.append(f"Строка #{idx} пропущена: неподдерживаемый формат.")
            continue
        try:
            node = parse_proxy_uri(line)
            nodes.append(node)
        except ProtocolParseError as exc:
            warnings.append(f"Строка #{idx} отклонена: {exc}")

    if not nodes:
        detail = warnings[0] if warnings else "нет валидных серверов"
        raise ProtocolParseError(f"Ни один сервер не прошёл проверку ({detail}).")

    return nodes, warnings
