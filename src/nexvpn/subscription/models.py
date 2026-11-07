"""Typed data models for VPN server nodes, subscriptions, and connection history."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
import hashlib
import json
from typing import Any


@dataclass
class TLSOptions:
    """TLS / Reality parameters for proxy outbounds."""

    enabled: bool = False
    server_name: str = ""
    insecure: bool = False
    alpn: list[str] = field(default_factory=list)
    utls_fingerprint: str = ""
    reality_enabled: bool = False
    reality_public_key: str = ""
    reality_short_id: str = ""


@dataclass
class TransportOptions:
    """V2Ray / Xray / sing-box transport layer options."""

    type: str = ""  # "", "ws", "grpc", "http", "httpupgrade", "xhttp"
    path: str = ""
    host: str = ""
    service_name: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    mode: str = ""  # XHTTP mode ("auto", "packet-up", "stream-up", "stream-one")
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ServerNode:
    """Normalized VPN server specification across supported protocols."""

    protocol: str  # vless, vmess, trojan, shadowsocks, hysteria2, tuic
    name: str
    host: str
    port: int

    # Protocol-specific credentials
    uuid: str = ""
    password: str = ""
    method: str = ""  # Shadowsocks cipher or VMess security
    alter_id: int = 0
    flow: str = ""
    packet_encoding: str = ""

    # Shadowsocks SIP003 plugin
    plugin: str = ""
    plugin_opts: str = ""

    # Hysteria2 extras
    obfs_type: str = ""
    obfs_password: str = ""
    up_mbps: int | None = None
    down_mbps: int | None = None

    # TUIC extras
    congestion_control: str = "bbr"
    udp_relay_mode: str = "native"
    zero_rtt_handshake: bool = False

    # Nested TLS & Transport
    tls: TLSOptions = field(default_factory=TLSOptions)
    transport: TransportOptions = field(default_factory=TransportOptions)

    # Optional cluster peers from multi-outbound JSON profiles (balanced endpoints)
    additional_outbounds: list[dict[str, Any]] = field(default_factory=list)

    def compute_fingerprint(self) -> str:
        """Compute deterministic SHA-256 identity ignoring mutable display remarks."""
        parts = [
            self.protocol.lower(),
            self.host.lower(),
            str(self.port),
            self.uuid,
            self.password,
            self.method.lower(),
            self.flow.lower(),
            self.transport.type.lower(),
            self.transport.path,
            self.transport.service_name,
            self.tls.server_name.lower(),
            "1" if self.tls.reality_enabled else "0",
            self.tls.reality_public_key,
        ]
        if self.transport.type.lower() == "xhttp":
            parts.append(self.transport.mode.lower())
        identity = "|".join(parts)
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def to_dict(self, include_additional: bool = True) -> dict[str, Any]:
        data = asdict(self)
        if not include_additional:
            data.pop("additional_outbounds", None)
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(include_additional=True), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServerNode:
        raw = dict(data)
        tls_raw = raw.pop("tls", None) or {}
        tr_raw = raw.pop("transport", None) or {}
        tls_keys = {f.name for f in fields(TLSOptions)}
        tr_keys = {f.name for f in fields(TransportOptions)}
        node_keys = {f.name for f in fields(cls)} - {"tls", "transport"}
        return cls(
            tls=TLSOptions(**{k: v for k, v in tls_raw.items() if k in tls_keys}),
            transport=TransportOptions(**{k: v for k, v in tr_raw.items() if k in tr_keys}),
            **{k: v for k, v in raw.items() if k in node_keys},
        )

    @classmethod
    def from_json(cls, payload: str) -> ServerNode:
        raw: dict[str, Any] = json.loads(payload)
        return cls.from_dict(raw)

    def iter_cluster_nodes(self) -> list[ServerNode]:
        """Return `[self, *peers]` for single-node or multi-outbound cluster servers."""
        nodes = [self]
        for peer_dict in self.additional_outbounds:
            if isinstance(peer_dict, dict):
                try:
                    nodes.append(ServerNode.from_dict(peer_dict))
                except Exception:
                    continue
        return nodes


@dataclass
class ServerRecord:
    """Persisted server row combined with decrypted ServerNode."""

    id: int
    subscription_id: int | None
    fingerprint: str
    name: str
    custom_name: str | None
    protocol: str
    host: str
    port: int
    node: ServerNode
    is_favorite: bool
    latency_ms: int | None
    sort_order: int
    created_at: str
    updated_at: str

    @property
    def display_name(self) -> str:
        if self.custom_name and self.custom_name.strip():
            return self.custom_name.strip()
        if self.name and self.name.strip():
            return self.name.strip()
        return f"{self.host}:{self.port}"

    @property
    def endpoint_label(self) -> str:
        host_fmt = f"[{self.host}]" if ":" in self.host and not self.host.startswith("[") else self.host
        return f"{host_fmt}:{self.port}"

    @property
    def protocol_summary(self) -> str:
        """Human-readable protocol / transport / security summary (e.g. 'VLESS / XHTTP / TLS')."""
        parts: list[str] = [self.protocol.upper()]
        if self.node.transport.type:
            parts.append(self.node.transport.type.upper())
        if self.node.tls.reality_enabled:
            parts.append("REALITY")
        elif self.node.tls.enabled and self.protocol.lower() not in ("hysteria2", "tuic"):
            parts.append("TLS")
        return " / ".join(parts)


@dataclass
class SubscriptionRecord:
    """Persisted subscription metadata (URL decrypted only when needed)."""

    id: int
    name: str
    url: str | None
    source_type: str  # 'url' or 'file'
    auto_update: bool
    update_interval_min: int
    last_updated_at: str | None
    server_count: int
    created_at: str


@dataclass
class ConnectionHistoryRecord:
    """Audit/diagnostic history entry for VPN connection sessions."""

    id: int
    server_id: int | None
    server_name: str
    protocol: str
    mode: str
    started_at: str
    ended_at: str | None
    status: str
    bytes_up: int
    bytes_down: int
    error_message: str | None
