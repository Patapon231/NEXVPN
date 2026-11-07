"""Connection state machine definitions, modes, and diagnostic structures."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ConnectionState(StrEnum):
    """Strict VPN connection lifecycle states."""

    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    RECONNECTING = "RECONNECTING"
    DISCONNECTING = "DISCONNECTING"
    ERROR = "ERROR"


class ConnectionMode(StrEnum):
    """Supported routing modes."""

    SYSTEM_PROXY = "system_proxy"
    TUN = "tun"


@dataclass(frozen=True)
class TrafficStats:
    """Real-time upload and download throughput from sing-box Clash API."""

    upload_bps: int = 0
    download_bps: int = 0
    upload_total: int = 0
    download_total: int = 0
    available: bool = False


@dataclass
class DiagnosticInfo:
    """Live diagnostic snapshot of the current or last connection attempt."""

    state: ConnectionState = ConnectionState.DISCONNECTED
    mode: ConnectionMode = ConnectionMode.SYSTEM_PROXY
    core_version: str = ""
    local_proxy_port: int | None = None
    tun_interface: str | None = None
    latency_ms: int | None = None
    last_error: str = ""
    warnings: list[str] = field(default_factory=list)


def format_speed(bps: int) -> str:
    """Format bytes/second into human-readable rate."""
    if bps < 1024:
        return f"{bps} B/s"
    if bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    if bps < 1024 * 1024 * 1024:
        return f"{bps / (1024 * 1024):.2f} MB/s"
    return f"{bps / (1024 * 1024 * 1024):.2f} GB/s"


def format_bytes(num_bytes: int) -> str:
    """Format cumulative byte count."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    if num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.2f} MB"
    return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"
