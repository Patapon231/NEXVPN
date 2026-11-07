"""Network port checks and real TCP latency helpers."""

from __future__ import annotations

import socket
import time


def is_port_available(port: int, host: str = "127.0.0.1") -> bool:
    """Return True if a local TCP port is free to bind exclusively on Windows."""
    if not (1 <= port <= 65535):
        return False

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        excl_opt = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if excl_opt is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, excl_opt, 1)
            except OSError:
                pass
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def find_free_port(preferred: int = 0, host: str = "127.0.0.1") -> int:
    """Return preferred port if free, otherwise allocate an ephemeral local port."""
    if preferred and is_port_available(preferred, host=host):
        return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def is_local_port_listening(port: int, host: str = "127.0.0.1", timeout: float = 0.4) -> bool:
    """Return True when a local server is actively listening on host:port."""
    if not (1 <= port <= 65535):
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def measure_tcp_latency_ms(host: str, port: int, timeout: float = 3.5) -> int | None:
    """Perform a real TCP handshake to host:port and return RTT in ms, or None on failure."""
    if not host or not (1 <= port <= 65535):
        return None
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed_ms = round((time.perf_counter() - start) * 1000)
            return max(1, elapsed_ms)
    except OSError:
        return None
