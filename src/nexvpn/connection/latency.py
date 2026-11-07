"""Real network latency measurement (TCP handshake RTT and active local proxy HTTP 204 RTT)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time

import httpx
from PySide6.QtCore import QObject, QThread, Signal

from nexvpn.subscription.models import ServerRecord


def measure_node_tcp_rtt_ms(host: str, port: int, timeout: float = 3.2) -> int:
    """Measure real TCP SYN -> SYN-ACK roundtrip time in ms. Returns -1 on failure/timeout."""
    if not host or not (1 <= port <= 65535):
        return -1

    try:
        addr_infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return -1

    if not addr_infos:
        return -1

    for family, socktype, proto, _canon, sockaddr in addr_infos[:2]:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        start = time.perf_counter()
        try:
            sock.connect(sockaddr)
            elapsed_ms = round((time.perf_counter() - start) * 1000)
            return max(1, elapsed_ms)
        except OSError:
            continue
        finally:
            sock.close()

    return -1


def measure_server_tcp_rtt_ms(server: ServerRecord, timeout: float = 3.2) -> int:
    """Measure TCP RTT to a ServerRecord, falling back to cluster peers if primary endpoint times out."""
    primary_rtt = measure_node_tcp_rtt_ms(server.host, server.port, timeout=timeout)
    if primary_rtt >= 0 or not server.node.additional_outbounds:
        return primary_rtt

    seen: set[tuple[str, int]] = {(server.host.lower(), server.port)}
    peer_timeout = min(2.0, timeout)
    best = -1
    checked = 0
    for peer in server.node.iter_cluster_nodes()[1:]:
        key = (peer.host.lower(), peer.port)
        if key in seen:
            continue
        seen.add(key)
        checked += 1
        rtt = measure_node_tcp_rtt_ms(peer.host, peer.port, timeout=peer_timeout)
        if rtt >= 0 and (best < 0 or rtt < best):
            best = rtt
            break
        if checked >= 6:
            break
    return best


def measure_proxy_roundtrip_ms(
    local_mixed_port: int,
    test_url: str = "http://cp.cloudflare.com/generate_204",
    timeout: float = 5.0,
) -> int:
    """Measure real end-to-end HTTP 204 latency through active local sing-box mixed proxy."""
    proxy_url = f"http://127.0.0.1:{local_mixed_port}"
    try:
        with httpx.Client(
            proxy=proxy_url,
            timeout=httpx.Timeout(timeout, connect=3.0),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            start = time.perf_counter()
            resp = client.get(test_url)
            if 200 <= resp.status_code < 400:
                return max(1, round((time.perf_counter() - start) * 1000))
            return -1
    except Exception:
        return -1


class BatchLatencyWorker(QThread):
    """Non-blocking Qt worker performing concurrent real TCP latency checks across servers."""

    result_ready = Signal(int, int)  # (server_id, latency_ms_or_neg1)
    all_finished = Signal()

    def __init__(
        self,
        servers: list[ServerRecord],
        timeout: float = 3.0,
        max_workers: int = 8,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._servers = list(servers)
        self._timeout = timeout
        self._max_workers = max(1, min(max_workers, 16))
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        if not self._servers:
            self.all_finished.emit()
            return

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures = {
                pool.submit(measure_server_tcp_rtt_ms, srv, self._timeout): srv.id
                for srv in self._servers
            }
            for fut in as_completed(futures):
                if self._cancelled:
                    break
                srv_id = futures[fut]
                try:
                    ms = int(fut.result())
                except Exception:
                    ms = -1
                self.result_ready.emit(srv_id, ms)

        self.all_finished.emit()
