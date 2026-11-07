"""Non-blocking real-time traffic reader via sing-box local Clash API."""

from __future__ import annotations

import json

import httpx
from PySide6.QtCore import QObject, QThread, Signal

from nexvpn.connection.states import TrafficStats


class _TrafficStreamWorker(QThread):
    """Streams real upload/download throughput from `GET /traffic` on 127.0.0.1."""

    stats_updated = Signal(object)

    def __init__(self, port: int, secret: str, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.port = port
        self.secret = secret
        self._stop_requested = False

    def request_stop(self) -> None:
        self._stop_requested = True

    def run(self) -> None:
        url = f"http://127.0.0.1:{self.port}/traffic"
        headers = {"Authorization": f"Bearer {self.secret}"} if self.secret else {}
        up_total = 0
        down_total = 0

        try:
            with httpx.Client(
                timeout=httpx.Timeout(3.0, read=2.5),
                trust_env=False,
            ) as client:
                with client.stream("GET", url, headers=headers) as resp:
                    if resp.status_code != 200:
                        return
                    for line in resp.iter_lines():
                        if self._stop_requested:
                            break
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            up_bps = max(0, int(data.get("up", 0)))
                            down_bps = max(0, int(data.get("down", 0)))
                            up_total += up_bps
                            down_total += down_bps
                            self.stats_updated.emit(
                                TrafficStats(
                                    upload_bps=up_bps,
                                    download_bps=down_bps,
                                    upload_total=up_total,
                                    download_total=down_total,
                                    available=True,
                                )
                            )
                        except (ValueError, TypeError):
                            continue
        except Exception:
            return


class TrafficMonitor(QObject):
    """Controller for real-time sing-box traffic telemetry."""

    stats_updated = Signal(object)  # TrafficStats

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._worker: _TrafficStreamWorker | None = None
        self._latest = TrafficStats()

    @property
    def latest(self) -> TrafficStats:
        return self._latest

    def start(self, clash_port: int, secret: str) -> None:
        self.stop()
        self._latest = TrafficStats()
        worker = _TrafficStreamWorker(port=clash_port, secret=secret, parent=self)
        worker.stats_updated.connect(self._on_stats)
        self._worker = worker
        worker.start()

    def _on_stats(self, stats: object) -> None:
        if isinstance(stats, TrafficStats):
            self._latest = stats
            self.stats_updated.emit(stats)

    def stop(self) -> None:
        if self._worker is not None:
            self._worker.request_stop()
            self._worker.wait(2600)
            self._worker.deleteLater()
            self._worker = None
        self._latest = TrafficStats()
