"""Stage 6 & 8 security and TUN tests: privilege check, subnet conflict resolution, unsafe redirect block."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import threading

import pytest

from nexvpn.core.locator import inspect_sing_box, locate_sing_box
from nexvpn.database.repository import DatabaseRepository
from nexvpn.services import tun_service
from nexvpn.services.tun_service import (
    TunPermissionError,
    TunRouteConflictError,
    TunService,
)
from nexvpn.subscription.manager import (
    SubscriptionError,
    SubscriptionManager,
    validate_subscription_url,
)


def test_tun_permission_check_when_unprivileged(monkeypatch: pytest.MonkeyPatch) -> None:
    core_info = inspect_sing_box(locate_sing_box())
    svc = TunService()

    monkeypatch.setattr(tun_service, "is_running_as_admin", lambda: False)
    with pytest.raises(TunPermissionError):
        svc.preflight_check(core_info)


def test_tun_route_conflict_fallback_and_exhaustion(monkeypatch: pytest.MonkeyPatch) -> None:
    core_info = inspect_sing_box(locate_sing_box())
    svc = TunService()

    monkeypatch.setattr(tun_service, "is_running_as_admin", lambda: True)
    # Simulate 172.19.0.2 already used by another adapter -> falls back to 172.31.250.1/30
    monkeypatch.setattr(tun_service, "get_host_ipv4_addresses", lambda: {"172.19.0.2"})
    cidr, warnings = svc.preflight_check(core_info)
    assert cidr == "172.31.250.1/30"
    assert len(warnings) == 1

    # Simulate all candidate subnets occupied -> raises TunRouteConflictError
    monkeypatch.setattr(
        tun_service,
        "get_host_ipv4_addresses",
        lambda: {"172.19.0.1", "172.31.250.2", "198.18.0.2", "10.255.250.2"},
    )
    with pytest.raises(TunRouteConflictError):
        svc.preflight_check(core_info)

    # Verify Wintun driver failure diagnostic message
    diag_msg = svc.analyze_failure("FATAL[0000] create tun: Failed to load wintun.dll driver")
    assert "Wintun" in diag_msg


def test_subscription_ssrf_and_redirect_security(tmp_path: Path) -> None:
    # Private IP and non-HTTPS schemes must be blocked
    for unsafe_url in (
        "http://example.com/sub",
        "https://192.168.1.1/sub",
        "https://10.0.0.5/sub",
        "https://169.254.169.254/latest/meta-data/",
        "file:///C:/Windows/win.ini",
    ):
        with pytest.raises(SubscriptionError):
            validate_subscription_url(unsafe_url, allow_loopback_http=False)

    # Redirect to private IP must be blocked even if initial request was allowed
    class _EvilRedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "https://169.254.169.254/secret")
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            return

    httpd = HTTPServer(("127.0.0.1", 0), _EvilRedirectHandler)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    repo = DatabaseRepository(tmp_path / "sec.db")
    mgr = SubscriptionManager(repo, allow_loopback_http=True)
    try:
        with pytest.raises(SubscriptionError):
            mgr.add_subscription_from_url(f"http://127.0.0.1:{port}/start")
    finally:
        httpd.shutdown()
        repo.close()
