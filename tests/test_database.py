"""Stage 2 tests: DPAPI encryption, SQLite schema/migrations/corruption recovery, subscription atomic updates."""

from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sqlite3
import threading

import pytest

from nexvpn.database.crypto import DPAPIError, protect_secret, unprotect_secret
from nexvpn.database.repository import DatabaseRepository
from nexvpn.subscription.manager import SubscriptionError, SubscriptionManager


def test_dpapi_roundtrip_and_tamper_detection() -> None:
    secret = "https://sub.example.com/api/v1/token-998877?flag=singbox#Привет"
    enc = protect_secret(secret)
    assert enc.startswith("dpapi:v1:")
    assert "token-998877" not in enc
    assert unprotect_secret(enc) == secret

    with pytest.raises(DPAPIError):
        unprotect_secret("dpapi:v1:AAAA_invalid_cipher_blob====")


def test_sqlite_creation_integrity_and_corrupt_recovery(tmp_path: Path) -> None:
    db_file = tmp_path / "nexvpn.db"
    # Write garbage to simulate corrupted DB file
    db_file.write_bytes(b"NOT_A_VALID_SQLITE_DATABASE_HEADER_12345")

    repo = DatabaseRepository(db_file)
    try:
        assert repo.check_integrity() is True
        corrupt_backups = list(tmp_path.glob("nexvpn.db.corrupt.*.bak"))
        assert len(corrupt_backups) == 1
        assert repo.get_setting("connection_mode") == "system_proxy"
    finally:
        repo.close()


def test_secrets_encrypted_at_rest_in_sqlite(tmp_path: Path) -> None:
    db_file = tmp_path / "vault.db"
    repo = DatabaseRepository(db_file)
    try:
        sub = repo.create_subscription(
            name="TestSub",
            url="https://secret-provider.org/sub/superSecretTokenXYZ",
        )
        assert sub.url == "https://secret-provider.org/sub/superSecretTokenXYZ"
        repo.set_setting("api_secret", "topSecretValue999", is_secret=True)
        assert repo.get_setting("api_secret") == "topSecretValue999"
    finally:
        repo.close()

    # Inspect raw SQLite bytes / columns directly to ensure zero plaintext leakage
    with sqlite3.connect(str(db_file)) as raw_conn:
        row = raw_conn.execute("SELECT url_enc FROM subscriptions;").fetchone()
        assert row is not None
        assert "superSecretTokenXYZ" not in row[0]
        assert str(row[0]).startswith("dpapi:v1:")

        srow = raw_conn.execute("SELECT value FROM settings WHERE key='api_secret';").fetchone()
        assert srow is not None
        assert "topSecretValue999" not in srow[0]


def test_subscription_manager_atomic_refresh_preserves_favorites_and_renames(tmp_path: Path) -> None:
    payload_state = {
        "body": base64.b64encode(
            (
                "vless://11111111-2222-3333-4444-555555555555@de1.example.com:443?security=tls&sni=de1.example.com#Germany-1\n"
                "trojan://pass123@nl1.example.com:443?sni=nl1.example.com#Netherlands-1\n"
            ).encode("utf-8")
        ).decode("ascii"),
        "status": 200,
    }

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(payload_state["status"])
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(str(payload_state["body"]).encode("utf-8"))

        def log_message(self, fmt: str, *args: object) -> None:
            return

    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_port
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    repo = DatabaseRepository(tmp_path / "subs.db")
    mgr = SubscriptionManager(repo, allow_loopback_http=True)
    try:
        # Block plain HTTP when allow_loopback_http=False
        strict_mgr = SubscriptionManager(repo, allow_loopback_http=False)
        with pytest.raises(SubscriptionError):
            strict_mgr.add_subscription_from_url(f"http://127.0.0.1:{port}/sub")

        sub, warnings = mgr.add_subscription_from_url(f"http://127.0.0.1:{port}/sub", name="MySub")
        assert sub.server_count == 2
        assert warnings == []

        servers = repo.list_servers(sub.id)
        assert len(servers) == 2
        de_srv = next(s for s in servers if s.host == "de1.example.com")

        # User renames server, marks favorite, and selects it
        repo.rename_server(de_srv.id, "Мой Любимый DE")
        repo.toggle_server_favorite(de_srv.id, True)
        repo.set_setting("selected_server_id", str(de_srv.id))

        # Now server returns broken empty/garbage response -> previous servers MUST survive!
        payload_state["body"] = "<html>502 Bad Gateway</html>"
        with pytest.raises(SubscriptionError):
            mgr.refresh_subscription(sub.id)

        surviving = repo.list_servers(sub.id)
        assert len(surviving) == 2

        # Now server returns updated valid list (Germany-1 + new Finland-1)
        payload_state["body"] = (
            "vless://11111111-2222-3333-4444-555555555555@de1.example.com:443?security=tls&sni=de1.example.com#Germany-Updated\n"
            "ss://aes-256-gcm:secretpw@fi1.example.com:8388#Finland-1\n"
        )
        refreshed_sub, _ = mgr.refresh_subscription(sub.id)
        assert refreshed_sub.server_count == 2

        updated_servers = repo.list_servers(sub.id)
        de_after = next(s for s in updated_servers if s.host == "de1.example.com")
        assert de_after.custom_name == "Мой Любимый DE"
        assert de_after.display_name == "Мой Любимый DE"
        assert de_after.is_favorite is True
        assert repo.get_setting("selected_server_id") == str(de_after.id)
    finally:
        httpd.shutdown()
        repo.close()
