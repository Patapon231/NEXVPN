"""SQLite schema, migrations, and database integrity verification."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import shutil
import sqlite3

from nexvpn.utils.logger import get_logger

log = get_logger("database.schema")

CURRENT_SCHEMA_VERSION = 2

MIGRATIONS: dict[int, list[str]] = {
    1: [
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url_enc TEXT,
            source_type TEXT NOT NULL DEFAULT 'url',
            auto_update INTEGER NOT NULL DEFAULT 1,
            update_interval_min INTEGER NOT NULL DEFAULT 360,
            last_updated_at TEXT,
            server_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subscription_id INTEGER REFERENCES subscriptions(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL,
            name TEXT NOT NULL,
            custom_name TEXT,
            protocol TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            config_enc TEXT NOT NULL,
            is_favorite INTEGER NOT NULL DEFAULT 0,
            latency_ms INTEGER,
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            is_secret INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS connection_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER REFERENCES servers(id) ON DELETE SET NULL,
            server_name TEXT NOT NULL,
            protocol TEXT NOT NULL,
            mode TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            status TEXT NOT NULL,
            bytes_up INTEGER NOT NULL DEFAULT 0,
            bytes_down INTEGER NOT NULL DEFAULT 0,
            error_message TEXT
        );
        """,
    ],
    2: [
        "CREATE INDEX IF NOT EXISTS idx_servers_subscription ON servers(subscription_id);",
        "CREATE INDEX IF NOT EXISTS idx_servers_fingerprint ON servers(fingerprint);",
        "CREATE INDEX IF NOT EXISTS idx_servers_favorite ON servers(is_favorite);",
        "CREATE INDEX IF NOT EXISTS idx_history_started_at ON connection_history(started_at DESC);",
    ],
}

DEFAULT_SETTINGS: dict[str, str] = {
    "connection_mode": "system_proxy",
    "local_mixed_port": "10808",
    "dns_remote": "https://1.1.1.1/dns-query",
    "dns_direct": "1.1.1.1",
    "tun_stack": "system",
    "tun_strict_route": "1",
    "system_proxy_consent": "1",
    "bypass_lan": "1",
    "autostart": "0",
    "autoconnect": "0",
    "auto_update_subs": "1",
    "auto_update_interval_min": "360",
    "language": "ru",
    "selected_server_id": "",
}


def utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_and_open_database(db_path: Path) -> sqlite3.Connection:
    """Open SQLite DB, recover safely if missing or corrupted, and apply migrations."""
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if db_path.exists():
        if not _verify_file_integrity(db_path):
            ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            backup = db_path.with_suffix(f".db.corrupt.{ts}.bak")
            log.error(
                "Обнаружено повреждение базы SQLite (%s). Создана резервная копия %s, создаётся новая БД.",
                db_path.name,
                backup.name,
            )
            shutil.move(str(db_path), str(backup))
            for wal_ext in ("-wal", "-shm", "-journal"):
                side_file = Path(str(db_path) + wal_ext)
                if side_file.exists():
                    side_file.unlink(missing_ok=True)

    conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")

    apply_migrations(conn)
    _seed_default_settings(conn)
    return conn


def _verify_file_integrity(db_path: Path) -> bool:
    try:
        raw = db_path.read_bytes()[:16]
        if raw and not raw.startswith(b"SQLite format 3\x00"):
            return False
        with sqlite3.connect(str(db_path), timeout=5.0) as probe:
            row = probe.execute("PRAGMA integrity_check;").fetchone()
            return bool(row and row[0] == "ok")
    except sqlite3.DatabaseError:
        return False
    except OSError:
        return False


def get_schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations';"
    ).fetchone()
    if not row:
        return 0
    ver_row = conn.execute("SELECT MAX(version) FROM schema_migrations;").fetchone()
    return int(ver_row[0]) if ver_row and ver_row[0] is not None else 0


def apply_migrations(conn: sqlite3.Connection) -> int:
    """Apply pending schema migrations atomically."""
    current = get_schema_version(conn)
    for target_ver in sorted(MIGRATIONS.keys()):
        if target_ver <= current:
            continue
        log.info("Применение миграции SQLite до версии %d", target_ver)
        with conn:
            for stmt in MIGRATIONS[target_ver]:
                conn.execute(stmt)
            conn.execute(
                "INSERT OR REPLACE INTO schema_migrations (version, applied_at) VALUES (?, ?);",
                (target_ver, utc_now_iso()),
            )
        current = target_ver
    return current


def _seed_default_settings(conn: sqlite3.Connection) -> None:
    now = utc_now_iso()
    with conn:
        for key, val in DEFAULT_SETTINGS.items():
            conn.execute(
                """
                INSERT INTO settings (key, value, is_secret, updated_at)
                VALUES (?, ?, 0, ?)
                ON CONFLICT(key) DO NOTHING;
                """,
                (key, val, now),
            )
