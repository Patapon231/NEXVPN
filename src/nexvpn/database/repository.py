"""Thread-safe SQLite repository with Windows DPAPI protection for secrets."""

from __future__ import annotations

from pathlib import Path
import sqlite3
import threading

from nexvpn.database.crypto import DPAPIError, protect_secret, unprotect_secret
from nexvpn.database.schema import check_and_open_database, utc_now_iso
from nexvpn.subscription.models import (
    ConnectionHistoryRecord,
    ServerNode,
    ServerRecord,
    SubscriptionRecord,
)
from nexvpn.utils.logger import get_logger

log = get_logger("database.repository")


class DatabaseRepository:
    """Data access layer managing subscriptions, servers, settings, and connection history."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._closed = False
        self._conn: sqlite3.Connection = check_and_open_database(db_path)

    @property
    def is_closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                self._conn.close()

    def check_integrity(self) -> bool:
        with self._lock:
            row = self._conn.execute("PRAGMA integrity_check;").fetchone()
            return bool(row and row[0] == "ok")

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    def get_setting(self, key: str, default: str = "") -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT value, is_secret FROM settings WHERE key = ?;", (key,)
            ).fetchone()
        if row is None:
            return default
        val = str(row["value"])
        if int(row["is_secret"]):
            try:
                return unprotect_secret(val)
            except DPAPIError as exc:
                log.error("Не удалось расшифровать настройку '%s': %s", key, exc)
                return default
        return val

    def set_setting(self, key: str, value: str, is_secret: bool = False) -> None:
        stored = protect_secret(value) if is_secret and value else value
        now = utc_now_iso()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO settings (key, value, is_secret, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    is_secret = excluded.is_secret,
                    updated_at = excluded.updated_at;
                """,
                (key, stored, 1 if is_secret else 0, now),
            )

    def get_all_settings(self) -> dict[str, str]:
        with self._lock:
            rows = self._conn.execute("SELECT key, value, is_secret FROM settings;").fetchall()
        result: dict[str, str] = {}
        for r in rows:
            key = str(r["key"])
            val = str(r["value"])
            if int(r["is_secret"]) and val:
                try:
                    val = unprotect_secret(val)
                except DPAPIError:
                    val = ""
            result[key] = val
        return result

    # ------------------------------------------------------------------
    # Subscriptions
    # ------------------------------------------------------------------

    def create_subscription(
        self,
        name: str,
        url: str | None,
        source_type: str = "url",
        auto_update: bool = True,
        update_interval_min: int = 360,
    ) -> SubscriptionRecord:
        now = utc_now_iso()
        url_enc = protect_secret(url) if url else None
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                INSERT INTO subscriptions (
                    name, url_enc, source_type, auto_update, update_interval_min,
                    last_updated_at, server_count, created_at
                )
                VALUES (?, ?, ?, ?, ?, NULL, 0, ?);
                """,
                (name.strip() or "Subscription", url_enc, source_type, int(auto_update), update_interval_min, now),
            )
            sub_id = int(cur.lastrowid)  # type: ignore[arg-type]
        sub = self.get_subscription(sub_id)
        assert sub is not None
        return sub

    def get_subscription(self, sub_id: int) -> SubscriptionRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM subscriptions WHERE id = ?;", (sub_id,)
            ).fetchone()
        return self._row_to_subscription(row) if row else None

    def list_subscriptions(self) -> list[SubscriptionRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM subscriptions ORDER BY id ASC;"
            ).fetchall()
        return [self._row_to_subscription(r) for r in rows]

    def rename_subscription(self, sub_id: int, new_name: str) -> None:
        clean = new_name.strip()
        if not clean:
            return
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE subscriptions SET name = ? WHERE id = ?;",
                (clean, sub_id),
            )

    def set_subscription_auto_update(
        self, sub_id: int, enabled: bool, interval_min: int | None = None
    ) -> None:
        with self._lock, self._conn:
            if interval_min is not None:
                self._conn.execute(
                    "UPDATE subscriptions SET auto_update = ?, update_interval_min = ? WHERE id = ?;",
                    (int(enabled), max(5, interval_min), sub_id),
                )
            else:
                self._conn.execute(
                    "UPDATE subscriptions SET auto_update = ? WHERE id = ?;",
                    (int(enabled), sub_id),
                )

    def delete_subscription(self, sub_id: int) -> None:
        with self._lock, self._conn:
            selected_raw = self.get_setting("selected_server_id", "")
            self._conn.execute("DELETE FROM subscriptions WHERE id = ?;", (sub_id,))
            if selected_raw.isdigit():
                still_exists = self._conn.execute(
                    "SELECT 1 FROM servers WHERE id = ?;", (int(selected_raw),)
                ).fetchone()
                if not still_exists:
                    self._conn.execute(
                        "UPDATE settings SET value = '' WHERE key = 'selected_server_id';"
                    )

    def replace_subscription_servers(self, sub_id: int, new_nodes: list[ServerNode]) -> int:
        """Atomically replace servers of a subscription ONLY after new_nodes are parsed.

        Preserves user custom_name, is_favorite, latency_ms, and selected_server_id!
        """
        if not new_nodes:
            raise ValueError("Список серверов пуст — предыдущие серверы сохранены без изменений.")

        now = utc_now_iso()
        with self._lock, self._conn:
            old_rows = self._conn.execute(
                "SELECT * FROM servers WHERE subscription_id = ?;", (sub_id,)
            ).fetchall()

            # Index previous metadata by fingerprint, endpoint, and display name
            by_fp: dict[str, sqlite3.Row] = {}
            by_addr: dict[str, sqlite3.Row] = {}
            by_name: dict[str, sqlite3.Row] = {}
            for r in old_rows:
                by_fp[str(r["fingerprint"])] = r
                addr_key = f"{r['protocol']}|{str(r['host']).lower()}|{r['port']}"
                by_addr.setdefault(addr_key, r)
                norm_name = str(r["name"] or "").strip()
                if norm_name:
                    by_name.setdefault(norm_name, r)

            selected_raw = self.get_setting("selected_server_id", "")
            old_selected_id = int(selected_raw) if selected_raw.isdigit() else None
            old_selected_fp: str | None = None
            old_selected_addr: str | None = None
            old_selected_name: str | None = None
            for r in old_rows:
                if int(r["id"]) == old_selected_id:
                    old_selected_fp = str(r["fingerprint"])
                    old_selected_addr = f"{r['protocol']}|{str(r['host']).lower()}|{r['port']}"
                    old_selected_name = str(r["name"] or "").strip() or None
                    break

            prepared: list[tuple[str, ServerNode, str | None, int, int | None, str]] = []
            for node in new_nodes:
                fp = node.compute_fingerprint()
                addr_key = f"{node.protocol}|{node.host.lower()}|{node.port}"
                norm_name = node.name.strip()
                exact_match = by_fp.get(fp) or by_addr.get(addr_key)
                matched = exact_match or (by_name.get(norm_name) if norm_name else None)
                custom_name = str(matched["custom_name"]) if matched and matched["custom_name"] else None
                is_fav = int(matched["is_favorite"]) if matched else 0
                # Preserve latency only if the actual server endpoint matched
                latency = (
                    int(exact_match["latency_ms"])
                    if exact_match and exact_match["latency_ms"] is not None
                    else None
                )
                created = str(matched["created_at"]) if matched else now
                prepared.append((fp, node, custom_name, is_fav, latency, created))

            # Pre-encrypt all node configs BEFORE deleting old rows so any error aborts cleanly
            encrypted_configs = [protect_secret(item[1].to_json()) for item in prepared]

            self._conn.execute("DELETE FROM servers WHERE subscription_id = ?;", (sub_id,))

            new_selected_id: int | None = None
            fallback_selected_by_addr: int | None = None
            fallback_selected_by_name: int | None = None
            for order_idx, ((fp, node, custom_name, is_fav, latency, created), cfg_enc) in enumerate(
                zip(prepared, encrypted_configs, strict=True)
            ):
                cur = self._conn.execute(
                    """
                    INSERT INTO servers (
                        subscription_id, fingerprint, name, custom_name, protocol,
                        host, port, config_enc, is_favorite, latency_ms,
                        sort_order, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        sub_id,
                        fp,
                        node.name,
                        custom_name,
                        node.protocol,
                        node.host,
                        node.port,
                        cfg_enc,
                        is_fav,
                        latency,
                        order_idx,
                        created,
                        now,
                    ),
                )
                inserted_id = int(cur.lastrowid)  # type: ignore[arg-type]
                if old_selected_fp and fp == old_selected_fp and new_selected_id is None:
                    new_selected_id = inserted_id
                addr_key = f"{node.protocol}|{node.host.lower()}|{node.port}"
                if old_selected_addr and addr_key == old_selected_addr and fallback_selected_by_addr is None:
                    fallback_selected_by_addr = inserted_id
                if old_selected_name and node.name.strip() == old_selected_name and fallback_selected_by_name is None:
                    fallback_selected_by_name = inserted_id

            resolved_selected_id = (
                new_selected_id or fallback_selected_by_addr or fallback_selected_by_name
            )

            self._conn.execute(
                """
                UPDATE subscriptions
                SET last_updated_at = ?, server_count = ?
                WHERE id = ?;
                """,
                (now, len(prepared), sub_id),
            )

            if old_selected_fp is not None:
                self._conn.execute(
                    "UPDATE settings SET value = ?, updated_at = ? WHERE key = 'selected_server_id';",
                    (str(resolved_selected_id) if resolved_selected_id is not None else "", now),
                )

        return len(new_nodes)

    def _row_to_subscription(self, row: sqlite3.Row) -> SubscriptionRecord:
        url_plain: str | None = None
        if row["url_enc"]:
            try:
                url_plain = unprotect_secret(str(row["url_enc"]))
            except DPAPIError as exc:
                log.error("Не удалось расшифровать URL подписки #%s: %s", row["id"], exc)
        return SubscriptionRecord(
            id=int(row["id"]),
            name=str(row["name"]),
            url=url_plain,
            source_type=str(row["source_type"]),
            auto_update=bool(row["auto_update"]),
            update_interval_min=int(row["update_interval_min"]),
            last_updated_at=str(row["last_updated_at"]) if row["last_updated_at"] else None,
            server_count=int(row["server_count"]),
            created_at=str(row["created_at"]),
        )

    # ------------------------------------------------------------------
    # Servers
    # ------------------------------------------------------------------

    def add_standalone_servers(self, nodes: list[ServerNode]) -> list[ServerRecord]:
        """Insert manually imported standalone server URIs (subscription_id = NULL)."""
        now = utc_now_iso()
        inserted_ids: list[int] = []
        with self._lock, self._conn:
            max_row = self._conn.execute("SELECT COALESCE(MAX(sort_order), -1) FROM servers;").fetchone()
            base_order = int(max_row[0]) + 1 if max_row else 0
            for idx, node in enumerate(nodes):
                fp = node.compute_fingerprint()
                cfg_enc = protect_secret(node.to_json())
                cur = self._conn.execute(
                    """
                    INSERT INTO servers (
                        subscription_id, fingerprint, name, custom_name, protocol,
                        host, port, config_enc, is_favorite, latency_ms,
                        sort_order, created_at, updated_at
                    )
                    VALUES (NULL, ?, ?, NULL, ?, ?, ?, ?, 0, NULL, ?, ?, ?);
                    """,
                    (
                        fp,
                        node.name,
                        node.protocol,
                        node.host,
                        node.port,
                        cfg_enc,
                        base_order + idx,
                        now,
                        now,
                    ),
                )
                inserted_ids.append(int(cur.lastrowid))  # type: ignore[arg-type]

        records: list[ServerRecord] = []
        for sid in inserted_ids:
            rec = self.get_server(sid)
            if rec:
                records.append(rec)
        return records

    def get_server(self, server_id: int) -> ServerRecord | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM servers WHERE id = ?;", (server_id,)).fetchone()
        return self._row_to_server(row) if row else None

    def list_servers(self, subscription_id: int | None = None) -> list[ServerRecord]:
        with self._lock:
            if subscription_id is not None:
                rows = self._conn.execute(
                    "SELECT * FROM servers WHERE subscription_id = ? ORDER BY sort_order ASC, id ASC;",
                    (subscription_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM servers ORDER BY is_favorite DESC, sort_order ASC, id ASC;"
                ).fetchall()
        out: list[ServerRecord] = []
        for r in rows:
            rec = self._row_to_server(r)
            if rec is not None:
                out.append(rec)
        return out

    def rename_server(self, server_id: int, custom_name: str | None) -> None:
        clean = custom_name.strip() if custom_name else None
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE servers SET custom_name = ?, updated_at = ? WHERE id = ?;",
                (clean or None, utc_now_iso(), server_id),
            )

    def toggle_server_favorite(self, server_id: int, is_favorite: bool) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE servers SET is_favorite = ?, updated_at = ? WHERE id = ?;",
                (1 if is_favorite else 0, utc_now_iso(), server_id),
            )

    def update_server_latency(self, server_id: int, latency_ms: int | None) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE servers SET latency_ms = ?, updated_at = ? WHERE id = ?;",
                (latency_ms, utc_now_iso(), server_id),
            )

    def delete_server(self, server_id: int) -> None:
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT subscription_id FROM servers WHERE id = ?;", (server_id,)
            ).fetchone()
            self._conn.execute("DELETE FROM servers WHERE id = ?;", (server_id,))
            if row and row["subscription_id"] is not None:
                sub_id = int(row["subscription_id"])
                cnt_row = self._conn.execute(
                    "SELECT COUNT(*) FROM servers WHERE subscription_id = ?;", (sub_id,)
                ).fetchone()
                cnt = int(cnt_row[0]) if cnt_row else 0
                self._conn.execute(
                    "UPDATE subscriptions SET server_count = ? WHERE id = ?;", (cnt, sub_id)
                )
            if self.get_setting("selected_server_id", "") == str(server_id):
                self._conn.execute(
                    "UPDATE settings SET value = '' WHERE key = 'selected_server_id';"
                )

    def _row_to_server(self, row: sqlite3.Row) -> ServerRecord | None:
        try:
            json_str = unprotect_secret(str(row["config_enc"]))
            node = ServerNode.from_json(json_str)
        except Exception as exc:
            log.error("Не удалось прочитать конфигурацию сервера #%s: %s", row["id"], exc)
            return None

        return ServerRecord(
            id=int(row["id"]),
            subscription_id=int(row["subscription_id"]) if row["subscription_id"] is not None else None,
            fingerprint=str(row["fingerprint"]),
            name=str(row["name"]),
            custom_name=str(row["custom_name"]) if row["custom_name"] else None,
            protocol=str(row["protocol"]),
            host=str(row["host"]),
            port=int(row["port"]),
            node=node,
            is_favorite=bool(row["is_favorite"]),
            latency_ms=int(row["latency_ms"]) if row["latency_ms"] is not None else None,
            sort_order=int(row["sort_order"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    # ------------------------------------------------------------------
    # Connection History
    # ------------------------------------------------------------------

    def record_connection_start(
        self,
        server_id: int | None,
        server_name: str,
        protocol: str,
        mode: str,
    ) -> int:
        now = utc_now_iso()
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                INSERT INTO connection_history (
                    server_id, server_name, protocol, mode, started_at, status
                )
                VALUES (?, ?, ?, ?, ?, 'CONNECTING');
                """,
                (server_id, server_name, protocol, mode, now),
            )
            return int(cur.lastrowid)  # type: ignore[arg-type]

    def update_connection_history(
        self,
        history_id: int,
        status: str,
        bytes_up: int = 0,
        bytes_down: int = 0,
        error_message: str | None = None,
        ended: bool = False,
    ) -> None:
        ended_at = utc_now_iso() if ended else None
        with self._lock, self._conn:
            if ended:
                self._conn.execute(
                    """
                    UPDATE connection_history
                    SET status = ?, ended_at = ?, bytes_up = ?, bytes_down = ?, error_message = ?
                    WHERE id = ?;
                    """,
                    (status, ended_at, bytes_up, bytes_down, error_message, history_id),
                )
            else:
                self._conn.execute(
                    """
                    UPDATE connection_history
                    SET status = ?, bytes_up = ?, bytes_down = ?, error_message = ?
                    WHERE id = ?;
                    """,
                    (status, bytes_up, bytes_down, error_message, history_id),
                )

    def list_connection_history(self, limit: int = 50) -> list[ConnectionHistoryRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM connection_history ORDER BY id DESC LIMIT ?;", (limit,)
            ).fetchall()
        return [
            ConnectionHistoryRecord(
                id=int(r["id"]),
                server_id=int(r["server_id"]) if r["server_id"] is not None else None,
                server_name=str(r["server_name"]),
                protocol=str(r["protocol"]),
                mode=str(r["mode"]),
                started_at=str(r["started_at"]),
                ended_at=str(r["ended_at"]) if r["ended_at"] else None,
                status=str(r["status"]),
                bytes_up=int(r["bytes_up"]),
                bytes_down=int(r["bytes_down"]),
                error_message=str(r["error_message"]) if r["error_message"] else None,
            )
            for r in rows
        ]
