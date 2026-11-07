"""Sanitized logging setup with secret redaction and UI ring buffer."""

from __future__ import annotations

import logging
import re
import threading
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Proxy protocol URI scheme detector
_PROXY_URI_RE = re.compile(
    r"\b(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|wireguard)://[^\s\"'<>]+",
    re.IGNORECASE,
)

# HTTP(S) URLs with path or query string (preserves scheme + host for diagnostics, hides path/tokens)
_HTTP_URL_SECRET_RE = re.compile(
    r"(https?://(?:[^\s/@\"'<>]+@)?[A-Za-z0-9.\-\[\]:]+)(/[^\s\"'<>]+|\?[^\s\"'<>]*)",
    re.IGNORECASE,
)

# URL basic-auth user:pass@host
_URL_USERINFO_RE = re.compile(
    r"(https?://)([^\s/@\"'<>]+:[^\s/@\"'<>]+@)",
    re.IGNORECASE,
)

# Standard UUID v1-v5 pattern
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

# JSON or key=value sensitive fields
_JSON_SECRET_RE = re.compile(
    r'("(?:password|uuid|secret|private_key|public_key|short_id|auth_str|auth|token)"\s*:\s*")([^"]*)(")',
    re.IGNORECASE,
)
_KV_SECRET_RE = re.compile(
    r"\b(password|uuid|secret|token|auth|pbk|sid)=([^\s&\"'<>]+)",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"(Authorization:\s*Bearer\s+)([^\s\"']+)", re.IGNORECASE)


def redact_secrets(text: str) -> str:
    """Remove subscription tokens, proxy URIs, UUIDs, and passwords from log strings."""
    if not text:
        return text
    sanitized = _PROXY_URI_RE.sub("<REDACTED_PROXY_URI>", text)
    sanitized = _URL_USERINFO_RE.sub(r"\1<REDACTED_AUTH>@", sanitized)
    sanitized = _HTTP_URL_SECRET_RE.sub(r"\1/<REDACTED_URL_PATH>", sanitized)
    sanitized = _JSON_SECRET_RE.sub(r"\1<REDACTED>\3", sanitized)
    sanitized = _KV_SECRET_RE.sub(r"\1=<REDACTED>", sanitized)
    sanitized = _BEARER_RE.sub(r"\1<REDACTED>", sanitized)
    sanitized = _UUID_RE.sub("<REDACTED_UUID>", sanitized)
    return sanitized


class SecretRedactionFilter(logging.Filter):
    """Logging filter that scrubs sensitive data before formatting/output."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_secrets(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: redact_secrets(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact_secrets(a) if isinstance(a, str) else a for a in record.args
                )
        return True


@dataclass(frozen=True)
class LogEntry:
    """Structured log entry for the UI Logs viewer."""

    timestamp: str
    level: str
    source: str
    message: str

    def format_line(self) -> str:
        return f"[{self.timestamp}] [{self.level:<7}] [{self.source}] {self.message}"


class InMemoryLogHandler(logging.Handler):
    """Thread-safe ring buffer handler feeding the UI Logs page."""

    def __init__(self, max_entries: int = 2000) -> None:
        super().__init__()
        self._entries: deque[LogEntry] = deque(maxlen=max_entries)
        self._lock = threading.Lock()
        self._listeners: list[Callable[[LogEntry], None]] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = redact_secrets(record.getMessage())
            ts = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
            entry = LogEntry(
                timestamp=ts,
                level=record.levelname,
                source=record.name,
                message=msg,
            )
            with self._lock:
                self._entries.append(entry)
                listeners = list(self._listeners)
            for callback in listeners:
                try:
                    callback(entry)
                except Exception:
                    pass
        except Exception:
            self.handleError(record)

    def get_entries(self, level_filter: str | None = None, search_query: str = "") -> list[LogEntry]:
        with self._lock:
            items = list(self._entries)
        if level_filter and level_filter.upper() != "ALL":
            lvl = level_filter.upper()
            items = [e for e in items if e.level == lvl]
        if search_query:
            q = search_query.lower()
            items = [
                e
                for e in items
                if q in e.message.lower() or q in e.source.lower() or q in e.level.lower()
            ]
        return items

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def add_listener(self, callback: Callable[[LogEntry], None]) -> None:
        with self._lock:
            if callback not in self._listeners:
                self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[LogEntry], None]) -> None:
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)


_memory_handler: InMemoryLogHandler | None = None


def setup_logging(log_file: Path | None = None, level: int = logging.INFO) -> InMemoryLogHandler:
    """Configure root 'nexvpn' logger with file rotation, redaction, and UI memory buffer."""
    global _memory_handler
    logger = logging.getLogger("nexvpn")
    logger.setLevel(level)
    logger.propagate = False

    redactor = SecretRedactionFilter()

    if _memory_handler is None:
        _memory_handler = InMemoryLogHandler(max_entries=2000)
        _memory_handler.addFilter(redactor)

    # Clear duplicate handlers on re-init while keeping memory handler entries
    for h in list(logger.handlers):
        if h is not _memory_handler:
            logger.removeHandler(h)
            h.close()

    if _memory_handler not in logger.handlers:
        logger.addHandler(_memory_handler)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(redactor)
        logger.addHandler(file_handler)

    return _memory_handler


def get_memory_log_handler() -> InMemoryLogHandler:
    """Return the active InMemoryLogHandler, initializing if needed."""
    global _memory_handler
    if _memory_handler is None:
        return setup_logging()
    return _memory_handler


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the 'nexvpn' hierarchy."""
    if not name.startswith("nexvpn"):
        name = f"nexvpn.{name}"
    return logging.getLogger(name)
