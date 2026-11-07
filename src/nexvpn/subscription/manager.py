"""Subscription manager: secure HTTPS fetching, file import, atomic updates, auto-update."""

from __future__ import annotations

import base64
import ipaddress
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from nexvpn import __version__
from nexvpn.database.repository import DatabaseRepository
from nexvpn.subscription.models import ServerNode, SubscriptionRecord
from nexvpn.subscription.parsers import ProtocolParseError, parse_subscription_payload
from nexvpn.utils.logger import get_logger

log = get_logger("subscription.manager")

MAX_SUBSCRIPTION_BYTES = 8 * 1024 * 1024  # 8 MB cap
MAX_SAFE_REDIRECTS = 5


class SubscriptionError(RuntimeError):
    """User-facing error during subscription add, import, or refresh."""


def validate_subscription_url(url: str, allow_loopback_http: bool = False) -> str:
    """Validate subscription URL scheme, host, and SSRF/downgrade safety."""
    cleaned = url.strip()
    if not cleaned:
        raise SubscriptionError("Введите URL подписки.")

    parts = urlsplit(cleaned)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").strip()

    if not host:
        raise SubscriptionError("URL подписки не содержит корректного домена или хоста.")

    is_loopback_host = host.lower() == "localhost"
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_loopback:
            is_loopback_host = True
        elif ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
            raise SubscriptionError(
                "Загрузка подписок с приватных или локальных сетевых адресов заблокирована."
            )
    except ValueError:
        pass

    if scheme == "https":
        return cleaned
    if scheme == "http" and allow_loopback_http and is_loopback_host:
        return cleaned
    if scheme == "http":
        raise SubscriptionError(
            "В целях безопасности разрешены только защищённые HTTPS-ссылки подписок."
        )
    raise SubscriptionError(f"Неподдерживаемая схема URL подписки: {scheme!r} (требуется https://).")


def _extract_profile_title(headers: httpx.Headers) -> str | None:
    raw = headers.get("profile-title") or headers.get("Profile-Title")
    if not raw:
        return None
    raw = raw.strip()
    if raw.lower().startswith("base64:"):
        b64_part = raw[7:].strip()
        try:
            pad = (-len(b64_part)) % 4
            decoded = base64.b64decode(b64_part + ("=" * pad)).decode("utf-8", errors="ignore")
            clean = "".join(ch for ch in decoded if ch.isprintable()).strip()
            return clean[:80] if clean else None
        except Exception:
            return None
    clean = "".join(ch for ch in raw if ch.isprintable()).strip()
    return clean[:80] if clean else None


class SubscriptionManager:
    """High-level service managing remote and local VPN subscriptions."""

    def __init__(
        self,
        repo: DatabaseRepository,
        allow_loopback_http: bool = False,
        timeout_sec: float = 15.0,
    ) -> None:
        self.repo = repo
        self.allow_loopback_http = allow_loopback_http
        self.timeout_sec = timeout_sec

    def fetch_remote_payload(self, url: str) -> tuple[str, str | None]:
        """Download subscription payload with strict TLS verification and safe redirect checks."""
        current_url = validate_subscription_url(url, allow_loopback_http=self.allow_loopback_http)

        headers = {
            # Advertise full Xray/XHTTP JSON capability alongside NEXVPN version so
            # Remnawave / Marzban / 3x-ui panels serve genuine XHTTP/TLS configs instead
            # of server-side fallback templates.
            "User-Agent": f"Happ/1.5.0 (Windows; NEXVPN/{__version__})",
            "Accept": "application/json, text/plain, */*;q=0.8",
        }

        try:
            with httpx.Client(
                verify=True,
                follow_redirects=False,
                timeout=httpx.Timeout(self.timeout_sec, connect=8.0),
                trust_env=False,  # Fetch directly without circular system proxy loop
            ) as client:
                for _hop in range(MAX_SAFE_REDIRECTS + 1):
                    with client.stream("GET", current_url, headers=headers) as resp:
                        if resp.status_code in (301, 302, 303, 307, 308):
                            loc = resp.headers.get("location")
                            if not loc:
                                raise SubscriptionError("Сервер вернул некорректное перенаправление без заголовка Location.")
                            next_url = urljoin(current_url, loc)
                            # Enforce no HTTPS -> HTTP downgrade and no private IP redirect
                            if current_url.lower().startswith("https://") and not next_url.lower().startswith("https://"):
                                raise SubscriptionError(
                                    "Отклонено небезопасное перенаправление с HTTPS на незащищённый протокол."
                                )
                            current_url = validate_subscription_url(
                                next_url, allow_loopback_http=self.allow_loopback_http
                            )
                            continue

                        if resp.status_code >= 400:
                            raise SubscriptionError(
                                f"Сервер подписки вернул ошибку HTTP {resp.status_code}."
                            )

                        chunks: list[bytes] = []
                        total = 0
                        for chunk in resp.iter_bytes(chunk_size=16384):
                            total += len(chunk)
                            if total > MAX_SUBSCRIPTION_BYTES:
                                raise SubscriptionError(
                                    "Размер ответа подписки превышает допустимый лимит (8 МБ)."
                                )
                            chunks.append(chunk)

                        body_text = b"".join(chunks).decode("utf-8", errors="replace")
                        suggested_title = _extract_profile_title(resp.headers)
                        return body_text, suggested_title

                raise SubscriptionError("Слишком много перенаправлений при загрузке подписки.")
        except SubscriptionError:
            raise
        except httpx.TimeoutException as exc:
            raise SubscriptionError(
                "Превышено время ожидания ответа от сервера подписки. Проверьте подключение к интернету."
            ) from exc
        except httpx.ConnectError as exc:
            raise SubscriptionError(
                "Не удалось установить соединение с сервером подписки (ошибка сети или TLS)."
            ) from exc
        except httpx.HTTPError as exc:
            raise SubscriptionError(f"Сетевая ошибка при загрузке подписки: {type(exc).__name__}") from exc

    def add_subscription_from_url(
        self,
        url: str,
        name: str = "",
        auto_update: bool = True,
        update_interval_min: int = 360,
    ) -> tuple[SubscriptionRecord, list[str]]:
        """Validate, download, parse, and persist a new URL subscription."""
        clean_url = validate_subscription_url(url, allow_loopback_http=self.allow_loopback_http)
        payload, header_title = self.fetch_remote_payload(clean_url)

        try:
            nodes, warnings = parse_subscription_payload(payload)
        except ProtocolParseError as exc:
            raise SubscriptionError(str(exc)) from exc

        host_fallback = urlsplit(clean_url).hostname or "Subscription"
        final_name = name.strip() or header_title or host_fallback

        sub = self.repo.create_subscription(
            name=final_name,
            url=clean_url,
            source_type="url",
            auto_update=auto_update,
            update_interval_min=update_interval_min,
        )
        self.repo.replace_subscription_servers(sub.id, nodes)
        self._ensure_default_selected_server()

        updated_sub = self.repo.get_subscription(sub.id)
        assert updated_sub is not None
        log.info(
            "Добавлена подписка '%s' (#%d): загружено серверов — %d",
            updated_sub.name,
            updated_sub.id,
            updated_sub.server_count,
        )
        return updated_sub, warnings

    def import_from_file(self, file_path: Path, name: str = "") -> tuple[SubscriptionRecord, list[str]]:
        """Import subscription or URI list from a local text/base64 file."""
        if not file_path.is_file():
            raise SubscriptionError(f"Файл не найден: {file_path}")
        if file_path.stat().st_size > MAX_SUBSCRIPTION_BYTES:
            raise SubscriptionError("Файл слишком велик (максимум 8 МБ).")

        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = file_path.read_bytes().decode("utf-8", errors="replace")
        except OSError as exc:
            raise SubscriptionError(f"Не удалось прочитать файл: {exc}") from exc

        try:
            nodes, warnings = parse_subscription_payload(content)
        except ProtocolParseError as exc:
            raise SubscriptionError(str(exc)) from exc

        final_name = name.strip() or file_path.stem or "Локальный импорт"
        sub = self.repo.create_subscription(
            name=final_name,
            url=None,
            source_type="file",
            auto_update=False,
            update_interval_min=360,
        )
        self.repo.replace_subscription_servers(sub.id, nodes)
        self._ensure_default_selected_server()

        updated_sub = self.repo.get_subscription(sub.id)
        assert updated_sub is not None
        log.info(
            "Импортирован файл подписки '%s' (#%d): серверов — %d",
            updated_sub.name,
            updated_sub.id,
            updated_sub.server_count,
        )
        return updated_sub, warnings

    def import_raw_text(self, raw_text: str) -> tuple[list[ServerNode], list[str]]:
        """Import one or multiple standalone proxy URIs directly into the server list."""
        try:
            nodes, warnings = parse_subscription_payload(raw_text)
        except ProtocolParseError as exc:
            raise SubscriptionError(str(exc)) from exc
        self.repo.add_standalone_servers(nodes)
        self._ensure_default_selected_server()
        log.info("Импортировано отдельных серверов: %d", len(nodes))
        return nodes, warnings

    def refresh_subscription(self, sub_id: int) -> tuple[SubscriptionRecord, list[str]]:
        """Refresh an existing URL subscription safely; preserves previous servers on failure."""
        sub = self.repo.get_subscription(sub_id)
        if sub is None:
            raise SubscriptionError("Подписка не найдена.")
        if sub.source_type != "url" or not sub.url:
            raise SubscriptionError("Локально импортированная подписка не имеет URL для обновления.")

        payload, _title = self.fetch_remote_payload(sub.url)
        try:
            nodes, warnings = parse_subscription_payload(payload)
        except ProtocolParseError as exc:
            log.warning(
                "Обновление подписки '%s' отклонено (%s) — сохранён предыдущий рабочий список.",
                sub.name,
                exc,
            )
            raise SubscriptionError(str(exc)) from exc

        self.repo.replace_subscription_servers(sub_id, nodes)
        self._ensure_default_selected_server()

        refreshed = self.repo.get_subscription(sub_id)
        assert refreshed is not None
        log.info(
            "Подписка '%s' успешно обновлена: %d серверов.",
            refreshed.name,
            refreshed.server_count,
        )
        return refreshed, warnings

    def _ensure_default_selected_server(self) -> None:
        selected = self.repo.get_setting("selected_server_id", "")
        if selected.isdigit() and self.repo.get_server(int(selected)) is not None:
            return
        servers = self.repo.list_servers()
        if servers:
            self.repo.set_setting("selected_server_id", str(servers[0].id))
