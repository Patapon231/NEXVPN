"""Windows System Proxy controller using WinINET API and HKCU Internet Settings."""

from __future__ import annotations

import ctypes
import json
import sys
from dataclasses import asdict, dataclass

if sys.platform == "win32":
    import winreg

from nexvpn.database.repository import DatabaseRepository
from nexvpn.utils.logger import get_logger

log = get_logger("services.system_proxy")

INTERNET_Settings_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
POLICY_INET_SETTINGS_PATH = r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
POLICY_IE_CONTROL_PATH = r"Software\Policies\Microsoft\Internet Explorer\Control Panel"

INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37

LAN_BYPASS_OVERRIDE = (
    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;"
    "172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;"
    "172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"
)
MINIMAL_OVERRIDE = "localhost;127.*;<local>"


class SystemProxyError(RuntimeError):
    """Base exception for Windows System Proxy configuration failures."""


class SystemProxyPolicyError(SystemProxyError):
    """Raised when Windows Group Policy forbids user-level proxy changes."""


@dataclass
class ProxySnapshot:
    """Saved state of Windows Internet Settings prior to NEXVPN activation."""

    proxy_enable: int | None
    proxy_server: str | None
    proxy_override: str | None
    auto_config_url: str | None
    nexvpn_target: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_json(cls, raw: str) -> ProxySnapshot:
        data = json.loads(raw)
        return cls(**data)


def notify_wininet_proxy_changed() -> None:
    """Broadcast WinINET proxy change notification to running Windows applications."""
    if sys.platform != "win32":
        return
    try:
        wininet = ctypes.WinDLL("wininet", use_last_error=True)
        wininet.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
        wininet.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)
    except OSError as exc:
        log.warning("Не удалось отправить уведомление WinINET: %s", exc)


class SystemProxyService:
    """Manages enabling, conflict detection, crash recovery, and restoration of Windows System Proxy."""

    BACKUP_SETTING_KEY = "system_proxy_backup"

    def __init__(
        self,
        repo: DatabaseRepository,
        registry_subkey: str = INTERNET_Settings_PATH,
        notify_wininet: bool = True,
    ) -> None:
        self.repo = repo
        self.registry_subkey = registry_subkey
        self.notify_wininet = notify_wininet
        self._active = False

    @property
    def is_active(self) -> bool:
        return self._active

    def check_policy_restrictions(self) -> None:
        """Raise SystemProxyPolicyError if Group Policy locks user proxy configuration."""
        if sys.platform != "win32":
            return
        # Check machine-level ProxySettingsPerUser == 0
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, POLICY_INET_SETTINGS_PATH, 0, winreg.KEY_READ
            ) as key:
                val, _ = winreg.QueryValueEx(key, "ProxySettingsPerUser")
                if int(val) == 0:
                    raise SystemProxyPolicyError(
                        "Настройки прокси управляются администратором компьютера (ProxySettingsPerUser=0). "
                        "Изменение без прав политики заблокировано."
                    )
        except FileNotFoundError:
            pass
        except OSError:
            pass

        # Check HKCU / HKLM IE Control Panel Proxy lock == 1
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(hive, POLICY_IE_CONTROL_PATH, 0, winreg.KEY_READ) as key:
                    val, _ = winreg.QueryValueEx(key, "Proxy")
                    if int(val) == 1:
                        raise SystemProxyPolicyError(
                            "Изменение системного прокси заблокировано групповой политикой организации."
                        )
            except FileNotFoundError:
                continue
            except OSError:
                continue

    def read_current_state(self) -> ProxySnapshot:
        """Read current WinINET proxy values from HKCU."""
        if sys.platform != "win32":
            return ProxySnapshot(None, None, None, None)

        try:
            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER, self.registry_subkey, 0, winreg.KEY_READ
            ) as key:
                p_enable = self._query_opt(key, "ProxyEnable")
                p_server = self._query_opt(key, "ProxyServer")
                p_override = self._query_opt(key, "ProxyOverride")
                auto_url = self._query_opt(key, "AutoConfigURL")
                return ProxySnapshot(
                    proxy_enable=int(p_enable) if p_enable is not None else None,
                    proxy_server=str(p_server) if p_server is not None else None,
                    proxy_override=str(p_override) if p_override is not None else None,
                    auto_config_url=str(auto_url) if auto_url is not None else None,
                )
        except OSError as exc:
            raise SystemProxyError(f"Ошибка чтения настроек реестра Windows Proxy: {exc}") from exc

    def enable(self, host: str, port: int, bypass_lan: bool = True) -> list[str]:
        """Save previous Windows proxy state and enable local proxy. Returns diagnostic warnings."""
        if sys.platform != "win32":
            raise SystemProxyError("System Proxy поддерживается только в Windows.")

        if self.registry_subkey == INTERNET_Settings_PATH:
            self.check_policy_restrictions()

        warnings: list[str] = []
        target = f"{host}:{port}"
        current = self.read_current_state()

        # Preserve pre-NEXVPN snapshot if we aren't already holding an un-restored backup
        existing_backup = self.repo.get_setting(self.BACKUP_SETTING_KEY, "")
        if not existing_backup:
            if current.proxy_enable == 1 and current.proxy_server and current.proxy_server != target:
                warn = (
                    f"Обнаружен ранее активный системный прокси ({current.proxy_server}). "
                    "Его параметры сохранены и будут восстановлены при отключении."
                )
                log.warning(warn)
                warnings.append(warn)
            current.nexvpn_target = target
            self.repo.set_setting(self.BACKUP_SETTING_KEY, current.to_json())

        override_val = LAN_BYPASS_OVERRIDE if bypass_lan else MINIMAL_OVERRIDE
        try:
            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER, self.registry_subkey, 0, winreg.KEY_SET_VALUE
            ) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, target)
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, override_val)
                self._delete_opt(key, "AutoConfigURL")
        except PermissionError as exc:
            raise SystemProxyPolicyError(
                "Доступ к настройкам системного прокси запрещён политикой безопасности Windows."
            ) from exc
        except OSError as exc:
            raise SystemProxyError(f"Не удалось применить системный прокси: {exc}") from exc

        if self.notify_wininet:
            notify_wininet_proxy_changed()

        self._active = True
        log.info("Системный прокси Windows включён -> %s", target)
        return warnings

    def disable(self) -> None:
        """Restore exact previous Windows proxy settings saved before activation."""
        if sys.platform != "win32":
            self._active = False
            return

        backup_json = self.repo.get_setting(self.BACKUP_SETTING_KEY, "")
        if not backup_json:
            if self._active:
                try:
                    with winreg.CreateKeyEx(
                        winreg.HKEY_CURRENT_USER, self.registry_subkey, 0, winreg.KEY_SET_VALUE
                    ) as key:
                        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                    if self.notify_wininet:
                        notify_wininet_proxy_changed()
                except OSError as exc:
                    log.error("Ошибка аварийного отключения системного прокси: %s", exc)
            self._active = False
            return

        try:
            snap = ProxySnapshot.from_json(backup_json)
            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER, self.registry_subkey, 0, winreg.KEY_SET_VALUE
            ) as key:
                if snap.proxy_enable is None:
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                else:
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(snap.proxy_enable))

                if snap.proxy_server is None:
                    self._delete_opt(key, "ProxyServer")
                else:
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, snap.proxy_server)

                if snap.proxy_override is None:
                    self._delete_opt(key, "ProxyOverride")
                else:
                    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, snap.proxy_override)

                if snap.auto_config_url is None:
                    self._delete_opt(key, "AutoConfigURL")
                else:
                    winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, snap.auto_config_url)

            if self.notify_wininet:
                notify_wininet_proxy_changed()
            self.repo.set_setting(self.BACKUP_SETTING_KEY, "")
            log.info("Предыдущие настройки системного прокси Windows успешно восстановлены.")
        except Exception as exc:
            log.error("Не удалось восстановить системный прокси из резервной копии: %s", exc)
        finally:
            self._active = False

    def recover_if_dirty(self) -> bool:
        """Restore Windows proxy if a previous NEXVPN session crashed while proxy was enabled."""
        backup_json = self.repo.get_setting(self.BACKUP_SETTING_KEY, "")
        if not backup_json:
            return False
        log.warning("Обнаружена незавершённая сессия System Proxy — выполняется восстановление настроек Windows.")
        self.disable()
        return True

    @staticmethod
    def _query_opt(key: object, value_name: str) -> object | None:
        try:
            val, _ = winreg.QueryValueEx(key, value_name)  # type: ignore[arg-type]
            return val
        except FileNotFoundError:
            return None

    @staticmethod
    def _delete_opt(key: object, value_name: str) -> None:
        try:
            winreg.DeleteValue(key, value_name)  # type: ignore[arg-type]
        except FileNotFoundError:
            pass
