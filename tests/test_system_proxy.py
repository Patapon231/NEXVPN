"""Stage 5 & 8 tests: Windows System Proxy backup, conflict preservation, restore, and crash recovery."""

from __future__ import annotations

from pathlib import Path
import sys
import winreg

import pytest

from nexvpn.database.repository import DatabaseRepository
from nexvpn.services.autostart import is_autostart_enabled, set_autostart_enabled
from nexvpn.services.system_proxy import SystemProxyService

TEST_PROXY_SUBKEY = r"Software\NEXVPN_Pytest_Isolated_InternetSettings"
TEST_RUN_SUBKEY = r"Software\NEXVPN_Pytest_Isolated_Run"


def _delete_hkcu_subkey(subkey: str) -> None:
    if sys.platform != "win32":
        return
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)
    except FileNotFoundError:
        pass


@pytest.fixture()
def isolated_reg() -> object:
    _delete_hkcu_subkey(TEST_PROXY_SUBKEY)
    _delete_hkcu_subkey(TEST_RUN_SUBKEY)
    yield
    _delete_hkcu_subkey(TEST_PROXY_SUBKEY)
    _delete_hkcu_subkey(TEST_RUN_SUBKEY)


def test_system_proxy_enable_conflict_backup_and_exact_restore(
    tmp_path: Path, isolated_reg: object
) -> None:
    # Seed pre-existing user proxy + PAC URL in isolated HKCU test key
    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER, TEST_PROXY_SUBKEY, 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "127.0.0.1:7890")
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "corp.internal;<local>")
        winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, "http://pac.corp.internal/proxy.pac")

    repo = DatabaseRepository(tmp_path / "proxy.db")
    svc = SystemProxyService(repo=repo, registry_subkey=TEST_PROXY_SUBKEY, notify_wininet=False)
    try:
        warnings = svc.enable("127.0.0.1", 10808, bypass_lan=True)
        assert len(warnings) == 1
        assert "127.0.0.1:7890" in warnings[0]

        active_state = svc.read_current_state()
        assert active_state.proxy_enable == 1
        assert active_state.proxy_server == "127.0.0.1:10808"
        assert active_state.auto_config_url is None

        # Simulate crash recovery on next app launch without clean disable()
        crashed_svc = SystemProxyService(
            repo=repo, registry_subkey=TEST_PROXY_SUBKEY, notify_wininet=False
        )
        assert crashed_svc.recover_if_dirty() is True

        restored = crashed_svc.read_current_state()
        assert restored.proxy_enable == 1
        assert restored.proxy_server == "127.0.0.1:7890"
        assert restored.proxy_override == "corp.internal;<local>"
        assert restored.auto_config_url == "http://pac.corp.internal/proxy.pac"
    finally:
        repo.close()


def test_autostart_registry_toggle(isolated_reg: object) -> None:
    assert is_autostart_enabled(TEST_RUN_SUBKEY) is False
    assert set_autostart_enabled(True, TEST_RUN_SUBKEY) is True
    assert is_autostart_enabled(TEST_RUN_SUBKEY) is True
    assert set_autostart_enabled(False, TEST_RUN_SUBKEY) is True
    assert is_autostart_enabled(TEST_RUN_SUBKEY) is False
