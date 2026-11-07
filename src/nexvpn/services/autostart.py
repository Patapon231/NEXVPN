"""User-level Windows Autostart management via HKCU\\...\\Run."""

from __future__ import annotations

from pathlib import Path
import sys

if sys.platform == "win32":
    import winreg

from nexvpn.utils.logger import get_logger
from nexvpn.utils.paths import is_frozen

log = get_logger("services.autostart")

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_VALUE_NAME = "NEXVPN"


def build_autostart_command() -> str:
    """Build quoted startup command line for frozen EXE or Python dev script."""
    if is_frozen():
        exe = Path(sys.executable).resolve()
        return f'"{exe}" --minimized'
    main_script = Path(__file__).resolve().parents[3] / "main.py"
    py_exe = Path(sys.executable).resolve()
    return f'"{py_exe}" "{main_script}" --minimized'


def is_autostart_enabled(reg_subkey: str = RUN_KEY_PATH) -> bool:
    if sys.platform != "win32":
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_subkey, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, AUTOSTART_VALUE_NAME)
            return bool(val)
    except FileNotFoundError:
        return False
    except OSError:
        return False


def set_autostart_enabled(enabled: bool, reg_subkey: str = RUN_KEY_PATH) -> bool:
    """Enable or remove HKCU Run entry for NEXVPN."""
    if sys.platform != "win32":
        return False
    try:
        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, reg_subkey, 0, winreg.KEY_SET_VALUE
        ) as key:
            if enabled:
                cmd = build_autostart_command()
                winreg.SetValueEx(key, AUTOSTART_VALUE_NAME, 0, winreg.REG_SZ, cmd)
                log.info("Автозапуск Windows включён: %s", cmd)
            else:
                try:
                    winreg.DeleteValue(key, AUTOSTART_VALUE_NAME)
                    log.info("Автозапуск Windows отключён.")
                except FileNotFoundError:
                    pass
        return True
    except OSError as exc:
        log.error("Не удалось изменить параметр автозапуска Windows: %s", exc)
        return False
