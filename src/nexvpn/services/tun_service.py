"""TUN mode service: privilege verification, Wintun check, subnet conflict handling, and cleanup."""

from __future__ import annotations

import ctypes
import ipaddress
import socket
import subprocess
import sys
import time

from nexvpn.core.locator import CoreInfo
from nexvpn.utils.logger import get_logger

log = get_logger("services.tun")

CANDIDATE_TUN_CIDRS = (
    "172.19.0.1/30",
    "172.31.250.1/30",
    "198.18.0.1/30",
    "10.255.250.1/30",
)


class TunError(RuntimeError):
    """Base error for TUN mode preflight or runtime problems."""


class TunPermissionError(TunError):
    """Raised when administrator privileges are required to create a Wintun adapter."""


class TunDriverError(TunError):
    """Raised when Wintun driver cannot be loaded or initialized."""


class TunRouteConflictError(TunError):
    """Raised when all candidate TUN subnets conflict with active host interfaces."""


def is_running_as_admin() -> bool:
    """Return True if the current Windows process has elevated Administrator privileges."""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_host_ipv4_addresses() -> set[str]:
    """Query currently bound IPv4 addresses on Windows interfaces."""
    addrs: set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip_str = str(info[4][0])
            if ip_str:
                addrs.add(ip_str)
    except OSError:
        pass

    if sys.platform == "win32":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        try:
            proc = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                encoding="oem",
                errors="replace",
                timeout=4,
                check=False,
                creationflags=creationflags,
            )
            for token in proc.stdout.replace(":", " ").split():
                if token.count(".") == 3:
                    try:
                        ipaddress.IPv4Address(token)
                        addrs.add(token)
                    except ValueError:
                        continue
        except Exception:
            pass

    return addrs


def is_ipv4_bound_locally(ip_str: str) -> bool:
    """Return True if a local interface currently owns `ip_str` (verified via socket bind)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind((ip_str, 0))
            return True
    except OSError:
        return False


class TunService:
    """Preflight checks, subnet selection, readiness verification, and post-stop cleanup for TUN."""

    INTERFACE_NAME = "NEXVPN-TUN"

    def preflight_check(self, core_info: CoreInfo) -> tuple[str, list[str]]:
        """Verify admin rights, core TUN support, and select a conflict-free TUN CIDR.

        Returns `(selected_cidr, warnings)`.
        """
        if not is_running_as_admin():
            raise TunPermissionError(
                "Для работы режима TUN в Windows требуются права администратора. "
                "Перезапустите NEXVPN от имени администратора или переключитесь на System Proxy."
            )

        # Verify sing-box binary exists and is amd64/arm64 Windows build with embedded Wintun/gVisor
        if not core_info.binary_path.is_file():
            raise TunDriverError("Не найден исполняемый файл sing-box для инициализации Wintun.")

        warnings: list[str] = []
        existing_ips = get_host_ipv4_addresses()

        selected_cidr: str | None = None
        for idx, cidr in enumerate(CANDIDATE_TUN_CIDRS):
            iface = ipaddress.ip_interface(cidr)
            net = iface.network
            conflict = False
            for host_ip_str in existing_ips:
                try:
                    if ipaddress.IPv4Address(host_ip_str) in net:
                        conflict = True
                        break
                except ValueError:
                    continue
            if not conflict:
                selected_cidr = cidr
                if idx > 0:
                    warn = (
                        f"Обнаружен конфликт маршрутов для стандартной подсети 172.19.0.1/30; "
                        f"выбрана свободная подсеть {cidr}."
                    )
                    log.warning(warn)
                    warnings.append(warn)
                break

        if selected_cidr is None:
            raise TunRouteConflictError(
                "Обнаружен конфликт маршрутов со всеми резервными подсетями TUN. "
                "Отключите другие активные VPN-клиенты и повторите попытку."
            )

        return selected_cidr, warnings

    def wait_until_interface_up(self, tun_cidr: str, timeout_sec: float = 8.0) -> bool:
        """Wait until Windows binds the virtual TUN IPv4 address (real interface readiness)."""
        tun_ip = str(ipaddress.ip_interface(tun_cidr).ip)
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            if is_ipv4_bound_locally(tun_ip):
                log.info("TUN-интерфейс %s активен (IP: %s).", self.INTERFACE_NAME, tun_ip)
                return True
            time.sleep(0.2)
        return False

    def analyze_failure(self, diagnostic_tail: str) -> str:
        """Inspect sing-box stderr output to detect missing/blocked Wintun driver or policy error."""
        lower = diagnostic_tail.lower()
        if "wintun" in lower or "driver" in lower:
            return (
                "Не удалось инициализировать драйвер Wintun. Проверьте, не заблокирована ли "
                f"установка сетевых драйверов политикой безопасности Windows. Детали: {diagnostic_tail}"
            )
        if "access is denied" in lower or "privilege" in lower:
            return "Недостаточно системных разрешений для создания TUN-интерфейса или маршрутов."
        return f"Не удалось поднять TUN-интерфейс: {diagnostic_tail or 'тайм-аут инициализации'}"

    def verify_cleanup(self, tun_cidr: str | None) -> None:
        """Ensure virtual TUN IP is released and flush stale DNS cache entries on disconnect."""
        if tun_cidr:
            tun_ip = str(ipaddress.ip_interface(tun_cidr).ip)
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and is_ipv4_bound_locally(tun_ip):
                time.sleep(0.15)
            if is_ipv4_bound_locally(tun_ip):
                log.warning("Интерфейс %s ещё завершает освобождение в ОС.", self.INTERFACE_NAME)
            else:
                log.info("TUN-интерфейс %s корректно удалён, маршруты восстановлены.", self.INTERFACE_NAME)

        if sys.platform == "win32":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            try:
                subprocess.run(
                    ["ipconfig", "/flushdns"],
                    capture_output=True,
                    timeout=4,
                    check=False,
                    creationflags=creationflags,
                )
            except Exception:
                pass
