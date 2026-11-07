"""Automatic discovery and version/capability inspection for sing-box."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from nexvpn.utils.logger import get_logger
from nexvpn.utils.paths import AppPaths

log = get_logger("core.locator")

_VERSION_RE = re.compile(r"sing-box\s+version\s+([0-9]+\.[0-9]+\.[0-9]+[^\s]*)", re.IGNORECASE)
_XRAY_VERSION_RE = re.compile(r"Xray\s+([0-9]+\.[0-9]+\.[0-9]+[^\s]*)", re.IGNORECASE)
_TAGS_RE = re.compile(r"^Tags:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


@dataclass(frozen=True)
class CoreInfo:
    """Metadata describing the discovered sing-box binary."""

    binary_path: Path
    version: str
    major: int
    minor: int
    patch: int
    tags: frozenset[str] = field(default_factory=frozenset)
    raw_output: str = ""

    @property
    def supports_quic(self) -> bool:
        """True if Hysteria2 and TUIC (QUIC-based protocols) are supported."""
        return "with_quic" in self.tags or (self.major, self.minor) >= (1, 12)

    @property
    def supports_utls(self) -> bool:
        return "with_utls" in self.tags

    @property
    def supports_clash_api(self) -> bool:
        return "with_clash_api" in self.tags

    @property
    def supports_gvisor(self) -> bool:
        return "with_gvisor" in self.tags


class CoreNotFoundError(FileNotFoundError):
    """Raised when sing-box.exe cannot be found."""


class XrayNotFoundError(CoreNotFoundError):
    """Raised when xray.exe companion binary for XHTTP transport cannot be found."""


class CoreVersionError(RuntimeError):
    """Raised when sing-box binary fails execution or reports an incompatible version."""


def locate_sing_box(paths: AppPaths | None = None, custom_path: Path | None = None) -> Path:
    """Locate sing-box executable in portable core/, environment override, or system PATH."""
    candidates: list[Path] = []

    if custom_path is not None:
        candidates.append(custom_path)

    env_bin = os.environ.get("NEXVPN_SINGBOX_PATH")
    if env_bin:
        candidates.append(Path(env_bin))

    resolved_paths = paths or AppPaths.resolve()
    candidates.append(resolved_paths.core_dir / "sing-box.exe")
    candidates.append(resolved_paths.root_dir / "sing-box.exe")

    which_path = shutil.which("sing-box")
    if which_path:
        candidates.append(Path(which_path))

    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()

    raise CoreNotFoundError(
        f"Ядро sing-box.exe не найдено. Ожидаемый путь: {resolved_paths.core_dir / 'sing-box.exe'}"
    )


def inspect_sing_box(binary_path: Path) -> CoreInfo:
    """Execute `sing-box version` and parse version numbers and build tags."""
    if not binary_path.is_file():
        raise CoreNotFoundError(f"Файл ядра не существует: {binary_path}")

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        proc = subprocess.run(
            [str(binary_path), "version"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=8,
            check=False,
            creationflags=creationflags,
        )
    except OSError as exc:
        raise CoreVersionError(f"Не удалось запустить sing-box: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CoreVersionError("Превышено время ожидания ответа от `sing-box version`.") from exc

    output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    if proc.returncode != 0:
        raise CoreVersionError(
            f"Команда `sing-box version` завершилась с кодом {proc.returncode}: {output.strip()}"
        )

    match = _VERSION_RE.search(output)
    if not match:
        raise CoreVersionError(f"Не удалось распознать версию sing-box: {output.strip()}")

    ver_str = match.group(1)
    num_parts = re.findall(r"\d+", ver_str)
    major = int(num_parts[0]) if len(num_parts) > 0 else 0
    minor = int(num_parts[1]) if len(num_parts) > 1 else 0
    patch = int(num_parts[2]) if len(num_parts) > 2 else 0

    tags: set[str] = set()
    tags_match = _TAGS_RE.search(output)
    if tags_match:
        tags = {t.strip() for t in tags_match.group(1).split(",") if t.strip()}

    info = CoreInfo(
        binary_path=binary_path.resolve(),
        version=ver_str,
        major=major,
        minor=minor,
        patch=patch,
        tags=frozenset(tags),
        raw_output=output.strip(),
    )
    log.info("Обнаружено ядро sing-box v%s (%s)", info.version, info.binary_path)
    return info


def locate_xray(paths: AppPaths | None = None, custom_path: Path | None = None) -> Path:
    """Locate official Xray-core executable for native XHTTP (`splithttp`) transport."""
    candidates: list[Path] = []

    if custom_path is not None:
        candidates.append(custom_path)

    env_bin = os.environ.get("NEXVPN_XRAY_PATH")
    if env_bin:
        candidates.append(Path(env_bin))

    resolved_paths = paths or AppPaths.resolve()
    candidates.append(resolved_paths.core_dir / "xray.exe")
    candidates.append(resolved_paths.root_dir / "xray.exe")

    which_path = shutil.which("xray")
    if which_path:
        candidates.append(Path(which_path))

    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()

    raise XrayNotFoundError(
        f"Для протокола XHTTP требуется модуль xray.exe, но он не найден ({resolved_paths.core_dir / 'xray.exe'})."
    )


def inspect_xray(binary_path: Path) -> str:
    """Execute `xray version` and return its version string."""
    if not binary_path.is_file():
        raise XrayNotFoundError(f"Файл xray.exe не существует: {binary_path}")

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        proc = subprocess.run(
            [str(binary_path), "version"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=8,
            check=False,
            creationflags=creationflags,
        )
    except OSError as exc:
        raise CoreVersionError(f"Не удалось запустить xray.exe: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CoreVersionError("Превышено время ожидания ответа от `xray version`.") from exc

    output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    if proc.returncode != 0:
        raise CoreVersionError(
            f"Команда `xray version` завершилась с кодом {proc.returncode}: {output.strip()}"
        )

    match = _XRAY_VERSION_RE.search(output)
    ver_str = match.group(1) if match else "unknown"
    log.info("Обнаружен модуль Xray v%s (%s)", ver_str, binary_path.resolve())
    return ver_str
