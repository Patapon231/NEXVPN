"""Portable path resolution and restricted file permission helpers."""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


def is_frozen() -> bool:
    """Return True when running inside a PyInstaller bundle."""
    return bool(getattr(sys, "frozen", False))


def get_portable_root() -> Path:
    """Return the root portable directory next to NEXVPN.exe (or repo root in dev)."""
    env_override = os.environ.get("NEXVPN_PORTABLE_ROOT")
    if env_override:
        return Path(env_override).resolve()

    if is_frozen():
        return Path(sys.executable).resolve().parent
    # src/nexvpn/utils/paths.py -> repo root is 3 levels up
    return Path(__file__).resolve().parents[3]


def get_bundle_dir() -> Path:
    """Return bundled read-only assets directory (_MEIPASS when frozen, else root)."""
    if is_frozen() and hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS")).resolve()
    return get_portable_root()


@dataclass(frozen=True)
class AppPaths:
    """Structured container separating core binaries, user data, runtime temp, and logs."""

    root_dir: Path
    bundle_dir: Path
    core_dir: Path
    data_dir: Path
    runtime_dir: Path
    logs_dir: Path
    assets_dir: Path
    db_file: Path
    log_file: Path

    @classmethod
    def resolve(cls, base_dir: Path | None = None) -> AppPaths:
        root = (base_dir or get_portable_root()).resolve()
        bundle = get_bundle_dir() if base_dir is None else root
        core_dir = root / "core"
        data_dir = root / "data"
        runtime_dir = data_dir / "runtime"
        logs_dir = root / "logs"
        assets_dir = bundle / "assets"

        return cls(
            root_dir=root,
            bundle_dir=bundle,
            core_dir=core_dir,
            data_dir=data_dir,
            runtime_dir=runtime_dir,
            logs_dir=logs_dir,
            assets_dir=assets_dir,
            db_file=data_dir / "nexvpn.db",
            log_file=logs_dir / "nexvpn.log",
        )

    def ensure_directories(self) -> None:
        """Create required portable directories and restrict runtime directory permissions."""
        self.core_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        restrict_path_to_current_user(self.runtime_dir)


def restrict_path_to_current_user(target: Path) -> bool:
    """Restrict file or directory ACL on Windows so only current user & SYSTEM/Admins have access."""
    if sys.platform != "win32" or not target.exists():
        return False

    username = os.environ.get("USERNAME")
    userdomain = os.environ.get("USERDOMAIN")
    if not username:
        return False

    principal = f"{userdomain}\\{username}" if userdomain else username
    grant_perm = "(OI)(CI)F" if target.is_dir() else "F"

    try:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        result = subprocess.run(
            [
                "icacls",
                str(target),
                "/inheritance:r",
                "/grant:r",
                f"{principal}:{grant_perm}",
                f"*S-1-5-18:{grant_perm}",  # NT AUTHORITY\SYSTEM
                f"*S-1-5-32-544:{grant_perm}",  # BUILTIN\Administrators
            ],
            capture_output=True,
            timeout=5,
            check=False,
            creationflags=creationflags,
        )
        return result.returncode == 0
    except Exception:
        return False
