"""Stage 9 tests: PyInstaller frozen path resolution and separation of runtime vs user data."""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

from nexvpn.utils.paths import AppPaths


def test_pyinstaller_frozen_paths_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    portable_root = tmp_path / "NEXVPN"
    internal_dir = portable_root / "_internal"
    (internal_dir / "assets" / "fonts").mkdir(parents=True)
    fake_exe = portable_root / "NEXVPN.exe"
    fake_exe.write_bytes(b"MZ")

    monkeypatch.delenv("NEXVPN_PORTABLE_ROOT", raising=False)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(fake_exe))
    monkeypatch.setattr(sys, "_MEIPASS", str(internal_dir), raising=False)

    paths = AppPaths.resolve()
    paths.ensure_directories()

    assert paths.root_dir == portable_root.resolve()
    assert paths.bundle_dir == internal_dir.resolve()
    assert paths.core_dir == (portable_root / "core").resolve()
    assert paths.data_dir == (portable_root / "data").resolve()
    assert paths.runtime_dir == (portable_root / "data" / "runtime").resolve()
    assert paths.logs_dir == (portable_root / "logs").resolve()
    assert paths.assets_dir == (internal_dir / "assets").resolve()
    assert paths.db_file == (portable_root / "data" / "nexvpn.db").resolve()
    assert paths.log_file == (portable_root / "logs" / "nexvpn.log").resolve()
