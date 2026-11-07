"""Automated Portable EXE builder for NEXVPN Desktop (PyInstaller + directory layout + ZIP)."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def generate_app_icon(ico_path: Path) -> None:
    from PySide6.QtGui import QGuiApplication

    from nexvpn.ui.icons import save_brand_ico

    _app = QGuiApplication.instance() or QGuiApplication([])
    save_brand_ico(ico_path)


def build_portable(preserve_existing_data: bool = False, output_folder_name: str = "NEXVPN") -> Path:
    dist_root = ROOT / "dist"
    build_root = ROOT / "build"
    portable_dir = dist_root / output_folder_name
    backup_data_dir = dist_root / "_nexvpn_data_backup"

    if backup_data_dir.exists():
        shutil.rmtree(backup_data_dir)
    if preserve_existing_data and (portable_dir / "data").is_dir():
        shutil.copytree(portable_dir / "data", backup_data_dir)

    if portable_dir.exists():
        shutil.rmtree(portable_dir)
    if build_root.exists():
        shutil.rmtree(build_root)

    target_distpath = dist_root
    out_portable_dir = dist_root / output_folder_name

    ico_path = ROOT / "assets" / "icon.ico"
    print("[1/4] Генерация иконки приложения assets/icon.ico...")
    generate_app_icon(ico_path)

    singbox_src = ROOT / "core" / "sing-box.exe"
    if not singbox_src.is_file():
        raise FileNotFoundError(
            f"Не найден {singbox_src}. Поместите sing-box.exe в каталог core/ перед сборкой."
        )

    excluded_modules = [
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
        "PySide6.QtWebChannel",
        "PySide6.QtPdf",
        "PySide6.QtPdfWidgets",
        "PySide6.QtQml",
        "PySide6.QtQuick",
        "PySide6.QtQuickWidgets",
        "PySide6.Qt3DCore",
        "PySide6.Qt3DRender",
        "PySide6.QtMultimedia",
        "PySide6.QtMultimediaWidgets",
        "PySide6.QtCharts",
        "PySide6.QtDataVisualization",
        "PySide6.QtSql",
        "PySide6.QtTest",
        "tkinter",
        "pytest",
    ]

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--windowed",
        "--distpath",
        str(target_distpath),
        "--name",
        "NEXVPN",
        "--paths",
        str(SRC),
        "--icon",
        str(ico_path),
        "--add-data",
        f"{ROOT / 'assets'};assets",
    ]
    for mod in excluded_modules:
        cmd.extend(["--exclude-module", mod])
    cmd.append(str(ROOT / "main.py"))

    print("[2/4] Сборка исполняемого файла NEXVPN.exe через PyInstaller...")
    subprocess.run(cmd, cwd=str(ROOT), check=True)

    print("[3/4] Формирование структуры Portable-дистрибутива NEXVPN/...")
    core_dst = out_portable_dir / "core"
    data_dst = out_portable_dir / "data"
    logs_dst = out_portable_dir / "logs"
    core_dst.mkdir(parents=True, exist_ok=True)
    data_dst.mkdir(parents=True, exist_ok=True)
    logs_dst.mkdir(parents=True, exist_ok=True)

    shutil.copy2(singbox_src, core_dst / "sing-box.exe")
    lic_sb = ROOT / "core" / "LICENSE.sing-box"
    if lic_sb.is_file():
        shutil.copy2(lic_sb, core_dst / "LICENSE.sing-box")

    xray_src = ROOT / "core" / "xray.exe"
    if xray_src.is_file():
        shutil.copy2(xray_src, core_dst / "xray.exe")
    lic_xr = ROOT / "core" / "LICENSE.xray"
    if lic_xr.is_file():
        shutil.copy2(lic_xr, core_dst / "LICENSE.xray")

    for doc_name in ("LICENSE", "THIRD_PARTY_NOTICES.md", "README.md"):
        doc_src = ROOT / doc_name
        if doc_src.is_file():
            shutil.copy2(doc_src, out_portable_dir / doc_name)

    print("[4/4] Создание архива dist/NEXVPN-Portable-win64.zip...")
    zip_base = dist_root / "NEXVPN-Portable-win64"
    archive_path = shutil.make_archive(
        base_name=str(zip_base),
        format="zip",
        root_dir=str(target_distpath),
        base_dir="NEXVPN",
    )

    if backup_data_dir.is_dir():
        shutil.copytree(backup_data_dir, data_dst, dirs_exist_ok=True)
        shutil.rmtree(backup_data_dir)

    final_dir = out_portable_dir

    print(f"Готово! Portable-папка: {final_dir}")
    print(f"Готово! Portable-архив: {archive_path}")
    return final_dir


if __name__ == "__main__":
    build_portable(preserve_existing_data=False)
