"""NEXVPN Desktop entry point."""

from __future__ import annotations

import argparse
import atexit
import sys
from pathlib import Path

# Ensure `src` is importable when running `python main.py` directly in dev
_ROOT = Path(__file__).resolve().parent
_SRC = _ROOT / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from PySide6.QtCore import Qt, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from nexvpn.ui.main_window import MainWindow  # noqa: E402
from nexvpn.ui.theme import apply_app_theme  # noqa: E402
from nexvpn.utils.logger import get_logger, setup_logging  # noqa: E402
from nexvpn.utils.paths import AppPaths  # noqa: E402
from nexvpn.utils.single_instance import SingleInstanceGuard  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NEXVPN Desktop VPN Client")
    parser.add_argument(
        "--self-test-ms",
        type=int,
        default=0,
        help="Automatically exit after N milliseconds (for automated startup verification).",
    )
    parser.add_argument(
        "--minimized",
        action="store_true",
        help="Start NEXVPN minimized (used by Windows autostart).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    paths = AppPaths.resolve()
    paths.ensure_directories()

    log_handler = setup_logging(paths.log_file)
    log = get_logger("app")
    log.info("Запуск NEXVPN (корень: %s)", paths.root_dir)

    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv if argv is None else [sys.argv[0], *argv])
    app.setApplicationName("NEXVPN")
    app.setOrganizationName("NEXVPN")

    font_family = apply_app_theme(app, paths.assets_dir)
    log.info("Активирована тема NEXVPN (шрифт: %s)", font_family)

    mutex_name = (
        "Local\\NEXVPN_Desktop_SelfTest_Mutex"
        if args.self_test_ms > 0
        else "Local\\NEXVPN_Desktop_SingleInstance_v1"
    )
    guard = SingleInstanceGuard(mutex_name)
    if not guard.acquire():
        log.warning("Попытка запуска второго экземпляра NEXVPN отклонена.")
        if args.self_test_ms <= 0:
            QMessageBox.warning(
                None,
                "NEXVPN",
                "Приложение NEXVPN уже запущено.",
            )
        return 1

    window: MainWindow | None = None
    cleaned_up = False

    def _ensure_shutdown() -> None:
        nonlocal cleaned_up
        if not cleaned_up and window is not None:
            cleaned_up = True
            window.shutdown_cleanly()

    atexit.register(_ensure_shutdown)

    try:
        window = MainWindow(
            paths=paths,
            log_handler=log_handler,
            enable_autoconnect=(args.self_test_ms <= 0),
        )
        app.aboutToQuit.connect(_ensure_shutdown)

        if args.minimized:
            window.showMinimized()
        else:
            window.show()

        if args.self_test_ms > 0:
            QTimer.singleShot(args.self_test_ms, window.close)

        return app.exec()
    finally:
        _ensure_shutdown()
        guard.release()
        log.info("Завершение работы NEXVPN.")


if __name__ == "__main__":
    raise SystemExit(main())
