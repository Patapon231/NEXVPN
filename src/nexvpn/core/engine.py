"""Asynchronous QProcess controller for sing-box with validation, ACL protection, and crash detection."""

from __future__ import annotations

from collections import deque
from pathlib import Path
import subprocess
import time
from typing import Any

from PySide6.QtCore import QCoreApplication, QEventLoop, QObject, QProcess, QTimer, Signal

from nexvpn.core.config_generator import serialize_config
from nexvpn.core.locator import (
    CoreInfo,
    inspect_sing_box,
    inspect_xray,
    locate_sing_box,
    locate_xray,
)
from nexvpn.utils.logger import get_logger, redact_secrets
from nexvpn.utils.network import is_local_port_listening
from nexvpn.utils.paths import AppPaths, restrict_path_to_current_user
from nexvpn.utils.single_instance import SingleInstanceGuard

log = get_logger("core.engine")


class CoreEngineError(RuntimeError):
    """Base error for sing-box process and validation failures."""


class CoreConfigInvalidError(CoreEngineError):
    """Raised when `sing-box check -c` rejects the generated configuration."""


class CoreAlreadyRunningError(CoreEngineError):
    """Raised on duplicate start attempts while sing-box is already active."""


class CoreEngine(QObject):
    """Manages lifecycle, config validation, log capture, and crash detection of sing-box."""

    started = Signal(int)  # OS PID
    stopped = Signal(int)  # exit_code
    crashed = Signal(int, str)  # (exit_code, diagnostic_tail)
    output_line = Signal(str, str)  # (stream: "stdout"|"stderr", sanitized_line)

    def __init__(
        self,
        paths: AppPaths,
        mutex_name: str = "Local\\NEXVPN_SingBox_Engine_Mutex_v1",
        config_filename: str = "active_config.json",
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.paths = paths
        self._config_path = paths.runtime_dir / config_filename
        self._xray_config_path = paths.runtime_dir / "active_xray.json"
        self._mutex = SingleInstanceGuard(mutex_name)
        self._proc: QProcess | None = None
        self._xray_proc: QProcess | None = None
        self._stopping = False
        self._recent_lines: deque[str] = deque(maxlen=40)
        self._stdout_buf = ""
        self._stderr_buf = ""
        self._xray_stdout_buf = ""
        self._xray_stderr_buf = ""
        self._core_info: CoreInfo | None = None
        self._xray_path: Path | None = None
        self._xray_version: str | None = None

    @property
    def is_running(self) -> bool:
        return (
            self._proc is not None
            and self._proc.state() != QProcess.ProcessState.NotRunning
        )

    @property
    def pid(self) -> int | None:
        if self.is_running and self._proc is not None:
            p = int(self._proc.processId())
            return p if p > 0 else None
        return None

    @property
    def core_info(self) -> CoreInfo | None:
        return self._core_info

    def ensure_core_ready(self) -> CoreInfo:
        """Locate sing-box binary and verify its version/tags."""
        bin_path = locate_sing_box(self.paths)
        if self._core_info is None or self._core_info.binary_path != bin_path:
            self._core_info = inspect_sing_box(bin_path)
        return self._core_info

    def ensure_xray_ready(self) -> tuple[Path, str]:
        """Locate xray.exe companion binary and verify its version."""
        bin_path = locate_xray(self.paths)
        if self._xray_path != bin_path or self._xray_version is None:
            self._xray_version = inspect_xray(bin_path)
            self._xray_path = bin_path
        return bin_path, self._xray_version

    def write_restricted_config(self, config: dict[str, Any], target_path: Path | None = None) -> Path:
        """Write config JSON to runtime directory and restrict Windows file ACLs."""
        cfg_file = target_path or self._config_path
        cfg_file.parent.mkdir(parents=True, exist_ok=True)
        restrict_path_to_current_user(cfg_file.parent)

        json_payload = serialize_config(config)
        cfg_file.write_text(json_payload, encoding="utf-8")
        restrict_path_to_current_user(cfg_file)
        return cfg_file

    def validate_config(self, config: dict[str, Any]) -> None:
        """Validate configuration dictionary using real `sing-box check -c`."""
        info = self.ensure_core_ready()
        check_path = self.paths.runtime_dir / f"validate_{id(config)}.json"
        try:
            self.write_restricted_config(config, target_path=check_path)
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            proc = subprocess.run(
                [str(info.binary_path), "check", "-c", str(check_path)],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=8,
                check=False,
                creationflags=creationflags,
            )
            if proc.returncode != 0:
                err_raw = (proc.stderr or proc.stdout or "Unknown config error").strip()
                sanitized = redact_secrets(err_raw)
                raise CoreConfigInvalidError(
                    f"Проверка конфигурации sing-box не пройдена: {sanitized}"
                )
        finally:
            self._secure_remove_file(check_path)

    def validate_xray_config(self, xray_config: dict[str, Any]) -> None:
        """Validate Xray bridge configuration dictionary using real `xray run -test -c`."""
        xray_bin, _ver = self.ensure_xray_ready()
        check_path = self.paths.runtime_dir / f"validate_xray_{id(xray_config)}.json"
        try:
            self.write_restricted_config(xray_config, target_path=check_path)
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            proc = subprocess.run(
                [str(xray_bin), "run", "-test", "-c", str(check_path)],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=8,
                check=False,
                creationflags=creationflags,
            )
            if proc.returncode != 0:
                err_raw = (proc.stderr or proc.stdout or "Unknown Xray config error").strip()
                sanitized = redact_secrets(err_raw)
                raise CoreConfigInvalidError(
                    f"Проверка конфигурации Xray не пройдена: {sanitized}"
                )
        finally:
            self._secure_remove_file(check_path)

    def start(
        self,
        config: dict[str, Any],
        xray_config: dict[str, Any] | None = None,
        xray_socks_port: int | None = None,
    ) -> None:
        """Validate configuration and spawn sing-box (plus optional Xray XHTTP bridge) via QProcess."""
        if self.is_running:
            raise CoreAlreadyRunningError("Процесс sing-box уже запущен.")

        if not self._mutex.acquire():
            raise CoreAlreadyRunningError(
                "Обнаружен другой активный экземпляр движка sing-box NEXVPN."
            )

        try:
            info = self.ensure_core_ready()
            self.validate_config(config)

            self._stopping = False
            self._recent_lines.clear()
            self._stdout_buf = ""
            self._stderr_buf = ""
            self._xray_stdout_buf = ""
            self._xray_stderr_buf = ""

            if xray_config is not None:
                xray_bin, _xray_ver = self.ensure_xray_ready()
                self.validate_xray_config(xray_config)
                xray_cfg_path = self.write_restricted_config(
                    xray_config, target_path=self._xray_config_path
                )

                xproc = QProcess(self)
                xproc.setProgram(str(xray_bin))
                xproc.setArguments(["run", "-c", str(xray_cfg_path)])
                xproc.setWorkingDirectory(str(self.paths.runtime_dir))
                xproc.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
                xproc.readyReadStandardOutput.connect(self._on_xray_stdout_ready)
                xproc.readyReadStandardError.connect(self._on_xray_stderr_ready)
                xproc.finished.connect(self._on_xray_finished)
                self._xray_proc = xproc
                xproc.start()

                if not xproc.waitForStarted(3000):
                    err_str = xproc.errorString()
                    self._cleanup_after_exit()
                    raise CoreEngineError(f"Не удалось запустить модуль Xray: {err_str}")

                if xray_socks_port is not None:
                    deadline = time.monotonic() + 3.0
                    while time.monotonic() < deadline:
                        if xproc.state() == QProcess.ProcessState.NotRunning:
                            break
                        if is_local_port_listening(xray_socks_port, timeout=0.15):
                            break
                        QCoreApplication.processEvents()
                        time.sleep(0.05)
                    if not is_local_port_listening(xray_socks_port, timeout=0.25):
                        diag = self.get_diagnostic_tail()
                        self._stopping = True
                        self._terminate_qprocess(xproc, 1000)
                        self._cleanup_after_exit()
                        raise CoreEngineError(
                            f"Мост Xray (порт {xray_socks_port}) не запустился вовремя. {diag}".strip()
                        )

            cfg_path = self.write_restricted_config(config)

            proc = QProcess(self)
            proc.setProgram(str(info.binary_path))
            proc.setArguments(["run", "-c", str(cfg_path), "-D", str(self.paths.runtime_dir)])
            proc.setWorkingDirectory(str(self.paths.runtime_dir))
            proc.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)

            proc.readyReadStandardOutput.connect(self._on_stdout_ready)
            proc.readyReadStandardError.connect(self._on_stderr_ready)
            proc.started.connect(self._on_process_started)
            proc.finished.connect(self._on_process_finished)
            proc.errorOccurred.connect(self._on_process_error)

            self._proc = proc
            proc.start()

            if not proc.waitForStarted(3000):
                err_str = proc.errorString()
                self._stopping = True
                if self._xray_proc is not None:
                    self._terminate_qprocess(self._xray_proc, 1000)
                self._cleanup_after_exit()
                raise CoreEngineError(f"Не удалось запустить процесс sing-box: {err_str}")
        except Exception:
            if not self.is_running:
                self._stopping = True
                if self._xray_proc is not None:
                    self._terminate_qprocess(self._xray_proc, 1000)
                self._cleanup_after_exit()
            raise

    def stop(self, timeout_ms: int = 3000) -> None:
        """Gracefully terminate sing-box and any Xray bridge without freezing the Qt event loop."""
        proc = self._proc
        xproc = self._xray_proc
        if (proc is None or proc.state() == QProcess.ProcessState.NotRunning) and (
            xproc is None or xproc.state() == QProcess.ProcessState.NotRunning
        ):
            self._cleanup_after_exit()
            return

        self._stopping = True
        if proc is not None and proc.state() != QProcess.ProcessState.NotRunning:
            log.info("Остановка процесса sing-box (PID: %s)...", proc.processId())
            self._terminate_qprocess(proc, timeout_ms)

        if xproc is not None and xproc.state() != QProcess.ProcessState.NotRunning:
            log.info("Остановка модуля Xray (PID: %s)...", xproc.processId())
            self._terminate_qprocess(xproc, min(2000, timeout_ms))

        self._cleanup_after_exit()

    def _terminate_qprocess(self, proc: QProcess, timeout_ms: int) -> None:
        if proc.state() == QProcess.ProcessState.NotRunning:
            return
        proc.terminate()
        self._wait_non_blocking(proc, min(800, timeout_ms))
        if proc.state() != QProcess.ProcessState.NotRunning:
            proc.kill()
            self._wait_non_blocking(proc, max(500, timeout_ms - 800))

    def get_diagnostic_tail(self) -> str:
        return "\n".join(self._recent_lines)

    def _wait_non_blocking(self, proc: QProcess, ms: int) -> None:
        if proc.state() == QProcess.ProcessState.NotRunning:
            return
        loop = QEventLoop()
        timer = QTimer()
        timer.setSingleShot(True)
        proc.finished.connect(loop.quit)
        timer.timeout.connect(loop.quit)
        timer.start(ms)
        loop.exec()

    def _on_process_started(self) -> None:
        pid = self.pid or 0
        log.info("Процесс sing-box запущен (PID: %d)", pid)
        self.started.emit(pid)

    def _on_stdout_ready(self) -> None:
        if self._proc is None:
            return
        chunk = bytes(self._proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        self._stdout_buf += chunk
        while "\n" in self._stdout_buf:
            line, self._stdout_buf = self._stdout_buf.split("\n", 1)
            self._record_stream_line("stdout", line)

    def _on_stderr_ready(self) -> None:
        if self._proc is None:
            return
        chunk = bytes(self._proc.readAllStandardError()).decode("utf-8", errors="replace")
        self._stderr_buf += chunk
        while "\n" in self._stderr_buf:
            line, self._stderr_buf = self._stderr_buf.split("\n", 1)
            self._record_stream_line("stderr", line)

    def _record_stream_line(self, stream: str, raw_line: str, source: str = "sing-box") -> None:
        clean = redact_secrets(raw_line.strip())
        if not clean:
            return
        self._recent_lines.append(f"[{source}] {clean}" if source != "sing-box" else clean)
        lower = clean.lower()
        if "fatal" in lower or "error" in lower:
            log.error("[%s] %s", source, clean)
        elif "warn" in lower:
            log.warning("[%s] %s", source, clean)
        else:
            log.info("[%s] %s", source, clean)
        self.output_line.emit(stream, clean)

    def _on_xray_stdout_ready(self) -> None:
        if self._xray_proc is None:
            return
        chunk = bytes(self._xray_proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        self._xray_stdout_buf += chunk
        while "\n" in self._xray_stdout_buf:
            line, self._xray_stdout_buf = self._xray_stdout_buf.split("\n", 1)
            self._record_stream_line("stdout", line, source="xray")

    def _on_xray_stderr_ready(self) -> None:
        if self._xray_proc is None:
            return
        chunk = bytes(self._xray_proc.readAllStandardError()).decode("utf-8", errors="replace")
        self._xray_stderr_buf += chunk
        while "\n" in self._xray_stderr_buf:
            line, self._xray_stderr_buf = self._xray_stderr_buf.split("\n", 1)
            self._record_stream_line("stderr", line, source="xray")

    def _on_xray_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        if self._xray_stdout_buf.strip():
            self._record_stream_line("stdout", self._xray_stdout_buf, source="xray")
            self._xray_stdout_buf = ""
        if self._xray_stderr_buf.strip():
            self._record_stream_line("stderr", self._xray_stderr_buf, source="xray")
            self._xray_stderr_buf = ""

        if self._stopping:
            return

        reason = (
            "CrashExit"
            if exit_status == QProcess.ExitStatus.CrashExit
            else f"код выхода {exit_code}"
        )
        log.error("Модуль Xray неожиданно завершился (%s). Остановка сессии...", reason)
        diag = self.get_diagnostic_tail()
        self._stopping = True
        if self._proc is not None and self._proc.state() != QProcess.ProcessState.NotRunning:
            self._terminate_qprocess(self._proc, 1500)
        self._cleanup_after_exit()
        self.crashed.emit(exit_code, diag or f"Модуль Xray завершился ({reason})")

    def _on_process_error(self, proc_err: QProcess.ProcessError) -> None:
        if self._stopping:
            return
        if proc_err == QProcess.ProcessError.Crashed:
            log.error("Обнаружено аварийное падение процесса sing-box.")

    def _on_process_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        # Drain any trailing stdout/stderr bytes
        if self._stdout_buf.strip():
            self._record_stream_line("stdout", self._stdout_buf)
            self._stdout_buf = ""
        if self._stderr_buf.strip():
            self._record_stream_line("stderr", self._stderr_buf)
            self._stderr_buf = ""

        was_stopping = self._stopping
        diag = self.get_diagnostic_tail()

        if was_stopping:
            log.info("Процесс sing-box остановлен (код выхода: %d).", exit_code)
            self.stopped.emit(exit_code)
            return

        if self._xray_proc is not None:
            self._stopping = True
            self._terminate_qprocess(self._xray_proc, 1000)
        self._cleanup_after_exit()

        reason = (
            "CrashExit"
            if exit_status == QProcess.ExitStatus.CrashExit
            else f"неожиданное завершение с кодом {exit_code}"
        )
        log.error("Процесс sing-box аварийно завершился (%s).", reason)
        self.crashed.emit(exit_code, diag or reason)

    def _cleanup_after_exit(self) -> None:
        self._secure_remove_file(self._config_path)
        self._secure_remove_file(self._xray_config_path)
        self._mutex.release()
        if self._proc is not None:
            proc = self._proc
            self._proc = None
            proc.deleteLater()
        if self._xray_proc is not None:
            xproc = self._xray_proc
            self._xray_proc = None
            xproc.deleteLater()

    @staticmethod
    def _secure_remove_file(path: Path) -> None:
        if not path.exists():
            return
        try:
            size = path.stat().st_size
            if 0 < size <= 1024 * 1024:
                path.write_bytes(b"\x00" * size)
            path.unlink(missing_ok=True)
        except OSError:
            pass
