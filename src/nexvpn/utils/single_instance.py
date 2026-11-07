"""Single-instance guard using Windows Named Mutex."""

from __future__ import annotations

import ctypes
import sys

ERROR_ALREADY_EXISTS = 183


class SingleInstanceGuard:
    """Prevents multiple concurrent instances of NEXVPN (or core controller)."""

    def __init__(self, mutex_name: str = "Local\\NEXVPN_Desktop_SingleInstance_v1") -> None:
        self.mutex_name = mutex_name
        self._handle: int | None = None
        self._acquired = False

    def acquire(self) -> bool:
        """Attempt to acquire named mutex. Returns False if another instance holds it."""
        if self._acquired:
            return True
        if sys.platform != "win32":
            self._acquired = True
            return True

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
        kernel32.CreateMutexW.restype = ctypes.c_void_p

        handle = kernel32.CreateMutexW(None, False, self.mutex_name)
        last_err = ctypes.get_last_error()
        if not handle:
            return False
        if last_err == ERROR_ALREADY_EXISTS:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
            return False

        self._handle = int(handle)
        self._acquired = True
        return True

    def release(self) -> None:
        """Release mutex handle on clean shutdown."""
        if self._handle is not None and sys.platform == "win32":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle(ctypes.c_void_p(self._handle))
        self._handle = None
        self._acquired = False

    def __enter__(self) -> SingleInstanceGuard:
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.release()
