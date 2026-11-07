"""Windows DPAPI encryption for sensitive subscription URLs and proxy credentials."""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import sys

CRYPTPROTECT_UI_FORBIDDEN = 0x01
_DPAPI_PREFIX = "dpapi:v1:"
_ENTROPY = b"NEXVPN_Windows_DPAPI_Context_v1"


class DPAPIError(RuntimeError):
    """Raised when DPAPI encryption or decryption fails."""


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _make_blob(raw: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    buf = ctypes.create_string_buffer(raw, len(raw))
    blob = _DataBlob(len(raw), buf)
    return blob, buf


def protect_secret(plaintext: str) -> str:
    """Encrypt a UTF-8 string with Windows DPAPI tied to the current user."""
    if plaintext == "":
        return ""
    if sys.platform != "win32":
        raise DPAPIError("Windows DPAPI поддерживается только в ОС Windows.")

    raw_bytes = plaintext.encode("utf-8")
    in_blob, _in_buf = _make_blob(raw_bytes)
    entropy_blob, _ent_buf = _make_blob(_ENTROPY)
    out_blob = _DataBlob()

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "NEXVPN Secret",
        ctypes.byref(entropy_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        err = ctypes.get_last_error()
        raise DPAPIError(f"Ошибка шифрования Windows DPAPI (код {err}).")

    try:
        encrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))

    b64 = base64.b64encode(encrypted).decode("ascii")
    return f"{_DPAPI_PREFIX}{b64}"


def unprotect_secret(protected: str) -> str:
    """Decrypt a DPAPI-protected string created by `protect_secret`."""
    if protected == "":
        return ""
    if not protected.startswith(_DPAPI_PREFIX):
        raise DPAPIError("Некорректный формат защищённых данных DPAPI.")
    if sys.platform != "win32":
        raise DPAPIError("Windows DPAPI поддерживается только в ОС Windows.")

    b64_payload = protected[len(_DPAPI_PREFIX) :]
    try:
        cipher_bytes = base64.b64decode(b64_payload.encode("ascii"), validate=True)
    except Exception as exc:
        raise DPAPIError("Повреждённый Base64 в защищённом поле DPAPI.") from exc

    if not cipher_bytes:
        raise DPAPIError("Пустой блок данных DPAPI.")

    in_blob, _in_buf = _make_blob(cipher_bytes)
    entropy_blob, _ent_buf = _make_blob(_ENTROPY)
    out_blob = _DataBlob()

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        err = ctypes.get_last_error()
        raise DPAPIError(
            f"Не удалось расшифровать секрет через Windows DPAPI (код {err}). "
            "Возможно, база была перенесена с другой учётной записи Windows."
        )

    try:
        plain_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))

    return plain_bytes.decode("utf-8")
