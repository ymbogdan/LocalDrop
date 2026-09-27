from __future__ import annotations

import hashlib
import os
import tempfile
from contextlib import contextmanager

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class KeyLocked(Exception):
    pass


def seal(pem: bytes, passphrase: str | None, *, prefer_tpm: bool) -> bytes:
    if prefer_tpm:
        wrapped = _tpm_wrap(pem)
        if wrapped is not None:
            return b"LDTP" + wrapped
    if passphrase:
        inner = _aes(pem, passphrase)
        if os.name == "nt":
            return b"LDPP" + _dpapi(inner)
        return b"LDPP" + inner
    if os.name == "nt":
        return b"LDDP" + _dpapi(pem)
    return pem


def open_secret(blob: bytes, passphrase: str | None) -> bytes:
    if blob.startswith(b"-----BEGIN"):
        return blob
    if blob.startswith(b"LDTP"):
        opened = _tpm_unwrap(blob[4:])
        if opened is None:
            raise KeyLocked()
        return opened
    if blob.startswith(b"LDDP"):
        return _dpapi_open(blob[4:])
    if blob.startswith(b"LDPP"):
        inner = _dpapi_open(blob[4:]) if os.name == "nt" else blob[4:]
        if not passphrase:
            raise KeyLocked()
        return _aes_open(inner, passphrase)
    raise ValueError("Chiave non riconosciuta")


def ask_passphrase(creating: bool) -> str | None:
    if os.name != "nt":
        return None
    if not creating:
        return _cred("Inserisci la passphrase per sbloccare la chiave di LocalDrop su questo computer.")
    for _ in range(3):
        first = _cred("Scegli una passphrase. Serve a ogni avvio per sbloccare la chiave di questo computer.")
        if not first:
            return None
        second = _cred("Ripeti la passphrase.")
        if first == second:
            return first
        _notice("Le due passphrase non coincidono.")
    return None


@contextmanager
def pem_file(pem: bytes):
    handle = tempfile.NamedTemporaryFile(prefix="localdrop-key-", suffix=".pem", delete=False)
    try:
        handle.write(pem)
        handle.close()
        try:
            os.chmod(handle.name, 0o600)
        except OSError:
            pass
        yield handle.name
    finally:
        try:
            os.remove(handle.name)
        except OSError:
            pass


def _aes(pem: bytes, passphrase: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return salt + nonce + AESGCM(key).encrypt(nonce, pem, b"localdrop-key")


def _aes_open(blob: bytes, passphrase: str) -> bytes:
    salt, nonce, ciphertext = blob[:16], blob[16:28], blob[28:]
    key = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return AESGCM(key).decrypt(nonce, ciphertext, b"localdrop-key")


def _dpapi(data: bytes) -> bytes:
    if os.name != "nt":
        return data
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt = ctypes.windll.crypt32
    kernel = ctypes.windll.kernel32
    raw = ctypes.create_string_buffer(data)
    incoming = _Blob(len(data), ctypes.cast(raw, ctypes.POINTER(ctypes.c_char)))
    outgoing = _Blob()
    crypt.CryptProtectData.argtypes = [
        ctypes.POINTER(_Blob),
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_Blob),
    ]
    crypt.CryptProtectData.restype = wintypes.BOOL
    if not crypt.CryptProtectData(ctypes.byref(incoming), None, None, None, None, 0x01, ctypes.byref(outgoing)):
        raise OSError("DPAPI")
    try:
        return ctypes.string_at(outgoing.pbData, outgoing.cbData)
    finally:
        kernel.LocalFree(outgoing.pbData)


def _dpapi_open(data: bytes) -> bytes:
    if os.name != "nt":
        return data
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt = ctypes.windll.crypt32
    kernel = ctypes.windll.kernel32
    raw = ctypes.create_string_buffer(data)
    incoming = _Blob(len(data), ctypes.cast(raw, ctypes.POINTER(ctypes.c_char)))
    outgoing = _Blob()
    crypt.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_Blob),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_Blob),
    ]
    crypt.CryptUnprotectData.restype = wintypes.BOOL
    if not crypt.CryptUnprotectData(ctypes.byref(incoming), None, None, None, None, 0x01, ctypes.byref(outgoing)):
        raise OSError("DPAPI")
    try:
        return ctypes.string_at(outgoing.pbData, outgoing.cbData)
    finally:
        kernel.LocalFree(outgoing.pbData)


def _notice(text: str) -> None:
    import ctypes

    ctypes.windll.user32.MessageBoxW(None, text, "LocalDrop", 0x30)


def _cred(message: str) -> str | None:
    import ctypes
    from ctypes import wintypes

    class _Info(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("hwndParent", wintypes.HWND),
            ("pszMessageText", wintypes.LPCWSTR),
            ("pszCaptionText", wintypes.LPCWSTR),
            ("hbmBanner", wintypes.HANDLE),
        ]

    credui = ctypes.windll.credui
    info = _Info()
    info.cbSize = ctypes.sizeof(_Info)
    info.pszMessageText = message
    info.pszCaptionText = "LocalDrop"
    user = ctypes.create_unicode_buffer("LocalDrop", 256)
    password = ctypes.create_unicode_buffer(256)
    save = wintypes.BOOL(False)
    flags = 0x00040000 | 0x00000080 | 0x00000002 | 0x00000008 | 0x00100000
    credui.CredUIPromptForCredentialsW.argtypes = [
        ctypes.POINTER(_Info),
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.LPWSTR,
        wintypes.ULONG,
        wintypes.LPWSTR,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.BOOL),
        wintypes.DWORD,
    ]
    credui.CredUIPromptForCredentialsW.restype = wintypes.DWORD
    code = credui.CredUIPromptForCredentialsW(
        ctypes.byref(info),
        "LocalDrop",
        None,
        0,
        user,
        256,
        password,
        256,
        ctypes.byref(save),
        flags,
    )
    try:
        if code != 0:
            return None
        return password.value or None
    finally:
        ctypes.memset(password, 0, ctypes.sizeof(password))


def _tpm_wrap(pem: bytes) -> bytes | None:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, EllipticCurvePrivateKey):
            return None
        der = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        if len(der) > 200:
            return None
        return _tpm_crypt(der, encrypt=True)
    except Exception:
        return None


def _tpm_unwrap(blob: bytes) -> bytes | None:
    try:
        from cryptography.hazmat.primitives import serialization

        der = _tpm_crypt(blob, encrypt=False)
        if der is None:
            return None
        key = serialization.load_der_private_key(der, password=None)
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    except Exception:
        return None


def _tpm_ui_policy(ncrypt, key, status_type) -> None:
    import ctypes
    from ctypes import wintypes

    class _Policy(ctypes.Structure):
        _fields_ = [
            ("dwVersion", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("pszCreationTitle", wintypes.LPCWSTR),
            ("pszFriendlyName", wintypes.LPCWSTR),
            ("pszDescription", wintypes.LPCWSTR),
        ]

    policy = _Policy(1, 0x1, "LocalDrop", "LocalDrop", "Sblocca la chiave di LocalDrop")
    ncrypt.NCryptSetProperty.argtypes = [
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    ncrypt.NCryptSetProperty.restype = status_type
    ncrypt.NCryptSetProperty(key, "UI Policy", ctypes.byref(policy), ctypes.sizeof(policy), 0)


def _tpm_crypt(data: bytes, *, encrypt: bool) -> bytes | None:
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    ncrypt = ctypes.WinDLL("ncrypt.dll")
    status_type = wintypes.LONG
    provider = ctypes.c_void_p()
    ncrypt.NCryptOpenStorageProvider.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.LPCWSTR, wintypes.DWORD]
    ncrypt.NCryptOpenStorageProvider.restype = status_type
    if ncrypt.NCryptOpenStorageProvider(ctypes.byref(provider), "Microsoft Platform Crypto Provider", 0) != 0:
        return None
    key = ctypes.c_void_p()
    try:
        ncrypt.NCryptOpenKey.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        ncrypt.NCryptOpenKey.restype = status_type
        opened = ncrypt.NCryptOpenKey(provider, ctypes.byref(key), "LocalDropWrap", 0, 0)
        if opened != 0:
            ncrypt.NCryptCreatePersistedKey.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
            ]
            ncrypt.NCryptCreatePersistedKey.restype = status_type
            if ncrypt.NCryptCreatePersistedKey(provider, ctypes.byref(key), "RSA", "LocalDropWrap", 0, 0) != 0:
                return None
            bits = wintypes.DWORD(2048)
            ncrypt.NCryptSetProperty.argtypes = [
                ctypes.c_void_p,
                wintypes.LPCWSTR,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
            ]
            ncrypt.NCryptSetProperty.restype = status_type
            if ncrypt.NCryptSetProperty(key, "Length", ctypes.byref(bits), 4, 0) != 0:
                return None
            _tpm_ui_policy(ncrypt, key, status_type)
            ncrypt.NCryptFinalizeKey.argtypes = [ctypes.c_void_p, wintypes.DWORD]
            ncrypt.NCryptFinalizeKey.restype = status_type
            if ncrypt.NCryptFinalizeKey(key, 0) != 0:
                return None
        out_len = wintypes.DWORD(0)
        pad = wintypes.DWORD(2)
        ncrypt.NCryptEncrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.DWORD,
        ]
        ncrypt.NCryptEncrypt.restype = status_type
        ncrypt.NCryptDecrypt.argtypes = ncrypt.NCryptEncrypt.argtypes
        ncrypt.NCryptDecrypt.restype = status_type
        call = ncrypt.NCryptEncrypt if encrypt else ncrypt.NCryptDecrypt
        raw = ctypes.create_string_buffer(data)
        if call(key, raw, len(data), None, None, 0, ctypes.byref(out_len), pad) != 0 or out_len.value <= 0:
            return None
        output = ctypes.create_string_buffer(out_len.value)
        if call(key, raw, len(data), None, output, out_len.value, ctypes.byref(out_len), pad) != 0:
            return None
        return output.raw[: out_len.value]
    except Exception:
        return None
    finally:
        ncrypt.NCryptFreeObject.argtypes = [ctypes.c_void_p]
        ncrypt.NCryptFreeObject.restype = status_type
        if key:
            ncrypt.NCryptFreeObject(key)
        if provider:
            ncrypt.NCryptFreeObject(provider)
