from __future__ import annotations

import hashlib


def verification_code(local_cert_der: bytes, remote_cert_der: bytes) -> str:
    first, second = sorted((local_cert_der, remote_cert_der))
    digest = hashlib.sha256(first + b"|" + second).digest()
    number = int.from_bytes(digest[:8], "big") % 1_000_000
    return f"{number:06d}"


def format_verification_code(code: str) -> str:
    if len(code) != 6 or not code.isdigit():
        raise ValueError("Invalid verification code")
    return f"{code[:3]} {code[3:]}"
