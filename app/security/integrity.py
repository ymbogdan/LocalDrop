from __future__ import annotations

import hashlib
import hmac
from pathlib import Path


def hash_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def hashes_match(expected: str, actual: str) -> bool:
    if len(expected) != len(actual) or len(expected) != 64:
        return False
    return hmac.compare_digest(expected.lower(), actual.lower())
