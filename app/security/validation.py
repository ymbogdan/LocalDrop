from __future__ import annotations

import unicodedata
from pathlib import Path
from urllib.parse import unquote

from app.security.limits import Limits


class SecurityError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
_FORBIDDEN = set('<>:"|?*')


def decoded_filename(filename: str) -> str:
    cleaned = filename
    for _ in range(8):
        decoded = unquote(cleaned)
        if decoded == cleaned:
            break
        cleaned = decoded
    else:
        return "file"
    return unicodedata.normalize("NFC", cleaned)


def validate_filename(filename: object) -> str:
    if not isinstance(filename, str) or not filename or filename != filename.strip():
        raise SecurityError("REJECTED", "Invalid filename")
    filename = decoded_filename(filename).strip()
    if not filename or filename != filename.strip():
        raise SecurityError("REJECTED", "Invalid filename")
    if "\x00" in filename or "/" in filename or "\\" in filename or ":" in filename:
        raise SecurityError("REJECTED", "Invalid filename")
    if any(ord(ch) < 32 or ch in _FORBIDDEN for ch in filename):
        raise SecurityError("REJECTED", "Invalid filename")
    if filename in {".", ".."} or ".." in filename:
        raise SecurityError("REJECTED", "Invalid filename")
    if Path(filename).name != filename:
        raise SecurityError("REJECTED", "Invalid filename")
    stem = Path(filename).stem.upper()
    if stem in _RESERVED:
        raise SecurityError("REJECTED", "Invalid filename")
    return filename


def destination_path(directory: Path, filename: str) -> Path:
    root = directory.resolve()
    root.mkdir(parents=True, exist_ok=True)
    candidate = (root / validate_filename(filename)).resolve()
    if candidate.parent != root:
        raise SecurityError("REJECTED", "Invalid filename")
    return candidate


def unique_destination(directory: Path, filename: str) -> Path:
    base = destination_path(directory, filename)
    if not base.exists():
        return base
    stem = base.stem
    suffix = base.suffix
    index = 1
    while True:
        candidate = base.with_name(f"{stem} ({index}){suffix}")
        if candidate.parent != base.parent:
            raise SecurityError("REJECTED", "Invalid filename")
        if not candidate.exists():
            return candidate
        index += 1


def validate_file_size(size: object, limits: Limits) -> int:
    if isinstance(size, bool) or not isinstance(size, int):
        raise SecurityError("REJECTED", "Invalid file size")
    if size < 0 or size > limits.max_file_bytes:
        raise SecurityError("REJECTED", "Invalid file size")
    return size


def validate_chunk_size(size: int, limits: Limits) -> None:
    if size < 0 or size > limits.max_chunk_bytes:
        raise SecurityError("REJECTED", "Invalid chunk size")
