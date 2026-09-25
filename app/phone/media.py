from __future__ import annotations

import base64
import io
import os
from datetime import datetime
from pathlib import Path

import qrcode
from PIL import ExifTags, Image

try:
    from pillow_heif import register_heif_opener
    register_heif_opener()
except ImportError:
    pass

_IMAGES = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic", ".heif"}
_SKIP = {"MakerNote", "UserComment", "PrintImageMatching", "XPComment", "XPKeywords"}


def qr_data_url(data: str) -> str:
    code = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    code.add_data(data)
    code.make(fit=True)
    image = code.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return "data:image/png;base64," + encoded


def thumbnail_data_url(path: Path) -> str:
    if path.suffix.lower() not in _IMAGES or not path.is_file():
        return ""
    try:
        with Image.open(path) as image:
            frame = image.convert("RGB")
            frame.thumbnail((280, 280))
            buffer = io.BytesIO()
            frame.save(buffer, format="JPEG", quality=70)
    except OSError:
        return ""
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return "data:image/jpeg;base64," + encoded


def thumbnail_bytes(path: Path) -> bytes:
    url = thumbnail_data_url(path)
    if not url:
        return b""
    return base64.b64decode(url.split(",", 1)[1])


def photo_metadata(path: Path) -> list[str]:
    lines: list[str] = []
    try:
        with Image.open(path) as image:
            exif = image.getexif()
    except OSError:
        return lines
    if not exif:
        return lines
    lines.extend(_exif_lines(exif))
    for ifd in (ExifTags.IFD.Exif, ExifTags.IFD.GPSInfo):
        try:
            lines.extend(_exif_lines(exif.get_ifd(ifd), gps=ifd == ExifTags.IFD.GPSInfo))
        except KeyError:
            continue
    unique: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if line not in seen:
            seen.add(line)
            unique.append(line)
    return unique


def apply_capture_time(path: Path) -> None:
    stamp = _capture_timestamp(path)
    if stamp is None:
        return
    os.utime(path, (stamp, stamp))


def _capture_timestamp(path: Path) -> float | None:
    try:
        with Image.open(path) as image:
            exif = image.getexif()
            nested = exif.get_ifd(ExifTags.IFD.Exif)
    except (OSError, KeyError):
        return None
    raw = nested.get(36867) or nested.get(36868) or exif.get(306)
    if not isinstance(raw, str):
        return None
    try:
        return datetime.strptime(raw.strip(), "%Y:%m:%d %H:%M:%S").timestamp()
    except ValueError:
        return None


def _exif_lines(values, gps: bool = False) -> list[str]:
    lines: list[str] = []
    names = ExifTags.GPSTAGS if gps else ExifTags.TAGS
    for tag, value in values.items():
        label = names.get(tag, str(tag))
        if label in _SKIP or isinstance(value, bytes):
            continue
        text = _format_value(label, value)
        if text:
            lines.append(f"{label}: {text}")
    return lines


def _format_value(label: str, value: object) -> str:
    if label in {"GPSLatitude", "GPSLongitude", "GPSAltitude"}:
        return str(value)
    if isinstance(value, tuple):
        return " ".join(str(part) for part in value)
    text = str(value).replace("\x00", "").strip()
    if len(text) > 300:
        return ""
    return text
