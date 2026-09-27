from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from app.i18n import normalize_language
from app.security.limits import DEFAULT_LIMITS


@dataclass
class Settings:
    download_dir: Path
    max_file_bytes: int = DEFAULT_LIMITS.max_file_bytes
    max_concurrent_transfers: int = DEFAULT_LIMITS.max_concurrent_transfers
    share_clipboard: bool = False
    expire_minutes: int = 5
    language: str = "en"

    @classmethod
    def load(cls, path: Path) -> "Settings":
        default_dir = Path.home() / "Downloads" / "LocalDrop"
        if not path.exists():
            settings = cls(download_dir=default_dir)
            settings.save(path)
            return settings
        raw = json.loads(path.read_text(encoding="utf-8"))
        minutes = int(raw.get("expire_minutes", 5) or 5)
        return cls(
            download_dir=Path(str(raw.get("download_dir") or default_dir)),
            max_file_bytes=int(raw.get("max_file_bytes", DEFAULT_LIMITS.max_file_bytes)),
            max_concurrent_transfers=int(raw.get("max_concurrent_transfers", DEFAULT_LIMITS.max_concurrent_transfers)),
            share_clipboard=bool(raw.get("share_clipboard", False)),
            expire_minutes=min(240, max(1, minutes)),
            language=normalize_language(raw.get("language", "en")),
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "download_dir": str(self.download_dir),
            "max_file_bytes": self.max_file_bytes,
            "max_concurrent_transfers": self.max_concurrent_transfers,
            "share_clipboard": self.share_clipboard,
            "expire_minutes": self.expire_minutes,
            "language": normalize_language(self.language),
        }
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
