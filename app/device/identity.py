from __future__ import annotations

import json
import os
import socket
import uuid
from dataclasses import dataclass
from pathlib import Path

IDENTITY_FILENAME = "identity.json"
MAX_NAME_LENGTH = 64


def default_data_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Roaming"
    else:
        base = os.environ.get("XDG_CONFIG_HOME")
        root = Path(base) if base else Path.home() / ".config"
    return root / "LocalDrop"


def default_device_name() -> str:
    name = socket.gethostname().strip()
    if not name:
        return "LocalDrop"
    return name[:MAX_NAME_LENGTH]


def normalize_device_name(name: str) -> str:
    cleaned = " ".join(name.split()).strip()
    if not cleaned:
        raise ValueError("Il nome del dispositivo non può essere vuoto")
    if len(cleaned) > MAX_NAME_LENGTH:
        raise ValueError(
            f"Il nome del dispositivo supera {MAX_NAME_LENGTH} caratteri"
        )
    return cleaned


@dataclass
class DeviceIdentity:
    device_id: str
    device_name: str
    path: Path

    def rename(self, name: str) -> None:
        self.device_name = normalize_device_name(name)
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "device_id": self.device_id,
            "device_name": self.device_name,
        }
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.path)


def load_or_create(path: Path | None = None) -> DeviceIdentity:
    target = path if path is not None else default_data_dir() / IDENTITY_FILENAME
    if target.exists():
        return _load(target)
    identity = DeviceIdentity(
        device_id=str(uuid.uuid4()),
        device_name=default_device_name(),
        path=target,
    )
    identity.save()
    return identity


def _load(path: Path) -> DeviceIdentity:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Identità non valida in {path}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"Identità non valida in {path}")
    device_id = raw.get("device_id")
    device_name = raw.get("device_name")
    if not isinstance(device_id, str) or not device_id:
        raise ValueError("device_id mancante")
    try:
        parsed = uuid.UUID(device_id)
    except ValueError as exc:
        raise ValueError("device_id non è un UUID valido") from exc
    if not isinstance(device_name, str):
        raise ValueError("device_name mancante")
    return DeviceIdentity(
        device_id=str(parsed),
        device_name=normalize_device_name(device_name),
        path=path,
    )
