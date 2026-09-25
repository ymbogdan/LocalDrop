from __future__ import annotations

import datetime
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.security.crypto_identity import device_id_from_certificate, fingerprint_der

TRUST_FILENAME = "trusted.json"


class TrustDecision(Enum):
    MATCH = "MATCH"
    UNKNOWN = "UNKNOWN"
    MISMATCH = "MISMATCH"


@dataclass(frozen=True)
class TrustedDevice:
    device_id: str
    device_name: str
    fingerprint: str
    certificate_pem: str
    paired_at: str = ""


class TrustStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._devices: dict[str, TrustedDevice] = {}
        if path.exists():
            self._load()

    def is_paired(self, device_id: str) -> bool:
        return device_id in self._devices

    def get(self, device_id: str) -> TrustedDevice | None:
        return self._devices.get(device_id)

    def paired_certificates(self) -> list[bytes]:
        return [item.certificate_pem.encode("utf-8") for item in self._devices.values()]

    def evaluate(self, device_id: str, fingerprint: str) -> TrustDecision:
        current = self._devices.get(device_id)
        if current is None:
            return TrustDecision.UNKNOWN
        if current.fingerprint == fingerprint:
            return TrustDecision.MATCH
        return TrustDecision.MISMATCH

    def forget(self, device_id: str) -> None:
        if device_id in self._devices:
            del self._devices[device_id]
            self._save()

    def trust(self, device_name: str, certificate_pem: bytes) -> TrustedDevice:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
        der = certificate.public_bytes(serialization.Encoding.DER)
        device_id = device_id_from_certificate(der)
        record = TrustedDevice(
            device_id=device_id,
            device_name=device_name,
            fingerprint=fingerprint_der(der),
            certificate_pem=certificate_pem.decode("utf-8"),
            paired_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        self._devices[device_id] = record
        self._save()
        return record

    def _load(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        devices = raw.get("devices", [])
        if not isinstance(devices, list):
            raise ValueError("Invalid trust store")
        for item in devices:
            record = TrustedDevice(
                device_id=str(item["device_id"]),
                device_name=str(item["device_name"]),
                fingerprint=str(item["fingerprint"]),
                certificate_pem=str(item["certificate_pem"]),
                paired_at=str(item.get("paired_at", "")),
            )
            self._devices[record.device_id] = record

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "devices": [
                {
                    "device_id": item.device_id,
                    "device_name": item.device_name,
                    "fingerprint": item.fingerprint,
                    "certificate_fingerprint": item.fingerprint,
                    "certificate_pem": item.certificate_pem,
                    "paired_at": item.paired_at,
                }
                for item in self._devices.values()
            ]
        }
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.path)
