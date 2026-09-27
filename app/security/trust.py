from __future__ import annotations

import base64
import datetime
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.security.crypto_identity import CryptoIdentity, device_id_from_certificate, fingerprint_der
from app.security.rotation import verify_successor

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
    successor_fingerprint: str = ""
    successor_certificate_pem: str = ""


class TrustStore:
    def __init__(self, path: Path, identity: CryptoIdentity | None = None) -> None:
        self.path = path
        self.identity = identity
        self._devices: dict[str, TrustedDevice] = {}
        if path.exists():
            self._load()
        elif identity is not None:
            self._save(backup=False)

    def is_paired(self, device_id: str) -> bool:
        return device_id in self._devices

    def get(self, device_id: str) -> TrustedDevice | None:
        return self._devices.get(device_id)

    def paired_certificates(self) -> list[bytes]:
        certificates: list[bytes] = []
        for item in self._devices.values():
            certificates.append(item.certificate_pem.encode("utf-8"))
            if item.successor_certificate_pem:
                certificates.append(item.successor_certificate_pem.encode("utf-8"))
        return certificates

    def evaluate(self, device_id: str, fingerprint: str) -> TrustDecision:
        current = self._devices.get(device_id)
        if current is None:
            return TrustDecision.UNKNOWN
        if current.fingerprint == fingerprint:
            return TrustDecision.MATCH
        if current.successor_fingerprint and current.successor_fingerprint == fingerprint:
            return TrustDecision.MATCH
        return TrustDecision.MISMATCH

    def accept_successor(self, device_id: str, certificate_pem: bytes | str, proof: str) -> bool:
        current = self._devices.get(device_id)
        if current is None or not proof:
            return False
        text = certificate_pem.decode("utf-8") if isinstance(certificate_pem, bytes) else certificate_pem
        try:
            certificate = x509.load_pem_x509_certificate(text.encode("utf-8"))
            der = certificate.public_bytes(serialization.Encoding.DER)
            presented_id = device_id_from_certificate(der)
            fingerprint = fingerprint_der(der)
        except Exception:
            return False
        if presented_id != device_id or fingerprint == current.fingerprint:
            return False
        if not verify_successor(current.certificate_pem, device_id, fingerprint, proof):
            return False
        self._devices[device_id] = TrustedDevice(
            device_id=current.device_id,
            device_name=current.device_name,
            fingerprint=current.fingerprint,
            certificate_pem=current.certificate_pem,
            paired_at=current.paired_at,
            successor_fingerprint=fingerprint,
            successor_certificate_pem=text,
        )
        self._save()
        return True

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

    def _reset(self) -> None:
        self._devices = {}
        if self.identity is not None:
            self._save(backup=False)

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeError, ValueError):
            self._reset()
            return
        if not isinstance(raw, dict) or raw.get("version", 1) != 1:
            self._reset()
            return
        devices = raw.get("devices", [])
        if not isinstance(devices, list):
            self._reset()
            return
        signature = raw.get("signature")
        if self.identity is not None:
            if isinstance(signature, str):
                if not _verify(self.identity, devices, signature):
                    self._reset()
                    return
            else:
                if not self._fill(devices):
                    self._reset()
                    return
                self._save()
                return
        elif isinstance(signature, str):
            self._reset()
            return
        if not self._fill(devices):
            self._reset()

    def _fill(self, devices: list) -> bool:
        loaded: dict[str, TrustedDevice] = {}
        try:
            for item in devices:
                if not isinstance(item, dict):
                    return False
                record = TrustedDevice(
                    device_id=str(item["device_id"]),
                    device_name=str(item["device_name"]),
                    fingerprint=str(item["fingerprint"]),
                    certificate_pem=str(item["certificate_pem"]),
                    paired_at=str(item.get("paired_at", "")),
                    successor_fingerprint=str(item.get("successor_fingerprint", "")),
                    successor_certificate_pem=str(item.get("successor_certificate_pem", "")),
                )
                loaded[record.device_id] = record
        except (KeyError, TypeError, ValueError):
            return False
        self._devices = loaded
        return True

    def _save(self, backup: bool = True) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        devices = [
            {
                "device_id": item.device_id,
                "device_name": item.device_name,
                "fingerprint": item.fingerprint,
                "certificate_fingerprint": item.fingerprint,
                "certificate_pem": item.certificate_pem,
                "paired_at": item.paired_at,
                "successor_fingerprint": item.successor_fingerprint,
                "successor_certificate_pem": item.successor_certificate_pem,
            }
            for item in self._devices.values()
        ]
        payload: dict[str, object] = {"version": 1, "devices": devices}
        if self.identity is not None:
            payload["signature"] = _sign(self.identity, devices)
        temporary = self.path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)
        if not backup:
            return
        try:
            copy = self.path.with_name(self.path.name + ".bak")
            copy.write_bytes(self.path.read_bytes())
        except OSError:
            return


def _canonical(devices: list) -> bytes:
    return json.dumps(devices, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(identity: CryptoIdentity, devices: list) -> str:
    key = serialization.load_pem_private_key(identity.private_key_pem(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("Invalid trust store")
    signature = key.sign(_canonical(devices), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")


def _verify(identity: CryptoIdentity, devices: list, signature: str) -> bool:
    try:
        certificate = x509.load_pem_x509_certificate(identity.certificate_pem)
        public_key = certificate.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        public_key.verify(base64.b64decode(signature), _canonical(devices), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
