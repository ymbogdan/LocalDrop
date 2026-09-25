from __future__ import annotations

import datetime
import hashlib
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

KEY_FILENAME = "device.key"
CERT_FILENAME = "device.crt"


@dataclass(frozen=True)
class CryptoIdentity:
    device_id: str
    key_path: Path
    cert_path: Path
    certificate_pem: bytes
    certificate_der: bytes
    fingerprint: str

    def private_key_pem(self) -> bytes:
        return self.key_path.read_bytes()


def fingerprint_der(certificate_der: bytes) -> str:
    digest = hashlib.sha256(certificate_der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def load_or_create_crypto(directory: Path, device_id: str) -> CryptoIdentity:
    uuid.UUID(device_id)
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / KEY_FILENAME
    cert_path = directory / CERT_FILENAME
    if key_path.exists() or cert_path.exists():
        return _load(device_id, key_path, cert_path)
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = _self_signed(device_id, key)
    key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    _write_private(key_path, key_bytes)
    cert_path.write_bytes(cert_bytes)
    return _identity(device_id, key_path, cert_path, certificate)


def device_id_from_certificate(certificate_der: bytes) -> str:
    certificate = x509.load_der_x509_certificate(certificate_der)
    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not names:
        raise ValueError("Certificate has no device id")
    device_id = str(names[0].value)
    return str(uuid.UUID(device_id))


def _self_signed(device_id: str, key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )


def _load(device_id: str, key_path: Path, cert_path: Path) -> CryptoIdentity:
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    if device_id_from_certificate(certificate.public_bytes(serialization.Encoding.DER)) != device_id:
        raise ValueError("Certificate does not match device id")
    key_path.read_bytes()
    return _identity(device_id, key_path, cert_path, certificate)


def _identity(
    device_id: str,
    key_path: Path,
    cert_path: Path,
    certificate: x509.Certificate,
) -> CryptoIdentity:
    der = certificate.public_bytes(serialization.Encoding.DER)
    return CryptoIdentity(
        device_id=device_id,
        key_path=key_path,
        cert_path=cert_path,
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
        certificate_der=der,
        fingerprint=fingerprint_der(der),
    )


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
