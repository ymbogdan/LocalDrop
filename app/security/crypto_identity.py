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

from app.security.key_guard import KeyLocked, ask_passphrase, open_secret, seal
from app.security.rotation import sign_successor, verify_successor

KEY_FILENAME = "device.key"
CERT_FILENAME = "device.crt"
NEXT_CERT_FILENAME = "device.next.crt"
NEXT_KEY_FILENAME = "device.next.key"
NEXT_PROOF_FILENAME = "device.next.proof"
CERT_DAYS = 365
SUCCESSOR_WINDOW_DAYS = 30


@dataclass(frozen=True)
class CryptoIdentity:
    device_id: str
    key_path: Path
    cert_path: Path
    certificate_pem: bytes
    certificate_der: bytes
    fingerprint: str
    key_pem: bytes
    successor_certificate_pem: bytes = b""
    successor_proof: str = ""

    def private_key_pem(self) -> bytes:
        return self.key_pem


def fingerprint_der(certificate_der: bytes) -> str:
    digest = hashlib.sha256(certificate_der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def load_or_create_crypto(directory: Path, device_id: str, *, interactive: bool = False) -> CryptoIdentity:
    uuid.UUID(device_id)
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / KEY_FILENAME
    cert_path = directory / CERT_FILENAME
    if key_path.exists() or cert_path.exists():
        return _load(device_id, key_path, cert_path, interactive)
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = _self_signed(device_id, key)
    key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    _write_private(key_path, _store_secret(key_bytes, interactive, fresh=True))
    cert_path.write_bytes(cert_bytes)
    return _identity(device_id, key_path, cert_path, certificate, key_bytes)


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
        .not_valid_after(now + datetime.timedelta(days=CERT_DAYS))
        .sign(key, hashes.SHA256())
    )


def _load(device_id: str, key_path: Path, cert_path: Path, interactive: bool) -> CryptoIdentity:
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    if device_id_from_certificate(certificate.public_bytes(serialization.Encoding.DER)) != device_id:
        raise ValueError("Certificate does not match device id")
    blob = key_path.read_bytes()
    passphrase = None
    if blob.startswith(b"LDPP") and interactive:
        passphrase = ask_passphrase(False)
        if not passphrase:
            raise KeyLocked()
    pem = open_secret(blob, passphrase)
    if blob.startswith(b"-----BEGIN"):
        _write_private(key_path, _store_secret(pem, interactive, fresh=True))
    elif interactive and blob.startswith(b"LDDP"):
        upgraded = _store_secret(pem, True, fresh=True)
        if not upgraded.startswith(b"LDDP"):
            _write_private(key_path, upgraded)
    identity = _identity(device_id, key_path, cert_path, certificate, pem)
    return _prepare_successor(identity, interactive)


def _store_secret(pem: bytes, interactive: bool, *, fresh: bool) -> bytes:
    if not fresh:
        return seal(pem, None, prefer_tpm=False)
    if interactive:
        wrapped = seal(pem, None, prefer_tpm=True)
        if wrapped.startswith(b"LDTP"):
            return wrapped
        passphrase = ask_passphrase(True)
        if not passphrase:
            raise KeyLocked()
        return seal(pem, passphrase, prefer_tpm=False)
    return seal(pem, None, prefer_tpm=False)


def _identity(
    device_id: str,
    key_path: Path,
    cert_path: Path,
    certificate: x509.Certificate,
    key_pem: bytes,
) -> CryptoIdentity:
    der = certificate.public_bytes(serialization.Encoding.DER)
    return CryptoIdentity(
        device_id=device_id,
        key_path=key_path,
        cert_path=cert_path,
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
        certificate_der=der,
        fingerprint=fingerprint_der(der),
        key_pem=key_pem,
    )


def _expiry(certificate: x509.Certificate) -> datetime.datetime:
    expiry = getattr(certificate, "not_valid_after_utc", None)
    if isinstance(expiry, datetime.datetime):
        return expiry
    return certificate.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def _prepare_successor(identity: CryptoIdentity, interactive: bool) -> CryptoIdentity:
    certificate = x509.load_pem_x509_certificate(identity.certificate_pem)
    remaining = _expiry(certificate) - datetime.datetime.now(datetime.timezone.utc)
    directory = identity.cert_path.parent
    if remaining.total_seconds() <= 0:
        promoted = _promote_successor(identity, interactive)
        if promoted is not None:
            return promoted
    if remaining < datetime.timedelta(days=SUCCESSOR_WINDOW_DAYS):
        _ensure_successor(identity, interactive)
    return _attach_successor(identity)


def _ensure_successor(identity: CryptoIdentity, interactive: bool) -> None:
    directory = identity.cert_path.parent
    cert_path = directory / NEXT_CERT_FILENAME
    key_path = directory / NEXT_KEY_FILENAME
    proof_path = directory / NEXT_PROOF_FILENAME
    if cert_path.is_file() and key_path.is_file() and proof_path.is_file():
        return
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = _self_signed(identity.device_id, key)
    der = certificate.public_bytes(serialization.Encoding.DER)
    proof = sign_successor(identity.key_pem, identity.device_id, fingerprint_der(der))
    key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    _write_private(key_path, _store_secret(key_bytes, interactive, fresh=True))
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    proof_path.write_text(proof, encoding="ascii")


def _attach_successor(identity: CryptoIdentity) -> CryptoIdentity:
    directory = identity.cert_path.parent
    cert_path = directory / NEXT_CERT_FILENAME
    proof_path = directory / NEXT_PROOF_FILENAME
    if not cert_path.is_file() or not proof_path.is_file():
        return identity
    certificate_pem = cert_path.read_bytes()
    proof = proof_path.read_text(encoding="ascii").strip()
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
        der = certificate.public_bytes(serialization.Encoding.DER)
        if device_id_from_certificate(der) != identity.device_id:
            return identity
        fingerprint = fingerprint_der(der)
    except Exception:
        return identity
    if not verify_successor(identity.certificate_pem, identity.device_id, fingerprint, proof):
        return identity
    return CryptoIdentity(
        device_id=identity.device_id,
        key_path=identity.key_path,
        cert_path=identity.cert_path,
        certificate_pem=identity.certificate_pem,
        certificate_der=identity.certificate_der,
        fingerprint=identity.fingerprint,
        key_pem=identity.key_pem,
        successor_certificate_pem=certificate_pem,
        successor_proof=proof,
    )


def _promote_successor(identity: CryptoIdentity, interactive: bool) -> CryptoIdentity | None:
    attached = _attach_successor(identity)
    if not attached.successor_certificate_pem or not attached.successor_proof:
        return None
    directory = identity.cert_path.parent
    key_path = directory / NEXT_KEY_FILENAME
    if not key_path.is_file():
        return None
    try:
        pem = open_secret(key_path.read_bytes(), None)
    except Exception:
        return None
    _write_private(identity.key_path, _store_secret(pem, interactive, fresh=False))
    identity.cert_path.write_bytes(attached.successor_certificate_pem)
    for name in (NEXT_CERT_FILENAME, NEXT_KEY_FILENAME, NEXT_PROOF_FILENAME):
        try:
            (directory / name).unlink()
        except OSError:
            pass
    certificate = x509.load_pem_x509_certificate(attached.successor_certificate_pem)
    return _identity(identity.device_id, identity.key_path, identity.cert_path, certificate, pem)


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
