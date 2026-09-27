from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.security.crypto_identity import fingerprint_der
from app.security.key_guard import open_secret, seal


def phone_material(directory: Path | None, hosts: list[str]) -> tuple[bytes, bytes, str]:
    names = _names(hosts)
    if directory is not None:
        directory.mkdir(parents=True, exist_ok=True)
        cert_path = directory / "phone.crt"
        key_path = directory / "phone.key"
        if cert_path.is_file() and key_path.is_file():
            try:
                cert_pem = cert_path.read_bytes()
                key_pem = open_secret(key_path.read_bytes(), None)
                certificate = x509.load_pem_x509_certificate(cert_pem)
                if _covers(certificate, names):
                    der = certificate.public_bytes(serialization.Encoding.DER)
                    return cert_pem, key_pem, fingerprint_der(der)
            except Exception:
                pass
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = _issue(key, names)
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    if directory is not None:
        cert_path = directory / "phone.crt"
        key_path = directory / "phone.key"
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(seal(key_pem, None, prefer_tpm=False))
    der = certificate.public_bytes(serialization.Encoding.DER)
    return cert_pem, key_pem, fingerprint_der(der)


def _names(hosts: list[str]) -> list[str]:
    found = ["127.0.0.1"]
    for host in hosts:
        if host not in found:
            found.append(host)
    return found


def _issue(key: ec.EllipticCurvePrivateKey, hosts: list[str]) -> x509.Certificate:
    san = [x509.IPAddress(ipaddress.ip_address(host)) for host in hosts]
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LocalDrop")])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .sign(key, hashes.SHA256())
    )


def _covers(certificate: x509.Certificate, hosts: list[str]) -> bool:
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    present = {str(item) for item in san.get_values_for_type(x509.IPAddress)}
    return all(host in present for host in hosts)
