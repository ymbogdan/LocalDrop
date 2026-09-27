from __future__ import annotations

import base64

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def successor_message(device_id: str, fingerprint: str) -> bytes:
    return f"{device_id}|{fingerprint}".encode("utf-8")


def sign_successor(key_pem: bytes, device_id: str, fingerprint: str) -> str:
    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("Invalid key")
    signature = key.sign(successor_message(device_id, fingerprint), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")


def verify_successor(certificate_pem: bytes | str, device_id: str, fingerprint: str, proof: str) -> bool:
    try:
        raw = certificate_pem.encode("utf-8") if isinstance(certificate_pem, str) else certificate_pem
        certificate = x509.load_pem_x509_certificate(raw)
        public_key = certificate.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        public_key.verify(
            base64.b64decode(proof),
            successor_message(device_id, fingerprint),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except Exception:
        return False
