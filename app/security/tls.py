from __future__ import annotations

import ssl

from app.security.crypto_identity import CryptoIdentity


def server_context(identity: CryptoIdentity, trusted_certificates: list[bytes]) -> ssl.SSLContext:
    context = _base_context(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(identity.cert_path), keyfile=str(identity.key_path))
    if trusted_certificates:
        context.load_verify_locations(cadata=_pem_bundle(trusted_certificates))
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def client_context(identity: CryptoIdentity, peer_certificate_pem: bytes) -> ssl.SSLContext:
    context = _base_context(ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(certfile=str(identity.cert_path), keyfile=str(identity.key_path))
    context.load_verify_locations(cadata=_pem_bundle([peer_certificate_pem]))
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    return context


def _pem_bundle(certificates: list[bytes | str]) -> str:
    parts: list[str] = []
    for certificate in certificates:
        text = certificate.decode("utf-8") if isinstance(certificate, bytes) else certificate
        if not text.endswith("\n"):
            text += "\n"
        parts.append(text)
    return "".join(parts)


def _base_context(protocol: int) -> ssl.SSLContext:
    context = ssl.SSLContext(protocol)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET
    return context
