from __future__ import annotations

import ssl

from app.security.crypto_identity import CryptoIdentity
from app.security.key_guard import pem_file


def server_context(identity: CryptoIdentity, trusted_certificates: list[bytes]) -> ssl.SSLContext:
    context = _base_context(ssl.PROTOCOL_TLS_SERVER)
    _load_chain(context, identity)
    if trusted_certificates:
        context.load_verify_locations(cadata=_pem_bundle(trusted_certificates))
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def client_context(
    identity: CryptoIdentity,
    peer_certificate_pem: bytes,
    extra_certificates: list[bytes] | None = None,
) -> ssl.SSLContext:
    context = _base_context(ssl.PROTOCOL_TLS_CLIENT)
    _load_chain(context, identity)
    bundle = [peer_certificate_pem]
    if extra_certificates:
        bundle.extend(extra_certificates)
    context.load_verify_locations(cadata=_pem_bundle(bundle))
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    return context


def _load_chain(context: ssl.SSLContext, identity: CryptoIdentity) -> None:
    with pem_file(identity.private_key_pem()) as keyfile:
        context.load_cert_chain(certfile=str(identity.cert_path), keyfile=keyfile)


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
