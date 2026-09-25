from __future__ import annotations

import asyncio
import logging
import ssl
import struct
from collections.abc import Callable
from enum import Enum
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.network.constants import TCP_PORT
from app.network.protocol import (
    MAX_CONTROL_MESSAGE_SIZE,
    ErrorCode,
    Message,
    MessageType,
    ProtocolError,
    decode_message,
    encode_message,
    hello_payload,
    make_error,
    make_pair_request,
    make_pair_response,
    message_to_dict,
    parse_message,
    read_size,
    validate_hello,
)
from app.security.crypto_identity import CryptoIdentity, device_id_from_certificate, fingerprint_der
from app.security.pairing import verification_code
from app.security.tls import client_context, server_context
from app.security.trust import TrustDecision, TrustStore

log = logging.getLogger("localdrop")

ConfirmPairing = Callable[[str, str, str], bool]
MAX_CERTIFICATE_BYTES = 16 * 1024


class SecureState(Enum):
    DISCOVERED = "DISCOVERED"
    TCP_CONNECTING = "TCP_CONNECTING"
    TLS_HANDSHAKE = "TLS_HANDSHAKE"
    PEER_AUTHENTICATED = "PEER_AUTHENTICATED"
    TRUST_CHECK = "TRUST_CHECK"
    PAIRING_REQUIRED = "PAIRING_REQUIRED"
    TRUSTED = "TRUSTED"
    READY = "READY"
    FAILED = "FAILED"


class SecureError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SecureSession:
    def __init__(self) -> None:
        self.state = SecureState.DISCOVERED
        self.device_id = ""
        self.device_name = ""
        self.fingerprint = ""
        self.tls_version = ""
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.queues: dict[str, asyncio.Queue] = {}
        self.write_lock = asyncio.Lock()


class SecureNode:
    def __init__(
        self,
        identity: CryptoIdentity,
        device_name: str,
        trust_path: Path,
        confirm_pairing: ConfirmPairing | None = None,
    ) -> None:
        self.identity = identity
        self.device_name = device_name
        self.trust = TrustStore(trust_path)
        self.confirm_pairing = confirm_pairing
        self.on_incoming = None
        self._server: asyncio.Server | None = None
        self.port = 0

    async def start(self, host: str = "0.0.0.0", port: int = TCP_PORT) -> int:
        try:
            self._server = await asyncio.start_server(self._accept, host, port)
        except OSError:
            if port == 0:
                raise
            self._server = await asyncio.start_server(self._accept, host, 0)
        self.port = int(self._server.sockets[0].getsockname()[1])
        log.info("TCP server started on port %s", self.port)
        return self.port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def connect(
        self,
        host: str,
        port: int,
        *,
        allow_pairing: bool = True,
        opening: Message | None = None,
    ) -> SecureSession:
        session = SecureSession()
        session.state = SecureState.TCP_CONNECTING
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 5)
            session.reader = reader
            session.writer = writer
            await self._upgrade(session, server_side=False)
            await self._hello(session)
            await self._authorize(session, initiator=True, allow_pairing=allow_pairing, opening=opening)
            if session.state == SecureState.READY:
                asyncio.create_task(self._pump(session))
            return session
        except SecureError:
            await _close(session)
            raise
        except (ssl.SSLError, asyncio.IncompleteReadError, ConnectionError, TimeoutError, OSError, ProtocolError) as exc:
            log.warning("[TLS] Handshake failed")
            session.state = SecureState.FAILED
            await _close(session)
            raise SecureError("REJECTED") from exc

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        session = SecureSession()
        session.reader = reader
        session.writer = writer
        try:
            await self._upgrade(session, server_side=True)
            await self._hello(session)
            await self._authorize(session, initiator=False, allow_pairing=True, opening=None)
            if session.state == SecureState.READY:
                await self._pump(session)
        except SecureError as exc:
            if exc.code == "REJECTED" and session.state not in {
                SecureState.DISCOVERED,
                SecureState.TCP_CONNECTING,
                SecureState.TLS_HANDSHAKE,
            }:
                await _write_message(session, make_error(ErrorCode.NOT_AUTHORIZED))
            log.warning("[TLS] Peer certificate rejected")
        except (ssl.SSLError, asyncio.IncompleteReadError, ConnectionError, TimeoutError, OSError, ProtocolError):
            log.warning("[TLS] Connection closed")
        finally:
            await _close(session)

    async def _upgrade(self, session: SecureSession, *, server_side: bool) -> None:
        session.state = SecureState.TLS_HANDSHAKE
        log.info("TLS handshake started")
        peer_pem = await _exchange_certificate(session, self.identity.certificate_pem)
        if server_side:
            context = server_context(self.identity, [peer_pem])
        else:
            context = client_context(self.identity, peer_pem)
        writer = session.writer
        if writer is None:
            raise SecureError("REJECTED")
        await writer.start_tls(context)
        ssl_object = writer.get_extra_info("ssl_object")
        version = ssl_object.version() if ssl_object is not None else None
        if version != "TLSv1.3":
            log.warning("[TLS] Handshake failed")
            raise SecureError("REJECTED")
        session.tls_version = version
        der = ssl_object.getpeercert(True) if ssl_object is not None else None
        if not der:
            raise SecureError("REJECTED")
        session.fingerprint = fingerprint_der(der)
        session.device_id = device_id_from_certificate(der)
        presented = fingerprint_der(x509.load_pem_x509_certificate(peer_pem).public_bytes(serialization.Encoding.DER))
        if presented != session.fingerprint:
            raise SecureError("REJECTED")
        session.state = SecureState.PEER_AUTHENTICATED
        log.info("TLS 1.3 established")
        log.info("Peer authenticated")

    async def _hello(self, session: SecureSession) -> None:
        await _write_message(session, parse_message(hello_payload(self.identity.device_id, self.device_name)))
        message = await _read_message(session)
        device_id, device_name = validate_hello(message_to_dict(message))
        if device_id != session.device_id:
            raise SecureError("REJECTED")
        session.device_name = device_name

    async def _authorize(
        self,
        session: SecureSession,
        *,
        initiator: bool,
        allow_pairing: bool,
        opening: Message | None,
    ) -> None:
        session.state = SecureState.TRUST_CHECK
        decision = self.trust.evaluate(session.device_id, session.fingerprint)
        if decision == TrustDecision.MISMATCH:
            log.warning("[TLS] Peer certificate rejected")
            raise SecureError("REJECTED")
        if decision == TrustDecision.MATCH:
            session.state = SecureState.READY
            log.info("Peer fingerprint verified")
            log.info("Trusted device connected")
            return
        session.state = SecureState.PAIRING_REQUIRED
        if opening is not None:
            await _write_message(session, opening)
            reply = await _read_message(session)
            if reply.type == MessageType.ERROR:
                raise SecureError("REJECTED")
            raise SecureError("REJECTED")
        if not allow_pairing:
            raise SecureError("PAIRING REQUIRED")
        remote_der = x509.load_pem_x509_certificate(self._peer_pem(session)).public_bytes(serialization.Encoding.DER)
        code = verification_code(self.identity.certificate_der, remote_der)
        if initiator:
            request = make_pair_request(self.identity.device_id, self.device_name)
            await _write_message(session, request)
            response = await _read_message(session)
            accepted = response.type == MessageType.PAIR_RESPONSE and response.payload.get("accepted") is True
        else:
            incoming = await _read_message(session)
            if incoming.type == MessageType.TRANSFER_REQUEST:
                await _write_message(session, make_error(ErrorCode.NOT_AUTHORIZED, request_id=incoming.request_id))
                raise SecureError("REJECTED")
            if incoming.type != MessageType.PAIR_REQUEST:
                raise SecureError("REJECTED")
            accepted = self._user_accepts(session, code)
            await _write_message(session, make_pair_response(incoming.request_id or "", accepted))
        if initiator:
            accepted = bool(accepted) and self._user_accepts(session, code)
        if not accepted:
            raise SecureError("REJECTED")
        peer_pem = self._peer_pem(session)
        self.trust.trust(session.device_name, peer_pem)
        session.state = SecureState.TRUSTED
        session.state = SecureState.READY
        log.info("Peer fingerprint verified")
        log.info("Trusted device connected")

    async def _pump(self, session: SecureSession) -> None:
        try:
            while session.state == SecureState.READY and session.reader is not None:
                message = await _read_message(session)
                await self._route(session, message)
        except asyncio.CancelledError:
            raise
        except (SecureError, asyncio.IncompleteReadError, ConnectionError, TimeoutError, OSError, ProtocolError, ssl.SSLError):
            log.info("Peer disconnected")
        finally:
            for queue in list(session.queues.values()):
                queue.put_nowait(None)
            await _close(session)

    async def _route(self, session: SecureSession, message: Message) -> None:
        transfer_id = message.transfer_id or message.payload.get("transfer_id")
        if message.type == MessageType.TRANSFER_REQUEST:
            if not self.trust.is_paired(session.device_id):
                await _write_message(session, make_error(ErrorCode.NOT_AUTHORIZED, request_id=message.request_id))
                return
            if not isinstance(transfer_id, str):
                return
            queue: asyncio.Queue = asyncio.Queue()
            session.queues[transfer_id] = queue
            handler = self.on_incoming
            if handler is None:
                await _write_message(session, make_error(ErrorCode.NOT_AUTHORIZED, request_id=message.request_id))
                return
            asyncio.create_task(handler(session, message, queue))
            return
        if isinstance(transfer_id, str) and transfer_id in session.queues:
            await session.queues[transfer_id].put(message)

    def _user_accepts(self, session: SecureSession, code: str) -> bool:
        if self.confirm_pairing is None:
            return False
        return bool(self.confirm_pairing(session.device_name, session.fingerprint, code))

    def _peer_pem(self, session: SecureSession) -> bytes:
        ssl_object = session.writer.get_extra_info("ssl_object") if session.writer is not None else None
        der = ssl_object.getpeercert(True) if ssl_object is not None else None
        if not der:
            raise SecureError("REJECTED")
        certificate = x509.load_der_x509_certificate(der)
        return certificate.public_bytes(serialization.Encoding.PEM)


async def _exchange_certificate(session: SecureSession, local_pem: bytes) -> bytes:
    writer = session.writer
    reader = session.reader
    if writer is None or reader is None:
        raise SecureError("REJECTED")
    if len(local_pem) > MAX_CERTIFICATE_BYTES:
        raise SecureError("REJECTED")
    writer.write(struct.pack(">I", len(local_pem)) + local_pem)
    await writer.drain()
    header = await asyncio.wait_for(reader.readexactly(4), 5)
    size = struct.unpack(">I", header)[0]
    if size <= 0 or size > MAX_CERTIFICATE_BYTES:
        raise SecureError("REJECTED")
    peer_pem = await asyncio.wait_for(reader.readexactly(size), 5)
    try:
        x509.load_pem_x509_certificate(peer_pem)
    except ValueError as exc:
        raise SecureError("REJECTED") from exc
    return peer_pem


async def _write_message(session: SecureSession, message: Message) -> None:
    writer = session.writer
    if writer is None:
        raise SecureError("REJECTED")
    try:
        async with session.write_lock:
            writer.write(encode_message(message_to_dict(message), MAX_CONTROL_MESSAGE_SIZE))
            await writer.drain()
    except (ConnectionError, OSError):
        return


async def _read_message(session: SecureSession) -> Message:
    reader = session.reader
    if reader is None:
        raise SecureError("REJECTED")
    header = await asyncio.wait_for(reader.readexactly(4), 5)
    size = read_size(header, MAX_CONTROL_MESSAGE_SIZE)
    body = await asyncio.wait_for(reader.readexactly(size), 5)
    return parse_message(decode_message(body))


async def _close(session: SecureSession) -> None:
    writer = session.writer
    session.writer = None
    session.reader = None
    if writer is None:
        return
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError, ssl.SSLError):
        pass
