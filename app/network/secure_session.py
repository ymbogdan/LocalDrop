from __future__ import annotations

import asyncio
import json
import logging
import secrets
import ssl
import struct
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.network.constants import PROTOCOL_VERSION
from app.security.admission import Admission
from app.security.crypto_identity import CryptoIdentity, device_id_from_certificate, fingerprint_der
from app.security.integrity import hash_file, hashes_match
from app.security.limits import DEFAULT_LIMITS, Limits, transfer_budget
from app.security.sessions import SeenSessions, new_session_id
from app.security.pairing import verification_code
from app.security.tls import client_context, server_context
from app.security.trust import TrustDecision, TrustStore
from app.security.validation import (
    SecurityError,
    unique_destination,
    validate_chunk_size,
    validate_file_size,
    validate_filename,
)

log = logging.getLogger("localdrop")

HELLO = 1
HELLO_ACK = 2
TRANSFER_REQUEST = 3
TRANSFER_RESPONSE = 4
CHUNK = 5
COMPLETE = 6
ERROR = 7
PAIR_OFFER = 8

AcceptTransfer = Callable[[str, int, str], bool]


class SecureNode:
    def __init__(
        self,
        identity: CryptoIdentity,
        device_name: str,
        trust: TrustStore,
        download_dir: Path,
        *,
        limits: Limits = DEFAULT_LIMITS,
        accept_transfer: AcceptTransfer | None = None,
        accept_pairing: Callable[[str, str], bool] | None = None,
    ) -> None:
        self.identity = identity
        self.device_name = device_name
        self.trust = trust
        self.download_dir = download_dir
        self.limits = limits
        self.accept_transfer = accept_transfer or (lambda _name, _size, _peer: False)
        self.accept_pairing = accept_pairing or (lambda _name, _code: True)
        self._server: asyncio.Server | None = None
        self._connections = 0
        self._transfers = 0
        self._by_peer: dict[str, int] = {}
        self._sessions = SeenSessions()
        self._admission = Admission()

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> tuple[str, int]:
        self._server = await asyncio.start_server(self._handle_plain, host, port)
        socket_name = self._server.sockets[0].getsockname()
        return str(socket_name[0]), int(socket_name[1])

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def pair_with(self, host: str, port: int, accept: bool) -> str:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            code = await _pair_exchange(reader, writer, self.identity, self.device_name, self.trust, accept)
            return code
        finally:
            writer.close()
            await writer.wait_closed()

    async def send_file(self, host: str, port: int, device_id: str, path: Path) -> None:
        record = self.trust.get(device_id)
        if record is None:
            raise SecurityError("REJECTED", "Unknown device")
        extra = [record.successor_certificate_pem.encode("utf-8")] if record.successor_certificate_pem else None
        context = client_context(self.identity, record.certificate_pem.encode("utf-8"), extra)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context),
                self.limits.timeout_seconds,
            )
        except ssl.SSLCertVerificationError as exc:
            raise SecurityError("CONNECTION REJECTED", "Peer certificate rejected") from exc
        except ssl.SSLError as exc:
            raise _from_ssl(exc) from exc
        try:
            await self._check_peer(writer)
            log.info("Secure connection established")
            session_id = new_session_id()
            hello = {"session_id": session_id, "protocol_version": PROTOCOL_VERSION, "sequence": 0}
            _attach_successor(hello, self.identity)
            await _write_frame(writer, HELLO, hello, self.limits)
            ack = await _read_frame(reader, self.limits)
            if ack[0] == ERROR:
                raise SecurityError(str(ack[1].get("code", "REJECTED")), "Transfer rejected")
            if ack[0] != HELLO_ACK or ack[1].get("session_id") != session_id:
                raise SecurityError("REJECTED", "Invalid session")
            _remember_successor(self.trust, device_id, ack[1])
            digest = hash_file(path, self.limits.max_chunk_bytes)
            size = path.stat().st_size
            validate_file_size(size, self.limits)
            sequence = 1
            await _write_frame(
                writer,
                TRANSFER_REQUEST,
                {
                    "session_id": session_id,
                    "sequence": sequence,
                    "transfer_id": str(uuid.uuid4()),
                    "filename": path.name,
                    "size": size,
                    "sha256": digest,
                    "protocol_version": PROTOCOL_VERSION,
                },
                self.limits,
            )
            response = await _read_frame(reader, self.limits)
            if response[0] == ERROR or not response[1].get("accepted"):
                code = str(response[1].get("code", "REJECTED"))
                raise SecurityError(code, str(response[1].get("message", "Transfer rejected")))
            log.info("Transfer started: %s", path.name)
            offset = 0
            with path.open("rb") as handle:
                while True:
                    block = handle.read(self.limits.max_chunk_bytes)
                    if not block:
                        break
                    sequence += 1
                    await _write_frame(
                        writer,
                        CHUNK,
                        {"session_id": session_id, "sequence": sequence, "offset": offset},
                        self.limits,
                        block,
                    )
                    offset += len(block)
            sequence += 1
            await _write_frame(
                writer,
                COMPLETE,
                {"session_id": session_id, "sequence": sequence, "sha256": digest},
                self.limits,
            )
            final = await _read_frame(reader, self.limits)
            if final[0] == ERROR or not final[1].get("ok"):
                raise SecurityError(str(final[1].get("code", "TRANSFER FAILED")), "Transfer failed")
            log.info("Transfer completed")
        except SecurityError:
            raise
        except (asyncio.IncompleteReadError, ConnectionError, TimeoutError, ssl.SSLError, OSError) as exc:
            raise SecurityError("REJECTED", "Connection closed") from exc
        finally:
            writer.close()
            await writer.wait_closed()

    async def _handle_plain(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip = _peer_ip(writer)
        if self._connections >= self.limits.max_connections or not self._admission.try_open(ip):
            writer.close()
            await writer.wait_closed()
            return
        self._connections += 1
        try:
            kind, header, _body = await _read_frame(reader, self.limits)
            if kind != PAIR_OFFER:
                raise SecurityError("REJECTED", "Secure session required")
            await _pair_exchange(
                reader,
                writer,
                self.identity,
                self.device_name,
                self.trust,
                True,
                header,
                self.accept_pairing,
            )
        except (SecurityError, asyncio.IncompleteReadError, ConnectionError, TimeoutError, json.JSONDecodeError, OSError):
            log.info("Pairing closed")
        finally:
            self._connections -= 1
            self._admission.close(ip)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def enable_tls(self) -> tuple[str, int]:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        context = server_context(self.identity, self.trust.paired_certificates())
        self._server = await asyncio.start_server(self._handle_tls, "127.0.0.1", 0, ssl=context)
        socket_name = self._server.sockets[0].getsockname()
        return str(socket_name[0]), int(socket_name[1])

    async def _handle_tls(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip = _peer_ip(writer)
        if not self._admission.try_open(ip):
            writer.close()
            await writer.wait_closed()
            return
        partial: Path | None = None
        started = False
        try:
            peer_id = await self._check_peer(writer)
            log.info("Peer authenticated")
            log.info("Secure connection established")
            kind, header, _body = await _read_frame(reader, self.limits)
            if kind != HELLO:
                raise SecurityError("REJECTED", "Expected hello")
            session_id = _require_session(header)
            if not self._sessions.admit(session_id):
                raise SecurityError("REJECTED", "Replay rejected")
            if header.get("protocol_version") != PROTOCOL_VERSION:
                raise SecurityError("REJECTED", "Unsupported protocol")
            _remember_successor(self.trust, peer_id, header)
            expected = 1
            ack = {"session_id": session_id, "sequence": 0}
            _attach_successor(ack, self.identity)
            await _write_frame(writer, HELLO_ACK, ack, self.limits)
            kind, header, _body = await _read_frame(reader, self.limits)
            expected = _next_sequence(header, session_id, expected)
            if kind != TRANSFER_REQUEST:
                raise SecurityError("REJECTED", "Expected transfer request")
            filename = validate_filename(header.get("filename"))
            size = validate_file_size(header.get("size"), self.limits)
            digest = header.get("sha256")
            if not isinstance(digest, str) or len(digest) != 64:
                raise SecurityError("REJECTED", "Invalid hash")
            peer_name = self.trust.get(peer_id).device_name if self.trust.get(peer_id) else peer_id
            if self._transfers >= self.limits.max_concurrent_transfers:
                raise SecurityError("REJECTED", "Too many transfers")
            if self._by_peer.get(peer_id, 0) >= self.limits.max_transfers_per_peer:
                raise SecurityError("REJECTED", "Too many transfers")
            if not self.accept_transfer(filename, size, peer_name):
                raise SecurityError("REJECTED", "Transfer refused")
            self._transfers += 1
            self._by_peer[peer_id] = self._by_peer.get(peer_id, 0) + 1
            started = True
            target = unique_destination(self.download_dir, filename)
            partial = self.download_dir / f".{secrets.token_hex(16)}.partial"
            await _write_frame(writer, TRANSFER_RESPONSE, {"accepted": True, "session_id": session_id}, self.limits)
            log.info("Transfer started: %s", filename)
            received = 0
            deadline = time.monotonic() + transfer_budget(size)
            with partial.open("wb") as handle:
                while received < size:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SecurityError("REJECTED", "Transfer timed out")
                    try:
                        kind, header, body = await _read_frame(
                            reader,
                            self.limits,
                            min(self.limits.timeout_seconds, remaining),
                        )
                    except TimeoutError as exc:
                        raise SecurityError("REJECTED", "Transfer timed out") from exc
                    expected = _next_sequence(header, session_id, expected)
                    if kind != CHUNK:
                        raise SecurityError("REJECTED", "Expected chunk")
                    validate_chunk_size(len(body), self.limits)
                    offset = header.get("offset")
                    if offset != received:
                        raise SecurityError("REJECTED", "Unexpected offset")
                    if received + len(body) > size:
                        raise SecurityError("REJECTED", "Too much data")
                    handle.write(body)
                    received += len(body)
            kind, header, _body = await _read_frame(reader, self.limits)
            _next_sequence(header, session_id, expected)
            if kind != COMPLETE:
                raise SecurityError("TRANSFER FAILED", "Incomplete transfer")
            actual = hash_file(partial, self.limits.max_chunk_bytes)
            if not hashes_match(digest, actual):
                raise SecurityError("TRANSFER FAILED", "File integrity verification failed.")
            partial.replace(target)
            partial = None
            await _write_frame(writer, COMPLETE, {"ok": True, "session_id": session_id}, self.limits)
            log.info("Transfer completed")
        except SecurityError as exc:
            await _write_error(writer, exc)
            log.info("Transfer rejected: %s", exc.code)
        except (asyncio.IncompleteReadError, ConnectionError, TimeoutError, ssl.SSLError, OSError):
            log.info("Connection interrupted")
        except Exception:
            log.exception("Transfer failed")
        finally:
            self._admission.close(ip)
            if started:
                self._transfers -= 1
                self._by_peer[peer_id] = self._by_peer.get(peer_id, 1) - 1
                if self._by_peer[peer_id] <= 0:
                    self._by_peer.pop(peer_id, None)
            if partial is not None and partial.exists():
                partial.unlink(missing_ok=True)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _check_peer(self, writer: asyncio.StreamWriter) -> str:
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            raise SecurityError("REJECTED", "Secure session required")
        der = ssl_object.getpeercert(True)
        if not der:
            raise SecurityError("CONNECTION REJECTED", "Missing peer certificate")
        device_id = device_id_from_certificate(der)
        decision = self.trust.evaluate(device_id, fingerprint_der(der))
        if decision == TrustDecision.UNKNOWN:
            raise SecurityError("REJECTED", "Unknown device")
        if decision == TrustDecision.MISMATCH:
            raise SecurityError("CONNECTION REJECTED", "Cryptographic identity changed")
        return device_id


async def _pair_exchange(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: CryptoIdentity,
    device_name: str,
    trust: TrustStore,
    accept: bool,
    remote_header: dict | None = None,
    accept_pairing: Callable[[str, str], bool] | None = None,
) -> str:
    offer = {
        "device_id": identity.device_id,
        "device_name": device_name,
        "certificate": identity.certificate_pem.decode("utf-8"),
    }
    if remote_header is None:
        await _write_frame(writer, PAIR_OFFER, offer, DEFAULT_LIMITS)
        kind, remote_header, _body = await _read_frame(reader, DEFAULT_LIMITS)
        if kind != PAIR_OFFER:
            raise SecurityError("REJECTED", "Expected pairing offer")
    else:
        await _write_frame(writer, PAIR_OFFER, offer, DEFAULT_LIMITS)
    remote_pem = remote_header.get("certificate")
    remote_name = remote_header.get("device_name")
    if not isinstance(remote_pem, str) or not isinstance(remote_name, str):
        raise SecurityError("REJECTED", "Invalid pairing offer")
    remote_cert = x509.load_pem_x509_certificate(remote_pem.encode("utf-8"))
    remote_der = remote_cert.public_bytes(serialization.Encoding.DER)
    code = verification_code(identity.certificate_der, remote_der)
    if not accept or (accept_pairing is not None and not accept_pairing(remote_name, code)):
        raise SecurityError("REJECTED", "Pairing rejected")
    trust.trust(remote_name, remote_pem.encode("utf-8"))
    return code


def _peer_ip(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    if not peer:
        return ""
    return str(peer[0]).split("%", 1)[0]


def _require_session(header: dict) -> str:
    session_id = header.get("session_id")
    if not isinstance(session_id, str) or len(session_id) != 32:
        raise SecurityError("REJECTED", "Invalid session")
    try:
        raw = bytes.fromhex(session_id)
    except ValueError as exc:
        raise SecurityError("REJECTED", "Invalid session") from exc
    if len(raw) != 16:
        raise SecurityError("REJECTED", "Invalid session")
    return session_id.lower()


def _attach_successor(header: dict, identity: CryptoIdentity) -> None:
    if identity.successor_certificate_pem and identity.successor_proof:
        header["successor_certificate"] = identity.successor_certificate_pem.decode("utf-8")
        header["successor_proof"] = identity.successor_proof


def _remember_successor(trust: TrustStore, device_id: str, header: dict) -> None:
    certificate = header.get("successor_certificate")
    proof = header.get("successor_proof")
    if isinstance(certificate, str) and isinstance(proof, str):
        trust.accept_successor(device_id, certificate, proof)


def _next_sequence(header: dict, session_id: str, expected: int) -> int:
    if header.get("session_id") != session_id:
        raise SecurityError("REJECTED", "Replay rejected")
    sequence = header.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence != expected or sequence < expected:
        raise SecurityError("REJECTED", "Replay rejected")
    return expected + 1


async def _write_frame(
    writer: asyncio.StreamWriter,
    kind: int,
    header: dict,
    limits: Limits,
    body: bytes = b"",
) -> None:
    payload = json.dumps(header, separators=(",", ":")).encode("utf-8")
    if len(payload) > limits.max_metadata_bytes:
        raise SecurityError("REJECTED", "Metadata too large")
    validate_chunk_size(len(body), limits)
    writer.write(bytes([kind]) + struct.pack(">II", len(payload), len(body)) + payload + body)
    await writer.drain()


async def _read_frame(reader: asyncio.StreamReader, limits: Limits, timeout: float | None = None) -> tuple[int, dict, bytes]:
    wait = limits.timeout_seconds if timeout is None else timeout
    prefix = await asyncio.wait_for(reader.readexactly(9), wait)
    kind = prefix[0]
    header_len, body_len = struct.unpack(">II", prefix[1:])
    if header_len > limits.max_metadata_bytes or body_len > limits.max_chunk_bytes:
        raise SecurityError("REJECTED", "Message too large")
    if kind not in {HELLO, HELLO_ACK, TRANSFER_REQUEST, TRANSFER_RESPONSE, CHUNK, COMPLETE, ERROR, PAIR_OFFER}:
        raise SecurityError("REJECTED", "Unknown message")
    header_bytes = await asyncio.wait_for(reader.readexactly(header_len), wait)
    body = await asyncio.wait_for(reader.readexactly(body_len), wait)
    header = json.loads(header_bytes.decode("utf-8"))
    if not isinstance(header, dict):
        raise SecurityError("REJECTED", "Invalid message")
    return kind, header, body


async def _write_error(writer: asyncio.StreamWriter, exc: SecurityError) -> None:
    try:
        await _write_frame(writer, ERROR, {"code": exc.code, "message": exc.message}, DEFAULT_LIMITS)
    except (ConnectionError, OSError, SecurityError):
        pass


def _from_ssl(exc: ssl.SSLError) -> SecurityError:
    text = str(exc).lower()
    if "unknown ca" in text or "bad certificate" in text or "certificate required" in text:
        return SecurityError("REJECTED", "Unknown device")
    return SecurityError("CONNECTION REJECTED", "Peer certificate rejected")
