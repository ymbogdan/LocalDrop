from __future__ import annotations

import asyncio
import tempfile
import unittest
import uuid
from pathlib import Path

from app.network.constants import PROTOCOL_VERSION
from app.network.discovery import encode_announcement
from app.network.secure_session import (
    CHUNK,
    COMPLETE,
    HELLO,
    TRANSFER_REQUEST,
    SecureNode,
    _read_frame,
    _write_frame,
)
from app.security.crypto_identity import load_or_create_crypto
from app.security.integrity import hash_file
from app.security.limits import Limits
from app.security.pairing import format_verification_code, verification_code
from app.security.trust import TrustDecision, TrustStore
from app.security.validation import SecurityError, destination_path, validate_file_size, validate_filename
from app.security import tls as tls_module


def _run(coro):
    return asyncio.run(coro)


class ValidationTests(unittest.TestCase):
    def test_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            for name in ("../../malicious.txt", "..\\..\\malicious.txt", r"C:\Windows\note.txt", "/etc/passwd"):
                with self.assertRaises(SecurityError) as caught:
                    destination_path(folder, name)
                self.assertEqual(caught.exception.code, "REJECTED")
            self.assertFalse((folder.parent / "malicious.txt").exists())

    def test_oversized_metadata_is_rejected(self) -> None:
        limits = Limits(max_file_bytes=1024)
        with self.assertRaises(SecurityError) as caught:
            validate_file_size(999999999999999999, limits)
        self.assertEqual(caught.exception.code, "REJECTED")

    def test_filename_rejects_parent_segments(self) -> None:
        with self.assertRaises(SecurityError) as caught:
            validate_filename("../../malicious.txt")
        self.assertEqual(caught.exception.code, "REJECTED")


class IdentityAndPairingTests(unittest.TestCase):
    def test_key_stays_local_and_fingerprint_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            device_id = str(uuid.uuid4())
            first = load_or_create_crypto(Path(root), device_id)
            second = load_or_create_crypto(Path(root), device_id)
            self.assertEqual(first.fingerprint, second.fingerprint)
            self.assertNotIn(b"PRIVATE", first.certificate_pem)
            self.assertTrue(first.key_path.is_file())

    def test_verification_code_matches_on_both_sides(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            left = load_or_create_crypto(Path(root) / "a", str(uuid.uuid4()))
            right = load_or_create_crypto(Path(root) / "b", str(uuid.uuid4()))
            seen_left = verification_code(left.certificate_der, right.certificate_der)
            seen_right = verification_code(right.certificate_der, left.certificate_der)
            self.assertEqual(seen_left, seen_right)
            self.assertEqual(len(format_verification_code(seen_left).replace(" ", "")), 6)

    def test_identity_change_is_not_trusted_automatically(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            store = TrustStore(Path(root) / "trusted.json")
            original = load_or_create_crypto(Path(root) / "old", str(uuid.uuid4()))
            store.trust("LAPTOP", original.certificate_pem)
            replacement = load_or_create_crypto(Path(root) / "new", original.device_id)
            self.assertEqual(store.evaluate(original.device_id, original.fingerprint), TrustDecision.MATCH)
            self.assertEqual(
                store.evaluate(original.device_id, replacement.fingerprint),
                TrustDecision.MISMATCH,
            )
            self.assertEqual(store.evaluate(str(uuid.uuid4()), original.fingerprint), TrustDecision.UNKNOWN)


class DiscoveryPrivacyTests(unittest.TestCase):
    def test_announcement_has_only_public_fields(self) -> None:
        packet = encode_announcement(str(uuid.uuid4()), "LAPTOP", 47822)
        text = packet.decode("utf-8")
        self.assertNotIn("PRIVATE", text)
        self.assertNotIn("password", text.lower())
        self.assertNotIn("token", text.lower())
        for field in ("device_id", "device_name", "port", "protocol_version"):
            self.assertIn(field, text)


class TlsPolicyTests(unittest.TestCase):
    def test_verification_is_not_disabled(self) -> None:
        source = Path(tls_module.__file__).read_text(encoding="utf-8")
        self.assertNotIn("verify=False", source)
        self.assertNotIn("CERT_NONE", source)
        self.assertIn("TLSv1_3", source)
        self.assertIn("CERT_REQUIRED", source)


class SecureTransferTests(unittest.TestCase):
    def test_sniffed_traffic_does_not_contain_file_bytes(self) -> None:
        marker = b"LOCALDROP-SECRET-PLAINTEXT-MARKER"

        async def scenario() -> None:
            async with _Pair() as nodes:
                captured = bytearray()
                proxy = await _start_proxy(nodes.receiver_port, captured)
                proxy_port = proxy.sockets[0].getsockname()[1]
                try:
                    await nodes.sender.send_file("127.0.0.1", proxy_port, nodes.receiver.identity.device_id, nodes.payload)
                finally:
                    proxy.close()
                    await proxy.wait_closed()
                self.assertIn(marker, nodes.payload.read_bytes())
                self.assertNotIn(marker, captured)
                saved = next(nodes.download.iterdir())
                self.assertEqual(saved.read_bytes(), nodes.payload.read_bytes())

        _run(scenario())

    def test_unknown_device_is_rejected(self) -> None:
        async def scenario() -> None:
            async with _Pair(pair=False) as nodes:
                nodes.sender.trust.trust(nodes.receiver.device_name, nodes.receiver.identity.certificate_pem)
                with self.assertRaises(SecurityError) as caught:
                    await nodes.sender.send_file(
                        "127.0.0.1",
                        nodes.receiver_port,
                        nodes.receiver.identity.device_id,
                        nodes.payload,
                    )
                self.assertEqual(caught.exception.code, "REJECTED")
                self.assertEqual(list(nodes.download.iterdir()), [])

        _run(scenario())

    def test_changed_identity_is_rejected(self) -> None:
        async def scenario() -> None:
            async with _Pair() as nodes:
                impostor = load_or_create_crypto(nodes.root / "impostor", str(uuid.uuid4()))
                foreign_trust = TrustStore(nodes.root / "impostor-trust.json")
                foreign_trust.trust(nodes.sender.device_name, nodes.sender.identity.certificate_pem)
                foreign = SecureNode(
                    impostor,
                    "LAPTOP",
                    foreign_trust,
                    nodes.root / "impostor-downloads",
                    limits=nodes.limits,
                    accept_transfer=lambda *_args: True,
                )
                await foreign.start()
                try:
                    host, port = await foreign.enable_tls()
                    nodes.sender.trust.trust("LAPTOP", nodes.receiver.identity.certificate_pem)
                    with self.assertRaises(SecurityError) as caught:
                        await nodes.sender.send_file(host, port, nodes.receiver.identity.device_id, nodes.payload)
                    self.assertEqual(caught.exception.code, "CONNECTION REJECTED")
                finally:
                    await foreign.stop()

        _run(scenario())

    def test_modified_file_fails_integrity_check(self) -> None:
        async def scenario() -> None:
            async with _Pair() as nodes:
                await _raw_transfer(
                    nodes,
                    filename="video.mp4",
                    payload=b"tampered-bytes",
                    digest="0" * 64,
                    size=len(b"tampered-bytes"),
                )
                self.assertEqual(list(nodes.download.iterdir()), [])

        _run(scenario())

    def test_replay_from_previous_session_is_rejected(self) -> None:
        async def scenario() -> None:
            async with _Pair() as nodes:
                code = await _exchange(nodes, HELLO, {"session_id": str(uuid.uuid4()), "protocol_version": PROTOCOL_VERSION, "sequence": 0})
                self.assertNotEqual(code, "REJECTED")
                rejected = await _exchange(
                    nodes,
                    CHUNK,
                    {"session_id": str(uuid.uuid4()), "sequence": 1, "offset": 0},
                    b"replay",
                )
                self.assertEqual(rejected, "REJECTED")

        _run(scenario())

    def test_path_traversal_transfer_is_rejected(self) -> None:
        async def scenario() -> None:
            async with _Pair() as nodes:
                code = await _exchange(
                    nodes,
                    TRANSFER_REQUEST,
                    _request(nodes, "../../malicious.txt", 4, "ab" * 32),
                    hello=True,
                )
                self.assertEqual(code, "REJECTED")
                self.assertFalse((nodes.download.parent / "malicious.txt").exists())

        _run(scenario())

    def test_oversized_transfer_is_rejected(self) -> None:
        async def scenario() -> None:
            async with _Pair() as nodes:
                code = await _exchange(
                    nodes,
                    TRANSFER_REQUEST,
                    _request(nodes, "big.bin", 999999999999999999, "ab" * 32),
                    hello=True,
                )
                self.assertEqual(code, "REJECTED")

        _run(scenario())

    def test_interrupted_transfer_removes_partial_file(self) -> None:
        async def scenario() -> None:
            async with _Pair() as nodes:
                reader, writer = await _connect(nodes)
                try:
                    session_id = str(uuid.uuid4())
                    nodes.session_id = session_id
                    await _write_frame(writer, HELLO, {"session_id": session_id, "protocol_version": PROTOCOL_VERSION, "sequence": 0}, nodes.limits)
                    await _read_frame(reader, nodes.limits)
                    await _write_frame(writer, TRANSFER_REQUEST, _request(nodes, "partial.bin", 100, hash_file(nodes.payload)), nodes.limits)
                    await _read_frame(reader, nodes.limits)
                    await _write_frame(writer, CHUNK, {"session_id": session_id, "sequence": 2, "offset": 0}, nodes.limits, b"abc")
                finally:
                    writer.close()
                    await writer.wait_closed()
                await asyncio.sleep(0.1)
                self.assertEqual(list(nodes.download.iterdir()), [])

        _run(scenario())


class _Pair:
    def __init__(self, pair: bool = True) -> None:
        self.pair = pair
        self.limits = Limits(max_file_bytes=1024 * 1024, max_chunk_bytes=64, timeout_seconds=2)

    async def __aenter__(self) -> "_Pair":
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.download = self.root / "downloads"
        self.download.mkdir()
        sender_id = str(uuid.uuid4())
        receiver_id = str(uuid.uuid4())
        sender_crypto = load_or_create_crypto(self.root / "sender", sender_id)
        receiver_crypto = load_or_create_crypto(self.root / "receiver", receiver_id)
        self.sender = SecureNode(
            sender_crypto,
            "DESKTOP-BOGDAN",
            TrustStore(self.root / "sender-trust.json"),
            self.root / "sender-downloads",
            limits=self.limits,
            accept_transfer=lambda *_args: True,
        )
        self.receiver = SecureNode(
            receiver_crypto,
            "LAPTOP",
            TrustStore(self.root / "receiver-trust.json"),
            self.download,
            limits=self.limits,
            accept_transfer=lambda *_args: True,
        )
        self.payload = self.root / "secret.bin"
        self.payload.write_bytes(b"LOCALDROP-SECRET-PLAINTEXT-MARKER")
        await self.receiver.start()
        if self.pair:
            host, port = self.receiver._server.sockets[0].getsockname()[:2]
            left = await self.sender.pair_with(host, port, True)
            right = self.receiver.trust.get(sender_id)
            self.assert_codes = left
            self.assertIsPaired = right is not None
            host, self.receiver_port = await self.receiver.enable_tls()
        else:
            _host, self.receiver_port = await self.receiver.enable_tls()
        return self

    async def __aexit__(self, *_args) -> None:
        await self.sender.stop()
        await self.receiver.stop()
        self._tmp.cleanup()


async def _start_proxy(target_port: int, captured: bytearray) -> asyncio.Server:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        remote_reader, remote_writer = await asyncio.open_connection("127.0.0.1", target_port)

        async def pump(source: asyncio.StreamReader, destination: asyncio.StreamWriter, record: bool) -> None:
            try:
                while True:
                    data = await source.read(65536)
                    if not data:
                        break
                    if record:
                        captured.extend(data)
                    destination.write(data)
                    await destination.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                destination.close()

        await asyncio.gather(
            pump(reader, remote_writer, True),
            pump(remote_reader, writer, True),
        )

    return await asyncio.start_server(handle, "127.0.0.1", 0)


async def _connect(nodes: _Pair):
    from app.security.tls import client_context

    record = nodes.sender.trust.get(nodes.receiver.identity.device_id)
    assert record is not None
    context = client_context(nodes.sender.identity, record.certificate_pem.encode("utf-8"))
    return await asyncio.open_connection("127.0.0.1", nodes.receiver_port, ssl=context)


def _request(nodes: _Pair, filename: str, size: int, digest: str) -> dict:
    return {
        "session_id": getattr(nodes, "session_id", ""),
        "sequence": 1,
        "transfer_id": str(uuid.uuid4()),
        "filename": filename,
        "size": size,
        "sha256": digest,
        "protocol_version": PROTOCOL_VERSION,
    }


async def _exchange(nodes: _Pair, kind: int, header: dict, body: bytes = b"", hello: bool = False) -> str:
    reader, writer = await _connect(nodes)
    try:
        session_id = str(uuid.uuid4())
        nodes.session_id = session_id
        await _write_frame(
            writer,
            HELLO,
            {"session_id": session_id, "protocol_version": PROTOCOL_VERSION, "sequence": 0},
            nodes.limits,
        )
        await _read_frame(reader, nodes.limits)
        if hello and kind == TRANSFER_REQUEST:
            header = dict(header)
            header["session_id"] = session_id
        if kind != HELLO:
            await _write_frame(writer, kind, header if kind != HELLO else header, nodes.limits, body)
            message = await _read_frame(reader, nodes.limits)
            return str(message[1].get("code", ""))
        return "OK"
    finally:
        writer.close()
        await writer.wait_closed()


async def _raw_transfer(nodes: _Pair, filename: str, payload: bytes, digest: str, size: int) -> None:
    reader, writer = await _connect(nodes)
    try:
        session_id = str(uuid.uuid4())
        await _write_frame(writer, HELLO, {"session_id": session_id, "protocol_version": PROTOCOL_VERSION, "sequence": 0}, nodes.limits)
        await _read_frame(reader, nodes.limits)
        await _write_frame(
            writer,
            TRANSFER_REQUEST,
            {
                "session_id": session_id,
                "sequence": 1,
                "transfer_id": str(uuid.uuid4()),
                "filename": filename,
                "size": size,
                "sha256": digest,
                "protocol_version": PROTOCOL_VERSION,
            },
            nodes.limits,
        )
        accepted = await _read_frame(reader, nodes.limits)
        if accepted[0] != 4:
            return
        await _write_frame(writer, CHUNK, {"session_id": session_id, "sequence": 2, "offset": 0}, nodes.limits, payload)
        await _write_frame(writer, COMPLETE, {"session_id": session_id, "sequence": 3, "sha256": digest}, nodes.limits)
        await _read_frame(reader, nodes.limits)
    finally:
        writer.close()
        await writer.wait_closed()
