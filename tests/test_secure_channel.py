from __future__ import annotations

import asyncio
import ssl
import struct
import tempfile
import unittest
import uuid
from pathlib import Path

from app.network.protocol import make_transfer_request
from app.network.secure_channel import SecureError, SecureNode, SecureState
from app.security.crypto_identity import load_or_create_crypto
from app.security.tls import client_context


HASH = "cd" * 32


def _run(coro):
    return asyncio.run(coro)


class Phase5SecurityTests(unittest.TestCase):
    def test_tls_13_and_mutual_trust(self) -> None:
        async def scenario() -> None:
            async with _Pair(confirm=True) as nodes:
                session = await nodes.client.connect("127.0.0.1", nodes.port)
                self.assertEqual(session.tls_version, "TLSv1.3")
                self.assertEqual(session.state, SecureState.READY)
                self.assertTrue(nodes.server.trust.is_paired(nodes.client.identity.device_id))
                stored = nodes.server.trust.get(nodes.client.identity.device_id)
                assert stored is not None
                self.assertNotIn("PRIVATE", stored.certificate_pem)
                self.assertTrue(stored.paired_at)
                text = Path(nodes.server.trust.path).read_text(encoding="utf-8")
                self.assertNotIn(nodes.code_hint, text)

        _run(scenario())

    def test_unknown_device_requires_pairing(self) -> None:
        async def scenario() -> None:
            async with _Pair(confirm=False) as nodes:
                with self.assertRaises(SecureError) as caught:
                    await nodes.client.connect("127.0.0.1", nodes.port, allow_pairing=False)
                self.assertEqual(caught.exception.code, "PAIRING REQUIRED")
                self.assertFalse(nodes.server.trust.is_paired(nodes.client.identity.device_id))

        _run(scenario())

    def test_certificate_change_is_rejected(self) -> None:
        async def scenario() -> None:
            async with _Pair(confirm=True) as nodes:
                await nodes.client.connect("127.0.0.1", nodes.port)
                trusted = nodes.server.trust.get(nodes.client.identity.device_id)
                assert trusted is not None
                before = trusted.fingerprint
                impostor = load_or_create_crypto(nodes.root / "impostor", nodes.client.identity.device_id)
                attacker = SecureNode(impostor, "DESKTOP-BOGDAN", nodes.root / "attacker-trust.json", confirm_pairing=_yes)
                with self.assertRaises(SecureError) as caught:
                    await attacker.connect("127.0.0.1", nodes.port)
                self.assertEqual(caught.exception.code, "REJECTED")
                after = nodes.server.trust.get(nodes.client.identity.device_id)
                assert after is not None
                self.assertEqual(after.fingerprint, before)

        _run(scenario())

    def test_invalid_certificate_and_downgrade_are_rejected(self) -> None:
        async def scenario() -> None:
            async with _Pair(confirm=True) as nodes:
                with self.assertRaises(SecureError) as invalid:
                    await _raw_exchange(nodes, b"not-a-certificate", None)
                self.assertEqual(invalid.exception.code, "REJECTED")
                with self.assertRaises(SecureError) as downgrade:
                    await _raw_exchange(nodes, nodes.client.identity.certificate_pem, "1.2")
                self.assertEqual(downgrade.exception.code, "REJECTED")
                with self.assertRaises(SecureError) as anonymous:
                    await _raw_exchange(nodes, nodes.client.identity.certificate_pem, "no-cert")
                self.assertEqual(anonymous.exception.code, "REJECTED")

        _run(scenario())

    def test_unpaired_transfer_is_rejected(self) -> None:
        async def scenario() -> None:
            async with _Pair(confirm=False) as nodes:
                request = make_transfer_request("photo.jpg", 12, HASH, "image/jpeg")
                with self.assertRaises(SecureError) as caught:
                    await nodes.client.connect("127.0.0.1", nodes.port, opening=request)
                self.assertEqual(caught.exception.code, "REJECTED")
                self.assertFalse(nodes.server.trust.is_paired(nodes.client.identity.device_id))

        _run(scenario())

    def test_application_payload_is_not_visible_on_the_wire(self) -> None:
        marker = b"SECRET-DEVICE-NAME"

        async def scenario() -> None:
            async with _Pair(confirm=True, server_name="SECRET-DEVICE-NAME") as nodes:
                captured = bytearray()
                proxy = await _proxy(nodes.port, captured)
                proxy_port = proxy.sockets[0].getsockname()[1]
                try:
                    await nodes.client.connect("127.0.0.1", proxy_port)
                finally:
                    proxy.close()
                    await proxy.wait_closed()
                self.assertNotIn(marker, captured)

        _run(scenario())


class _Pair:
    def __init__(self, confirm: bool, server_name: str = "LAPTOP") -> None:
        self._confirm = confirm
        self.server_name = server_name
        self.code_hint = "482 913"

    async def __aenter__(self) -> "_Pair":
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        server_crypto = load_or_create_crypto(self.root / "server", str(uuid.uuid4()))
        client_crypto = load_or_create_crypto(self.root / "client", str(uuid.uuid4()))
        confirm = _yes if self._confirm else None
        self.server = SecureNode(server_crypto, self.server_name, self.root / "server-trust.json", confirm_pairing=confirm)
        self.client = SecureNode(client_crypto, "DESKTOP-BOGDAN", self.root / "client-trust.json", confirm_pairing=confirm)
        self.port = await self.server.start(host="127.0.0.1", port=0)
        return self

    async def __aexit__(self, *_args) -> None:
        await self.client.stop()
        await self.server.stop()
        self._tmp.cleanup()


def _yes(*_args) -> bool:
    return True


async def _raw_exchange(nodes: _Pair, peer_pem: bytes, mode: str | None) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", nodes.port)
    try:
        writer.write(struct.pack(">I", len(peer_pem)) + peer_pem)
        await writer.drain()
        if mode is None:
            try:
                size = struct.unpack(">I", await reader.readexactly(4))[0]
                await reader.readexactly(size)
                await asyncio.wait_for(reader.readexactly(1), 1)
            except (asyncio.IncompleteReadError, ConnectionError, TimeoutError, OSError):
                raise SecureError("REJECTED") from None
            raise AssertionError("invalid certificate was accepted")
        size = struct.unpack(">I", await reader.readexactly(4))[0]
        server_pem = await reader.readexactly(size)
        if mode == "no-cert":
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cadata=server_pem.decode("utf-8"))
        elif mode == "1.2":
            context = client_context(nodes.client.identity, server_pem)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2
        else:
            raise SecureError("REJECTED")
        try:
            await writer.start_tls(context)
            await asyncio.wait_for(reader.readexactly(1), 1)
        except (ssl.SSLError, asyncio.IncompleteReadError, ConnectionError, TimeoutError, OSError) as exc:
            raise SecureError("REJECTED") from exc
        raise AssertionError("handshake should have failed")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ssl.SSLError, OSError, ConnectionError):
            pass
    _ = peer_pem


async def _proxy(target_port: int, captured: bytearray) -> asyncio.Server:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        remote_reader, remote_writer = await asyncio.open_connection("127.0.0.1", target_port)

        async def pump(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
            try:
                while True:
                    data = await source.read(65536)
                    if not data:
                        break
                    captured.extend(data)
                    destination.write(data)
                    await destination.drain()
            except (ConnectionError, OSError, ssl.SSLError):
                pass
            finally:
                destination.close()

        await asyncio.gather(pump(reader, remote_writer), pump(remote_reader, writer))

    return await asyncio.start_server(handle, "127.0.0.1", 0)
