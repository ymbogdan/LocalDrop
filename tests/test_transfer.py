from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from app.network.secure_channel import SecureNode
from app.security.crypto_identity import load_or_create_crypto
from app.security.limits import Limits
from app.transfer.service import TransferService


def _run(coro):
    return asyncio.run(coro)


class FileTransferTests(unittest.TestCase):
    def test_small_binary_unicode_and_spaced_names(self) -> None:
        async def scenario() -> None:
            async with _Link() as link:
                names = ["photo.jpg", "my file.pdf", "archivio.tar.gz", "immagine è.png", "empty.bin", "binary.bin"]
                payloads = [b"small", b"with space", b"tar", "ciao".encode(), b"", b"\x00\x01\xff"]
                for name, payload in zip(names, payloads, strict=True):
                    source = link.root / name
                    source.write_bytes(payload)
                    status = await link.sender_service.send_file(link.session, source)
                    self.assertEqual(status, "COMPLETED", name)
                    saved = link.download / name
                    self.assertEqual(saved.read_bytes(), payload)

        _run(scenario())

    def test_large_file_streams_in_chunks(self) -> None:
        async def scenario() -> None:
            async with _Link() as link:
                source = link.root / "video.mp4"
                source.write_bytes(os.urandom(100_000))
                status = await link.sender_service.send_file(link.session, source)
                self.assertEqual(status, "COMPLETED")
                self.assertEqual((link.download / "video.mp4").read_bytes(), source.read_bytes())

        _run(scenario())

    def test_duplicate_names_keep_extension(self) -> None:
        async def scenario() -> None:
            async with _Link() as link:
                source = link.root / "archive.tar.gz"
                source.write_bytes(b"one")
                await link.sender_service.send_file(link.session, source)
                source.write_bytes(b"two")
                await link.sender_service.send_file(link.session, source)
                self.assertEqual((link.download / "archive.tar.gz").read_bytes(), b"one")
                self.assertEqual((link.download / "archive.tar (1).gz").read_bytes(), b"two")

        _run(scenario())

    def test_bad_hash_deletes_partial(self) -> None:
        async def scenario() -> None:
            async with _Link() as link:
                source = link.root / "broken.bin"
                source.write_bytes(b"original")
                real_hash = __import__("app.security.integrity", fromlist=["hash_file"]).hash_file
                with patch("app.transfer.service.hash_file", side_effect=[ "ab" * 32, real_hash(source), "ab" * 32 ]):
                    status = await link.sender_service.send_file(link.session, source)
                self.assertEqual(status, "FAILED")
                self.assertEqual(list(link.download.iterdir()), [])

        _run(scenario())

    def test_cancel_and_disconnect_remove_partial(self) -> None:
        async def scenario() -> None:
            async with _Link() as link:
                source = link.root / "video.mp4"
                source.write_bytes(b"x" * 80_000)
                link.sender_service.on_progress = lambda transfer_id, *_args: link.sender_service.cancel(transfer_id)
                status = await link.sender_service.send_file(link.session, source)
                self.assertIn(status, {"CANCELLED", "FAILED"})
                self.assertEqual(list(link.download.glob("*.localdrop-partial")), [])

        _run(scenario())

    def test_insufficient_space_is_rejected(self) -> None:
        async def scenario() -> None:
            async with _Link() as link:
                source = link.root / "big.bin"
                source.write_bytes(b"12345")
                usage = __import__("shutil").disk_usage(link.download)
                fake = type(usage)(usage.total, usage.used, 1)
                with patch("app.transfer.service.shutil.disk_usage", return_value=fake):
                    status = await link.sender_service.send_file(link.session, source)
                self.assertEqual(status, "REJECTED")
                self.assertEqual(list(link.download.iterdir()), [])

        _run(scenario())

    def test_directory_is_rejected(self) -> None:
        async def scenario() -> None:
            async with _Link() as link:
                folder = link.root / "nested"
                folder.mkdir()
                result = await link.sender_service.send_files(link.session, [folder])
                self.assertEqual(result, ["REJECTED"])

        _run(scenario())

    def test_two_files_are_independent(self) -> None:
        async def scenario() -> None:
            async with _Link(concurrent=2) as link:
                first = link.root / "photo.jpg"
                second = link.root / "document.pdf"
                first.write_bytes(b"a" * 1000)
                second.write_bytes(b"b" * 1000)
                results = await link.sender_service.send_files(link.session, [first, second])
                self.assertEqual(results, ["COMPLETED", "COMPLETED"])
                self.assertTrue((link.download / "photo.jpg").is_file())
                self.assertTrue((link.download / "document.pdf").is_file())

        _run(scenario())


class _Link:
    def __init__(self, concurrent: int = 2) -> None:
        self.concurrent = concurrent

    async def __aenter__(self) -> "_Link":
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.download = self.root / "downloads"
        self.download.mkdir()
        limits = Limits(max_file_bytes=1024 * 1024, max_concurrent_transfers=self.concurrent, timeout_seconds=3)
        server_crypto = load_or_create_crypto(self.root / "server", str(uuid.uuid4()))
        client_crypto = load_or_create_crypto(self.root / "client", str(uuid.uuid4()))
        self.server = SecureNode(server_crypto, "LAPTOP", self.root / "server-trust.json", confirm_pairing=_yes)
        self.client = SecureNode(client_crypto, "DESKTOP-BOGDAN", self.root / "client-trust.json", confirm_pairing=_yes)
        self.receiver_service = TransferService(self.download, limits=limits, accept_transfer=lambda *_args: True)
        self.sender_service = TransferService(self.root / "out", limits=limits, accept_transfer=lambda *_args: True)
        self.server.on_incoming = self.receiver_service.receive
        port = await self.server.start(host="127.0.0.1", port=0)
        self.session = await self.client.connect("127.0.0.1", port)
        return self

    async def __aexit__(self, *_args) -> None:
        await self.client.stop()
        await self.server.stop()
        self._tmp.cleanup()


def _yes(*_args) -> bool:
    return True
