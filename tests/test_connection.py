from __future__ import annotations

import asyncio
import struct
import unittest
import uuid

from app.network.connection import ConnectionFailed, ConnectionManager, ConnectionState
from app.network.protocol import (
    MAX_CONTROL_MESSAGE_SIZE,
    ProtocolError,
    Timeouts,
    decode_message,
    encode_message,
    hello_payload,
    read_size,
    validate_hello,
)


def _run(coro):
    return asyncio.run(coro)


class FramingTests(unittest.TestCase):
    def test_one_message_roundtrip(self) -> None:
        payload = hello_payload(str(uuid.uuid4()), "LAPTOP")
        decoded = decode_message(encode_message(payload)[4:])
        self.assertEqual(decoded, payload)

    def test_concatenated_messages_are_separated(self) -> None:
        async def scenario() -> None:
            first = hello_payload(str(uuid.uuid4()), "PC-A")
            second = hello_payload(str(uuid.uuid4()), "PC-B")
            received = await _collect_frames(encode_message(first) + encode_message(second), 2)
            self.assertEqual(received, [first, second])

        _run(scenario())

    def test_split_message_is_reassembled(self) -> None:
        async def scenario() -> None:
            payload = hello_payload(str(uuid.uuid4()), "PC-A")
            frame = encode_message(payload)

            async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                writer.write(frame[:3])
                await writer.drain()
                await asyncio.sleep(0.05)
                writer.write(frame[3:])
                await writer.drain()
                await asyncio.sleep(0.05)
                writer.close()

            server = await asyncio.start_server(handle, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                message = await _read_one(reader, MAX_CONTROL_MESSAGE_SIZE, 2)
                self.assertEqual(message["device_name"], "PC-A")
            finally:
                writer.close()
                await writer.wait_closed()
                server.close()
                await server.wait_closed()

        _run(scenario())

    def test_oversized_message_is_rejected(self) -> None:
        with self.assertRaises(ProtocolError) as caught:
            read_size(struct.pack(">I", MAX_CONTROL_MESSAGE_SIZE + 1))
        self.assertEqual(caught.exception.code, "INVALID_MESSAGE_SIZE")


class HandshakeValidationTests(unittest.TestCase):
    def test_valid_hello(self) -> None:
        device_id = str(uuid.uuid4())
        parsed_id, name = validate_hello(hello_payload(device_id, "DESKTOP-BOGDAN"))
        self.assertEqual(parsed_id, device_id)
        self.assertEqual(name, "DESKTOP-BOGDAN")

    def test_invalid_hello(self) -> None:
        with self.assertRaises(ProtocolError) as version:
            validate_hello({"type": "HELLO", "protocol_version": 99, "device_id": str(uuid.uuid4()), "device_name": "PC"})
        self.assertEqual(version.exception.code, "INVALID_PROTOCOL_VERSION")
        with self.assertRaises(ProtocolError) as device:
            validate_hello({"type": "HELLO", "protocol_version": 1, "device_id": "nope", "device_name": "PC"})
        self.assertEqual(device.exception.code, "INVALID_DEVICE_ID")
        with self.assertRaises(ProtocolError):
            decode_message(b"{")


class TcpConnectionTests(unittest.TestCase):
    def test_server_accepts_and_stops(self) -> None:
        async def scenario() -> None:
            manager = _manager()
            port = await manager.start_server(host="127.0.0.1", port=0)
            self.assertGreater(port, 0)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            await manager.stop()
            with self.assertRaises(OSError):
                await asyncio.open_connection("127.0.0.1", port)

        _run(scenario())

    def test_client_reaches_ready(self) -> None:
        async def scenario() -> None:
            server = _manager("SERVER")
            client = _manager("CLIENT")
            port = await server.start_server(host="127.0.0.1", port=0)
            try:
                connection = await client.connect("127.0.0.1", port)
                await _wait_ready(server)
                self.assertEqual(connection.state, ConnectionState.READY)
                self.assertEqual(connection.device_name, "SERVER")
                self.assertEqual(server.connections()[0].device_name, "CLIENT")
            finally:
                await client.stop()
                await server.stop()

        _run(scenario())

    def test_connection_refused(self) -> None:
        async def scenario() -> None:
            client = _manager()
            with self.assertRaises(ConnectionFailed):
                await client.connect("127.0.0.1", 1)
            self.assertEqual(client.connections(), [])

        _run(scenario())

    def test_handshake_timeout(self) -> None:
        async def scenario() -> None:
            async def hang(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                try:
                    await asyncio.sleep(5)
                finally:
                    writer.close()
                    await writer.wait_closed()

            listener = await asyncio.start_server(hang, "127.0.0.1", 0)
            port = listener.sockets[0].getsockname()[1]
            client = ConnectionManager(
                str(uuid.uuid4()),
                "CLIENT",
                timeouts=Timeouts(connect=1, handshake=0.2, read=0.2, write=0.2, idle=0.2),
            )
            try:
                with self.assertRaises(ConnectionFailed):
                    await client.connect("127.0.0.1", port)
            finally:
                listener.close()
                await listener.wait_closed()

        _run(scenario())

    def test_invalid_hello_does_not_crash(self) -> None:
        async def scenario() -> None:
            server = _manager()
            port = await server.start_server(host="127.0.0.1", port=0)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                writer.write(encode_message({"type": "HELLO", "protocol_version": 1, "device_id": "bad", "device_name": "PC"}))
                await writer.drain()
                await asyncio.sleep(0.1)
                self.assertEqual(server.connections(), [])
            finally:
                writer.close()
                await writer.wait_closed()
                await server.stop()

        _run(scenario())

    def test_peer_disconnect_does_not_crash(self) -> None:
        async def scenario() -> None:
            server = _manager()
            client = _manager("CLIENT")
            port = await server.start_server(host="127.0.0.1", port=0)
            connection = await client.connect("127.0.0.1", port)
            await _wait_ready(server)
            await connection.close()
            await asyncio.sleep(0.1)
            await server.stop()
            await client.stop()

        _run(scenario())

    def test_multiple_clients(self) -> None:
        async def scenario() -> None:
            server = _manager("SERVER")
            port = await server.start_server(host="127.0.0.1", port=0)
            clients = [_manager(f"PC-{index}") for index in range(3)]
            try:
                opened = []
                for client in clients:
                    opened.append(await client.connect("127.0.0.1", port))
                await _wait_ready(server, 3)
                self.assertEqual(len(server.connections()), 3)
                self.assertTrue(all(item.state == ConnectionState.READY for item in opened))
            finally:
                for client in clients:
                    await client.stop()
                await server.stop()

        _run(scenario())


def _manager(name: str = "PC") -> ConnectionManager:
    return ConnectionManager(
        str(uuid.uuid4()),
        name,
        timeouts=Timeouts(connect=1, handshake=1, read=1, write=1, idle=2),
    )


async def _wait_ready(manager: ConnectionManager, count: int = 1) -> None:
    for _ in range(20):
        ready = [item for item in manager.connections() if item.state == ConnectionState.READY]
        if len(ready) >= count:
            return
        await asyncio.sleep(0.05)
    raise AssertionError("connection was not ready")


async def _collect_frames(blob: bytes, count: int) -> list[dict]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            writer.write(blob)
            await writer.drain()
            await reader.read(1)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        messages = []
        for _ in range(count):
            messages.append(await _read_one(reader, MAX_CONTROL_MESSAGE_SIZE, 2))
        return messages
    finally:
        writer.close()
        await writer.wait_closed()
        server.close()
        await server.wait_closed()


async def _read_one(reader: asyncio.StreamReader, limit: int, timeout: float) -> dict:
    header = await asyncio.wait_for(reader.readexactly(4), timeout)
    size = read_size(header, limit)
    body = await asyncio.wait_for(reader.readexactly(size), timeout)
    return decode_message(body)
