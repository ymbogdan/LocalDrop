from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from enum import Enum

from app.network.constants import TCP_PORT
from app.network.protocol import (
    MAX_CONTROL_MESSAGE_SIZE,
    ProtocolError,
    Timeouts,
    decode_message,
    encode_message,
    error_payload,
    hello_payload,
    peer_error_code,
    read_size,
    validate_hello,
)

log = logging.getLogger("localdrop")

StateListener = Callable[["PeerConnection", "ConnectionState"], None]


class ConnectionState(Enum):
    DISCOVERED = "DISCOVERED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    HELLO_SENT = "HELLO_SENT"
    HELLO_RECEIVED = "HELLO_RECEIVED"
    READY = "READY"
    DISCONNECTING = "DISCONNECTING"
    DISCONNECTED = "DISCONNECTED"
    FAILED = "FAILED"


class ConnectionFailed(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class PeerConnection:
    def __init__(self, address: str) -> None:
        self.address = address
        self.device_id = ""
        self.device_name = ""
        self.state = ConnectionState.DISCOVERED
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self._listeners: list[StateListener] = []

    @property
    def key(self) -> str:
        writer = self.writer
        if writer is None:
            return self.address
        peer = writer.get_extra_info("peername")
        if not peer:
            return self.address
        return f"{peer[0]}:{peer[1]}"

    def add_listener(self, listener: StateListener) -> None:
        self._listeners.append(listener)

    def set_state(self, state: ConnectionState) -> None:
        self.state = state
        for listener in list(self._listeners):
            try:
                listener(self, state)
            except Exception:
                log.exception("Connection listener failed")

    async def close(self) -> None:
        if self.state not in {ConnectionState.DISCONNECTED, ConnectionState.FAILED}:
            self.set_state(ConnectionState.DISCONNECTING)
        writer = self.writer
        self.writer = None
        self.reader = None
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
        if self.state == ConnectionState.DISCONNECTING:
            self.set_state(ConnectionState.DISCONNECTED)


class ConnectionManager:
    def __init__(
        self,
        device_id: str,
        device_name: str,
        *,
        timeouts: Timeouts | None = None,
        max_message_size: int = MAX_CONTROL_MESSAGE_SIZE,
    ) -> None:
        self.device_id = device_id
        self.device_name = device_name
        self.timeouts = timeouts or Timeouts()
        self.max_message_size = max_message_size
        self._server: asyncio.Server | None = None
        self._connections: dict[str, PeerConnection] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._listeners: list[StateListener] = []
        self.port = 0

    def add_listener(self, listener: StateListener) -> None:
        self._listeners.append(listener)

    def connections(self) -> list[PeerConnection]:
        return list(self._connections.values())

    async def start_server(self, host: str = "0.0.0.0", port: int = TCP_PORT) -> int:
        try:
            self._server = await asyncio.start_server(self._accept, host, port)
        except OSError:
            if port == 0:
                raise
            self._server = await asyncio.start_server(self._accept, host, 0)
        bound = self._server.sockets[0].getsockname()
        self.port = int(bound[1])
        log.info("TCP server started on port %s", self.port)
        return self.port

    async def stop(self) -> None:
        connections = list(self._connections.values())
        for connection in connections:
            await connection.close()
        self._connections.clear()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def connect(self, host: str, port: int) -> PeerConnection:
        connection = PeerConnection(host)
        self._bind_listener(connection)
        connection.set_state(ConnectionState.CONNECTING)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                self.timeouts.connect,
            )
        except ConnectionRefusedError as exc:
            connection.set_state(ConnectionState.FAILED)
            raise ConnectionFailed("Connection refused") from exc
        except (TimeoutError, OSError) as exc:
            connection.set_state(ConnectionState.FAILED)
            raise ConnectionFailed("Server unavailable") from exc
        connection.reader = reader
        connection.writer = writer
        connection.address = host
        log.info("TCP connection established")
        try:
            await self._handshake(connection)
        except (ProtocolError, asyncio.IncompleteReadError, ConnectionError, TimeoutError, OSError) as exc:
            await self._fail(connection, exc)
            raise ConnectionFailed(str(exc)) from exc
        self._connections[connection.key] = connection
        self._tasks.add(asyncio.create_task(self._watch(connection)))
        return connection

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        address = str(peer[0]) if peer else ""
        log.info("Connection from %s", address)
        connection = PeerConnection(address)
        connection.reader = reader
        connection.writer = writer
        self._bind_listener(connection)
        connection.set_state(ConnectionState.CONNECTED)
        log.info("TCP connection established")
        try:
            await self._handshake(connection)
            self._connections[connection.key] = connection
            await self._watch(connection)
        except asyncio.CancelledError:
            await connection.close()
            raise
        except Exception as exc:
            await self._fail(connection, exc)

    async def _handshake(self, connection: PeerConnection) -> None:
        connection.set_state(ConnectionState.CONNECTED)
        await self._write(connection, hello_payload(self.device_id, self.device_name), self.timeouts.handshake)
        connection.set_state(ConnectionState.HELLO_SENT)
        payload = await self._read(connection, self.timeouts.handshake)
        connection.set_state(ConnectionState.HELLO_RECEIVED)
        if payload.get("type") == "ERROR":
            raise ProtocolError(peer_error_code(payload), "Peer rejected handshake")
        device_id, device_name = validate_hello(payload)
        connection.device_id = device_id
        connection.device_name = device_name
        log.info("Received HELLO from %s", device_name)
        log.info("HELLO exchanged")
        connection.set_state(ConnectionState.READY)
        log.info("Connection READY")

    async def _watch(self, connection: PeerConnection) -> None:
        try:
            while connection.state == ConnectionState.READY:
                await self._read(connection, self.timeouts.idle)
        except asyncio.CancelledError:
            raise
        except (asyncio.IncompleteReadError, ConnectionError, TimeoutError, OSError, ProtocolError):
            log.info("Peer disconnected")
        finally:
            self._connections.pop(connection.key, None)
            if connection.state == ConnectionState.READY:
                await connection.close()

    async def _read(self, connection: PeerConnection, timeout: float) -> dict:
        reader = connection.reader
        if reader is None:
            raise ConnectionError("Connection is closed")
        try:
            header = await asyncio.wait_for(reader.readexactly(4), timeout)
            size = read_size(header, self.max_message_size)
            body = await asyncio.wait_for(reader.readexactly(size), timeout)
        except ProtocolError:
            await self._write_error(connection, "INVALID_MESSAGE_SIZE")
            raise
        return decode_message(body)

    async def _write(self, connection: PeerConnection, payload: dict, timeout: float) -> None:
        writer = connection.writer
        if writer is None:
            raise ConnectionError("Connection is closed")
        writer.write(encode_message(payload, self.max_message_size))
        await asyncio.wait_for(writer.drain(), timeout)

    async def _write_error(self, connection: PeerConnection, code: str) -> None:
        try:
            await self._write(connection, error_payload(code), self.timeouts.write)
        except (ConnectionError, TimeoutError, OSError, ProtocolError):
            pass

    async def _fail(self, connection: PeerConnection, exc: Exception) -> None:
        if isinstance(exc, ProtocolError):
            log.warning("Connection failed: %s", exc.code)
            if exc.code != "INVALID_MESSAGE_SIZE":
                await self._write_error(connection, exc.code)
        elif isinstance(exc, (asyncio.IncompleteReadError, ConnectionError, TimeoutError, OSError)):
            log.warning("Connection failed: %s", exc.__class__.__name__)
        else:
            log.exception("Connection failed")
        self._connections.pop(connection.key, None)
        connection.set_state(ConnectionState.FAILED)
        await connection.close()

    def _bind_listener(self, connection: PeerConnection) -> None:
        for listener in self._listeners:
            connection.add_listener(listener)
