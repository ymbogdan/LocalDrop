from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
import struct
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from app.device.identity import normalize_device_name
from app.network.adapters import _allowed_indexes
from app.network.constants import DISCOVERY_PORT, PROTOCOL_VERSION

log = logging.getLogger("localdrop")

DISCOVERY_TYPE = "DISCOVERY"
MAX_PACKET_BYTES = 1024
DEFAULT_INTERVAL_SECONDS = 2.0
DEFAULT_TIMEOUT_SECONDS = 7.0

EventKind = Literal["appeared", "updated", "disappeared"]
Listener = Callable[[EventKind, "Peer"], None]


@dataclass(frozen=True)
class Peer:
    device_id: str
    device_name: str
    address: str
    port: int


@dataclass(frozen=True)
class Announcement:
    device_id: str
    device_name: str
    port: int
    protocol_version: int


@dataclass
class _PeerRecord:
    device_id: str
    device_name: str
    address: str
    port: int
    last_seen: float

    def snapshot(self) -> Peer:
        return Peer(self.device_id, self.device_name, self.address, self.port)


class _DiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self, service: DiscoveryService) -> None:
        self._service = service

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._service.handle_datagram(data, addr[0])

    def error_received(self, exc: Exception) -> None:
        log.warning("Discovery socket error: %s", exc)


class DiscoveryService:
    def __init__(
        self,
        device_id: str,
        device_name: str,
        tcp_port: int,
        *,
        discovery_port: int = DISCOVERY_PORT,
        interval: float = DEFAULT_INTERVAL_SECONDS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        announce_targets: list[tuple[str, int]] | None = None,
        bind_host: str = "0.0.0.0",
    ) -> None:
        self.device_id = device_id
        self.device_name = device_name
        self.tcp_port = tcp_port
        self._discovery_port = discovery_port
        self._interval = interval
        self._timeout = timeout
        self._announce_targets = announce_targets
        self._dynamic_targets = announce_targets is None
        self._bind_host = bind_host
        self._bound_port = discovery_port
        self._transport: asyncio.DatagramTransport | None = None
        self._tasks: list[asyncio.Task[None]] = []
        self._peers: dict[str, _PeerRecord] = {}
        self._listeners: list[Listener] = []
        self._lock = threading.Lock()

    @property
    def port(self) -> int:
        return self._bound_port

    def set_announce_targets(self, targets: list[tuple[str, int]]) -> None:
        self._dynamic_targets = False
        self._announce_targets = list(targets)

    def update_device_name(self, name: str) -> None:
        self.device_name = normalize_device_name(name)

    def add_listener(self, listener: Listener) -> None:
        self._listeners.append(listener)

    def peers(self) -> list[Peer]:
        with self._lock:
            return [record.snapshot() for record in self._peers.values()]

    async def start(self) -> None:
        if self._transport is not None:
            return
        loop = asyncio.get_running_loop()
        self._transport, _protocol = await loop.create_datagram_endpoint(
            lambda: _DiscoveryProtocol(self),
            local_addr=(self._bind_host, self._discovery_port),
            allow_broadcast=True,
        )
        sockname = self._transport.get_extra_info("sockname")
        self._bound_port = int(sockname[1])
        self._tasks = [
            asyncio.create_task(self._announce_loop(), name="discovery-announce"),
            asyncio.create_task(self._expire_loop(), name="discovery-expire"),
        ]
        log.info("Discovery started")

    async def stop(self) -> None:
        tasks = list(self._tasks)
        self._tasks.clear()
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        log.info("Discovery stopped")

    async def announce_now(self) -> None:
        self._send_announcement()

    def handle_datagram(self, data: bytes, source_ip: str) -> None:
        announcement = decode_announcement(data)
        if announcement is None:
            return
        if announcement.protocol_version != PROTOCOL_VERSION:
            log.debug("Ignoring incompatible discovery packet from %s", source_ip)
            return
        if announcement.device_id == self.device_id:
            return
        now = time.monotonic()
        event: tuple[EventKind, Peer] | None = None
        with self._lock:
            current = self._peers.get(announcement.device_id)
            if current is None:
                record = _PeerRecord(
                    device_id=announcement.device_id,
                    device_name=announcement.device_name,
                    address=source_ip,
                    port=announcement.port,
                    last_seen=now,
                )
                self._peers[announcement.device_id] = record
                event = ("appeared", record.snapshot())
            else:
                changed = (
                    current.device_name != announcement.device_name
                    or current.address != source_ip
                    or current.port != announcement.port
                )
                current.device_name = announcement.device_name
                current.address = source_ip
                current.port = announcement.port
                current.last_seen = now
                if changed:
                    event = ("updated", current.snapshot())
        if event is None:
            return
        kind, peer = event
        if kind == "appeared":
            log.info("Device discovered: %s", peer.device_name)
        elif kind == "updated":
            log.info("Device updated: %s", peer.device_name)
        self._emit(kind, peer)

    async def _announce_loop(self) -> None:
        while True:
            self._send_announcement()
            await asyncio.sleep(self._interval)

    async def _expire_loop(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            self._expire_peers()

    def _expire_peers(self) -> None:
        now = time.monotonic()
        lost: list[Peer] = []
        with self._lock:
            for device_id, record in list(self._peers.items()):
                if now - record.last_seen <= self._timeout:
                    continue
                lost.append(record.snapshot())
                del self._peers[device_id]
        for peer in lost:
            log.info("Device lost: %s", peer.device_name)
            self._emit("disappeared", peer)

    def _send_announcement(self) -> None:
        transport = self._transport
        if self._dynamic_targets:
            targets = default_announce_targets(self._discovery_port or self._bound_port)
        else:
            targets = self._announce_targets or []
        if transport is None or not targets:
            return
        packet = encode_announcement(
            device_id=self.device_id,
            device_name=self.device_name,
            tcp_port=self.tcp_port,
        )
        for host, port in targets:
            try:
                transport.sendto(packet, (host, port))
            except OSError as exc:
                log.warning("Discovery announce failed for %s:%s: %s", host, port, exc)

    def _emit(self, kind: EventKind, peer: Peer) -> None:
        for listener in list(self._listeners):
            try:
                listener(kind, peer)
            except Exception:
                log.exception("Discovery listener failed")


def encode_announcement(device_id: str, device_name: str, tcp_port: int) -> bytes:
    payload = {
        "type": DISCOVERY_TYPE,
        "device_id": device_id,
        "device_name": device_name,
        "port": tcp_port,
        "protocol_version": PROTOCOL_VERSION,
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode_announcement(data: bytes) -> Announcement | None:
    if len(data) > MAX_PACKET_BYTES:
        log.debug("Ignoring oversized discovery packet")
        return None
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        log.debug("Ignoring malformed discovery packet")
        return None
    if not isinstance(raw, dict) or raw.get("type") != DISCOVERY_TYPE:
        return None
    device_id = raw.get("device_id")
    device_name = raw.get("device_name")
    port = raw.get("port")
    version = raw.get("protocol_version")
    if not isinstance(device_id, str):
        return None
    try:
        parsed_id = str(uuid.UUID(device_id))
    except ValueError:
        return None
    if not isinstance(device_name, str):
        return None
    try:
        parsed_name = normalize_device_name(device_name)
    except ValueError:
        return None
    if not _valid_port(port) or not _valid_version(version):
        return None
    return Announcement(
        device_id=parsed_id,
        device_name=parsed_name,
        port=port,
        protocol_version=version,
    )


def default_announce_targets(port: int) -> list[tuple[str, int]]:
    targets = {("255.255.255.255", port)}
    for interface in local_ipv4_networks():
        if interface.ip.is_loopback or interface.ip.is_link_local:
            continue
        network = interface.network
        if network.prefixlen >= 31:
            continue
        targets.add((str(network.broadcast_address), port))
        hosts = [host for host in network.hosts() if host != interface.ip]
        if len(hosts) <= 30:
            for host in hosts:
                targets.add((str(host), port))
    return sorted(targets)


def local_ipv6_link_networks() -> list[ipaddress.IPv6Network]:
    found: list[ipaddress.IPv6Network] = []
    seen: set[str] = set()
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)
    except OSError:
        infos = []
    for info in infos:
        raw = str(info[4][0]).split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if not isinstance(ip, ipaddress.IPv6Address) or not ip.is_link_local:
            continue
        network = ipaddress.IPv6Network(f"{ip}/64", strict=False)
        if str(network) in seen:
            continue
        seen.add(str(network))
        found.append(network)
    return found


def local_ipv4_networks() -> list[ipaddress.IPv4Interface]:
    found = _windows_ipv4_networks()
    if found or _allowed_indexes() is not None:
        return found
    networks: list[ipaddress.IPv4Interface] = []
    for address in local_ipv4_addresses():
        try:
            interface = ipaddress.IPv4Interface(f"{address}/24")
        except ipaddress.AddressValueError:
            continue
        if interface.ip.is_loopback:
            continue
        networks.append(interface)
    return networks


def _windows_ipv4_networks() -> list[ipaddress.IPv4Interface]:
    if not hasattr(socket, "AF_INET"):
        return []
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return []
    if not hasattr(ctypes, "windll"):
        return []

    class _Row(ctypes.Structure):
        _fields_ = [
            ("dwAddr", wintypes.DWORD),
            ("dwIndex", wintypes.DWORD),
            ("dwMask", wintypes.DWORD),
            ("dwBCastAddr", wintypes.DWORD),
            ("dwReasmSize", wintypes.DWORD),
            ("unused1", wintypes.WORD),
            ("wType", wintypes.WORD),
        ]

    class _Table(ctypes.Structure):
        _fields_ = [("dwNumEntries", wintypes.DWORD), ("table", _Row * 64)]

    table = _Table()
    size = wintypes.DWORD(ctypes.sizeof(table))
    try:
        result = ctypes.windll.iphlpapi.GetIpAddrTable(ctypes.byref(table), ctypes.byref(size), 0)
    except (AttributeError, OSError):
        return []
    if result != 0:
        return []
    networks: list[ipaddress.IPv4Interface] = []
    allowed = _allowed_indexes()
    count = min(int(table.dwNumEntries), 64)
    for index in range(count):
        row = table.table[index]
        if allowed is not None and int(row.dwIndex) not in allowed:
            continue
        address = socket.inet_ntoa(struct.pack("<L", row.dwAddr))
        mask = socket.inet_ntoa(struct.pack("<L", row.dwMask))
        try:
            interface = ipaddress.IPv4Interface(f"{address}/{mask}")
        except ipaddress.AddressValueError:
            continue
        if interface.ip.is_loopback or interface.ip.is_unspecified or int(interface.netmask) == 0:
            continue
        networks.append(interface)
    return networks


def local_ipv4_addresses() -> set[str]:
    found: set[str] = set()
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        infos = []
    for info in infos:
        found.add(str(info[4][0]))
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        found.add(str(probe.getsockname()[0]))
    except OSError:
        pass
    finally:
        probe.close()
    return found


def _valid_port(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def _valid_version(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0
