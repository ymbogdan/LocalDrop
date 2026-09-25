from __future__ import annotations

import asyncio
import ipaddress
import json
import unittest
import uuid
from unittest.mock import patch

from app.network.constants import PROTOCOL_VERSION
from app.network.discovery import (
    DiscoveryService,
    decode_announcement,
    default_announce_targets,
    encode_announcement,
)


def _run(coro):
    return asyncio.run(coro)


class AnnouncementCodecTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        device_id = str(uuid.uuid4())
        packet = encode_announcement(device_id, "LAPTOP", 47822)
        announcement = decode_announcement(packet)
        self.assertIsNotNone(announcement)
        assert announcement is not None
        self.assertEqual(announcement.device_id, device_id)
        self.assertEqual(announcement.device_name, "LAPTOP")
        self.assertEqual(announcement.port, 47822)
        self.assertEqual(announcement.protocol_version, PROTOCOL_VERSION)

    def test_ignores_malformed_packets(self) -> None:
        self.assertIsNone(decode_announcement(b"\xff"))
        self.assertIsNone(decode_announcement(b"{"))
        self.assertIsNone(decode_announcement(b"x" * 2000))
        self.assertIsNone(
            decode_announcement(
                json.dumps({"type": "DISCOVERY", "device_id": "nope"}).encode("utf-8")
            )
        )

    def test_rejects_bool_port(self) -> None:
        device_id = str(uuid.uuid4())
        packet = json.dumps(
            {
                "type": "DISCOVERY",
                "device_id": device_id,
                "device_name": "PC",
                "port": True,
                "protocol_version": 1,
            }
        ).encode("utf-8")
        self.assertIsNone(decode_announcement(packet))


class AnnounceTargetTests(unittest.TestCase):
    def test_includes_global_and_subnet_broadcast(self) -> None:
        with patch(
            "app.network.discovery.local_ipv4_networks",
            return_value=[
                ipaddress.IPv4Interface("127.0.0.1/8"),
                ipaddress.IPv4Interface("192.168.1.25/24"),
            ],
        ):
            targets = default_announce_targets(47821)
        self.assertIn(("255.255.255.255", 47821), targets)
        self.assertIn(("192.168.1.255", 47821), targets)
        self.assertNotIn(("127.0.0.255", 47821), targets)
        self.assertNotIn(("192.168.1.1", 47821), targets)

    def test_small_hotspot_uses_real_broadcast_and_unicast(self) -> None:
        with patch(
            "app.network.discovery.local_ipv4_networks",
            return_value=[ipaddress.IPv4Interface("172.20.10.2/28")],
        ):
            targets = default_announce_targets(47821)
        self.assertIn(("172.20.10.15", 47821), targets)
        self.assertIn(("172.20.10.1", 47821), targets)
        self.assertNotIn(("172.20.10.2", 47821), targets)
        self.assertNotIn(("172.20.10.255", 47821), targets)


class DiscoveryServiceTests(unittest.TestCase):
    def test_two_instances_discover_each_other(self) -> None:
        events: list[tuple[str, str]] = []

        async def scenario() -> None:
            left = DiscoveryService(
                str(uuid.uuid4()),
                "DESKTOP-BOGDAN",
                47001,
                discovery_port=0,
                announce_targets=[],
                interval=5,
                timeout=30,
            )
            right = DiscoveryService(
                str(uuid.uuid4()),
                "LAPTOP",
                47002,
                discovery_port=0,
                announce_targets=[],
                interval=5,
                timeout=30,
            )
            right.add_listener(lambda kind, peer: events.append((kind, peer.device_name)))
            await left.start()
            await right.start()
            try:
                left.set_announce_targets([("127.0.0.1", right.port)])
                right.set_announce_targets([("127.0.0.1", left.port)])
                await left.announce_now()
                await right.announce_now()
                await asyncio.sleep(0.05)
                peers = right.peers()
                self.assertEqual(len(peers), 1)
                self.assertEqual(peers[0].device_name, "DESKTOP-BOGDAN")
                self.assertEqual(peers[0].address, "127.0.0.1")
                self.assertEqual(peers[0].port, 47001)
                self.assertEqual(events, [("appeared", "DESKTOP-BOGDAN")])
            finally:
                await left.stop()
                await right.stop()

        _run(scenario())

    def test_ignores_own_announcement(self) -> None:
        async def scenario() -> None:
            device_id = str(uuid.uuid4())
            service = DiscoveryService(
                device_id,
                "PC",
                47001,
                discovery_port=0,
                announce_targets=[],
            )
            await service.start()
            try:
                service.set_announce_targets([("127.0.0.1", service.port)])
                await service.announce_now()
                await asyncio.sleep(0.05)
                self.assertEqual(service.peers(), [])
            finally:
                await service.stop()

        _run(scenario())

    def test_peer_disappears_after_timeout(self) -> None:
        async def scenario() -> None:
            left = DiscoveryService(
                str(uuid.uuid4()),
                "DESKTOP-BOGDAN",
                47001,
                discovery_port=0,
                announce_targets=[],
                interval=0.05,
                timeout=0.15,
            )
            right = DiscoveryService(
                str(uuid.uuid4()),
                "LAPTOP",
                47002,
                discovery_port=0,
                announce_targets=[],
                interval=0.05,
                timeout=0.15,
            )
            await left.start()
            await right.start()
            try:
                right.set_announce_targets([("127.0.0.1", left.port)])
                await right.announce_now()
                await asyncio.sleep(0.05)
                self.assertEqual(len(left.peers()), 1)
                await right.stop()
                await asyncio.sleep(0.35)
                self.assertEqual(left.peers(), [])
            finally:
                await left.stop()

        _run(scenario())

    def test_name_change_emits_update(self) -> None:
        async def scenario() -> None:
            events: list[str] = []
            left = DiscoveryService(
                str(uuid.uuid4()),
                "LAPTOP",
                47002,
                discovery_port=0,
                announce_targets=[],
                interval=5,
                timeout=30,
            )
            right = DiscoveryService(
                str(uuid.uuid4()),
                "DESKTOP-BOGDAN",
                47001,
                discovery_port=0,
                announce_targets=[],
                interval=5,
                timeout=30,
            )
            left.add_listener(lambda kind, _peer: events.append(kind))
            await left.start()
            await right.start()
            try:
                right.set_announce_targets([("127.0.0.1", left.port)])
                await right.announce_now()
                await asyncio.sleep(0.05)
                right.update_device_name("OFFICE")
                await right.announce_now()
                await asyncio.sleep(0.05)
                self.assertEqual(events, ["appeared", "updated"])
                self.assertEqual(left.peers()[0].device_name, "OFFICE")
            finally:
                await left.stop()
                await right.stop()

        _run(scenario())

    def test_malformed_datagram_does_not_crash(self) -> None:
        async def scenario() -> None:
            service = DiscoveryService(
                str(uuid.uuid4()),
                "PC",
                47001,
                discovery_port=0,
                announce_targets=[],
            )
            await service.start()
            try:
                service.handle_datagram(b"not-json", "127.0.0.1")
                self.assertEqual(service.peers(), [])
            finally:
                await service.stop()

        _run(scenario())


if __name__ == "__main__":
    unittest.main()
