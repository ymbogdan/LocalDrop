from __future__ import annotations

import asyncio
import logging
import queue
import threading
from pathlib import Path

from app.device.identity import load_or_create
from app.i18n import normalize_language, tr
from app.network.discovery import DiscoveryService, Peer
from app.network.secure_channel import SecureError, SecureNode
from app.phone.server import PhoneBridge
from app.security.crypto_identity import load_or_create_crypto
from app.security.limits import Limits
from app.security.pairing import format_verification_code
from app.settings_store import Settings
from app.transfer.service import TransferService

log = logging.getLogger("localdrop")


class DesktopApp:
    def __init__(self, events: queue.Queue, commands: queue.Queue) -> None:
        self.events = events
        self.commands = commands
        self.loop = asyncio.new_event_loop()
        self.identity = load_or_create()
        self.settings_path = self.identity.path.parent / "settings.json"
        self.settings = Settings.load(self.settings_path)
        self.crypto = load_or_create_crypto(self.identity.path.parent, self.identity.device_id)
        if self.settings.download_dir:
            self.identity.rename(self.identity.device_name)
        self.node = SecureNode(
            self.crypto,
            self.identity.device_name,
            self.identity.path.parent / "trusted.json",
            confirm_pairing=self._confirm_pairing,
        )
        self.transfers = TransferService(
            self.settings.download_dir,
            limits=self._limits(),
            accept_transfer=self._accept_transfer,
            on_progress=self._progress,
        )
        self.node.on_incoming = self.transfers.receive
        self.phone = PhoneBridge(
            self.settings.download_dir,
            self.settings.max_file_bytes,
            on_event=self._phone_event,
            cert_dir=self.identity.path.parent,
        )
        self.phone.share_clipboard = self.settings.share_clipboard
        self.phone.expire_seconds = self.settings.expire_minutes * 60
        self.phone.language = self.settings.language
        self.discovery: DiscoveryService | None = None
        self.peers: dict[str, Peer] = {}
        self.sessions = {}

    def _limits(self) -> Limits:
        return Limits(
            max_file_bytes=self.settings.max_file_bytes,
            max_concurrent_transfers=self.settings.max_concurrent_transfers,
        )

    def start(self) -> None:
        self.events.put(("language", self.settings.language))
        self.phone.start()
        threading.Thread(target=self._run_loop, daemon=True).start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.create_task(self._serve())
        self.loop.create_task(self._commands())
        self.loop.run_forever()

    async def _serve(self) -> None:
        port = await self.node.start()
        self.discovery = DiscoveryService(self.identity.device_id, self.identity.device_name, port)
        self.discovery.add_listener(self._on_peer)
        await self.discovery.start()
        log.info("Secure connection established")

    def _on_peer(self, kind: str, peer: Peer) -> None:
        if kind == "disappeared":
            self.peers.pop(peer.device_id, None)
        else:
            self.peers[peer.device_id] = peer
            log.info("Device discovered")
        self._publish_devices()

    def _publish_devices(self) -> None:
        view = {}
        for peer in self.peers.values():
            trusted = self.node.trust.is_paired(peer.device_id)
            state = "Trusted · Available" if trusted else "Pairing required"
            mark = "🟢" if trusted else "🔴"
            view[peer.device_id] = f"{mark} {peer.device_name}   {state}   {peer.address}"
        self.events.put(("devices", view))

    async def _commands(self) -> None:
        last_link = None
        while True:
            link = (
                tuple(self.phone.urls()),
                self.phone.pin_text,
                str(self.phone.download_dir),
                self.phone.fresh_ticket(),
                self.phone.cert_fingerprint,
            )
            if link != last_link:
                last_link = link
                self.events.put(("phone-link", list(link[0]), link[1], link[2], link[3], link[4]))
                self.phone.publish_clips()
            await asyncio.sleep(0.2)
            try:
                command = self.commands.get_nowait()
            except queue.Empty:
                continue
            kind = command[0]
            if kind == "quit":
                self.phone.stop()
                if self.discovery is not None:
                    await self.discovery.stop()
                await self.node.stop()
                self.loop.stop()
                return
            if kind == "share":
                self.phone.share([Path(path) for path in command[1]])
            elif kind == "clear-shares":
                self.phone.clear_shares()
            elif kind == "clear-history":
                self.phone.clear_history()
            elif kind == "resend-share":
                self.phone.resend_share(command[1])
            elif kind == "offer-incoming":
                self.phone.offer_incoming(list(command[1]))
            elif kind == "save-incoming":
                self.phone.save_incoming(list(command[1]), command[2])
            elif kind == "discard-incoming":
                self.phone.discard_incoming(list(command[1]))
            elif kind == "send":
                await self._send(command[1], command[2])
            elif kind == "settings":
                trusted = [(item.device_id, item.device_name) for item in self.node.trust._devices.values()]
                self.events.put(("settings", {
                    "device_name": self.identity.device_name,
                    "download_dir": str(self.settings.download_dir),
                    "max_file_bytes": self.settings.max_file_bytes,
                    "max_concurrent_transfers": self.settings.max_concurrent_transfers,
                    "share_clipboard": self.settings.share_clipboard,
                    "expire_minutes": self.settings.expire_minutes,
                    "trusted": trusted,
                }))
            elif kind == "save-settings":
                self._save_settings(command[1], command[2], command[3], command[4], command[5], command[6])
            elif kind == "set-language":
                self.phone.set_language(command[1])
            elif kind == "share-clipboard":
                self.settings.share_clipboard = bool(command[1])
                self.settings.save(self.settings_path)
                self.phone.share_clipboard = self.settings.share_clipboard
                self.phone.publish_clips()
            elif kind == "clip-to-phone":
                if self.phone.push_clip(str(command[1]), "pc"):
                    self.events.put(("phone-log", tr(self.settings.language, "text_sent")))
                else:
                    self.events.put(("error", tr(self.settings.language, "notes_off")))
            elif kind == "forget":
                self.node.trust.forget(command[1])
                self._publish_devices()

    async def _send(self, device_id: str, paths: list[str]) -> None:
        peer = self.peers.get(device_id)
        if peer is None:
            self.events.put(("error", tr(self.settings.language, "device_unavailable")))
            return
        try:
            session = self.sessions.get(device_id)
            if session is None or session.state.value != "READY":
                session = await self.node.connect(peer.address, peer.port)
                self.sessions[device_id] = session
            await self.transfers.send_files(session, [Path(path) for path in paths])
        except SecureError as exc:
            self.events.put(("error", exc.code))
        except OSError as exc:
            self.events.put(("error", str(exc)))

    def _save_settings(self, name: str, folder: str, limit: str, slots: str, minutes: str, share: str) -> None:
        try:
            self.identity.rename(name)
            self.node.device_name = self.identity.device_name
            self.settings.download_dir = Path(folder)
            self.settings.max_file_bytes = int(limit)
            self.settings.max_concurrent_transfers = int(slots)
            try:
                chosen = int(minutes)
            except (TypeError, ValueError):
                chosen = 5
            self.settings.expire_minutes = min(240, max(1, chosen))
            self.settings.share_clipboard = str(share).lower() in {"1", "true", "on", "yes"}
            self.settings.save(self.settings_path)
            self.transfers.download_dir = self.settings.download_dir
            self.transfers.limits = self._limits()
            self.phone.download_dir = self.settings.download_dir
            self.phone.max_file_bytes = self.settings.max_file_bytes
            self.phone.expire_seconds = self.settings.expire_minutes * 60
            self.phone.share_clipboard = self.settings.share_clipboard
            self.phone.publish_clips()
        except ValueError as exc:
            self.events.put(("error", str(exc)))

    def _confirm_pairing(self, device_name: str, fingerprint: str, code: str) -> bool:
        result: dict[str, bool] = {}
        done = threading.Event()
        self.events.put(("pair", device_name, fingerprint, format_verification_code(code), result, done))
        done.wait(timeout=120)
        return bool(result.get("ok"))

    def _accept_transfer(self, name: str, size: int, sender: str) -> bool:
        result: dict[str, bool] = {}
        done = threading.Event()
        self.events.put(("incoming", name, size, sender, result, done))
        done.wait(timeout=120)
        return bool(result.get("ok"))

    def _progress(self, transfer_id: str, name: str, sent: int, total: int, speed: float, eta: float, state: str) -> None:
        self.events.put(("progress", transfer_id, name, sent, total, speed, eta, state))

    def _phone_event(self, kind: str, payload: object) -> None:
        if kind == "language":
            self.settings.language = normalize_language(payload)
            self.settings.save(self.settings_path)
            self.phone.language = self.settings.language
        self.events.put((kind, payload))
