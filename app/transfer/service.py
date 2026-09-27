from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import mimetypes
import secrets
import shutil
import time
from collections.abc import Callable
from pathlib import Path

from app.network.protocol import (
    CancelReason,
    ErrorCode,
    Message,
    MessageType,
    RejectReason,
    make_error,
    make_transfer_accept,
    make_transfer_cancel,
    make_transfer_complete,
    make_transfer_reject,
    make_transfer_request,
    make_transfer_start,
    parse_message,
)
from app.network.secure_channel import SecureSession, _write_message
from app.security.integrity import hash_file, hashes_match
from app.security.limits import DEFAULT_LIMITS, Limits, transfer_budget
from app.security.validation import unique_destination

log = logging.getLogger("localdrop")

CHUNK_BYTES = 32 * 1024
ProgressCallback = Callable[[str, str, int, int, float, float, str], None]
AcceptCallback = Callable[[str, int, str], bool]


async def _dir_rejected() -> str:
    return "REJECTED"


class TransferService:
    def __init__(
        self,
        download_dir: Path,
        *,
        limits: Limits = DEFAULT_LIMITS,
        accept_transfer: AcceptCallback | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> None:
        self.download_dir = download_dir
        self.limits = limits
        self.accept_transfer = accept_transfer or (lambda *_args: False)
        self.on_progress = on_progress
        self._active = 0
        self._by_peer: dict[str, int] = {}
        self._cancel: dict[str, asyncio.Event] = {}

    def _acquire(self, peer: str) -> bool:
        if self._active >= self.limits.max_concurrent_transfers:
            return False
        if self._by_peer.get(peer, 0) >= self.limits.max_transfers_per_peer:
            return False
        self._active += 1
        self._by_peer[peer] = self._by_peer.get(peer, 0) + 1
        return True

    def _release(self, peer: str) -> None:
        self._active = max(0, self._active - 1)
        left = self._by_peer.get(peer, 0) - 1
        if left <= 0:
            self._by_peer.pop(peer, None)
        else:
            self._by_peer[peer] = left

    def cancel(self, transfer_id: str) -> None:
        event = self._cancel.get(transfer_id)
        if event is not None:
            event.set()

    async def send_files(self, session: SecureSession, paths: list[Path]) -> list[str]:
        results = await asyncio.gather(*(self.send_file(session, path) if path.is_file() else _dir_rejected() for path in paths))
        return list(results)

    async def send_file(self, session: SecureSession, path: Path) -> str:
        if not path.is_file():
            return "FAILED"
        size = path.stat().st_size
        if size > self.limits.max_file_bytes:
            return "REJECTED"
        digest = hash_file(path, CHUNK_BYTES)
        if not self._acquire(session.device_id):
            return "REJECTED"
        message = make_transfer_request(
            path.name,
            size,
            digest,
            mimetypes.guess_type(path.name)[0] or "",
        )
        transfer_id = str(message.payload["transfer_id"])
        queue: asyncio.Queue = asyncio.Queue()
        session.queues[transfer_id] = queue
        self._cancel[transfer_id] = asyncio.Event()
        log.info("Transfer requested")
        try:
            await _write_message(session, message)
            reply = await asyncio.wait_for(queue.get(), self.limits.timeout_seconds)
            if reply is None or reply.type != MessageType.TRANSFER_ACCEPT:
                return "REJECTED"
            log.info("Transfer accepted")
            await _write_message(session, make_transfer_start(message.request_id or "", transfer_id))
            log.info("Transfer started")
            sent = 0
            started = time.monotonic()
            deadline = started + transfer_budget(size)
            running = hashlib.sha256()
            with path.open("rb") as handle:
                while True:
                    if time.monotonic() >= deadline:
                        await _write_message(session, make_transfer_cancel(transfer_id, CancelReason.TIMEOUT))
                        return "FAILED"
                    if self._cancel[transfer_id].is_set():
                        await _write_message(session, make_transfer_cancel(transfer_id, CancelReason.USER_CANCELLED))
                        await self._wait_result(queue)
                        return "CANCELLED"
                    block = handle.read(CHUNK_BYTES)
                    if not block:
                        break
                    running.update(block)
                    payload = parse_message(
                        {
                            "type": MessageType.TRANSFER_DATA.value,
                            "protocol_version": 1,
                            "transfer_id": transfer_id,
                            "payload": {
                                "offset": sent,
                                "data_b64": base64.b64encode(block).decode("ascii"),
                            },
                        }
                    )
                    await _write_message(session, payload)
                    sent += len(block)
                    self._report(path.name, transfer_id, sent, size, started, "TRANSFERRING")
            if running.hexdigest() != digest:
                await _write_message(session, make_transfer_cancel(transfer_id, CancelReason.INTERNAL_ERROR))
                await self._wait_result(queue)
                return "FAILED"
            await _write_message(session, make_transfer_complete(transfer_id, digest))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "FAILED"
            final = await asyncio.wait_for(queue.get(), min(self.limits.timeout_seconds, remaining))
            if final is None or final.type == MessageType.ERROR:
                return "FAILED"
            if final.type == MessageType.TRANSFER_CANCEL:
                return "CANCELLED"
            self._report(path.name, transfer_id, size, size, started, "COMPLETED")
            log.info("Transfer completed")
            return "COMPLETED"
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return "FAILED"
        finally:
            self._release(session.device_id)
            self._cancel.pop(transfer_id, None)
            session.queues.pop(transfer_id, None)

    async def _wait_result(self, queue: asyncio.Queue) -> None:
        try:
            await asyncio.wait_for(queue.get(), 1)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return

    async def receive(self, session: SecureSession, request: Message, queue: asyncio.Queue) -> str:
        transfer_id = str(request.payload["transfer_id"])
        name = str(request.payload["file_name"])
        size = int(request.payload["file_size"])
        digest = str(request.payload["file_hash"])
        partial: Path | None = None
        self._cancel[transfer_id] = asyncio.Event()
        held = False
        try:
            if size > self.limits.max_file_bytes:
                await _write_message(session, make_transfer_reject(request.request_id or "", transfer_id, RejectReason.INVALID_REQUEST))
                return "REJECTED"
            self.download_dir.mkdir(parents=True, exist_ok=True)
            free = shutil.disk_usage(self.download_dir).free
            if free < size:
                await _write_message(
                    session,
                    make_transfer_reject(request.request_id or "", transfer_id, RejectReason.INSUFFICIENT_STORAGE),
                )
                return "REJECTED"
            if not self.accept_transfer(name, size, session.device_name):
                await _write_message(session, make_transfer_reject(request.request_id or "", transfer_id, RejectReason.USER_REJECTED))
                return "REJECTED"
            if not self._acquire(session.device_id):
                await _write_message(session, make_transfer_reject(request.request_id or "", transfer_id, RejectReason.INVALID_REQUEST))
                return "REJECTED"
            held = True
            target = unique_destination(self.download_dir, name)
            partial = self.download_dir / f".{secrets.token_hex(16)}.localdrop-partial"
            await _write_message(session, make_transfer_accept(request.request_id or "", transfer_id))
            log.info("Transfer accepted")
            received = 0
            seen: set[int] = set()
            started = time.monotonic()
            deadline = started + transfer_budget(size)
            with partial.open("wb") as handle:
                while True:
                    if time.monotonic() >= deadline:
                        await _write_message(session, make_transfer_cancel(transfer_id, CancelReason.TIMEOUT))
                        return "FAILED"
                    if self._cancel[transfer_id].is_set():
                        await _write_message(session, make_transfer_cancel(transfer_id, CancelReason.USER_CANCELLED))
                        return "CANCELLED"
                    remaining = deadline - time.monotonic()
                    item = await asyncio.wait_for(queue.get(), min(self.limits.timeout_seconds, remaining))
                    if item is None:
                        return "FAILED"
                    if item.type == MessageType.TRANSFER_CANCEL:
                        if partial is not None:
                            partial.unlink(missing_ok=True)
                            partial = None
                        return "CANCELLED"
                    if item.type == MessageType.TRANSFER_DATA:
                        data = item.payload["data"]
                        offset = item.payload["offset"]
                        if offset in seen or offset != received or received + len(data) > size:
                            await _write_message(session, make_error(ErrorCode.INVALID_PAYLOAD))
                            return "FAILED"
                        seen.add(offset)
                        handle.write(data)
                        received += len(data)
                        self._report(name, transfer_id, received, size, started, "TRANSFERRING")
                    elif item.type == MessageType.TRANSFER_COMPLETE:
                        break
                    elif item.type != MessageType.TRANSFER_START:
                        return "FAILED"
            actual = hash_file(partial, CHUNK_BYTES)
            if not hashes_match(digest, actual) or received != size:
                await _write_message(session, make_error(ErrorCode.INVALID_PAYLOAD))
                log.info("Transfer failed")
                return "FAILED"
            partial.replace(target)
            partial = None
            await _write_message(session, make_transfer_complete(transfer_id, actual))
            self._report(name, transfer_id, size, size, started, "COMPLETED")
            log.info("Transfer completed")
            return "COMPLETED"
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return "FAILED"
        finally:
            if held:
                self._release(session.device_id)
            self._cancel.pop(transfer_id, None)
            if partial is not None and partial.exists():
                partial.unlink(missing_ok=True)

    def _report(self, name: str, transfer_id: str, sent: int, total: int, started: float, state: str) -> None:
        if self.on_progress is None:
            return
        elapsed = max(time.monotonic() - started, 0.001)
        speed = sent / elapsed
        remaining = max(total - sent, 0)
        eta = remaining / speed if speed else 0
        self.on_progress(transfer_id, name, sent, total, speed, eta, state)
