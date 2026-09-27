from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import ssl
import tempfile
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit
from collections.abc import Callable

from app.network.adapters import interface_allowed, local_on_allowed_adapter
from app.network.constants import PHONE_PORT
from app.network.discovery import local_ipv4_networks, local_ipv6_link_networks
from app.i18n import format_duration, normalize_language, tr
from app.phone.cert import phone_material
from app.phone.media import apply_capture_time, photo_metadata, thumbnail_bytes, thumbnail_data_url
from app.security.key_guard import pem_file
from app.security.validation import SecurityError, decoded_filename, unique_destination, validate_filename

log = logging.getLogger("localdrop")

PARTIAL_SUFFIX = ".localdrop-partial"
_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
_ID = re.compile(r"^[0-9a-f]{32}$")
_PIN_TTL = 24 * 60 * 60


def _fresh_pin() -> str:
    return f"{secrets.randbelow(90_000_000) + 10_000_000}"


def _scope_key(ip: str) -> str:
    host = ip.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return host
    if isinstance(addr, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{addr}/24", strict=False))
    if addr.is_link_local:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return host


def _redact_log(text: str) -> str:
    if "pin=" in text:
        text = text.split("pin=", 1)[0] + "pin=***"
    return re.sub(r"([?&]t=)[^&\s]+", r"\1***", text)


class PhoneBridge:
    def __init__(
        self,
        download_dir: Path,
        max_file_bytes: int,
        on_event: Callable[[str, object], None] | None = None,
        cert_dir: Path | None = None,
    ) -> None:
        self.download_dir = download_dir
        self.max_file_bytes = max_file_bytes
        self.on_event = on_event
        self.cert_dir = cert_dir
        self.pin = _fresh_pin()
        self.token = secrets.token_urlsafe(32)
        self.form_token = secrets.token_urlsafe(32)
        self.gate = secrets.token_urlsafe(18)
        self.cert_fingerprint = ""
        self._names: dict[str, str] = {}
        self._pin_born = time.monotonic()
        self._ticket = ""
        self._ticket_until = 0.0
        self._ticket_hits = 0
        self._tickets: dict[str, float] = {}
        self._ip_fail: dict[str, int] = {}
        self._ip_lock: dict[str, float] = {}
        self._scope_fail: dict[str, list[float]] = {}
        self._scope_lock: dict[str, float] = {}
        self._global_fail: list[float] = []
        self._cert_names: tuple[str, ...] = ()
        self._key_pem = b""
        self._cert_pem = b""
        self.port = PHONE_PORT
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._staging = Path(tempfile.mkdtemp(prefix="localdrop-inbox-"))
        self._sent_dir = Path(tempfile.mkdtemp(prefix="localdrop-sent-"))
        self._shares: dict[str, Path] = {}
        self._inbox: dict[str, Path] = {}
        self._phone_sent: dict[str, Path] = {}
        self._pc_sent: dict[str, Path] = {}
        self._received: list[str] = []
        self._last_progress = 0.0
        self.share_clipboard = False
        self.expire_seconds = 300
        self.language = "en"
        self._born: dict[str, float] = {}
        self._clips: dict[str, dict[str, str]] = {}
        self._phone_refresh = False
        self._sweep_stop = threading.Event()

    @property
    def pin_text(self) -> str:
        return f"{self.pin[:4]} {self.pin[4:]}"

    def set_language(self, language: str) -> None:
        chosen = normalize_language(language)
        if chosen == self.language:
            return
        self.language = chosen
        self._phone_refresh = True
        self._emit("language", chosen)

    def start(self, port: int = PHONE_PORT) -> None:
        if self._httpd is not None:
            return
        self._sweep_stop.clear()
        self._listen(port)
        threading.Thread(target=self._sweep_loop, name="phone-expire", daemon=True).start()

    def _listen(self, port: int) -> None:
        hosts = self._lan_hosts()
        cert_pem, key_pem, fingerprint = phone_material(self.cert_dir, hosts)
        self._cert_pem = cert_pem
        self._key_pem = key_pem
        self.cert_fingerprint = fingerprint
        self._cert_names = tuple(hosts)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        cert_file = tempfile.NamedTemporaryFile(prefix="localdrop-phone-", suffix=".crt", delete=False)
        cert_file.write(cert_pem)
        cert_file.close()
        try:
            with pem_file(key_pem) as keyfile:
                context.load_cert_chain(certfile=cert_file.name, keyfile=keyfile)
        finally:
            try:
                os.remove(cert_file.name)
            except OSError:
                pass
        httpd = _Server(("0.0.0.0", port), _Handler, self, context)
        self._httpd = httpd
        self.port = int(httpd.server_address[1])
        self._thread = threading.Thread(target=httpd.serve_forever, name="phone-http", daemon=True)
        self._thread.start()
        log.info("Phone page on port %s", self.port)

    def _rebind(self, hosts: list[str]) -> None:
        del hosts
        port = self.port or PHONE_PORT
        httpd = self._httpd
        self._httpd = None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        self._listen(port)

    def stop(self) -> None:
        self._sweep_stop.set()
        httpd = self._httpd
        self._httpd = None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        shutil.rmtree(self._staging, ignore_errors=True)
        shutil.rmtree(self._sent_dir, ignore_errors=True)

    def _lan_hosts(self) -> list[str]:
        hosts = []
        for interface in local_ipv4_networks():
            if interface.ip.is_loopback or interface.ip.is_link_local:
                continue
            hosts.append(str(interface.ip))
        hosts.sort(key=_rank_host)
        return hosts

    def urls(self) -> list[str]:
        hosts = self._lan_hosts()
        if self._httpd is not None and tuple(hosts) != self._cert_names:
            self._rebind(hosts)
        if not hosts:
            return []
        return [f"https://{host}:{self.port}" for host in hosts]

    def fresh_ticket(self) -> str:
        now = time.monotonic()
        with self._lock:
            self._expire_pin_locked(now)
            if self._ticket and now < self._ticket_until:
                return self._ticket
            self._tickets.pop(self._ticket, None)
            token = secrets.token_urlsafe(32)
            self._ticket = token
            self._ticket_until = now + 60
            self._ticket_hits = 0
            self._tickets[token] = self._ticket_until
            return token

    def redeem_ticket(self, token: str) -> bool:
        now = time.monotonic()
        with self._lock:
            deadline = self._tickets.get(token)
            if deadline is None or now > deadline or token != self._ticket or self._ticket_hits >= 4:
                self._drop_ticket_locked(token)
                return False
            self._ticket_hits += 1
        self._open_session()
        return True

    def adopt_session(self) -> None:
        with self._lock:
            self._drop_ticket_locked(self._ticket)

    def _drop_ticket_locked(self, token: str) -> None:
        if not token:
            return
        self._tickets.pop(token, None)
        if token == self._ticket:
            self._ticket = ""
            self._ticket_until = 0.0

    def _open_session(self) -> None:
        with self._lock:
            self.token = secrets.token_urlsafe(32)

    def _file_id(self) -> str:
        return secrets.token_hex(16)

    def _opaque(self, root: Path) -> tuple[str, Path]:
        file_id = self._file_id()
        folder = root / file_id[:2]
        folder.mkdir(parents=True, exist_ok=True)
        return file_id, folder / file_id

    def share(self, paths: list[Path]) -> None:
        with self._lock:
            for path in paths:
                if not path.is_file():
                    continue
                self._remember_pc_locked(path)
                if path.resolve() in {item.resolve() for item in self._shares.values()}:
                    continue
                file_id = self._file_id()
                self._shares[file_id] = path
                self._names[file_id] = self._names.get(str(path), path.name)
                self._born[f"share:{file_id}"] = time.monotonic()
        self._emit("phone-shares", self.share_entries())
        self._emit("phone-sent", self.pc_sent_entries())

    def clear_shares(self) -> None:
        with self._lock:
            for file_id in self._shares:
                self._born.pop(f"share:{file_id}", None)
            self._shares.clear()
        self._emit("phone-shares", [])
        self._emit("phone-sent", self.pc_sent_entries())

    def clear_history(self) -> None:
        dropped: list[str] = []
        with self._lock:
            for file_id, path in list(self._inbox.items()):
                self._born.pop(f"in:{file_id}", None)
                self._erase(path)
            self._inbox.clear()
            self._received.clear()
            for file_id, path in list(self._shares.items()):
                self._born.pop(f"share:{file_id}", None)
                self._drop_owned(path)
            self._shares.clear()
            for file_id, path in list(self._phone_sent.items()):
                self._born.pop(f"up:{file_id}", None)
                self._erase(path)
            self._phone_sent.clear()
            for path in list(self._pc_sent.values()):
                self._drop_owned(path)
            self._pc_sent.clear()
            for clip_id, item in list(self._clips.items()):
                self._born.pop(f"clip:{clip_id}", None)
                dropped.append(item["text"])
            self._clips.clear()
            self._phone_refresh = True
        self._emit("phone-inbox", self.inbox_items())
        self._emit("phone-shares", self.share_entries())
        self._emit("phone-sent", self.pc_sent_entries())
        self.publish_clips(dropped)
        self._emit("phone-history", "")

    def resend_share(self, file_id: str) -> None:
        if not _ID.match(file_id):
            return
        with self._lock:
            path = self._pc_sent.get(file_id)
        if path is None:
            return
        if not path.is_file():
            self._emit("phone-log", tr(self.language, "file_missing", name=path.name))
            return
        self.share([path])
        self._emit("phone-log", tr(self.language, "again_phone", name=path.name))

    def offer_incoming(self, file_ids: list[str]) -> None:
        copies: list[Path] = []
        with self._lock:
            for file_id in file_ids:
                source = self._inbox.get(file_id)
                if source is None or not source.is_file():
                    continue
                label = self._names.get(file_id, _safe_name(source.name))
                _copy_id, target = self._opaque(self._sent_dir)
                shutil.copy2(source, target)
                self._names[str(target)] = label
                copies.append(target)
        if not copies:
            return
        self.share(copies)
        for path in copies:
            self._emit("phone-log", tr(self.language, "again_phone", name=path.name))

    def pc_sent_entries(self) -> list[dict[str, str]]:
        with self._lock:
            return [{"id": file_id, "name": self._names.get(file_id, path.name)} for file_id, path in self._pc_sent.items()]

    def sent_uploads(self) -> list[tuple[str, str]]:
        with self._lock:
            return [(file_id, self._names.get(file_id, path.name)) for file_id, path in self._phone_sent.items()]

    def resend_upload(self, file_id: str) -> bool:
        if not _ID.match(file_id):
            return False
        with self._lock:
            source = self._phone_sent.get(file_id)
            label = self._names.get(file_id, "file")
        if source is None or not source.is_file():
            return False
        destination = _reserve(self, label)
        if destination is None:
            return False
        partial = destination.with_name(destination.name + PARTIAL_SUFFIX)
        try:
            shutil.copy2(source, partial)
            os.replace(partial, destination)
        except OSError:
            partial.unlink(missing_ok=True)
            return False
        self.hold(destination, remember=False)
        return True

    def _remember_pc_locked(self, path: Path) -> None:
        try:
            resolved = path.resolve()
        except OSError:
            return
        for item in self._pc_sent.values():
            try:
                if item.resolve() == resolved:
                    return
            except OSError:
                continue
        while len(self._pc_sent) >= 30:
            self._pc_sent.pop(next(iter(self._pc_sent)))
        sent_id = self._file_id()
        self._pc_sent[sent_id] = path
        self._names[sent_id] = self._names.get(str(path), path.name)

    def _keep_upload(self, path: Path) -> None:
        file_id, target = self._opaque(self._sent_dir)
        shutil.copy2(path, target)
        removed: list[Path] = []
        with self._lock:
            self._names[file_id] = self._names.get(str(path), _safe_name(path.name))
            self._phone_sent[file_id] = target
            self._born[f"up:{file_id}"] = time.monotonic()
            while len(self._phone_sent) > 20:
                old_id = next(iter(self._phone_sent))
                old = self._phone_sent.pop(old_id)
                self._born.pop(f"up:{old_id}", None)
                removed.append(old)
        for old in removed:
            shutil.rmtree(old.parent, ignore_errors=True)

    def share_entries(self) -> list[dict[str, str]]:
        with self._lock:
            return [
                {"name": self._names.get(file_id, path.name), "preview": thumbnail_data_url(path)}
                for file_id, path in self._shares.items()
            ]

    def shared_file(self, file_id: str) -> Path | None:
        if not _ID.match(file_id):
            return None
        with self._lock:
            path = self._shares.get(file_id)
        if path is None or not path.is_file():
            return None
        return path

    def check_pin(self, given: str, ip: str = "") -> bool:
        now = time.monotonic()
        host = ip.split("%", 1)[0]
        scope = _scope_key(host)
        with self._lock:
            self._expire_pin_locked(now)
            if now < self._ip_lock.get(host, 0.0) or now < self._scope_lock.get(scope, 0.0):
                return False
        cleaned = "".join(ch for ch in given if ch.isdigit())
        if len(cleaned) != len(self.pin) or not hmac.compare_digest(cleaned, self.pin):
            self._note_failure(host, now)
            return False
        with self._lock:
            self._ip_fail[host] = 0
        return True

    def _note_failure(self, host: str, now: float) -> None:
        reset = False
        with self._lock:
            scope = _scope_key(host)
            self._ip_fail[host] = self._ip_fail.get(host, 0) + 1
            if self._ip_fail[host] >= 5:
                self._ip_lock[host] = time.monotonic() + 15
                self._ip_fail[host] = 0
            recent = [stamp for stamp in self._scope_fail.get(scope, []) if now - stamp < 60]
            recent.append(now)
            if len(recent) >= 5:
                self._scope_lock[scope] = time.monotonic() + 15
                recent = []
            self._scope_fail[scope] = recent
            self._global_fail = [stamp for stamp in self._global_fail if now - stamp < 60]
            self._global_fail.append(now)
            if len(self._global_fail) >= 20:
                self._global_fail.clear()
                reset = True
        if reset:
            self.regenerate_pin()

    def regenerate_pin(self) -> None:
        with self._lock:
            self.pin = _fresh_pin()
            self._pin_born = time.monotonic()
            self.token = secrets.token_urlsafe(32)
            self.form_token = secrets.token_urlsafe(32)
            self.gate = secrets.token_urlsafe(18)
            self._ip_fail.clear()
            self._ip_lock.clear()
            self._scope_fail.clear()
            self._scope_lock.clear()
        self._emit("phone-log", tr(self.language, "pin_regenerated"))

    def _expire_pin_locked(self, now: float) -> None:
        if now - self._pin_born < _PIN_TTL:
            return
        self.pin = _fresh_pin()
        self._pin_born = now
        self.token = secrets.token_urlsafe(32)
        self.form_token = secrets.token_urlsafe(32)
        self.gate = secrets.token_urlsafe(18)

    def hold(self, path: Path, remember: bool = True, seconds: float | None = None) -> None:
        if remember:
            self._keep_upload(path)
        file_id = self._file_id()
        label = self._names.get(str(path), _safe_name(path.name))
        with self._lock:
            self._names[file_id] = label
            self._inbox[file_id] = path
            self._born[f"in:{file_id}"] = time.monotonic()
            self._received.insert(0, label)
            del self._received[12:]
        self._emit("phone-inbox", self.inbox_items())
        if seconds is None:
            self._emit("phone-log", tr(self.language, "waiting", name=path.name))
        else:
            self._emit("phone-log", tr(self.language, "waiting_time", name=path.name, time=format_duration(seconds)))
        size = path.stat().st_size if path.is_file() else 0
        started = None if seconds is None else time.monotonic() - max(seconds, 0.0)
        self.report_progress(path.name, size, size, started)

    def inbox_items(self) -> list[dict[str, object]]:
        with self._lock:
            items = []
            for file_id, path in self._inbox.items():
                size = path.stat().st_size if path.is_file() else 0
                items.append({
                    "id": file_id,
                    "name": self._names.get(file_id, path.name),
                    "size": size,
                    "preview": thumbnail_data_url(path),
                    "meta": photo_metadata(path),
                })
            return items

    def save_incoming(self, file_ids: list[str], directory: str) -> None:
        folder = Path(directory) if str(directory).strip() else self.download_dir
        saved: list[Path] = []
        try:
            folder.mkdir(parents=True, exist_ok=True)
        except OSError:
            self._emit("phone-log", tr(self.language, "folder_unavailable"))
            return
        with self._lock:
            for file_id in file_ids:
                source = self._inbox.get(file_id)
                if source is None or not source.is_file():
                    continue
                label = self._names.get(file_id, "file")
                partial: Path | None = None
                try:
                    target = unique_destination(folder, label)
                    partial = target.with_name(target.name + PARTIAL_SUFFIX)
                    shutil.copy2(source, partial)
                    os.replace(partial, target)
                    apply_capture_time(target)
                    if not target.is_file() or target.stat().st_size != source.stat().st_size:
                        target.unlink(missing_ok=True)
                        continue
                    source.unlink(missing_ok=True)
                    del self._inbox[file_id]
                    self._born.pop(f"in:{file_id}", None)
                    saved.append(target)
                except (OSError, SecurityError):
                    if partial is not None:
                        partial.unlink(missing_ok=True)
                    continue
        self._emit("phone-inbox", self.inbox_items())
        for path in saved:
            self._emit("phone-log", tr(self.language, "saved", path=path))
        if file_ids and not saved:
            self._emit("phone-log", tr(self.language, "save_failed"))

    def report_progress(self, name: str, sent: int, total: int, started: float | None = None) -> None:
        finished = total > 0 and sent >= total
        now = time.monotonic()
        if not finished and now - self._last_progress < 0.25:
            return
        self._last_progress = now
        payload: dict[str, object] = {"name": name, "sent": sent, "total": max(total, 1)}
        if started is not None:
            payload["seconds"] = round(max(0.0, now - started), 1)
        self._emit("phone-progress", payload)

    def discard_incoming(self, file_ids: list[str]) -> None:
        with self._lock:
            for file_id in file_ids:
                source = self._inbox.pop(file_id, None)
                self._born.pop(f"in:{file_id}", None)
                if source is not None:
                    source.unlink(missing_ok=True)
        self._emit("phone-inbox", self.inbox_items())

    def received_names(self) -> list[str]:
        with self._lock:
            return list(self._received)

    def snapshot(self) -> tuple[list[tuple[str, str]], list[str]]:
        with self._lock:
            shares = [(file_id, self._names.get(file_id, path.name)) for file_id, path in self._shares.items()]
            received = list(self._received)
        return shares, received

    def push_clip(self, text: str, way: str) -> bool:
        cleaned = text.replace("\x00", "").strip()
        if not self.share_clipboard or not cleaned or len(cleaned) > 20000 or way not in {"phone", "pc"}:
            return False
        clip_id = secrets.token_hex(16)
        with self._lock:
            self._clips[clip_id] = {"text": cleaned, "way": way}
            self._born[f"clip:{clip_id}"] = time.monotonic()
            while len(self._clips) > 20:
                old_id = next(iter(self._clips))
                self._clips.pop(old_id)
                self._born.pop(f"clip:{old_id}", None)
        self.publish_clips()
        return True

    def clip_snapshot(self, dropped: list[str] | None = None, consume_refresh: bool = False) -> dict[str, object]:
        now = time.monotonic()
        with self._lock:
            items = []
            for clip_id, item in self._clips.items():
                born = self._born.get(f"clip:{clip_id}", now)
                left = max(0, int(self.expire_seconds - (now - born)))
                items.append({"id": clip_id, "text": item["text"], "way": item["way"], "left": left})
            refresh = self._phone_refresh
            if consume_refresh:
                self._phone_refresh = False
            minutes = min(240, max(1, int(self.expire_seconds // 60) or 1))
            return {
                "open": self.share_clipboard,
                "minutes": minutes,
                "items": items,
                "dropped": list(dropped or []),
                "refresh": refresh,
            }

    def publish_clips(self, dropped: list[str] | None = None) -> None:
        self._emit("phone-clips", self.clip_snapshot(dropped))

    def expire_due(self) -> None:
        now = time.monotonic()
        limit = self.expire_seconds
        dropped: list[str] = []
        inbox_changed = False
        shares_changed = False
        sent_changed = False
        with self._lock:
            def aged(key: str) -> bool:
                born = self._born.get(key)
                return born is not None and now - born >= limit

            for file_id in [item for item in self._inbox if aged(f"in:{item}")]:
                path = self._inbox.pop(file_id)
                self._born.pop(f"in:{file_id}", None)
                if path.name in self._received:
                    self._received.remove(path.name)
                self._erase(path)
                inbox_changed = True
            for file_id in [item for item in self._shares if aged(f"share:{item}")]:
                path = self._shares.pop(file_id)
                self._born.pop(f"share:{file_id}", None)
                self._drop_owned(path)
                shares_changed = True
                self._phone_refresh = True
            for file_id in [item for item in self._phone_sent if aged(f"up:{item}")]:
                path = self._phone_sent.pop(file_id)
                self._born.pop(f"up:{file_id}", None)
                self._erase(path)
                self._phone_refresh = True
                sent_changed = True
            for clip_id in [item for item in self._clips if aged(f"clip:{item}")]:
                item = self._clips.pop(clip_id)
                self._born.pop(f"clip:{clip_id}", None)
                dropped.append(item["text"])
        if inbox_changed:
            self._emit("phone-inbox", self.inbox_items())
            self._emit("phone-log", tr(self.language, "expired_deleted"))
        if shares_changed:
            self._emit("phone-shares", self.share_entries())
            self._emit("phone-sent", self.pc_sent_entries())
            self._emit("phone-log", tr(self.language, "expired_phone"))
        if dropped or inbox_changed or shares_changed or sent_changed:
            self.publish_clips(dropped)

    def _sweep_loop(self) -> None:
        while not self._sweep_stop.wait(1):
            try:
                now = time.monotonic()
                with self._lock:
                    aged = now - self._pin_born >= _PIN_TTL
                    if aged:
                        self._expire_pin_locked(now)
                if aged:
                    self._emit("phone-log", tr(self.language, "pin_regenerated"))
                self.expire_due()
            except Exception:
                log.exception("Expire failed")

    def _owned(self, path: Path) -> bool:
        try:
            resolved = path.resolve()
        except OSError:
            return False
        for root in (self._staging, self._sent_dir):
            try:
                base = root.resolve()
            except OSError:
                continue
            if resolved == base or base in resolved.parents:
                return True
        return False

    def _erase(self, path: Path) -> None:
        if not self._owned(path):
            return
        path.unlink(missing_ok=True)
        Path(str(path) + PARTIAL_SUFFIX).unlink(missing_ok=True)
        parent = path.parent
        try:
            resolved = parent.resolve()
            if resolved in {self._staging.resolve(), self._sent_dir.resolve()}:
                return
            if not any(parent.iterdir()):
                parent.rmdir()
        except OSError:
            return

    def _drop_owned(self, path: Path) -> None:
        if not self._owned(path):
            return
        for sent_id, item in list(self._pc_sent.items()):
            try:
                same = item.resolve() == path.resolve()
            except OSError:
                same = False
            if same:
                self._pc_sent.pop(sent_id, None)
        self._erase(path)

    def _emit(self, kind: str, payload: object) -> None:
        if self.on_event is None:
            return
        try:
            self.on_event(kind, payload)
        except Exception:
            log.exception("Phone event failed")


def client_on_lan(address: str) -> bool:
    host, separator, zone = address.partition("%")
    if not separator:
        zone = ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return True
    if isinstance(ip, ipaddress.IPv6Address):
        if not ip.is_link_local:
            return False
        if zone.isdigit():
            allowed = interface_allowed(int(zone))
            if allowed is False:
                return False
        for network in local_ipv6_link_networks():
            if ip in network:
                return True
        return False
    if not isinstance(ip, ipaddress.IPv4Address):
        return False
    for interface in local_ipv4_networks():
        if interface.ip.is_loopback or interface.ip.is_link_local:
            continue
        if ip in interface.network:
            return True
    return False


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        bridge: PhoneBridge,
        context: ssl.SSLContext,
    ) -> None:
        self.bridge = bridge
        self._ssl = context
        super().__init__(address, handler)

    def server_bind(self) -> None:
        super().server_bind()
        self.socket = self._ssl.wrap_socket(self.socket, server_side=True)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 600

    def log_message(self, fmt: str, *args: object) -> None:
        log.info("Phone %s", _redact_log(fmt % args))

    def do_GET(self) -> None:
        if self._refuse_outsider():
            return
        bridge: PhoneBridge = self.server.bridge
        path = urlsplit(self.path).path
        if path.startswith("/file/"):
            file_id, gate = _split_id(path, "/file/")
            if not self._authorized():
                self._html(401, self._login("enter_code"))
                return
            target = bridge.shared_file(file_id)
            if target is None:
                self._html(404, self._msg("not_found"))
                return
            started = time.monotonic()
            self._send_file(target, download_name=bridge._names.get(file_id, target.name), started=started)
            elapsed = time.monotonic() - started
            bridge._emit("phone-log", tr(bridge.language, "toward_phone_time", name=target.name, time=format_duration(elapsed)))
            return
        if path.startswith("/view/") or path.startswith("/raw/"):
            raw = path.startswith("/raw/")
            file_id, gate = _split_id(path, "/raw/" if raw else "/view/")
            if not self._authorized():
                self._html(401, self._login("enter_code"))
                return
            target = bridge.shared_file(file_id)
            if target is None:
                self._html(404, self._msg("not_found"))
                return
            if raw:
                _kind, mime = _media_kind(target.name)
                self._send_file(target, mime)
                return
            self._html(200, _gallery_page(file_id, bridge._names.get(file_id, target.name), bridge.language, bridge.form_token))
            return
        if path.startswith("/preview/"):
            file_id, gate = _split_id(path, "/preview/")
            if not self._authorized():
                self._html(401, self._login("enter_code"))
                return
            target = bridge.shared_file(file_id)
            if target is None:
                self._html(404, self._msg("not_found"))
                return
            data = thumbnail_bytes(target)
            if not data:
                self._html(404, self._msg("no_preview"))
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return
        if path.startswith("/svg/"):
            icon = _svg_file(path.removeprefix("/svg/"))
            if icon is None:
                self._html(404, self._msg("page_missing"))
                return
            data = icon.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/clips":
            if not self._authorized():
                self._json(401, {"ok": False})
                return
            self._json(200, bridge.clip_snapshot(consume_refresh=True))
            return
        if path == "/jsqr.js":
            script = _jsqr_bytes()
            if script is None:
                self._html(404, self._msg("page_missing"))
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(script)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(script)
            return
        if path == "/glass.css":
            css = _glass_css().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/css; charset=utf-8")
            self.send_header("Content-Length", str(len(css)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(css)
            return
        if path != "/":
            self._html(404, self._msg("page_missing"))
            return
        query = urlsplit(self.path).query
        if not self._authorized():
            ticket = ""
            for part in query.split("&"):
                name, sep, value = part.partition("=")
                if sep and name == "t":
                    ticket = unquote(value.replace("+", " "))
            if ticket:
                if bridge.redeem_ticket(ticket):
                    self.send_response(303)
                    self.send_header("Location", "/")
                    self.send_header("Set-Cookie", _session_cookie(bridge))
                    self._finish_headers()
                    return
                self._html(401, self._login("qr_expired"))
                return
            self._html(200, self._login())
            return
        notice = ""
        if "ok=1" in query:
            elapsed = _query_seconds(query)
            notice = tr(bridge.language, "notice_ok_time", time=format_duration(elapsed)) if elapsed is not None else tr(bridge.language, "notice_ok")
        error = tr(bridge.language, "too_big") if "err=size" in query else ""
        shares, received = bridge.snapshot()
        self._html(200, _home_page(shares, received, bridge.sent_uploads(), notice, error, bridge.gate, bridge.form_token, bridge.language))

    def do_POST(self) -> None:
        if self._refuse_outsider():
            return
        bridge: PhoneBridge = self.server.bridge
        path = urlsplit(self.path).path
        if path == "/language":
            length = self._length(4096)
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            fields = _form_fields(raw)
            if not _token_matches(fields.get("csrf", ""), bridge.form_token):
                self._html(403, self._login("bad_request"))
                return
            bridge.set_language(fields.get("lang", "en"))
            self.send_response(303)
            self.send_header("Location", "/")
            self._finish_headers()
            return
        if path == "/unlock":
            length = self._length(4096)
            if length is None:
                self._html(400, self._login("bad_request"))
                return
            raw = self.rfile.read(length).decode("utf-8", "replace")
            fields = _form_fields(raw)
            if not _token_matches(fields.get("csrf", ""), bridge.form_token) and not self._csrf_header(bridge):
                self._html(403, self._login("bad_request"))
                return
            if not bridge.check_pin(fields.get("pin", ""), self.client_address[0]):
                self._html(401, self._login("bad_pin"))
                return
            bridge._open_session()
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", _session_cookie(bridge))
            self._finish_headers()
            return
        if path == "/clip":
            if not self._authorized() or not self._csrf_header(bridge):
                self._json(401, {"ok": False})
                return
            length = self._length(80_000)
            if length is None:
                self._json(400, {"ok": False})
                return
            raw = self.rfile.read(length).decode("utf-8", "replace")
            text = ""
            for part in raw.split("&"):
                name, sep, value = part.partition("=")
                if sep and name == "text":
                    text = unquote(value.replace("+", " "))
            if bridge.push_clip(text, "phone"):
                self._json(200, {"ok": True})
                return
            self._json(403, {"ok": False})
            return
        if path == "/history":
            if not self._authorized():
                self._html(401, self._login("enter_code"))
                return
            if not self._csrf_header(bridge):
                self._html(403, self._login("bad_request"))
                return
            bridge.clear_history()
            self._json(200, {"ok": True})
            return
        if path.startswith("/resend/"):
            if not self._authorized():
                self._html(401, self._login("enter_code"))
                return
            length = self._length(4096)
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            fields = _form_fields(raw)
            if not self._csrf_header(bridge) and not _token_matches(fields.get("csrf", ""), bridge.form_token):
                self._html(403, self._login("bad_request"))
                return
            if bridge.resend_upload(path.removeprefix("/resend/").split("/")[0]):
                self.send_response(303)
                self.send_header("Location", "/?ok=1")
                self._finish_headers()
                return
            self._html(404, self._msg("not_found"))
            return
        if path != "/upload":
            self._html(404, self._msg("page_missing"))
            return
        if not self._authorized() or not self._csrf_header(bridge):
            self._html(401, self._login("enter_code"))
            return
        saved, status, elapsed = _save_upload(self, bridge)
        if status == "size":
            self.send_response(303)
            self.send_header("Location", "/?err=size")
            self._finish_headers()
            return
        if saved:
            self.send_response(303)
            self.send_header("Location", f"/?ok=1&s={elapsed:.3f}")
            self._finish_headers()
            return
        self._html(400, self._msg("none_received"))

    def _login(self, key: str = "") -> str:
        bridge: PhoneBridge = self.server.bridge
        message = tr(bridge.language, key) if key else ""
        return _login_page(message, bridge.form_token, bridge.language)

    def _msg(self, key: str) -> str:
        bridge: PhoneBridge = self.server.bridge
        return _message_page(tr(bridge.language, key), bridge.language, bridge.form_token)

    def _authorized(self) -> bool:
        bridge: PhoneBridge = self.server.bridge
        token = ""
        for part in self.headers.get("Cookie", "").split(";"):
            item = part.strip()
            if item.startswith("ld="):
                token = item[3:]
        if len(token) != len(bridge.token) or not hmac.compare_digest(token, bridge.token):
            return False
        bridge.adopt_session()
        return True

    def _csrf_header(self, bridge: PhoneBridge) -> bool:
        return _token_matches(self.headers.get("X-LocalDrop-CSRF", ""), bridge.form_token)

    def _refuse_outsider(self) -> bool:
        remote = self.client_address[0]
        local = ""
        try:
            local = str(self.connection.getsockname()[0])
        except OSError:
            local = ""
        if client_on_lan(remote) and (not local or local_on_allowed_adapter(local)):
            return False
        self._html(403, self._msg("lan_only"))
        return True

    def _length(self, limit: int) -> int | None:
        raw = self.headers.get("Content-Length")
        if raw is None or not raw.isdigit():
            return None
        length = int(raw)
        if length < 0 or length > limit:
            return None
        return length

    def _send_file(self, path: Path, content_type: str = "application/octet-stream", download_name: str | None = None, started: float | None = None) -> None:
        size = path.stat().st_size
        shown = download_name or path.name
        begun = time.monotonic() if started is None else started
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        disposition = "inline" if content_type.startswith(("image/", "video/")) else "attachment"
        self.send_header("Content-Disposition", f"{disposition}; filename*=UTF-8''{quote(shown)}")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        sent = 0
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)
                sent += len(chunk)
                self.server.bridge.report_progress(path.name, sent, size, begun)
        self.server.bridge.report_progress(path.name, sent, size or 1, begun)

    def _json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _html(self, status: int, body: str, set_cookie: bool = False) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if set_cookie:
            bridge: PhoneBridge = self.server.bridge
            self.send_header("Set-Cookie", _session_cookie(bridge))
        self.end_headers()
        self.wfile.write(data)

    def _finish_headers(self) -> None:
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()


def _query_seconds(query: str) -> float | None:
    for part in query.split("&"):
        name, sep, value = part.partition("=")
        if not sep or name != "s":
            continue
        try:
            seconds = float(unquote(value.replace("+", " ")))
        except ValueError:
            return None
        if seconds < 0 or seconds > 86400:
            return None
        return seconds
    return None


def _save_upload(handler: _Handler, bridge: PhoneBridge) -> tuple[int, str, float]:
    begun = time.monotonic()

    def finish(saved: int, status: str) -> tuple[int, str, float]:
        return saved, status, max(0.0, time.monotonic() - begun)

    header = handler.headers.get("Content-Type", "")
    marker = "boundary="
    if "multipart/form-data" not in header or marker not in header:
        return finish(0, "bad")
    raw_boundary = header.split(marker, 1)[1].strip().strip('"')
    if not raw_boundary or len(raw_boundary) > 200:
        return finish(0, "bad")
    length_raw = handler.headers.get("Content-Length")
    if length_raw is None or not length_raw.isdigit():
        return finish(0, "bad")
    length = int(length_raw)
    ceiling = bridge.max_file_bytes * 16 + 1_000_000
    if length > ceiling:
        return finish(0, "size")
    reader = _Reader(handler.rfile, length)
    boundary = raw_boundary.encode("ascii", "ignore")
    if not reader.sync(b"--" + boundary):
        return finish(0, "bad")
    saved = 0
    while True:
        if reader.buf.startswith(b"--"):
            break
        if reader.buf.startswith(b"\r\n"):
            reader.buf = reader.buf[2:]
        headers = reader.headers()
        if headers is None:
            break
        filename = _filename_from_headers(headers)
        if filename is None:
            state = reader.stream_until(b"\r\n--" + boundary, bridge.max_file_bytes, None)
            if state != "ok":
                return finish(saved, "size" if state == "big" else "bad")
            continue
        destination = _reserve(bridge, filename)
        if destination is None:
            return finish(saved, "bad")
        partial = destination.with_name(destination.name + PARTIAL_SUFFIX)
        file_started = time.monotonic()
        try:
            sent = 0

            def write(chunk: bytes) -> None:
                nonlocal sent
                handle.write(chunk)
                sent += len(chunk)
                bridge.report_progress(filename, sent, length, file_started)

            with partial.open("wb") as handle:
                state = reader.stream_until(b"\r\n--" + boundary, bridge.max_file_bytes, write)
            if state != "ok":
                partial.unlink(missing_ok=True)
                return finish(saved, "size" if state == "big" else "bad")
            os.replace(partial, destination)
        except OSError:
            partial.unlink(missing_ok=True)
            log.exception("Phone upload failed")
            return finish(saved, "bad")
        saved += 1
        bridge.hold(destination, seconds=time.monotonic() - file_started)
    return finish(saved, "ok")


def _reserve(bridge: PhoneBridge, filename: str) -> Path | None:
    try:
        label = _safe_name(filename)
        with bridge._lock:
            _file_id, destination = bridge._opaque(bridge._staging)
            root = bridge._staging.resolve()
            if root not in destination.resolve().parents:
                return None
            bridge._names[str(destination)] = label
            partial = Path(str(destination) + PARTIAL_SUFFIX)
            partial.touch(exist_ok=False)
        return destination
    except (SecurityError, OSError):
        return None


class _Reader:
    def __init__(self, source, length: int) -> None:
        self.source = source
        self.left = length
        self.buf = b""

    def _pull(self) -> bool:
        if self.left <= 0:
            return False
        chunk = self.source.read(min(65536, self.left))
        if not chunk:
            self.left = 0
            return False
        self.left -= len(chunk)
        self.buf += chunk
        return True

    def sync(self, token: bytes) -> bool:
        while True:
            index = self.buf.find(token)
            if index != -1:
                self.buf = self.buf[index + len(token) :]
                return True
            keep = len(token) - 1
            if len(self.buf) > keep:
                self.buf = self.buf[-keep:]
            if not self._pull():
                return False

    def headers(self) -> str | None:
        token = b"\r\n\r\n"
        while True:
            index = self.buf.find(token)
            if index != -1:
                raw = self.buf[:index]
                self.buf = self.buf[index + 4 :]
                if len(raw) > 8192:
                    return None
                return raw.decode("utf-8", "replace")
            if len(self.buf) > 8192:
                return None
            if not self._pull():
                return None

    def stream_until(self, token: bytes, limit: int, write) -> str:
        written = 0
        while True:
            index = self.buf.find(token)
            if index != -1:
                piece = self.buf[:index]
                if written + len(piece) > limit:
                    return "big"
                if piece and write is not None:
                    write(piece)
                self.buf = self.buf[index + len(token) :]
                return "ok"
            keep = len(token) - 1
            if len(self.buf) > keep:
                piece = self.buf[:-keep]
                self.buf = self.buf[-keep:]
                if written + len(piece) > limit:
                    return "big"
                written += len(piece)
                if piece and write is not None:
                    write(piece)
            if not self._pull():
                return "bad"


def _filename_from_headers(headers: str) -> str | None:
    for line in headers.split("\r\n"):
        if not line.lower().startswith("content-disposition:"):
            continue
        matched = re.search(r"filename\*=UTF-8''([^;\r]+)", line, re.IGNORECASE)
        if matched:
            raw = unquote(matched.group(1).strip().strip('"'))
        else:
            matched = re.search(r'filename="([^"]*)"', line)
            if matched:
                raw = matched.group(1)
            else:
                matched = re.search(r"filename=([^;]+)", line)
                if not matched:
                    return None
                raw = matched.group(1).strip().strip('"')
        return _safe_name(raw)
    return None


def _safe_name(raw: str) -> str:
    decoded = decoded_filename(raw)
    if decoded == "file" and raw != "file":
        changed = raw
        for _ in range(8):
            nxt = unquote(changed)
            if nxt == changed:
                break
            changed = nxt
        else:
            return "file"
    decoded = decoded.replace("\\", "/")
    cleaned = decoded.split("/")[-1].strip()
    cleaned = "".join(ch for ch in cleaned if ord(ch) >= 32 and ch not in '<>:"|?*')
    cleaned = unicodedata.normalize("NFC", cleaned).strip().strip(".")
    if not cleaned or cleaned in {".", ".."}:
        return "file"
    stem = Path(cleaned).stem.upper()
    if stem in _RESERVED:
        return "file"
    try:
        return validate_filename(cleaned)
    except SecurityError:
        return "file"


def _split_id(path: str, prefix: str) -> tuple[str, str]:
    parts = [part for part in path.removeprefix(prefix).split("/") if part]
    if not parts:
        return "", ""
    return parts[0], parts[1] if len(parts) > 1 else ""


def _form_fields(raw: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in raw.split("&"):
        name, sep, value = part.partition("=")
        if not sep:
            continue
        fields[unquote(name.replace("+", " "))] = unquote(value.replace("+", " "))
    return fields


def _token_matches(given: str, expected: str) -> bool:
    if not given or len(given) != len(expected):
        return False
    return hmac.compare_digest(given, expected)


def _session_cookie(bridge: PhoneBridge) -> str:
    return f"ld={bridge.token}; HttpOnly; Path=/; SameSite=Strict; Secure; Max-Age=86400"


def _csrf_field(token: str) -> str:
    return f"<input type=\"hidden\" name=\"csrf\" value=\"{_esc(token)}\">"


def _rank_host(host: str) -> tuple[int, str]:
    if host.startswith("172.20.10.") or host.startswith("192.168.42."):
        return (0, host)
    if host.startswith("192.168."):
        return (1, host)
    if host.startswith("10."):
        return (2, host)
    return (3, host)


def _esc(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _glass_css() -> str:
    path = Path(__file__).resolve().parent.parent / "gui" / "glass.css"
    return path.read_text(encoding="utf-8")


def _jsqr_bytes() -> bytes | None:
    path = Path(__file__).resolve().parent / "jsqr.js"
    if not path.is_file():
        return None
    return path.read_bytes()


def _svg_file(name: str) -> Path | None:
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.svg", name):
        return None
    root = (Path(__file__).resolve().parent.parent.parent / "svg-animazioni").resolve()
    target = (root / name).resolve()
    if target.parent != root or not target.is_file():
        return None
    return target


def _icon(name: str) -> str:
    return f"<img class=\"btn-ico\" src=\"/svg/{name}\" alt=\"\">"


def _lang_switch(lang: str, csrf: str) -> str:
    en = " on" if lang != "it" else ""
    it = " on" if lang == "it" else ""
    return (
        f"<form method=\"post\" action=\"/language\" class=\"lang\" aria-label=\"Language\">"
        f"{_csrf_field(csrf)}"
        f"<button class=\"lang-btn{en}\" name=\"lang\" value=\"en\" type=\"submit\">EN</button>"
        f"<button class=\"lang-btn{it}\" name=\"lang\" value=\"it\" type=\"submit\">IT</button>"
        f"</form>"
    )


def _page(body: str, lang: str = "en", csrf: str = "") -> str:
    chosen = normalize_language(lang)
    return (
        f"<!DOCTYPE html><html lang=\"{chosen}\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>LocalDrop</title><link rel=\"stylesheet\" href=\"/glass.css\"></head><body class=\"phone\">"
        "<div class=\"shell\"><header class=\"head\">"
        "<div class=\"logo-wrap\"><h1 class=\"depth\" id=\"logo\">LocalDrop</h1></div>"
        f"<div class=\"top\">{_lang_switch(chosen, csrf)}"
        f"<button class=\"squish\" id=\"theme\" type=\"button\" role=\"switch\" aria-checked=\"true\" aria-label=\"{tr(chosen, 'theme')}\">"
        "<span class=\"squish-knob\">"
        "<img class=\"squish-moon\" src=\"/svg/moon.svg\" alt=\"\">"
        "<img class=\"squish-sun\" src=\"/svg/sun.svg\" alt=\"\">"
        "</span></button></div></header>"
        f"{body}</div><script>"
        "const themeKey='localdrop-theme';"
        "const themeButton=document.getElementById('theme');"
        "function paintTheme(dark,animate){"
        "document.body.classList.toggle('dark',dark);"
        "if(!themeButton)return;"
        "themeButton.setAttribute('aria-checked',dark?'true':'false');"
        "if(!animate)return;"
        "themeButton.classList.add('moving');"
        "clearTimeout(themeButton._timer);"
        "themeButton._timer=setTimeout(()=>themeButton.classList.remove('moving'),320);"
        "}"
        "paintTheme(localStorage.getItem(themeKey)!=='light',false);"
        "if(themeButton)themeButton.onclick=()=>{const dark=!document.body.classList.contains('dark');localStorage.setItem(themeKey,dark?'dark':'light');paintTheme(dark,true);};"
        "const logo=document.getElementById('logo');"
        "if(logo){const face=logo.textContent;logo.textContent='';"
        "const faceNode=document.createElement('span');faceNode.className='depth-face';faceNode.textContent=face;logo.appendChild(faceNode);"
        "for(let layer=1;layer<=34;layer+=1){const slab=document.createElement('span');slab.className='depth-layer';"
        "slab.setAttribute('aria-hidden','true');slab.textContent=face;slab.style.transform='translateZ('+(-layer*2.4)+'px)';logo.appendChild(slab);}"
        "let aimX=0,aimY=0,tiltX=0,tiltY=0,orbit=0,lastTick=performance.now();"
        "logo.addEventListener('pointermove',(event)=>{const box=logo.getBoundingClientRect();"
        "aimX=((event.clientX-box.left)/box.width-0.5)*16;aimY=((event.clientY-box.top)/box.height-0.5)*-12;});"
        "logo.addEventListener('pointerleave',()=>{aimX=0;aimY=0;});"
        "function spinLogo(now){const step=Math.min(0.05,(now-lastTick)/1000);lastTick=now;orbit+=0.35*step;"
        "const turnX=Math.sin(orbit)*7.5;const turnY=Math.cos(orbit*0.8)*5;"
        "tiltX+=(aimX+turnX-tiltX)*0.14;tiltY+=(aimY+turnY-tiltY)*0.14;"
        "logo.style.transform='rotateX('+tiltY.toFixed(2)+'deg) rotateY('+tiltX.toFixed(2)+'deg)';requestAnimationFrame(spinLogo);}"
        "requestAnimationFrame(spinLogo);}"
        "</script></body></html>"
    )


def _login_page(message: str, csrf: str = "", lang: str = "en") -> str:
    note = f"<p class=\"note\">{_esc(message)}</p>" if message else ""
    copy = json.dumps(
        {
            "hint": tr(lang, "scan_hint"),
            "bad": tr(lang, "scan_bad"),
            "denied": tr(lang, "scan_denied"),
            "missing": tr(lang, "scan_missing"),
        },
        ensure_ascii=False,
    )
    camera = (
        "<svg class=\"scan-ico\" viewBox=\"0 0 24 24\" aria-hidden=\"true\">"
        "<path d=\"M9 7.2 10.2 5h3.6L15 7.2h2.2A1.8 1.8 0 0 1 19 9v8.2a1.8 1.8 0 0 1-1.8 1.8H6.8A1.8 1.8 0 0 1 5 17.2V9a1.8 1.8 0 0 1 1.8-1.8H9Zm3 9.2a3.4 3.4 0 1 0 0-6.8 3.4 3.4 0 0 0 0 6.8Z\"/>"
        "</svg>"
    )
    return _page(
        f"<p class=\"subtitle\">{_esc(tr(lang, 'pin_prompt'))}</p>"
        + note
        + "<section class=\"glass\"><form method=\"post\" action=\"/unlock\">"
        + _csrf_field(csrf)
        + f"<input class=\"code-input\" name=\"pin\" inputmode=\"numeric\" autocomplete=\"one-time-code\" maxlength=\"8\" autofocus placeholder=\"{_esc(tr(lang, 'pin_placeholder'))}\">"
        + f"<button class=\"primary\" type=\"submit\">{_icon('check.svg')}{_esc(tr(lang, 'enter'))}</button></form>"
        + f"<button class=\"ghost scan-open\" id=\"scan\" type=\"button\">{camera}{_esc(tr(lang, 'scan_qr'))}</button>"
        + "<p class=\"hint scan-status\" id=\"scan-status\"></p></section>"
        + "<div class=\"scan-layer\" id=\"scan-layer\" hidden>"
        + "<video id=\"scan-video\" playsinline muted autoplay></video>"
        + "<div class=\"scan-frame\"></div>"
        + "<p class=\"scan-note\" id=\"scan-note\"></p>"
        + f"<button class=\"ghost scan-close\" id=\"scan-close\" type=\"button\">{_esc(tr(lang, 'scan_close'))}</button></div>"
        + "<script src=\"/jsqr.js\"></script><script>"
        + _scan_script(copy)
        + "</script>",
        lang,
        csrf,
    )


def _scan_script(copy: str) -> str:
    return """
const ldScan=__COPY__;
const scanBtn=document.getElementById("scan");
const layer=document.getElementById("scan-layer");
const video=document.getElementById("scan-video");
const note=document.getElementById("scan-note");
const status=document.getElementById("scan-status");
const closeBtn=document.getElementById("scan-close");
const canvas=document.createElement("canvas");
let stream=null;
let timer=0;
let busy=false;
let last=0;
function stopScan(){
  cancelAnimationFrame(timer);
  timer=0;
  busy=false;
  if(stream){stream.getTracks().forEach((track)=>track.stop());stream=null;}
  video.srcObject=null;
  layer.hidden=true;
}
function ticketFrom(text){
  let url;
  try{url=new URL(String(text||"").trim());}catch(error){return "";}
  if(url.protocol!=="https:"||url.pathname!=="/")return "";
  const token=url.searchParams.get("t")||"";
  return /^[A-Za-z0-9_-]{20,128}$/.test(token)?token:"";
}
async function readCode(detector){
  if(detector){
    const found=await detector.detect(video);
    return found.length?(found[0].rawValue||""):"";
  }
  if(typeof jsQR!=="function"||video.readyState<2)return "";
  const width=video.videoWidth;
  const height=video.videoHeight;
  if(!width||!height)return "";
  const scale=Math.min(1,480/Math.max(width,height));
  canvas.width=Math.max(1,Math.round(width*scale));
  canvas.height=Math.max(1,Math.round(height*scale));
  const ctx=canvas.getContext("2d",{willReadFrequently:true});
  ctx.drawImage(video,0,0,canvas.width,canvas.height);
  const image=ctx.getImageData(0,0,canvas.width,canvas.height);
  const code=jsQR(image.data,image.width,image.height,{inversionAttempts:"dontInvert"});
  return code&&code.data?code.data:"";
}
async function loop(detector){
  if(layer.hidden)return;
  const now=performance.now();
  if(!busy&&now-last>180){
    last=now;
    busy=true;
    try{
      const text=await readCode(detector);
      const token=text?ticketFrom(text):"";
      if(token){
        stopScan();
        location.replace("/?t="+encodeURIComponent(token));
        return;
      }
      if(text)note.textContent=ldScan.bad;
    }catch(error){
    }finally{busy=false;}
  }
  timer=requestAnimationFrame(()=>loop(detector));
}
async function detectorFor(){
  if(!("BarcodeDetector" in window))return null;
  try{
    const formats=await BarcodeDetector.getSupportedFormats();
    if(!formats.includes("qr_code"))return null;
    return new BarcodeDetector({formats:["qr_code"]});
  }catch(error){return null;}
}
scanBtn.onclick=async()=>{
  status.textContent="";
  if(!navigator.mediaDevices||!navigator.mediaDevices.getUserMedia){
    status.textContent=ldScan.missing;
    return;
  }
  layer.hidden=false;
  note.textContent=ldScan.hint;
  try{
    stream=await navigator.mediaDevices.getUserMedia({audio:false,video:{facingMode:{ideal:"environment"}}});
  }catch(error){
    note.textContent=ldScan.denied;
    return;
  }
  video.srcObject=stream;
  video.muted=true;
  video.playsInline=true;
  try{await video.play();}
  catch(error){
    stopScan();
    status.textContent=ldScan.denied;
    return;
  }
  const detector=await detectorFor();
  if(!detector&&typeof jsQR!=="function"){
    stopScan();
    status.textContent=ldScan.missing;
    return;
  }
  loop(detector);
};
closeBtn.onclick=stopScan;
document.addEventListener("visibilitychange",()=>{if(document.hidden)stopScan();});
""".replace("__COPY__", copy, 1)


def _home_page(
    shares: list[tuple[str, str]],
    received: list[str],
    sent: list[tuple[str, str]],
    notice: str,
    error: str,
    gate: str,
    csrf: str,
    lang: str = "en",
) -> str:
    parts = []
    if notice:
        parts.append(f"<p class=\"note\">{_esc(notice)}</p>")
    if error:
        parts.append(f"<p class=\"note\">{_esc(error)}</p>")
    parts.append(f"<section class=\"glass lead\"><h2 class=\"with-ico\"><img src=\"/svg/upload.svg\" alt=\"\">{_esc(tr(lang, 'send_computer'))}</h2>")
    parts.append("<div class=\"bar\"><div id=\"bar-fill\"></div></div><p class=\"hint\" id=\"bar-label\"></p>")
    parts.append("<div class=\"list\" id=\"local-preview\"></div>")
    parts.append("<form class=\"upload\" method=\"post\" action=\"/upload\" enctype=\"multipart/form-data\">")
    parts.append(_csrf_field(csrf))
    parts.append("<input id=\"files\" type=\"file\" name=\"files\" multiple required>")
    parts.append(f"<button class=\"primary\" type=\"submit\">{_icon('upload.svg')}{_esc(tr(lang, 'send_computer'))}</button></form>")
    if sent:
        parts.append(f"<p class=\"empty\" style=\"margin-top:12px\">{_esc(tr(lang, 'already_sent'))}</p><div class=\"list\">")
        for file_id, name in sent:
            parts.append(
                f"<form method=\"post\" action=\"/resend/{file_id}\">{_csrf_field(csrf)}<div class=\"item\">{_icon('document.svg')}{_esc(name)}"
                f"<button class=\"ghost\" type=\"submit\" style=\"margin-top:8px;width:100%\">{_icon('cartoon-square-arrow-right-enter.svg')}{_esc(tr(lang, 'resend'))}</button></div></form>"
            )
        parts.append("</div>")
    if received:
        parts.append(f"<p class=\"empty\" style=\"margin-top:12px\">{_esc(tr(lang, 'waiting_computer'))}</p><div class=\"list\">")
        for name in received:
            parts.append(f"<div class=\"item\">{_icon('document.svg')}{_esc(name)}</div>")
        parts.append("</div>")
    parts.append(f"</section><section class=\"glass\"><h2 class=\"with-ico\"><img src=\"/svg/cartoon-copy.svg\" alt=\"\">{_esc(tr(lang, 'notes'))}</h2>")
    parts.append(f"<p class=\"hint\" id=\"clip-note\">{_esc(tr(lang, 'clip_closed'))}</p>")
    parts.append(f"<textarea id=\"clip-text\" class=\"field\" maxlength=\"20000\" placeholder=\"{_esc(tr(lang, 'clip_placeholder'))}\"></textarea>")
    parts.append(f"<button class=\"primary\" id=\"clip-send\" type=\"button\" style=\"margin-top:8px\">{_icon('cartoon-square-arrow-right-enter.svg')}{_esc(tr(lang, 'send_to_computer'))}</button>")
    parts.append("<div class=\"list\" id=\"clip-list\"></div></section>")
    parts.append(f"<section class=\"glass\"><h2 class=\"with-ico\"><img src=\"/svg/solid-download.svg\" alt=\"\">{_esc(tr(lang, 'download_computer'))}</h2>")
    if not shares:
        parts.append(f"<p class=\"empty\">{_esc(tr(lang, 'no_share'))}</p>")
    else:
        parts.append("<div class=\"list\">")
        for file_id, name in shares:
            kind, _mime = _media_kind(name)
            parts.append(f"<a class=\"file-link secondary\" href=\"/file/{file_id}\" data-name=\"{_esc(name)}\">{_icon('document.svg')}{_esc(name)}</a>")
            if kind == "image":
                parts.append(f"<img class=\"preview\" src=\"/preview/{file_id}\" alt=\"\">")
                parts.append(f"<a class=\"primary\" href=\"/view/{file_id}\" style=\"margin-top:8px\">{_icon('save.svg')}{_esc(tr(lang, 'save_photos'))}</a>")
            elif kind == "video":
                parts.append(f"<a class=\"primary\" href=\"/view/{file_id}\" style=\"margin-top:8px\">{_icon('save.svg')}{_esc(tr(lang, 'save_video'))}</a>")
        parts.append("</div>")
    parts.append("</section>")
    parts.append(
        f"<button class=\"ghost history-clear\" id=\"history-clear\" type=\"button\">{_icon('cartoon-close-cross.svg')}"
        f"<span data-done=\"{_esc(tr(lang, 'history_cleared'))}\">{_esc(tr(lang, 'clear_history'))}</span></button>"
    )
    parts.append(
        "<script>"
        f"const ldCopy={json.dumps({'clip_open': tr(lang, 'clip_open'), 'clip_closed': tr(lang, 'clip_closed'), 'from_computer': tr(lang, 'from_computer'), 'sent_computer': tr(lang, 'sent_computer'), 'seconds_left': tr(lang, 'seconds_left'), 'copy': tr(lang, 'copy'), 'sending': tr(lang, 'sending')}, ensure_ascii=False)};"
        f"const ldHeaders={{'X-LocalDrop-CSRF':'{csrf}'}};"
        "const input=document.getElementById('files');"
        "const local=document.getElementById('local-preview');"
        "const fill=document.getElementById('bar-fill');"
        "const label=document.getElementById('bar-label');"
        "function formatDuration(seconds){const value=Math.max(0,Number(seconds)||0);"
        "if(value<60){const shown=Math.max(value,value>0?0.1:0).toFixed(1).replace(/\\.0$/,'');return shown+' s';}"
        "const whole=Math.round(value);const minutes=Math.floor(whole/60);const rest=whole%60;"
        "return rest?minutes+' min '+rest+' s':minutes+' min';}"
        "function setBar(name,pct,seconds){fill.style.width=pct+'%';"
        "label.textContent=name+' '+pct+'%'+(seconds==null?'':' · '+formatDuration(seconds));}"
        "input.addEventListener('change',()=>{local.innerHTML='';[...input.files].forEach(file=>{"
        "if(!file.type.startsWith('image/'))return;const img=document.createElement('img');"
        "img.className='preview';img.src=URL.createObjectURL(file);local.appendChild(img);});});"
        "document.querySelector('form.upload').addEventListener('submit',(event)=>{"
        "event.preventDefault();const xhr=new XMLHttpRequest();xhr.open('POST','/upload');"
        "const started=performance.now();"
        "Object.entries(ldHeaders).forEach(([key,value])=>xhr.setRequestHeader(key,value));"
        "xhr.upload.onprogress=(e)=>{if(e.lengthComputable)setBar(ldCopy.sending,Math.round(e.loaded*100/e.total),(performance.now()-started)/1000);};"
        "xhr.onload=()=>{setBar(ldCopy.sending,100,(performance.now()-started)/1000);location.href=xhr.responseURL||'/?ok=1';};xhr.send(new FormData(event.target));});"
        "document.querySelectorAll('a.file-link').forEach(link=>link.addEventListener('click',async(event)=>{"
        "event.preventDefault();const started=performance.now();const response=await fetch(link.href,{headers:ldHeaders});"
        "const total=Number(response.headers.get('Content-Length')||0);const reader=response.body.getReader();"
        "const chunks=[];let sent=0;while(true){const step=await reader.read();if(step.done)break;chunks.push(step.value);sent+=step.value.length;"
        "setBar(link.textContent.trim(),total?Math.round(sent*100/total):0,(performance.now()-started)/1000);}"
        "setBar(link.textContent.trim(),100,(performance.now()-started)/1000);"
        "const url=URL.createObjectURL(new Blob(chunks));const a=document.createElement('a');a.href=url;a.download=link.textContent.trim();a.click();}));"
        "const clipNote=document.getElementById('clip-note');"
        "const clipText=document.getElementById('clip-text');"
        "const clipList=document.getElementById('clip-list');"
        "const clipSend=document.getElementById('clip-send');"
        "function paintClips(data){"
        "clipNote.textContent=data.open?ldCopy.clip_open.replace('{minutes}',data.minutes):ldCopy.clip_closed;"
        "clipText.disabled=!data.open;clipSend.disabled=!data.open;clipList.innerHTML='';"
        "data.items.forEach(item=>{const row=document.createElement('div');row.className='item';"
        "const title=document.createElement('p');title.className='hint';title.textContent=item.way==='pc'?ldCopy.from_computer:ldCopy.sent_computer;"
        "const body=document.createElement('p');body.className='clip-text';body.textContent=item.text;"
        "const left=document.createElement('p');left.className='hint';left.textContent=ldCopy.seconds_left.replace('{left}',item.left);"
        "row.appendChild(title);row.appendChild(body);row.appendChild(left);"
        "if(item.way==='pc'){const button=document.createElement('button');button.className='ghost';button.type='button';button.textContent=ldCopy.copy;"
        "button.style.marginTop='8px';button.style.width='100%';button.onclick=()=>navigator.clipboard.writeText(item.text);row.appendChild(button);}"
        "clipList.appendChild(row);});"
        "if(data.refresh && !clipText.value) location.reload();}"
        "async function pullClips(){const response=await fetch('/clips',{headers:ldHeaders});if(response.ok) paintClips(await response.json());}"
        "const historyClear=document.getElementById('history-clear');"
        "if(historyClear)historyClear.onclick=async()=>{const label=historyClear.querySelector('span');"
        "historyClear.disabled=true;if(label)label.textContent=label.dataset.done||label.textContent;"
        "const response=await fetch('/history',{method:'POST',headers:ldHeaders});"
        "if(response.ok)location.reload();else historyClear.disabled=false;};"
        "clipSend.onclick=async()=>{const text=clipText.value.trim();if(!text)return;"
        "const response=await fetch('/clip',{method:'POST',headers:{...ldHeaders,'Content-Type':'application/x-www-form-urlencoded'},body:'text='+encodeURIComponent(text)});"
        "if(response.ok){clipText.value='';pullClips();}};"
        "pullClips();setInterval(pullClips,1000);"
        "</script>"
    )
    return _page("".join(parts), lang, csrf)


def _gallery_page(file_id: str, name: str, lang: str = "en", csrf: str = "") -> str:
    kind, mime = _media_kind(name)
    if kind == "image":
        media = f"<img class=\"preview\" src=\"/raw/{file_id}\" alt=\"{_esc(name)}\" style=\"max-height:none\">"
        hint = tr(lang, "hold_photo")
    else:
        media = f"<video class=\"preview\" src=\"/raw/{file_id}\" controls playsinline style=\"max-height:70vh\"></video>"
        hint = tr(lang, "hold_video")
    return _page(
        f"<section class=\"glass\"><h2>{_esc(name)}</h2>{media}"
        f"<p class=\"subtitle\">{_esc(hint)}</p>"
        f"<a class=\"primary\" href=\"/\">{_icon('cartoon-close-cross.svg')}{_esc(tr(lang, 'back'))}</a></section>",
        lang,
        csrf,
    )


def _media_kind(name: str) -> tuple[str, str]:
    suffix = Path(name).suffix.lower()
    images = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".bmp": "image/bmp",
        ".heic": "image/heic",
        ".heif": "image/heif",
    }
    videos = {
        ".mp4": "video/mp4",
        ".mov": "video/quicktime",
        ".m4v": "video/mp4",
    }
    if suffix in images:
        return "image", images[suffix]
    if suffix in videos:
        return "video", videos[suffix]
    return "file", "application/octet-stream"


def _message_page(message: str, lang: str = "en", csrf: str = "") -> str:
    return _page(f"<p>{_esc(message)}</p>", lang, csrf)
