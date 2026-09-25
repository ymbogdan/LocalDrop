from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import re
import secrets
import shutil
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit
from collections.abc import Callable

from app.network.constants import PHONE_PORT
from app.network.discovery import local_ipv4_networks
from app.phone.media import apply_capture_time, photo_metadata, thumbnail_bytes, thumbnail_data_url
from app.security.validation import SecurityError, unique_destination, validate_filename

log = logging.getLogger("localdrop")

PARTIAL_SUFFIX = ".localdrop-partial"
_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
_ID = re.compile(r"^[0-9a-f]{16}$")


class PhoneBridge:
    def __init__(
        self,
        download_dir: Path,
        max_file_bytes: int,
        on_event: Callable[[str, object], None] | None = None,
    ) -> None:
        self.download_dir = download_dir
        self.max_file_bytes = max_file_bytes
        self.on_event = on_event
        self.pin = f"{secrets.randbelow(900000) + 100000}"
        self.token = secrets.token_urlsafe(32)
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
        self._failures = 0
        self._locked_until = 0.0
        self._last_progress = 0.0

    @property
    def pin_text(self) -> str:
        return f"{self.pin[:3]} {self.pin[3:]}"

    def start(self, port: int = PHONE_PORT) -> None:
        if self._httpd is not None:
            return
        httpd = _Server(("0.0.0.0", port), _Handler, self)
        self._httpd = httpd
        self.port = int(httpd.server_address[1])
        self._thread = threading.Thread(target=httpd.serve_forever, name="phone-http", daemon=True)
        self._thread.start()
        log.info("Phone page on port %s", self.port)

    def stop(self) -> None:
        httpd = self._httpd
        self._httpd = None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        shutil.rmtree(self._staging, ignore_errors=True)
        shutil.rmtree(self._sent_dir, ignore_errors=True)

    def urls(self) -> list[str]:
        hosts = []
        for interface in local_ipv4_networks():
            if interface.ip.is_loopback or interface.ip.is_link_local:
                continue
            hosts.append(str(interface.ip))
        hosts.sort(key=_rank_host)
        if not hosts:
            return []
        return [f"http://{host}:{self.port}" for host in hosts]

    def share(self, paths: list[Path]) -> None:
        with self._lock:
            for path in paths:
                if not path.is_file():
                    continue
                self._remember_pc_locked(path)
                if path.resolve() in {item.resolve() for item in self._shares.values()}:
                    continue
                self._shares[secrets.token_hex(8)] = path
        self._emit("phone-shares", self.share_entries())
        self._emit("phone-sent", self.pc_sent_entries())

    def clear_shares(self) -> None:
        with self._lock:
            self._shares.clear()
        self._emit("phone-shares", [])
        self._emit("phone-sent", self.pc_sent_entries())

    def resend_share(self, file_id: str) -> None:
        if not _ID.match(file_id):
            return
        with self._lock:
            path = self._pc_sent.get(file_id)
        if path is None:
            return
        if not path.is_file():
            self._emit("phone-log", f"File non più trovato: {path.name}")
            return
        self.share([path])
        self._emit("phone-log", f"Di nuovo sul telefono: {path.name}")

    def offer_incoming(self, file_ids: list[str]) -> None:
        copies: list[Path] = []
        with self._lock:
            for file_id in file_ids:
                source = self._inbox.get(file_id)
                if source is None or not source.is_file():
                    continue
                folder = self._sent_dir / secrets.token_hex(8)
                folder.mkdir()
                target = folder / _safe_name(source.name)
                shutil.copy2(source, target)
                copies.append(target)
        if not copies:
            return
        self.share(copies)
        for path in copies:
            self._emit("phone-log", f"Di nuovo sul telefono: {path.name}")

    def pc_sent_entries(self) -> list[dict[str, str]]:
        with self._lock:
            return [{"id": file_id, "name": path.name} for file_id, path in self._pc_sent.items()]

    def sent_uploads(self) -> list[tuple[str, str]]:
        with self._lock:
            return [(file_id, path.name) for file_id, path in self._phone_sent.items()]

    def resend_upload(self, file_id: str) -> bool:
        if not _ID.match(file_id):
            return False
        with self._lock:
            source = self._phone_sent.get(file_id)
        if source is None or not source.is_file():
            return False
        destination = _reserve(self, source.name)
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
        self._pc_sent[secrets.token_hex(8)] = path

    def _keep_upload(self, path: Path) -> None:
        file_id = secrets.token_hex(8)
        folder = self._sent_dir / file_id
        folder.mkdir()
        target = folder / _safe_name(path.name)
        shutil.copy2(path, target)
        removed: list[Path] = []
        with self._lock:
            self._phone_sent[file_id] = target
            while len(self._phone_sent) > 20:
                old = self._phone_sent.pop(next(iter(self._phone_sent)))
                removed.append(old)
        for old in removed:
            shutil.rmtree(old.parent, ignore_errors=True)

    def share_entries(self) -> list[dict[str, str]]:
        with self._lock:
            return [{"name": path.name, "preview": thumbnail_data_url(path)} for path in self._shares.values()]

    def shared_file(self, file_id: str) -> Path | None:
        if not _ID.match(file_id):
            return None
        with self._lock:
            path = self._shares.get(file_id)
        if path is None or not path.is_file():
            return None
        return path

    def check_pin(self, given: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if now < self._locked_until:
                return False
        cleaned = "".join(ch for ch in given if ch.isdigit())
        if len(cleaned) != len(self.pin) or not hmac.compare_digest(cleaned, self.pin):
            with self._lock:
                self._failures += 1
                if self._failures >= 5:
                    self._locked_until = time.monotonic() + 15
                    self._failures = 0
            return False
        with self._lock:
            self._failures = 0
        return True

    def hold(self, path: Path, remember: bool = True) -> None:
        if remember:
            self._keep_upload(path)
        file_id = secrets.token_hex(8)
        with self._lock:
            self._inbox[file_id] = path
            self._received.insert(0, path.name)
            del self._received[12:]
        self._emit("phone-inbox", self.inbox_items())
        self._emit("phone-log", f"In attesa: {path.name}")
        size = path.stat().st_size if path.is_file() else 0
        self.report_progress(path.name, size, size)

    def inbox_items(self) -> list[dict[str, object]]:
        with self._lock:
            items = []
            for file_id, path in self._inbox.items():
                size = path.stat().st_size if path.is_file() else 0
                items.append({
                    "id": file_id,
                    "name": path.name,
                    "size": size,
                    "preview": thumbnail_data_url(path),
                    "meta": photo_metadata(path),
                })
            return items

    def save_incoming(self, file_ids: list[str], directory: str) -> None:
        folder = Path(directory)
        saved: list[str] = []
        with self._lock:
            folder.mkdir(parents=True, exist_ok=True)
            for file_id in file_ids:
                source = self._inbox.get(file_id)
                if source is None or not source.is_file():
                    continue
                target = unique_destination(folder, source.name)
                shutil.move(str(source), target)
                apply_capture_time(target)
                del self._inbox[file_id]
                saved.append(target.name)
                self._remember_pc_locked(target)
        self._emit("phone-inbox", self.inbox_items())
        self._emit("phone-sent", self.pc_sent_entries())
        for name in saved:
            self._emit("phone-log", f"Salvato: {name}")

    def report_progress(self, name: str, sent: int, total: int) -> None:
        finished = total > 0 and sent >= total
        now = time.monotonic()
        if not finished and now - self._last_progress < 0.25:
            return
        self._last_progress = now
        self._emit("phone-progress", {"name": name, "sent": sent, "total": max(total, 1)})

    def discard_incoming(self, file_ids: list[str]) -> None:
        with self._lock:
            for file_id in file_ids:
                source = self._inbox.pop(file_id, None)
                if source is not None:
                    source.unlink(missing_ok=True)
        self._emit("phone-inbox", self.inbox_items())

    def received_names(self) -> list[str]:
        with self._lock:
            return list(self._received)

    def snapshot(self) -> tuple[list[tuple[str, str]], list[str]]:
        with self._lock:
            shares = [(file_id, path.name) for file_id, path in self._shares.items()]
            received = list(self._received)
        return shares, received

    def _emit(self, kind: str, payload: object) -> None:
        if self.on_event is None:
            return
        try:
            self.on_event(kind, payload)
        except Exception:
            log.exception("Phone event failed")


def client_on_lan(address: str) -> bool:
    host = address.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return True
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

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], bridge: PhoneBridge) -> None:
        self.bridge = bridge
        super().__init__(address, handler)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 600

    def log_message(self, fmt: str, *args: object) -> None:
        text = fmt % args
        if "pin=" in text:
            text = text.split("pin=", 1)[0] + "pin=***"
        log.info("Phone %s", text)

    def do_GET(self) -> None:
        if self._refuse_outsider():
            return
        bridge: PhoneBridge = self.server.bridge
        path = urlsplit(self.path).path
        if path.startswith("/file/"):
            if not self._authorized():
                self._html(401, _login_page("Inserisci il codice mostrato sul computer."))
                return
            file_id = path.removeprefix("/file/")
            target = bridge.shared_file(file_id)
            if target is None:
                self._html(404, _message_page("File non trovato."))
                return
            self._send_file(target)
            bridge.report_progress(target.name, target.stat().st_size, target.stat().st_size)
            bridge._emit("phone-log", f"Verso il telefono: {target.name}")
            return
        if path.startswith("/view/") or path.startswith("/raw/"):
            if not self._authorized():
                self._html(401, _login_page("Inserisci il codice mostrato sul computer."))
                return
            raw = path.startswith("/raw/")
            file_id = path.removeprefix("/raw/" if raw else "/view/")
            target = bridge.shared_file(file_id)
            if target is None:
                self._html(404, _message_page("File non trovato."))
                return
            if raw:
                _kind, mime = _media_kind(target.name)
                self._send_file(target, mime)
                return
            self._html(200, _gallery_page(file_id, target.name))
            return
        if path.startswith("/preview/"):
            if not self._authorized():
                self._html(401, _login_page("Inserisci il codice mostrato sul computer."))
                return
            target = bridge.shared_file(path.removeprefix("/preview/"))
            if target is None:
                self._html(404, _message_page("File non trovato."))
                return
            data = thumbnail_bytes(target)
            if not data:
                self._html(404, _message_page("Anteprima non disponibile."))
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
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
            self._html(404, _message_page("Pagina non trovata."))
            return
        query = urlsplit(self.path).query
        if not self._authorized():
            pin = ""
            for part in query.split("&"):
                if part.startswith("pin="):
                    pin = unquote(part[4:].replace("+", " "))
            if pin:
                if bridge.check_pin(pin):
                    self.send_response(303)
                    self.send_header("Location", "/")
                    self.send_header("Set-Cookie", f"ld={bridge.token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=86400")
                    self._finish_headers()
                    return
                self._html(401, _login_page("Codice sbagliato."))
                return
            self._html(200, _login_page(""))
            return
        notice = "In attesa sul computer. Scegli lì quali salvare." if "ok=1" in query else ""
        error = "File troppo grande." if "err=size" in query else ""
        shares, received = bridge.snapshot()
        self._html(200, _home_page(shares, received, bridge.sent_uploads(), notice, error))

    def do_POST(self) -> None:
        if self._refuse_outsider():
            return
        bridge: PhoneBridge = self.server.bridge
        path = urlsplit(self.path).path
        if path == "/unlock":
            length = self._length(2048)
            if length is None:
                self._html(400, _login_page("Richiesta non valida."))
                return
            raw = self.rfile.read(length).decode("utf-8", "replace")
            pin = ""
            for part in raw.split("&"):
                if part.startswith("pin="):
                    pin = unquote(part[4:].replace("+", " "))
            if not bridge.check_pin(pin):
                self._html(401, _login_page("Codice sbagliato."))
                return
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", f"ld={bridge.token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=86400")
            self._finish_headers()
            return
        if path.startswith("/resend/"):
            if not self._authorized():
                self._html(401, _login_page("Inserisci il codice mostrato sul computer."))
                return
            if bridge.resend_upload(path.removeprefix("/resend/")):
                self.send_response(303)
                self.send_header("Location", "/?ok=1")
                self._finish_headers()
                return
            self._html(404, _message_page("File non trovato."))
            return
        if path != "/upload":
            self._html(404, _message_page("Pagina non trovata."))
            return
        if not self._authorized():
            self._html(401, _login_page("Inserisci il codice mostrato sul computer."))
            return
        saved, status = _save_upload(self, bridge)
        if status == "size":
            self.send_response(303)
            self.send_header("Location", "/?err=size")
            self._finish_headers()
            return
        if saved:
            self.send_response(303)
            self.send_header("Location", "/?ok=1")
            self._finish_headers()
            return
        self._html(400, _message_page("Nessun file ricevuto."))

    def _authorized(self) -> bool:
        bridge: PhoneBridge = self.server.bridge
        token = ""
        for part in self.headers.get("Cookie", "").split(";"):
            item = part.strip()
            if item.startswith("ld="):
                token = item[3:]
        if len(token) != len(bridge.token):
            return False
        return hmac.compare_digest(token, bridge.token)

    def _refuse_outsider(self) -> bool:
        if client_on_lan(self.client_address[0]):
            return False
        self._html(403, _message_page("Accesso consentito solo dalla rete di casa."))
        return True

    def _length(self, limit: int) -> int | None:
        raw = self.headers.get("Content-Length")
        if raw is None or not raw.isdigit():
            return None
        length = int(raw)
        if length < 0 or length > limit:
            return None
        return length

    def _send_file(self, path: Path, content_type: str = "application/octet-stream") -> None:
        size = path.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        disposition = "inline" if content_type.startswith(("image/", "video/")) else "attachment"
        self.send_header("Content-Disposition", f"{disposition}; filename*=UTF-8''{quote(path.name)}")
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
                self.server.bridge.report_progress(path.name, sent, size)

    def _html(self, status: int, body: str, set_cookie: bool = False) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if set_cookie:
            bridge: PhoneBridge = self.server.bridge
            self.send_header("Set-Cookie", f"ld={bridge.token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=86400")
        self.end_headers()
        self.wfile.write(data)

    def _finish_headers(self) -> None:
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()


def _save_upload(handler: _Handler, bridge: PhoneBridge) -> tuple[int, str]:
    header = handler.headers.get("Content-Type", "")
    marker = "boundary="
    if "multipart/form-data" not in header or marker not in header:
        return 0, "bad"
    raw_boundary = header.split(marker, 1)[1].strip().strip('"')
    if not raw_boundary or len(raw_boundary) > 200:
        return 0, "bad"
    length_raw = handler.headers.get("Content-Length")
    if length_raw is None or not length_raw.isdigit():
        return 0, "bad"
    length = int(length_raw)
    ceiling = bridge.max_file_bytes * 16 + 1_000_000
    if length > ceiling:
        return 0, "size"
    reader = _Reader(handler.rfile, length)
    boundary = raw_boundary.encode("ascii", "ignore")
    if not reader.sync(b"--" + boundary):
        return 0, "bad"
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
                return saved, "size" if state == "big" else "bad"
            continue
        destination = _reserve(bridge, filename)
        if destination is None:
            return saved, "bad"
        partial = destination.with_name(destination.name + PARTIAL_SUFFIX)
        try:
            sent = 0

            def write(chunk: bytes) -> None:
                nonlocal sent
                handle.write(chunk)
                sent += len(chunk)
                bridge.report_progress(filename, sent, length)

            with partial.open("wb") as handle:
                state = reader.stream_until(b"\r\n--" + boundary, bridge.max_file_bytes, write)
            if state != "ok":
                partial.unlink(missing_ok=True)
                return saved, "size" if state == "big" else "bad"
            os.replace(partial, destination)
        except OSError:
            partial.unlink(missing_ok=True)
            log.exception("Phone upload failed")
            return saved, "bad"
        saved += 1
        bridge.hold(destination)
    return saved, "ok"


def _reserve(bridge: PhoneBridge, filename: str) -> Path | None:
    try:
        with bridge._lock:
            destination = unique_destination(bridge._staging, filename)
            partial = destination.with_name(destination.name + PARTIAL_SUFFIX)
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
    cleaned = raw.replace("\\", "/").split("/")[-1].strip().replace(":", "")
    if not cleaned or cleaned in {".", ".."}:
        return "file"
    stem = Path(cleaned).stem.upper()
    suffix = Path(cleaned).suffix
    safe_suffix = suffix if re.fullmatch(r"\.[A-Za-z0-9]{1,8}", suffix) else ""
    if stem in _RESERVED:
        return "file" + safe_suffix
    try:
        return validate_filename(cleaned)
    except SecurityError:
        return "file" + safe_suffix


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


def _page(body: str) -> str:
    return (
        "<!DOCTYPE html><html lang=\"it\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>LocalDrop</title><link rel=\"stylesheet\" href=\"/glass.css\"></head><body>"
        f"<div class=\"shell\">{body}</div></body></html>"
    )


def _login_page(message: str) -> str:
    note = f"<p class=\"note\">{_esc(message)}</p>" if message else ""
    return _page(
        "<h1>LocalDrop</h1><p class=\"subtitle\">Inserisci il codice che vedi sul computer.</p>"
        + note
        + "<section class=\"glass\"><form method=\"post\" action=\"/unlock\">"
        + "<input class=\"code-input\" name=\"pin\" inputmode=\"numeric\" autocomplete=\"off\" autofocus placeholder=\"Inserisci il codice\">"
        + "<button class=\"primary\" type=\"submit\">Entra</button></form></section>"
    )


def _home_page(shares: list[tuple[str, str]], received: list[str], sent: list[tuple[str, str]], notice: str, error: str) -> str:
    parts = ["<h1>LocalDrop</h1>"]
    if notice:
        parts.append(f"<p class=\"note\">{_esc(notice)}</p>")
    if error:
        parts.append(f"<p class=\"note\">{_esc(error)}</p>")
    parts.append("<section class=\"glass\"><h2>Invia al computer</h2>")
    parts.append("<div class=\"bar\"><div id=\"bar-fill\"></div></div><p class=\"hint\" id=\"bar-label\"></p>")
    parts.append("<div class=\"list\" id=\"local-preview\"></div>")
    parts.append("<form class=\"upload\" method=\"post\" action=\"/upload\" enctype=\"multipart/form-data\">")
    parts.append("<input id=\"files\" type=\"file\" name=\"files\" multiple required>")
    parts.append("<button class=\"primary\" type=\"submit\">Invia al computer</button></form>")
    if sent:
        parts.append("<p class=\"empty\" style=\"margin-top:12px\">Già inviati. Reinvia senza scegliere di nuovo il file.</p><div class=\"list\">")
        for file_id, name in sent:
            parts.append(
                f"<form method=\"post\" action=\"/resend/{file_id}\"><div class=\"item\">{_esc(name)}"
                "<button class=\"ghost\" type=\"submit\" style=\"margin-top:8px;width:100%\">Reinvia</button></div></form>"
            )
        parts.append("</div>")
    if received:
        parts.append("<p class=\"empty\" style=\"margin-top:12px\">In attesa sul computer</p><div class=\"list\">")
        for name in received:
            parts.append(f"<div class=\"item\">{_esc(name)}</div>")
        parts.append("</div>")
    parts.append("</section><section class=\"glass\"><h2>Scarica dal computer</h2>")
    if not shares:
        parts.append("<p class=\"empty\">Nessun file. Sul computer scegli i file da mandare al telefono.</p>")
    else:
        parts.append("<div class=\"list\">")
        for file_id, name in shares:
            kind, _mime = _media_kind(name)
            parts.append(f"<a class=\"file-link secondary\" href=\"/file/{file_id}\" data-name=\"{_esc(name)}\">{_esc(name)}</a>")
            if kind == "image":
                parts.append(f"<img class=\"preview\" src=\"/preview/{file_id}\" alt=\"\">")
                parts.append(f"<a class=\"primary\" href=\"/view/{file_id}\" style=\"margin-top:8px\">Salva in Foto</a>")
            elif kind == "video":
                parts.append(f"<a class=\"primary\" href=\"/view/{file_id}\" style=\"margin-top:8px\">Salva video in Foto</a>")
        parts.append("</div>")
    parts.append("</section>")
    parts.append(
        "<script>"
        "const input=document.getElementById('files');"
        "const local=document.getElementById('local-preview');"
        "const fill=document.getElementById('bar-fill');"
        "const label=document.getElementById('bar-label');"
        "function setBar(name,pct){fill.style.width=pct+'%';label.textContent=name+' '+pct+'%';}"
        "input.addEventListener('change',()=>{local.innerHTML='';[...input.files].forEach(file=>{"
        "if(!file.type.startsWith('image/'))return;const img=document.createElement('img');"
        "img.className='preview';img.src=URL.createObjectURL(file);local.appendChild(img);});});"
        "document.querySelector('form.upload').addEventListener('submit',(event)=>{"
        "event.preventDefault();const xhr=new XMLHttpRequest();xhr.open('POST','/upload');"
        "xhr.upload.onprogress=(e)=>{if(e.lengthComputable)setBar('Invio',Math.round(e.loaded*100/e.total));};"
        "xhr.onload=()=>{location.href=xhr.responseURL||'/?ok=1';};xhr.send(new FormData(event.target));});"
        "document.querySelectorAll('a.file-link').forEach(link=>link.addEventListener('click',async(event)=>{"
        "event.preventDefault();const response=await fetch(link.href);"
        "const total=Number(response.headers.get('Content-Length')||0);const reader=response.body.getReader();"
        "const chunks=[];let sent=0;while(true){const step=await reader.read();if(step.done)break;chunks.push(step.value);sent+=step.value.length;"
        "setBar(link.textContent.trim(),total?Math.round(sent*100/total):0);}"
        "const url=URL.createObjectURL(new Blob(chunks));const a=document.createElement('a');a.href=url;a.download=link.textContent.trim();a.click();}));"
        "</script>"
    )
    return _page("".join(parts))


def _gallery_page(file_id: str, name: str) -> str:
    kind, mime = _media_kind(name)
    if kind == "image":
        media = f"<img class=\"preview\" src=\"/raw/{file_id}\" alt=\"{_esc(name)}\" style=\"max-height:none\">"
        hint = "Tieni premuta la foto e scegli Salva immagine. Va in Foto, con la qualità originale."
    else:
        media = f"<video class=\"preview\" src=\"/raw/{file_id}\" controls playsinline style=\"max-height:70vh\"></video>"
        hint = "Tieni premuto il video e scegli Salva video. Va in Foto, con la qualità originale."
    return _page(
        f"<h1>{_esc(name)}</h1><section class=\"glass\">{media}"
        f"<p class=\"subtitle\">{hint}</p>"
        f"<a class=\"primary\" href=\"/\">Torna indietro</a></section>"
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


def _message_page(message: str) -> str:
    return _page(f"<p>{_esc(message)}</p>")
