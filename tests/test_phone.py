from __future__ import annotations

import http.client
import ipaddress
import ssl
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from app.i18n import format_duration
from app.phone.server import PhoneBridge, _safe_name, client_on_lan
from app.settings_store import Settings


def _body(filename: str, content: bytes, boundary: str = "bound") -> bytes:
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="files"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    return head + content + f"\r\n--{boundary}--\r\n".encode()


class PhonePageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.bridge = PhoneBridge(Path(self.directory.name), max_file_bytes=1024)
        self.bridge.start(0)
        context = ssl._create_unverified_context()
        self.conn = http.client.HTTPSConnection("127.0.0.1", self.bridge.port, timeout=5, context=context)

    def tearDown(self) -> None:
        self.conn.close()
        self.bridge.stop()
        self.directory.cleanup()

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {
            "X-LocalDrop-CSRF": self.bridge.form_token,
            "X-Requested-With": "LocalDrop",
        }
        if extra:
            headers.update(extra)
        return headers

    def _cookie(self) -> str:
        body = f"pin={self.bridge.pin}&csrf={self.bridge.form_token}"
        self.conn.request(
            "POST",
            "/unlock",
            body,
            self._headers({"Content-Type": "application/x-www-form-urlencoded"}),
        )
        response = self.conn.getresponse()
        response.read()
        cookie = response.getheader("Set-Cookie") or ""
        self.assertIn("ld=", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Secure", cookie)
        return cookie.split(";", 1)[0]

    def test_qr_token_survives_the_certificate_prompt(self) -> None:
        token = self.bridge.fresh_ticket()
        self.conn.request("GET", f"/?t={token}")
        response = self.conn.getresponse()
        response.read()
        self.assertEqual(response.status, 303)
        self.assertIn("ld=", response.getheader("Set-Cookie") or "")
        self.assertEqual(response.getheader("Location"), "/")
        self.conn.request("GET", f"/?t={token}")
        again = self.conn.getresponse()
        again.read()
        self.assertEqual(again.status, 303)
        cookie = (again.getheader("Set-Cookie") or "").split(";", 1)[0]
        self.conn.request("GET", "/", headers={"Cookie": cookie})
        home = self.conn.getresponse()
        page = home.read()
        self.assertEqual(home.status, 200)
        self.assertIn(b"Send to computer", page)
        self.conn.request("GET", f"/?t={token}")
        spent = self.conn.getresponse()
        spent.read()
        self.assertNotEqual(spent.status, 303)

    def test_expired_and_modified_qr_tokens_are_refused(self) -> None:
        token = self.bridge.fresh_ticket()
        self.bridge._tickets[token] = time.monotonic() - 5
        self.conn.request("GET", f"/?t={token}")
        expired = self.conn.getresponse()
        expired.read()
        self.assertNotEqual(expired.status, 303)
        modified = token[:-1] + ("A" if token[-1] != "A" else "B")
        self.conn.request("GET", f"/?t={modified}")
        changed = self.conn.getresponse()
        changed.read()
        self.assertNotEqual(changed.status, 303)

    def test_pin_in_the_address_does_not_open_the_page(self) -> None:
        self.conn.request("GET", f"/?pin={self.bridge.pin}")
        response = self.conn.getresponse()
        response.read()
        self.assertNotIn("ld=", response.getheader("Set-Cookie") or "")
        self.assertNotEqual(response.status, 303)

    def test_login_page_can_scan_the_qr_again(self) -> None:
        self.conn.request("GET", "/")
        page = self.conn.getresponse()
        body = page.read()
        self.assertEqual(page.status, 200)
        self.assertIn(b"Scan the QR", body)
        self.assertIn(b"/jsqr.js", body)
        self.assertIn(b"id=\"scan\"", body)
        self.conn.request("GET", "/jsqr.js")
        script = self.conn.getresponse()
        source = script.read()
        self.assertEqual(script.status, 200)
        self.assertIn(b"function jsQR", source)
        self.bridge.set_language("it")
        self.conn.request("GET", "/")
        italian = self.conn.getresponse().read()
        self.assertIn("Scansiona il QR".encode(), italian)
        self.assertIn("Inquadra il codice sul computer.".encode(), italian)

    def test_wrong_pin_hides_page(self) -> None:
        body = f"pin=000000&csrf={self.bridge.form_token}"
        self.conn.request("POST", "/unlock", body, self._headers({"Content-Type": "application/x-www-form-urlencoded"}))
        response = self.conn.getresponse()
        body = response.read()
        self.assertEqual(response.status, 401)
        self.assertNotIn(b"Send to computer", body)

    def test_language_defaults_to_english_and_can_switch_to_italian(self) -> None:
        cookie = self._cookie()
        self.conn.request("GET", "/", headers={"Cookie": cookie})
        english = self.conn.getresponse().read()
        self.assertIn(b"Send to computer", english)
        self.assertIn(b'lang="en"', english)
        body = f"lang=it&csrf={self.bridge.form_token}"
        self.conn.request("POST", "/language", body, self._headers({"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie}))
        switched = self.conn.getresponse()
        switched.read()
        self.assertEqual(switched.status, 303)
        self.assertEqual(self.bridge.language, "it")
        self.conn.request("GET", "/", headers={"Cookie": cookie})
        italian = self.conn.getresponse().read()
        self.assertIn("Invia al computer".encode(), italian)
        self.assertIn(b'lang="it"', italian)
        self.bridge.set_language("nope")
        self.assertEqual(self.bridge.language, "en")

    def test_finished_transfer_records_how_long_it_took(self) -> None:
        self.assertEqual(format_duration(3.24), "3.2 s")
        self.assertEqual(format_duration(61.2), "1 min 1 s")
        lines: list[tuple[str, object]] = []
        self.bridge.on_event = lambda kind, payload: lines.append((kind, payload))
        self.bridge.language = "it"
        path = Path(self.directory.name) / "nota.txt"
        path.write_bytes(b"abc")
        self.bridge.hold(path, seconds=3.2)
        self.assertIn(("phone-log", "In attesa: nota.txt · 3.2 s"), lines)
        progress = [payload for kind, payload in lines if kind == "phone-progress"]
        self.assertTrue(progress)
        self.assertIn("seconds", progress[-1])

    def test_clear_history_removes_waiting_items_and_keeps_originals(self) -> None:
        source = Path(self.directory.name) / "nota.txt"
        source.write_bytes(b"abc")
        self.bridge.share([source])
        self.bridge.share_clipboard = True
        self.assertTrue(self.bridge.push_clip("segreto", "pc"))
        owned = self.bridge._staging / "owned.txt"
        owned.write_bytes(b"secret")
        self.bridge.hold(owned, remember=False)
        self.bridge.clear_history()
        self.assertEqual(self.bridge.inbox_items(), [])
        self.assertEqual(self.bridge.share_entries(), [])
        self.assertEqual(self.bridge.pc_sent_entries(), [])
        self.assertEqual(self.bridge.sent_uploads(), [])
        self.assertEqual(self.bridge.clip_snapshot()["items"], [])
        self.assertFalse(owned.exists())
        self.assertEqual(source.read_bytes(), b"abc")

    def test_history_button_clears_the_phone_page(self) -> None:
        cookie = self._cookie()
        source = Path(self.directory.name) / "nota.txt"
        source.write_bytes(b"abc")
        self.bridge.share([source])
        self.conn.request("POST", "/history", "", {"Content-Length": "0"})
        refused = self.conn.getresponse()
        refused.read()
        self.assertEqual(refused.status, 401)
        self.conn.request("POST", "/history", "", self._headers({"Cookie": cookie, "Content-Length": "0"}))
        cleared = self.conn.getresponse()
        cleared.read()
        self.assertEqual(cleared.status, 200)
        self.assertEqual(self.bridge.share_entries(), [])
        self.conn.request("GET", "/", headers={"Cookie": cookie})
        page = self.conn.getresponse().read()
        self.assertIn(b"Clear history", page)
        self.assertNotIn(b"Already sent", page)
        self.assertTrue(source.is_file())

    def test_upload_waits_until_a_folder_is_chosen(self) -> None:
        cookie = self._cookie()
        payload = _body("foto.jpg", b"hello-phone")
        self.conn.request(
            "POST",
            "/upload",
            payload,
            self._headers({"Content-Type": "multipart/form-data; boundary=bound", "Content-Length": str(len(payload)), "Cookie": cookie}),
        )
        response = self.conn.getresponse()
        response.read()
        self.assertEqual(response.status, 303)
        location = response.getheader("Location") or ""
        self.assertIn("ok=1", location)
        self.assertIn("s=", location)
        self.conn.request("GET", location, headers={"Cookie": cookie})
        page = self.conn.getresponse().read()
        self.assertIn(b"Loaded in", page)
        self.assertIn(b" s.", page)
        self.assertFalse((Path(self.directory.name) / "foto.jpg").exists())
        waiting = self.bridge.inbox_items()
        self.assertEqual(len(waiting), 1)
        destination = tempfile.TemporaryDirectory()
        self.addCleanup(destination.cleanup)
        self.bridge.save_incoming([str(waiting[0]["id"])], destination.name)
        saved = Path(destination.name) / "foto.jpg"
        self.assertEqual(saved.read_bytes(), b"hello-phone")
        self.assertEqual(self.bridge.inbox_items(), [])
        self.assertEqual(self.bridge.pc_sent_entries(), [])
        sent = self.bridge.sent_uploads()
        self.assertEqual(len(sent), 1)
        self.conn.request("POST", f"/resend/{sent[0][0]}", "", self._headers({"Cookie": cookie, "Content-Length": "0"}))
        again = self.conn.getresponse()
        again.read()
        self.assertEqual(again.status, 303)
        waiting = self.bridge.inbox_items()
        self.assertEqual(len(waiting), 1)
        stored = self.bridge._inbox[str(waiting[0]["id"])]
        self.assertEqual(stored.read_bytes(), b"hello-phone")

    def test_cleared_share_can_be_sent_again(self) -> None:
        source = Path(self.directory.name) / "nota.txt"
        source.write_bytes(b"abc")
        self.bridge.share([source])
        self.bridge.clear_shares()
        self.assertEqual(self.bridge.share_entries(), [])
        sent = self.bridge.pc_sent_entries()
        self.bridge.resend_share(sent[0]["id"])
        self.assertEqual([item["name"] for item in self.bridge.share_entries()], ["nota.txt"])

    def test_upload_without_code_is_refused(self) -> None:
        payload = _body("segreto.txt", b"nascosto")
        self.conn.request(
            "POST",
            "/upload",
            payload,
            {"Content-Type": "multipart/form-data; boundary=bound", "Content-Length": str(len(payload))},
        )
        response = self.conn.getresponse()
        response.read()
        self.assertEqual(response.status, 401)
        self.assertFalse((Path(self.directory.name) / "segreto.txt").exists())

    def test_traversal_name_stays_in_folder(self) -> None:
        cookie = self._cookie()
        payload = _body("../../segreto.txt", b"ok")
        self.conn.request(
            "POST",
            "/upload",
            payload,
            self._headers({"Content-Type": "multipart/form-data; boundary=bound", "Content-Length": str(len(payload)), "Cookie": cookie}),
        )
        response = self.conn.getresponse()
        response.read()
        self.assertFalse((Path(self.directory.name) / "segreto.txt").exists())
        waiting = self.bridge.inbox_items()
        self.assertEqual(waiting[0]["name"], "segreto.txt")
        staged = self.bridge._inbox[str(waiting[0]["id"])]
        self.assertIn(self.bridge._staging.resolve(), staged.resolve().parents)
        self.assertEqual(len(staged.name), 32)
        self.assertNotIn("segreto", staged.name)

    def test_oversized_upload_is_removed(self) -> None:
        cookie = self._cookie()
        payload = _body("grande.bin", b"x" * 2000)
        self.conn.request(
            "POST",
            "/upload",
            payload,
            self._headers({"Content-Type": "multipart/form-data; boundary=bound", "Content-Length": str(len(payload)), "Cookie": cookie}),
        )
        response = self.conn.getresponse()
        response.read()
        self.assertEqual(response.status, 303)
        self.assertEqual(response.getheader("Location"), "/?err=size")
        self.assertEqual(list(Path(self.directory.name).iterdir()), [])
        self.assertEqual(self.bridge.inbox_items(), [])

    def test_download_requires_code_and_returns_bytes(self) -> None:
        source = Path(self.directory.name) / "dal-pc.txt"
        source.write_bytes(b"verso-telefono")
        self.bridge.share([source])
        file_id = next(iter(self.bridge._shares))
        self.conn.request("GET", f"/file/{file_id}")
        blocked = self.conn.getresponse()
        blocked_body = blocked.read()
        self.assertEqual(blocked.status, 401)
        self.assertNotIn(b"verso-telefono", blocked_body)
        cookie = self._cookie()
        self.conn.request("GET", f"/file/{file_id}", headers={"Cookie": cookie})
        allowed = self.conn.getresponse()
        self.assertEqual(allowed.read(), b"verso-telefono")
        self.assertEqual(len(file_id), 32)


    def test_clipboard_reaches_the_computer_and_then_expires(self) -> None:
        cookie = self._cookie()
        blocked = "text=segreto"
        self.conn.request(
            "POST",
            "/clip",
            blocked,
            self._headers({"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(blocked)), "Cookie": cookie}),
        )
        denied = self.conn.getresponse()
        denied.read()
        self.assertEqual(denied.status, 403)
        self.bridge.share_clipboard = True
        payload = "text=otp-482913"
        self.conn.request(
            "POST",
            "/clip",
            payload,
            self._headers({"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(payload)), "Cookie": cookie}),
        )
        accepted = self.conn.getresponse()
        accepted.read()
        self.assertEqual(accepted.status, 200)
        self.conn.request("GET", "/clips", headers=self._headers({"Cookie": cookie}))
        listed = self.conn.getresponse()
        listed.read()
        self.assertEqual(self.bridge.clip_snapshot()["items"][0]["text"], "otp-482913")
        self.bridge.expire_seconds = 0
        self.bridge.expire_due()
        self.assertEqual(self.bridge.clip_snapshot()["items"], [])

    def test_uploaded_file_expires_without_deleting_a_real_file(self) -> None:
        cookie = self._cookie()
        payload = _body("nota.txt", b"temporaneo")
        self.conn.request(
            "POST",
            "/upload",
            payload,
            self._headers({"Content-Type": "multipart/form-data; boundary=bound", "Content-Length": str(len(payload)), "Cookie": cookie}),
        )
        response = self.conn.getresponse()
        response.read()
        self.assertEqual(len(self.bridge.inbox_items()), 1)
        kept = Path(self.directory.name) / "tieni.txt"
        kept.write_text("resto", encoding="utf-8")
        self.bridge.share([kept])
        self.bridge.expire_seconds = 0
        self.bridge.expire_due()
        self.assertEqual(self.bridge.inbox_items(), [])
        self.assertEqual(self.bridge.snapshot()[0], [])
        self.assertEqual(kept.read_text(encoding="utf-8"), "resto")


class LanAccessTests(unittest.TestCase):
    def test_allows_same_network_and_blocks_outsiders(self) -> None:
        with patch(
            "app.phone.server.local_ipv4_networks",
            return_value=[ipaddress.IPv4Interface("192.168.1.20/24")],
        ):
            self.assertTrue(client_on_lan("127.0.0.1"))
            self.assertTrue(client_on_lan("192.168.1.55"))
            self.assertFalse(client_on_lan("8.8.8.8"))
            self.assertFalse(client_on_lan("10.0.0.4"))
            self.assertFalse(client_on_lan("2001:4860:4860::8888"))

    def test_link_local_ipv6_stays_on_the_local_prefix(self) -> None:
        with patch(
            "app.phone.server.local_ipv6_link_networks",
            return_value=[ipaddress.IPv6Network("fe80::/64")],
        ):
            self.assertTrue(client_on_lan("fe80::1234"))
            self.assertFalse(client_on_lan("2001:db8::5"))
        with patch("app.phone.server.local_ipv6_link_networks", return_value=[ipaddress.IPv6Network("fe80::/64")]):
            with patch("app.phone.server.interface_allowed", return_value=False):
                self.assertFalse(client_on_lan("fe80::1234%12"))
            with patch("app.phone.server.interface_allowed", return_value=True):
                self.assertTrue(client_on_lan("fe80::1234%12"))

    def test_virtual_adapters_are_not_a_lan(self) -> None:
        from app.network.adapters import adapter_allowed

        self.assertTrue(adapter_allowed(6, "Ethernet", 1))
        self.assertTrue(adapter_allowed(71, "Wi-Fi", 1))
        self.assertFalse(adapter_allowed(131, "WireGuard Tunnel", 1))
        self.assertFalse(adapter_allowed(6, "vEthernet (WSL)", 1))
        self.assertFalse(adapter_allowed(6, "Ethernet", 2))


class SafeNameTests(unittest.TestCase):
    def test_keeps_plain_name(self) -> None:
        self.assertEqual(_safe_name("foto.jpg"), "foto.jpg")

    def test_drops_directories(self) -> None:
        self.assertEqual(_safe_name("..\\..\\foto.jpg"), "foto.jpg")

    def test_double_encoding_does_not_escape_the_folder(self) -> None:
        self.assertEqual(_safe_name("%252e%252e%252fsegreto.txt"), "segreto.txt")
        self.assertNotIn("..", _safe_name("%252e%252e%252f"))
        nested = "../segreto.txt"
        for _ in range(9):
            nested = urllib.parse.quote(nested, safe="")
        self.assertEqual(_safe_name(nested), "file")
        self.assertEqual(_safe_name("CON"), "file")
        self.assertEqual(_safe_name("COM1"), "file")
        self.assertEqual(_safe_name("caf\u00e9.txt"), "café.txt")
        self.assertEqual(_safe_name(""), "file")
        self.assertEqual(_safe_name("a\x01b.txt"), "ab.txt")


class PinLockTests(unittest.TestCase):
    def test_one_address_and_its_subnet_lock(self) -> None:
        bridge = PhoneBridge(Path(tempfile.mkdtemp()), max_file_bytes=1024)
        self.addCleanup(bridge.stop)
        self.assertEqual(len(bridge.pin), 8)
        address = "192.0.2.8"
        for _ in range(5):
            self.assertFalse(bridge.check_pin("00000000", address))
        self.assertFalse(bridge.check_pin(bridge.pin, address))
        other = PhoneBridge(Path(tempfile.mkdtemp()), max_file_bytes=1024)
        self.addCleanup(other.stop)
        for index in range(5):
            self.assertFalse(other.check_pin("00000000", f"10.9.8.{index + 1}"))
        self.assertFalse(other.check_pin(other.pin, "10.9.8.200"))

    def test_global_failures_change_the_pin(self) -> None:
        bridge = PhoneBridge(Path(tempfile.mkdtemp()), max_file_bytes=1024)
        self.addCleanup(bridge.stop)
        previous = bridge.pin
        for index in range(20):
            bridge.check_pin("00000000", f"198.51.{index}.1")
        self.assertNotEqual(bridge.pin, previous)

    def test_logs_hide_the_pin_and_the_qr_token(self) -> None:
        from app.phone.server import _redact_log

        text = _redact_log("GET /?t=sekret&x=1 pin=12345678")
        self.assertNotIn("sekret", text)
        self.assertNotIn("12345678", text)
        self.assertIn("pin=***", text)
        self.assertIn("t=***", text)


class LanguageStoreTests(unittest.TestCase):
    def test_language_is_english_until_saved(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = Path(folder.name) / "settings.json"
        settings = Settings.load(path)
        self.assertEqual(settings.language, "en")
        settings.language = "it"
        settings.save(path)
        again = Settings.load(path)
        self.assertEqual(again.language, "it")
        settings.language = "fr"
        settings.save(path)
        self.assertEqual(Settings.load(path).language, "en")
