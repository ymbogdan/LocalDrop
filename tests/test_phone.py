from __future__ import annotations

import http.client
import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.phone.server import PhoneBridge, _safe_name, client_on_lan


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
        self.conn = http.client.HTTPConnection("127.0.0.1", self.bridge.port, timeout=5)

    def tearDown(self) -> None:
        self.conn.close()
        self.bridge.stop()
        self.directory.cleanup()

    def _cookie(self) -> str:
        self.conn.request("POST", "/unlock", f"pin={self.bridge.pin}", {"Content-Type": "application/x-www-form-urlencoded"})
        response = self.conn.getresponse()
        response.read()
        cookie = response.getheader("Set-Cookie") or ""
        self.assertIn("ld=", cookie)
        return cookie.split(";", 1)[0]

    def test_qr_pin_opens_the_page(self) -> None:
        self.conn.request("GET", f"/?pin={self.bridge.pin}")
        response = self.conn.getresponse()
        response.read()
        self.assertEqual(response.status, 303)
        self.assertIn("ld=", response.getheader("Set-Cookie") or "")
        self.assertEqual(response.getheader("Location"), "/")

    def test_wrong_pin_hides_page(self) -> None:
        self.conn.request("POST", "/unlock", "pin=000000", {"Content-Type": "application/x-www-form-urlencoded"})
        response = self.conn.getresponse()
        body = response.read()
        self.assertEqual(response.status, 401)
        self.assertNotIn(b"Invia al computer", body)

    def test_upload_waits_until_a_folder_is_chosen(self) -> None:
        cookie = self._cookie()
        payload = _body("foto.jpg", b"hello-phone")
        self.conn.request(
            "POST",
            "/upload",
            payload,
            {"Content-Type": "multipart/form-data; boundary=bound", "Content-Length": str(len(payload)), "Cookie": cookie},
        )
        response = self.conn.getresponse()
        response.read()
        self.assertEqual(response.status, 303)
        self.assertFalse((Path(self.directory.name) / "foto.jpg").exists())
        waiting = self.bridge.inbox_items()
        self.assertEqual(len(waiting), 1)
        destination = tempfile.TemporaryDirectory()
        self.addCleanup(destination.cleanup)
        self.bridge.save_incoming([str(waiting[0]["id"])], destination.name)
        saved = Path(destination.name) / "foto.jpg"
        self.assertEqual(saved.read_bytes(), b"hello-phone")
        self.assertEqual(self.bridge.inbox_items(), [])
        sent = self.bridge.sent_uploads()
        self.assertEqual(len(sent), 1)
        self.conn.request("POST", f"/resend/{sent[0][0]}", "", {"Cookie": cookie, "Content-Length": "0"})
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
            {"Content-Type": "multipart/form-data; boundary=bound", "Content-Length": str(len(payload)), "Cookie": cookie},
        )
        response = self.conn.getresponse()
        response.read()
        self.assertFalse((Path(self.directory.name) / "segreto.txt").exists())
        waiting = self.bridge.inbox_items()
        self.assertEqual(waiting[0]["name"], "segreto.txt")
        staged = self.bridge._inbox[str(waiting[0]["id"])]
        self.assertEqual(staged.parent, self.bridge._staging)

    def test_oversized_upload_is_removed(self) -> None:
        cookie = self._cookie()
        payload = _body("grande.bin", b"x" * 2000)
        self.conn.request(
            "POST",
            "/upload",
            payload,
            {"Content-Type": "multipart/form-data; boundary=bound", "Content-Length": str(len(payload)), "Cookie": cookie},
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


class SafeNameTests(unittest.TestCase):
    def test_keeps_plain_name(self) -> None:
        self.assertEqual(_safe_name("foto.jpg"), "foto.jpg")

    def test_drops_directories(self) -> None:
        self.assertEqual(_safe_name("..\\..\\foto.jpg"), "foto.jpg")
