from __future__ import annotations

import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from app.device.identity import (
    DeviceIdentity,
    default_device_name,
    load_or_create,
    normalize_device_name,
)


class NormalizeDeviceNameTests(unittest.TestCase):
    def test_collapses_whitespace(self) -> None:
        self.assertEqual(normalize_device_name("  DESKTOP   BOGDAN  "), "DESKTOP BOGDAN")

    def test_rejects_empty_name(self) -> None:
        with self.assertRaises(ValueError):
            normalize_device_name("   ")

    def test_rejects_name_too_long(self) -> None:
        with self.assertRaises(ValueError):
            normalize_device_name("A" * 65)


class DefaultDeviceNameTests(unittest.TestCase):
    def test_uses_hostname(self) -> None:
        with patch("app.device.identity.socket.gethostname", return_value="LAPTOP"):
            self.assertEqual(default_device_name(), "LAPTOP")

    def test_falls_back_when_hostname_is_blank(self) -> None:
        with patch("app.device.identity.socket.gethostname", return_value="  "):
            self.assertEqual(default_device_name(), "LocalDrop")


class LoadOrCreateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)

    def test_creates_persistent_identity(self) -> None:
        path = Path(self._tmpdir.name) / "identity.json"

        with patch("app.device.identity.socket.gethostname", return_value="DESKTOP-BOGDAN"):
            created = load_or_create(path)
            reloaded = load_or_create(path)

        self.assertEqual(created.device_id, reloaded.device_id)
        self.assertEqual(created.device_name, "DESKTOP-BOGDAN")
        uuid.UUID(created.device_id)
        stored = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(stored["device_id"], created.device_id)
        self.assertEqual(stored["device_name"], "DESKTOP-BOGDAN")

    def test_rename_keeps_device_id(self) -> None:
        path = self._temp_path("rename")
        identity = load_or_create(path)
        original_id = identity.device_id

        identity.rename("  LAPTOP   UFFICIO ")
        reloaded = load_or_create(path)

        self.assertEqual(reloaded.device_id, original_id)
        self.assertEqual(reloaded.device_name, "LAPTOP UFFICIO")

    def test_rename_rejects_empty_name_without_writing(self) -> None:
        path = self._temp_path("empty")
        identity = load_or_create(path)
        before = path.read_text(encoding="utf-8")

        with self.assertRaises(ValueError):
            identity.rename(" ")

        self.assertEqual(path.read_text(encoding="utf-8"), before)
        self.assertNotEqual(identity.device_name, "")

    def test_rejects_invalid_json(self) -> None:
        path = self._temp_path("invalid")
        path.write_text("{", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_or_create(path)

    def test_rejects_invalid_uuid(self) -> None:
        path = self._temp_path("uuid")
        path.write_text(
            json.dumps({"device_id": "not-a-uuid", "device_name": "PC"}),
            encoding="utf-8",
        )
        with self.assertRaises(ValueError):
            load_or_create(path)

    def _temp_path(self, suffix: str) -> Path:
        return Path(self._tmpdir.name) / f"{suffix}.json"


class DeviceIdentitySaveTests(unittest.TestCase):
    def test_save_creates_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "nested" / "identity.json"
            identity = DeviceIdentity(
                device_id=str(uuid.uuid4()),
                device_name="PC",
                path=path,
            )
            identity.save()
            self.assertTrue(path.is_file())


if __name__ == "__main__":
    unittest.main()
