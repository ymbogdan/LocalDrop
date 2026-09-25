from __future__ import annotations

import json
import queue
import threading
from pathlib import Path

import webview

from app.phone.media import qr_data_url


class DesktopApi:
    def __init__(self, commands: queue.Queue) -> None:
        self.commands = commands
        self._result: dict[str, bool] | None = None
        self._done: threading.Event | None = None

    def choose_files(self) -> None:
        selected = webview.windows[0].create_file_dialog(webview.OPEN_DIALOG, allow_multiple=True)
        if selected:
            self.commands.put(("share", list(selected)))

    def clear_shares(self) -> None:
        self.commands.put(("clear-shares",))

    def copy_text(self, value: str) -> None:
        webview.windows[0].evaluate_js(
            "navigator.clipboard.writeText(" + json.dumps(value) + ")"
        )

    def open_settings(self) -> None:
        self.commands.put(("settings",))

    def save_settings(self, name: str, folder: str, limit: str, slots: str) -> None:
        self.commands.put(("save-settings", name, folder, limit, slots))

    def pick_folder(self) -> str:
        selected = webview.windows[0].create_file_dialog(webview.FOLDER_DIALOG)
        if not selected:
            return ""
        return selected[0]

    def save_incoming(self, file_ids: list[str], folder: str) -> None:
        if file_ids and folder:
            self.commands.put(("save-incoming", list(file_ids), folder))

    def discard_incoming(self, file_ids: list[str]) -> None:
        if file_ids:
            self.commands.put(("discard-incoming", list(file_ids)))

    def resend_share(self, file_id: str) -> None:
        self.commands.put(("resend-share", file_id))

    def offer_incoming(self, file_ids: list[str]) -> None:
        if file_ids:
            self.commands.put(("offer-incoming", list(file_ids)))

    def forget(self, device_id: str) -> None:
        self.commands.put(("forget", device_id))

    def answer(self, ok: bool) -> None:
        if self._result is not None:
            self._result["ok"] = bool(ok)
        if self._done is not None:
            self._done.set()
        self._result = None
        self._done = None


class MainWindow:
    def __init__(self, commands: queue.Queue, events: queue.Queue) -> None:
        self.commands = commands
        self.events = events
        self.api = DesktopApi(commands)
        self.window: webview.Window | None = None
        self._activity: list[str] = []

    def _push(self, script: str) -> None:
        window = self.window
        if window is not None:
            window.evaluate_js(script)

    def _pump(self) -> None:
        while True:
            event = self.events.get()
            kind = event[0]
            if kind == "phone-link":
                urls, pin, folder = event[1:]
                digits = "".join(ch for ch in pin if ch.isdigit())
                opened = f"{urls[0]}/?pin={digits}" if urls and digits else ""
                qr = qr_data_url(opened) if opened else ""
                self._push(
                    "window.localdrop.link("
                    + json.dumps(urls) + ", "
                    + json.dumps(pin) + ", "
                    + json.dumps(folder) + ", "
                    + json.dumps(qr) + ")"
                )
            elif kind == "phone-shares":
                self._push(f"window.localdrop.shares({json.dumps(event[1])})")
            elif kind == "phone-sent":
                self._push(f"window.localdrop.sent({json.dumps(event[1])})")
            elif kind == "phone-inbox":
                self._push(f"window.localdrop.inbox({json.dumps(event[1])})")
            elif kind == "phone-progress":
                self._push(f"window.localdrop.progress({json.dumps(event[1])})")
            elif kind == "phone-log":
                self._push(f"window.localdrop.log({json.dumps(event[1])})")
            elif kind == "progress":
                _transfer_id, name, sent, total, speed, eta, state = event[1:]
                percent = 0 if total == 0 else int(sent * 100 / total)
                line = f"{name}  {percent}%  {state}"
                self._push(f"window.localdrop.log({json.dumps(line)})")
                self._push(f"window.localdrop.progress({json.dumps({'name': name, 'sent': sent, 'total': total})})")
            elif kind == "pair":
                name, fingerprint, code, result, done = event[1:]
                self.api._result = result
                self.api._done = done
                body = f"{name}\n\nFingerprint:\n{fingerprint}\n\nCodice:\n{code}\n\nI codici coincidono?"
                self._push(f"window.localdrop.ask('pair', 'Pairing', {json.dumps(body)})")
            elif kind == "incoming":
                name, size, sender, result, done = event[1:]
                self.api._result = result
                self.api._done = done
                body = f"{name}\n{size} byte\n\nDa:\n{sender}"
                self._push(f"window.localdrop.ask('incoming', 'File in arrivo', {json.dumps(body)})")
            elif kind == "settings":
                self._push(f"window.localdrop.settings({json.dumps(event[1])})")
            elif kind == "error":
                self._push(f"window.localdrop.ask('error', 'LocalDrop', {json.dumps(event[1])})")
            elif kind == "closed":
                return

    def run(self) -> None:
        page = Path(__file__).resolve().parent / "desktop.html"
        self.window = webview.create_window(
            "LocalDrop",
            url=page.as_uri(),
            js_api=self.api,
            width=640,
            height=980,
            min_size=(520, 760),
            background_color="#E7EEF4",
        )
        self.window.events.loaded += lambda: threading.Thread(target=self._pump, daemon=True).start()
        self.window.events.closing += self.close
        webview.start()

    def close(self) -> None:
        self.commands.put(("quit",))
        self.events.put(("closed",))
