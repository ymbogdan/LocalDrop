from __future__ import annotations

import json
import queue
import threading
from pathlib import Path

import webview

from app.gui.clipboard import clear_if, read_text, write_text
from app.i18n import normalize_language, tr
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

    def clear_history(self) -> None:
        self.commands.put(("clear-history",))

    def copy_text(self, value: str) -> None:
        webview.windows[0].evaluate_js(
            "navigator.clipboard.writeText(" + json.dumps(value) + ")"
        )

    def open_settings(self) -> None:
        self.commands.put(("settings",))

    def save_settings(self, name: str, folder: str, limit: str, slots: str, minutes: str, share: bool) -> None:
        enabled = share is True or str(share).lower() in {"1", "true", "on", "yes"}
        self.commands.put(("save-settings", name, folder, limit, slots, str(minutes), "true" if enabled else "false"))

    def set_share_clipboard(self, enabled: bool) -> None:
        self.commands.put(("share-clipboard", bool(enabled)))

    def read_clipboard(self) -> str:
        return read_text()

    def send_clip(self, text: str) -> None:
        self.commands.put(("clip-to-phone", text))

    def pick_folder(self) -> str:
        selected = webview.windows[0].create_file_dialog(webview.FOLDER_DIALOG)
        if not selected:
            return ""
        return selected[0]

    def save_incoming(self, file_ids: list[str], folder: str) -> None:
        if file_ids:
            self.commands.put(("save-incoming", list(file_ids), folder or ""))

    def discard_incoming(self, file_ids: list[str]) -> None:
        if file_ids:
            self.commands.put(("discard-incoming", list(file_ids)))

    def resend_share(self, file_id: str) -> None:
        self.commands.put(("resend-share", file_id))

    def offer_incoming(self, file_ids: list[str]) -> None:
        if file_ids:
            self.commands.put(("offer-incoming", list(file_ids)))

    def set_language(self, language: str) -> None:
        self.commands.put(("set-language", language))

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
        self._seen_clips: set[str] = set()
        self.language = "en"

    def _push(self, script: str) -> None:
        window = self.window
        if window is not None:
            window.evaluate_js(script)

    def _pump(self) -> None:
        while True:
            event = self.events.get()
            kind = event[0]
            if kind == "language":
                self.language = normalize_language(event[1])
                self._push(f"window.localdrop.language({json.dumps(self.language)})")
            elif kind == "phone-link":
                urls, pin, folder, ticket, fingerprint = event[1:]
                mark = str(fingerprint).replace(":", "")
                opened = f"{urls[0]}/?t={ticket}#fp={mark}" if urls and ticket else ""
                qr = qr_data_url(opened) if opened else ""
                self._push(
                    "window.localdrop.link("
                    + json.dumps(urls) + ", "
                    + json.dumps(pin) + ", "
                    + json.dumps(folder) + ", "
                    + json.dumps(qr) + ", "
                    + json.dumps(str(fingerprint)) + ")"
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
            elif kind == "phone-history":
                self._push("window.localdrop.activity([])")
            elif kind == "phone-clips":
                payload = event[1]
                for text in payload.get("dropped", []):
                    clear_if(str(text))
                fresh = False
                for item in payload.get("items", []):
                    if item.get("way") == "phone" and item.get("id") not in self._seen_clips:
                        self._seen_clips.add(str(item.get("id")))
                        write_text(str(item.get("text") or ""))
                        fresh = True
                if fresh:
                    self._push(f"window.localdrop.log({json.dumps(tr(self.language, 'clip_on_computer'))})")
                self._push(f"window.localdrop.clips({json.dumps(payload)})")
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
                body = tr(self.language, "pair_body", name=name, fingerprint=fingerprint, code=code)
                self._push(f"window.localdrop.ask('pair', {json.dumps(tr(self.language, 'pair_title'))}, {json.dumps(body)})")
            elif kind == "incoming":
                name, size, sender, result, done = event[1:]
                self.api._result = result
                self.api._done = done
                body = tr(self.language, "incoming_body", name=name, size=size, sender=sender)
                self._push(f"window.localdrop.ask('incoming', {json.dumps(tr(self.language, 'incoming_title'))}, {json.dumps(body)})")
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
            background_color="#08080A",
        )
        self.window.events.loaded += lambda: threading.Thread(target=self._pump, daemon=True).start()
        self.window.events.closing += self.close
        webview.start()

    def close(self) -> None:
        self.commands.put(("quit",))
        self.events.put(("closed",))
