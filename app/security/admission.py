from __future__ import annotations

import threading
import time


class Admission:
    def __init__(
        self,
        limit_window: int = 8,
        window: float = 10.0,
        block: float = 30.0,
        max_open: int = 4,
    ) -> None:
        self.limit_window = limit_window
        self.window = window
        self.block = block
        self.max_open = max_open
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}
        self._blocked: dict[str, float] = {}
        self._open: dict[str, int] = {}

    def try_open(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if now < self._blocked.get(ip, 0.0):
                return False
            if self._open.get(ip, 0) >= self.max_open:
                return False
            hits = [stamp for stamp in self._hits.get(ip, []) if now - stamp < self.window]
            if len(hits) >= self.limit_window:
                self._blocked[ip] = now + self.block
                self._hits[ip] = []
                return False
            hits.append(now)
            self._hits[ip] = hits
            self._open[ip] = self._open.get(ip, 0) + 1
            return True

    def close(self, ip: str) -> None:
        with self._lock:
            self._open[ip] = max(0, self._open.get(ip, 0) - 1)
