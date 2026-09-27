from __future__ import annotations

import os
from collections import deque


def new_session_id() -> str:
    return os.urandom(16).hex()


class SeenSessions:
    def __init__(self, limit: int = 64) -> None:
        self._order: deque[bytes] = deque()
        self._seen: set[bytes] = set()
        self.limit = limit

    def admit(self, session_id: str) -> bool:
        if len(session_id) != 32:
            return False
        try:
            raw = bytes.fromhex(session_id)
        except ValueError:
            return False
        if len(raw) != 16 or raw in self._seen:
            return False
        if len(self._order) == self.limit:
            previous = self._order.popleft()
            self._seen.discard(previous)
        self._order.append(raw)
        self._seen.add(raw)
        return True
