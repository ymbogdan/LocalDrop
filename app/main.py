from __future__ import annotations

import logging
import queue

from app.controller import DesktopApp
from app.gui.window import MainWindow
from app.logging_config import configure_logging
from app.security.key_guard import KeyLocked

log = logging.getLogger("localdrop")


def main() -> None:
    configure_logging()
    log.info("LocalDrop started")
    events: queue.Queue = queue.Queue()
    commands: queue.Queue = queue.Queue()
    try:
        app = DesktopApp(events, commands)
    except KeyLocked:
        log.info("Key unlock cancelled")
        return
    app.start()
    window = MainWindow(commands, events)
    window.run()


if __name__ == "__main__":
    main()
