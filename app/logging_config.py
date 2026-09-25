from __future__ import annotations

import logging

LOGGER_NAME = "localdrop"


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False
    if logger.handlers:
        return logger
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    return logger
