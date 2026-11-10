"""BotShield Structured Logging Module

Provides secure, structured logging with automatic credential redaction.
"""

import logging
import sys
from app.core.security import sanitize_credentials


class RedactingFormatter(logging.Formatter):
    """Custom formatter that automatically scrubs sensitive credentials from log records."""

    def format(self, record: logging.LogRecord) -> str:
        orig = super().format(record)
        return sanitize_credentials(orig)


def setup_logger(name: str = "botshield") -> logging.Logger:
    """Configures and returns a root application logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        formatter = RedactingFormatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


logger = setup_logger()
