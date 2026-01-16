"""Module with logging utilities"""

import logging
import sys
from typing import Any

from src.config import get_config


def obfuscate_secret(secret: bytes, visible_chars: int = 4) -> str:
    """Obfuscate secret for logging."""
    if len(secret) <= visible_chars * 2:
        return "*" * len(secret)

    secret_str = secret.hex()[:visible_chars] + "..." + secret.hex()[-visible_chars:]
    return secret_str


def setup_logger() -> logging.Logger:
    """Setup and configure logger."""
    config = get_config()
    logger = logging.getLogger("hmac_service")

    logger.handlers.clear()

    level = getattr(logging, config.log_level.upper(), logging.INFO)
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger


def get_logger() -> logging.Logger:
    """Get logger instance."""
    logger = logging.getLogger("hmac_service")
    if not logger.handlers:
        return setup_logger()
    return logger


def log_request(logger: logging.Logger, endpoint: str, msg_length: int) -> None:
    """Log request without exposing sensitive data."""
    logger.info(f"Request to {endpoint}: message length={msg_length} bytes")


def log_error(
    logger: logging.Logger, endpoint: str, error: str, details: Any = None
) -> None:
    """Log error without exposing sensitive data."""
    if details:
        logger.error(f"Error in {endpoint}: {error} - {details}")
    else:
        logger.error(f"Error in {endpoint}: {error}")
