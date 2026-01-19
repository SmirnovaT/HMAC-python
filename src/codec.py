"""Module with codec functions"""

import base64
import re

from src.constants import BASE64_BLOCK_SIZE


def encode_base64url(data: bytes) -> str:
    """Encode bytes to base64url string without padding."""
    encoded = base64.urlsafe_b64encode(data)
    return encoded.rstrip(b"=").decode("ascii")


def decode_base64url(data: str) -> bytes:
    """Decode base64url string to bytes."""
    if not isinstance(data, str):
        raise ValueError("Data must be a string")

    if not data:
        return b""

    padding = BASE64_BLOCK_SIZE - (len(data) % BASE64_BLOCK_SIZE)
    if padding != BASE64_BLOCK_SIZE:
        data += "=" * padding

    if not re.match(r"^[A-Za-z0-9_-]+=*$", data):
        raise ValueError("Invalid base64url format")

    try:
        return base64.urlsafe_b64decode(data)
    except Exception as e:
        raise ValueError(f"Invalid base64url encoding: {e}") from e


def is_valid_base64url(data: str) -> bool:
    """Check if string is valid base64url format."""
    try:
        decode_base64url(data)
        return True
    except ValueError:
        return False
