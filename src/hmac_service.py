"""Module with HMAC sign functions"""

import hmac
import hashlib

from src.codec import decode_base64url, encode_base64url
from src.config import Config, get_config


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of two byte strings."""
    if len(a) != len(b):
        return False

    diff = 0
    for i in range(len(a)):
        diff |= a[i] ^ b[i]

    return diff == 0


class HMACSigner:
    """Class for HMAC sign and verify signature"""

    def __init__(self, config: Config | None = None):
        """Initialize HMAC signer."""
        self.config = config or get_config()

    def sign(self, msg: str) -> bytes:
        """Sign message with HMAC algorithm."""
        msg_bytes = msg.encode("utf-8")
        signature = hmac.new(
            self.config.secret,
            msg_bytes,
            hashlib.sha256,
        ).digest()
        return signature

    def verify(self, msg: str, signature: bytes) -> bool:
        """Verify message signature with HMAC algorithm."""
        expected_signature = self.sign(msg)
        return constant_time_compare(expected_signature, signature)

    def sign_base64url(self, msg: str) -> str:
        """Sign message and return base64url encoded signature."""
        signature_bytes = self.sign(msg)
        return encode_base64url(signature_bytes)

    def verify_base64url(self, msg: str, signature: str) -> bool:
        """Verify message signature from base64url string."""
        try:
            signature_bytes = decode_base64url(signature)
        except ValueError as e:
            raise ValueError(f"Invalid signature format: {e}") from e

        return self.verify(msg, signature_bytes)


def hmac_service() -> HMACSigner:
    """Fabric for signer."""
    return HMACSigner()
