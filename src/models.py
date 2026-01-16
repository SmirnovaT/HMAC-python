"""Module with models"""

from dataclasses import dataclass


@dataclass(frozen=True)
class SignRequest:
    """Model for /sign request"""

    msg: str


@dataclass(frozen=True)
class VerifyRequest:
    """Model for /verify request"""

    msg: str
    signature: str


@dataclass(frozen=True)
class VerifyResponse:
    """Model for /verify response"""

    ok: bool
