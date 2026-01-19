"""Tests for HMAC service module"""

import base64
import tempfile
from pathlib import Path

import pytest

from src.config import load_config
from src.constants import DEFAULT_MAX_MSG_SIZE_BYTES, HMAC_SHA256_DIGEST_SIZE
from src.hmac_service import HMACSigner, constant_time_compare


def create_test_config(secret: bytes) -> str:
    """Create temporary test config file"""
    config_data = {
        "hmac_alg": "SHA256",
        "secret": base64.b64encode(secret).decode("ascii"),
        "log_level": "info",
        "listen": "0.0.0.0:8080",
        "max_msg_size_bytes": DEFAULT_MAX_MSG_SIZE_BYTES,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        import json

        json.dump(config_data, f)
        return f.name


def test_sign_is_bytes() -> None:
    """Test message signing returns bytes"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    try:
        config = load_config(config_path)
        signer = HMACSigner(config)

        msg = "hello world"
        signature = signer.sign(msg)

        assert isinstance(signature, bytes)
    finally:
        Path(config_path).unlink()


def test_sign_length() -> None:
    """Test message signing returns correct length"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    try:
        config = load_config(config_path)
        signer = HMACSigner(config)

        msg = "hello world"
        signature = signer.sign(msg)

        assert len(signature) == HMAC_SHA256_DIGEST_SIZE
    finally:
        Path(config_path).unlink()


def test_sign_deterministic() -> None:
    """Test that signing is deterministic"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    try:
        config = load_config(config_path)
        signer = HMACSigner(config)

        msg = "hello world"
        signature1 = signer.sign(msg)
        signature2 = signer.sign(msg)

        assert signature1 == signature2
    finally:
        Path(config_path).unlink()


def test_verify_valid() -> None:
    """Test signature verification with valid signature"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    try:
        config = load_config(config_path)
        signer = HMACSigner(config)

        msg = "hello world"
        signature = signer.sign(msg)

        assert signer.verify(msg, signature) is True
    finally:
        Path(config_path).unlink()


def test_verify_invalid() -> None:
    """Test signature verification with invalid signature"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    try:
        config = load_config(config_path)
        signer = HMACSigner(config)

        msg = "hello world"
        invalid_signature = b"x" * HMAC_SHA256_DIGEST_SIZE

        assert signer.verify(msg, invalid_signature) is False
    finally:
        Path(config_path).unlink()


def test_verify_different_message() -> None:
    """Test verification fails for different message"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    try:
        config = load_config(config_path)
        signer = HMACSigner(config)

        msg1 = "hello"
        msg2 = "hello!"
        signature = signer.sign(msg1)

        assert signer.verify(msg2, signature) is False
    finally:
        Path(config_path).unlink()


@pytest.mark.parametrize(
    "msg",
    [
        "hello world",
        "test",
        "",
        "a",
    ],
)
def test_sign_base64url_is_string(msg: str) -> None:
    """Test base64url signing returns string"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    try:
        config = load_config(config_path)
        signer = HMACSigner(config)

        signature_str = signer.sign_base64url(msg)

        assert isinstance(signature_str, str)
    finally:
        Path(config_path).unlink()


@pytest.mark.parametrize(
    "msg",
    [
        "hello world",
        "test",
        "",
        "a",
    ],
)
def test_sign_base64url_no_padding(msg: str) -> None:
    """Test base64url signing has no padding"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    try:
        config = load_config(config_path)
        signer = HMACSigner(config)

        signature_str = signer.sign_base64url(msg)

        assert "=" not in signature_str
    finally:
        Path(config_path).unlink()


@pytest.mark.parametrize(
    "msg",
    [
        "hello world",
        "test",
        "",
        "a",
    ],
)
def test_sign_base64url_no_slash(msg: str) -> None:
    """Test base64url signing has no slash"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    try:
        config = load_config(config_path)
        signer = HMACSigner(config)

        signature_str = signer.sign_base64url(msg)

        assert "/" not in signature_str
    finally:
        Path(config_path).unlink()


@pytest.mark.parametrize(
    "msg",
    [
        "hello world",
        "test",
        "",
        "a",
    ],
)
def test_sign_base64url_no_plus(msg: str) -> None:
    """Test base64url signing has no plus"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    try:
        config = load_config(config_path)
        signer = HMACSigner(config)

        signature_str = signer.sign_base64url(msg)

        assert "+" not in signature_str
    finally:
        Path(config_path).unlink()


def test_verify_base64url_valid() -> None:
    """Test base64url verification with valid signature"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    try:
        config = load_config(config_path)
        signer = HMACSigner(config)

        msg = "hello world"
        signature_str = signer.sign_base64url(msg)

        assert signer.verify_base64url(msg, signature_str) is True
    finally:
        Path(config_path).unlink()


def test_verify_base64url_invalid() -> None:
    """Test base64url verification with invalid signature"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    try:
        config = load_config(config_path)
        signer = HMACSigner(config)

        msg = "hello world"
        invalid_signature = "@@@invalid@@@"

        with pytest.raises(ValueError, match="Invalid signature format"):
            signer.verify_base64url(msg, invalid_signature)
    finally:
        Path(config_path).unlink()


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (b"hello world", b"hello world", True),
        (b"hello world", b"hello worlx", False),
        (b"hello", b"hello world", False),
        (b"", b"", True),
        (b"", b"a", False),
    ],
)
def test_constant_time_compare(a: bytes, b: bytes, expected: bool) -> None:
    """Test constant-time compare"""
    assert constant_time_compare(a, b) is expected
