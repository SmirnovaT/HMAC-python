"""Tests for HMAC service module"""

import base64
import tempfile
from pathlib import Path

import pytest

from src.config import load_config
from src.hmac_service import HMACSigner, constant_time_compare


def create_test_config(secret: bytes) -> str:
    """Create temporary test config file"""
    config_data = {
        "hmac_alg": "SHA256",
        "secret": base64.b64encode(secret).decode("ascii"),
        "log_level": "info",
        "listen": "0.0.0.0:8080",
        "max_msg_size_bytes": 1048576,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        import json

        json.dump(config_data, f)
        return f.name


def test_sign() -> None:
    """Test message signing"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    try:
        config = load_config(config_path)
        signer = HMACSigner(config)

        msg = "hello world"
        signature = signer.sign(msg)

        assert isinstance(signature, bytes)
        assert len(signature) == 32
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
        invalid_signature = b"x" * 32

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


def test_sign_base64url() -> None:
    """Test base64url signing"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    try:
        config = load_config(config_path)
        signer = HMACSigner(config)

        msg = "hello world"
        signature_str = signer.sign_base64url(msg)

        assert isinstance(signature_str, str)
        assert "=" not in signature_str
        assert "/" not in signature_str
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


def test_constant_time_compare_equal() -> None:
    """Test constant-time compare with equal strings"""
    a = b"hello world"
    b = b"hello world"
    assert constant_time_compare(a, b) is True


def test_constant_time_compare_different() -> None:
    """Test constant-time compare with different strings"""
    a = b"hello world"
    b = b"hello worlx"
    assert constant_time_compare(a, b) is False


def test_constant_time_compare_different_length() -> None:
    """Test constant-time compare with different lengths"""
    a = b"hello"
    b = b"hello world"
    assert constant_time_compare(a, b) is False


def test_constant_time_compare_empty() -> None:
    """Test constant-time compare with empty strings"""
    assert constant_time_compare(b"", b"") is True
    assert constant_time_compare(b"", b"a") is False
