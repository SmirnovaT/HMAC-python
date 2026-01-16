"""Tests for codec module"""

import base64

import pytest

from src.codec import decode_base64url, encode_base64url, is_valid_base64url


def test_encode_base64url() -> None:
    """Test base64url encoding"""
    data = b"hello world"
    encoded = encode_base64url(data)
    assert isinstance(encoded, str)
    assert "=" not in encoded
    assert "/" not in encoded
    assert "+" not in encoded


def test_decode_base64url() -> None:
    """Test base64url decoding"""
    data = b"hello world"
    encoded = encode_base64url(data)
    decoded = decode_base64url(encoded)
    assert decoded == data


def test_encode_decode_roundtrip() -> None:
    """Test roundtrip encoding/decoding"""
    test_cases = [
        b"",
        b"a",
        b"ab",
        b"abc",
        b"hello",
        b"hello world",
        b"\x00\x01\x02\xff",
        b"test" * 100,
    ]

    for data in test_cases:
        encoded = encode_base64url(data)
        decoded = decode_base64url(encoded)
        assert decoded == data, f"Failed for data: {data}"


def test_decode_invalid_base64url() -> None:
    """Test decoding invalid base64url"""
    invalid_cases = [
        "@@@",
        "!!!",
        "hello world",
        "hello+world",
        "hello/world",
    ]

    for invalid in invalid_cases:
        with pytest.raises(ValueError):
            decode_base64url(invalid)


def test_is_valid_base64url() -> None:
    """Test base64url validation"""
    valid_cases = [
        encode_base64url(b"hello"),
        encode_base64url(b"test"),
        "dGVzdA",
    ]

    invalid_cases = [
        "@@@",
        "!!!",
        "hello+world",
        "hello/world",
    ]

    for valid in valid_cases:
        assert is_valid_base64url(valid), f"Should be valid: {valid}"

    for invalid in invalid_cases:
        assert not is_valid_base64url(invalid), f"Should be invalid: {invalid}"


def test_encode_no_padding() -> None:
    """Test that encoding produces no padding"""
    for length in range(1, 100):
        data = b"a" * length
        encoded = encode_base64url(data)
        assert "=" not in encoded


def test_decode_with_padding() -> None:
    """Test that decoding handles padding correctly"""
    data = b"test"
    standard_b64 = base64.b64encode(data).decode("ascii")
    url_b64 = standard_b64.replace("+", "-").replace("/", "_")
    decoded = decode_base64url(url_b64)
    assert decoded == data
