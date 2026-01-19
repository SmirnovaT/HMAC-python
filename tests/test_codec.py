"""Tests for codec module"""

import base64

import pytest

from src.codec import decode_base64url, encode_base64url, is_valid_base64url


@pytest.mark.parametrize(
    "data",
    [
        b"hello world",
        b"test",
        b"",
        b"a",
        b"ab",
        b"abc",
    ],
)
def test_encode_base64url_is_string(data: bytes) -> None:
    """Test base64url encoding returns string"""
    encoded = encode_base64url(data)
    assert isinstance(encoded, str)


@pytest.mark.parametrize(
    "data",
    [
        b"hello world",
        b"test",
        b"",
        b"a",
        b"ab",
        b"abc",
    ],
)
def test_encode_base64url_no_padding(data: bytes) -> None:
    """Test base64url encoding has no padding"""
    encoded = encode_base64url(data)
    assert "=" not in encoded


@pytest.mark.parametrize(
    "data",
    [
        b"hello world",
        b"test",
        b"",
        b"a",
        b"ab",
        b"abc",
    ],
)
def test_encode_base64url_no_slash(data: bytes) -> None:
    """Test base64url encoding has no slash"""
    encoded = encode_base64url(data)
    assert "/" not in encoded


@pytest.mark.parametrize(
    "data",
    [
        b"hello world",
        b"test",
        b"",
        b"a",
        b"ab",
        b"abc",
    ],
)
def test_encode_base64url_no_plus(data: bytes) -> None:
    """Test base64url encoding has no plus"""
    encoded = encode_base64url(data)
    assert "+" not in encoded


def test_decode_base64url() -> None:
    """Test base64url decoding"""
    data = b"hello world"
    encoded = encode_base64url(data)
    decoded = decode_base64url(encoded)
    assert decoded == data


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"a",
        b"ab",
        b"abc",
        b"hello",
        b"hello world",
        b"\x00\x01\x02\xff",
        b"test" * 100,
    ],
)
def test_encode_decode_roundtrip(data: bytes) -> None:
    """Test roundtrip encoding/decoding"""
    encoded = encode_base64url(data)
    decoded = decode_base64url(encoded)
    assert decoded == data


@pytest.mark.parametrize(
    "invalid",
    [
        "@@@",
        "!!!",
        "hello world",
        "hello+world",
        "hello/world",
    ],
)
def test_decode_invalid_base64url(invalid: str) -> None:
    """Test decoding invalid base64url"""
    with pytest.raises(ValueError):
        decode_base64url(invalid)


@pytest.mark.parametrize(
    "valid",
    [
        encode_base64url(b"hello"),
        encode_base64url(b"test"),
        "dGVzdA",
    ],
)
def test_is_valid_base64url_valid(valid: str) -> None:
    """Test base64url validation for valid cases"""
    assert is_valid_base64url(valid)


@pytest.mark.parametrize(
    "invalid",
    [
        "@@@",
        "!!!",
        "hello+world",
        "hello/world",
    ],
)
def test_is_valid_base64url_invalid(invalid: str) -> None:
    """Test base64url validation for invalid cases"""
    assert not is_valid_base64url(invalid)


@pytest.mark.parametrize("length", range(1, 100))
def test_encode_no_padding(length: int) -> None:
    """Test that encoding produces no padding"""
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
