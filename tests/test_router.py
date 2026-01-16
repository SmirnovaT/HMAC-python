"""Tests for router module"""

import base64
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.app import app
from src.config import load_config


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


@pytest.fixture
def test_config():
    """Create test config and cleanup"""
    secret = b"test_secret_key"
    config_path = create_test_config(secret)
    yield config_path
    Path(config_path).unlink()


def test_sign_success(test_config) -> None:
    """Test successful message signing"""
    import src.config

    original_get_config = src.config.get_config
    src.config.get_config = lambda: load_config(test_config)

    try:
        client = TestClient(app)
        response = client.post("/sign", json={"msg": "hello"})

        assert response.status_code == 200
        data = response.json()
        assert "signature" in data
        assert isinstance(data["signature"], str)
        assert len(data["signature"]) > 0
    finally:
        src.config.get_config = original_get_config


def test_sign_empty_msg(test_config) -> None:
    """Test signing empty message returns 400"""
    import src.config

    original_get_config = src.config.get_config
    src.config.get_config = lambda: load_config(test_config)

    try:
        client = TestClient(app)
        response = client.post("/sign", json={"msg": ""})

        assert response.status_code == 400
        assert response.json()["detail"] == "invalid_msg"
    finally:
        src.config.get_config = original_get_config


def test_sign_missing_msg(test_config) -> None:
    """Test signing with missing msg field"""
    import src.config

    original_get_config = src.config.get_config
    src.config.get_config = lambda: load_config(test_config)

    try:
        client = TestClient(app)
        response = client.post("/sign", json={})

        assert response.status_code == 422
    finally:
        src.config.get_config = original_get_config


def test_sign_large_msg(test_config) -> None:
    """Test signing with message exceeding max size"""
    import src.config

    config = load_config(test_config)
    original_get_config = src.config.get_config
    src.config.get_config = lambda: config

    try:
        client = TestClient(app)
        large_msg = "a" * (config.max_msg_size_bytes + 1)
        response = client.post("/sign", json={"msg": large_msg})

        assert response.status_code == 413
        assert "detail" in response.json()
    finally:
        src.config.get_config = original_get_config


def test_verify_success(test_config) -> None:
    """Test successful signature verification"""
    import src.config

    original_get_config = src.config.get_config
    src.config.get_config = lambda: load_config(test_config)

    try:
        client = TestClient(app)
        sign_response = client.post("/sign", json={"msg": "hello"})
        assert sign_response.status_code == 200
        signature = sign_response.json()["signature"]

        verify_response = client.post(
            "/verify",
            json={"msg": "hello", "signature": signature},
        )

        assert verify_response.status_code == 200
        data = verify_response.json()
        assert data["ok"] is True
    finally:
        src.config.get_config = original_get_config


def test_verify_invalid_signature(test_config) -> None:
    """Test verification with invalid signature"""
    import src.config

    original_get_config = src.config.get_config
    src.config.get_config = lambda: load_config(test_config)

    try:
        client = TestClient(app)
        sign_response = client.post("/sign", json={"msg": "hello"})
        assert sign_response.status_code == 200
        signature = sign_response.json()["signature"]

        invalid_signature = signature[:-1] + "X"

        verify_response = client.post(
            "/verify",
            json={"msg": "hello", "signature": invalid_signature},
        )

        assert verify_response.status_code == 200
        data = verify_response.json()
        assert data["ok"] is False
    finally:
        src.config.get_config = original_get_config


def test_verify_changed_message(test_config) -> None:
    """Test verification with changed message"""
    import src.config

    original_get_config = src.config.get_config
    src.config.get_config = lambda: load_config(test_config)

    try:
        client = TestClient(app)
        sign_response = client.post("/sign", json={"msg": "hello"})
        assert sign_response.status_code == 200
        signature = sign_response.json()["signature"]

        verify_response = client.post(
            "/verify",
            json={"msg": "hello!", "signature": signature},
        )

        assert verify_response.status_code == 200
        data = verify_response.json()
        assert data["ok"] is False
    finally:
        src.config.get_config = original_get_config


def test_verify_invalid_base64url(test_config) -> None:
    """Test verification with invalid base64url signature"""
    import src.config

    original_get_config = src.config.get_config
    src.config.get_config = lambda: load_config(test_config)

    try:
        client = TestClient(app)
        response = client.post(
            "/verify",
            json={"msg": "hello", "signature": "@@@invalid@@@"},
        )

        assert response.status_code == 400
        assert response.json()["detail"] == "invalid_signature_format"
    finally:
        src.config.get_config = original_get_config


def test_verify_missing_fields(test_config) -> None:
    """Test verification with missing fields"""
    import src.config

    original_get_config = src.config.get_config
    src.config.get_config = lambda: load_config(test_config)

    try:
        client = TestClient(app)
        response = client.post("/verify", json={"msg": "hello"})
        assert response.status_code == 422

        response = client.post("/verify", json={"signature": "test"})
        assert response.status_code == 422
    finally:
        src.config.get_config = original_get_config


def test_sign_deterministic(test_config) -> None:
    """Test that signing produces same signature for same message"""
    import src.config

    original_get_config = src.config.get_config
    src.config.get_config = lambda: load_config(test_config)

    try:
        client = TestClient(app)
        msg = "hello"

        response1 = client.post("/sign", json={"msg": msg})
        response2 = client.post("/sign", json={"msg": msg})

        assert response1.status_code == 200
        assert response2.status_code == 200

        signature1 = response1.json()["signature"]
        signature2 = response2.json()["signature"]

        assert signature1 == signature2
    finally:
        src.config.get_config = original_get_config


def test_verify_large_message(test_config) -> None:
    """Test verification with large message"""
    import src.config

    config = load_config(test_config)
    original_get_config = src.config.get_config
    src.config.get_config = lambda: config

    try:
        client = TestClient(app)
        large_msg = "a" * (config.max_msg_size_bytes + 1)

        response = client.post(
            "/verify",
            json={"msg": large_msg, "signature": "test"},
        )

        assert response.status_code == 413
    finally:
        src.config.get_config = original_get_config
