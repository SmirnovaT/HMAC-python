"""Tests for config module"""

import json
import tempfile
from pathlib import Path

import pytest

from src.config import load_config
from src.constants import DEFAULT_MAX_MSG_SIZE_BYTES


@pytest.fixture
def valid_config_file():
    """Create valid config file for testing"""
    config_data = {
        "hmac_alg": "SHA256",
        "secret": "dGVzdCBzZWNyZXQ=",
        "log_level": "info",
        "listen": "0.0.0.0:8080",
        "max_msg_size_bytes": DEFAULT_MAX_MSG_SIZE_BYTES,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        config_path = f.name

    yield config_path
    Path(config_path).unlink()


def test_load_config_hmac_alg(valid_config_file) -> None:
    """Test loading valid config hmac_alg"""
    config = load_config(valid_config_file)
    assert config.hmac_alg == "SHA256"


def test_load_config_secret_type(valid_config_file) -> None:
    """Test loading valid config secret type"""
    config = load_config(valid_config_file)
    assert isinstance(config.secret, bytes)


def test_load_config_log_level(valid_config_file) -> None:
    """Test loading valid config log_level"""
    config = load_config(valid_config_file)
    assert config.log_level == "info"


def test_load_config_listen(valid_config_file) -> None:
    """Test loading valid config listen"""
    config = load_config(valid_config_file)
    assert config.listen == "0.0.0.0:8080"


def test_load_config_max_msg_size_bytes(valid_config_file) -> None:
    """Test loading valid config max_msg_size_bytes"""
    config = load_config(valid_config_file)
    assert config.max_msg_size_bytes == DEFAULT_MAX_MSG_SIZE_BYTES


def test_load_config_host(valid_config_file) -> None:
    """Test loading valid config host"""
    config = load_config(valid_config_file)
    assert config.host == "0.0.0.0"


def test_load_config_port(valid_config_file) -> None:
    """Test loading valid config port"""
    config = load_config(valid_config_file)
    assert config.port == 8080


def test_load_config_missing_field() -> None:
    """Test loading config with missing field"""
    config_data = {
        "hmac_alg": "SHA256",
        "secret": "dGVzdCBzZWNyZXQ=",
        "listen": "0.0.0.0:8080",
        "max_msg_size_bytes": DEFAULT_MAX_MSG_SIZE_BYTES,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        config_path = f.name

    try:
        with pytest.raises(ValueError, match="Missing required field"):
            load_config(config_path)
    finally:
        Path(config_path).unlink()


def test_load_config_invalid_secret() -> None:
    """Test loading config with invalid secret"""
    config_data = {
        "hmac_alg": "SHA256",
        "secret": "@@@invalid@@@",
        "log_level": "info",
        "listen": "0.0.0.0:8080",
        "max_msg_size_bytes": DEFAULT_MAX_MSG_SIZE_BYTES,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        config_path = f.name

    try:
        with pytest.raises(ValueError, match="Invalid base64 secret"):
            load_config(config_path)
    finally:
        Path(config_path).unlink()


def test_load_config_invalid_listen() -> None:
    """Test loading config with invalid listen format"""
    config_data = {
        "hmac_alg": "SHA256",
        "secret": "dGVzdCBzZWNyZXQ=",
        "log_level": "info",
        "listen": "invalid",
        "max_msg_size_bytes": DEFAULT_MAX_MSG_SIZE_BYTES,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        config_path = f.name

    try:
        with pytest.raises(ValueError, match="Invalid listen format"):
            load_config(config_path)
    finally:
        Path(config_path).unlink()


def test_load_config_invalid_port() -> None:
    """Test loading config with invalid port"""
    config_data = {
        "hmac_alg": "SHA256",
        "secret": "dGVzdCBzZWNyZXQ=",
        "log_level": "info",
        "listen": "0.0.0.0:99999",
        "max_msg_size_bytes": DEFAULT_MAX_MSG_SIZE_BYTES,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        config_path = f.name

    try:
        with pytest.raises(ValueError, match="Port must be in range"):
            load_config(config_path)
    finally:
        Path(config_path).unlink()


def test_load_config_invalid_max_msg_size() -> None:
    """Test loading config with invalid max_msg_size_bytes"""
    config_data = {
        "hmac_alg": "SHA256",
        "secret": "dGVzdCBzZWNyZXQ=",
        "log_level": "info",
        "listen": "0.0.0.0:8080",
        "max_msg_size_bytes": -1,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        config_path = f.name

    try:
        with pytest.raises(ValueError, match="must be a positive integer"):
            load_config(config_path)
    finally:
        Path(config_path).unlink()


def test_load_config_invalid_log_level() -> None:
    """Test loading config with invalid log level"""
    config_data = {
        "hmac_alg": "SHA256",
        "secret": "dGVzdCBzZWNyZXQ=",
        "log_level": "invalid_level",
        "listen": "0.0.0.0:8080",
        "max_msg_size_bytes": DEFAULT_MAX_MSG_SIZE_BYTES,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        config_path = f.name

    try:
        with pytest.raises(ValueError, match="Invalid log_level"):
            load_config(config_path)
    finally:
        Path(config_path).unlink()


def test_load_config_file_not_found() -> None:
    """Test loading non-existent config file"""
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/config.json")
