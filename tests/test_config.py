"""Tests for config module"""

import json
import tempfile
from pathlib import Path

import pytest

from src.config import load_config


def test_load_config_valid() -> None:
    """Test loading valid config"""
    config_data = {
        "hmac_alg": "SHA256",
        "secret": "dGVzdCBzZWNyZXQ=",
        "log_level": "info",
        "listen": "0.0.0.0:8080",
        "max_msg_size_bytes": 1048576,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        config_path = f.name

    try:
        config = load_config(config_path)
        assert config.hmac_alg == "SHA256"
        assert isinstance(config.secret, bytes)
        assert config.log_level == "info"
        assert config.listen == "0.0.0.0:8080"
        assert config.max_msg_size_bytes == 1048576
        assert config.host == "0.0.0.0"
        assert config.port == 8080
    finally:
        Path(config_path).unlink()


def test_load_config_missing_field() -> None:
    """Test loading config with missing field"""
    config_data = {
        "hmac_alg": "SHA256",
        "secret": "dGVzdCBzZWNyZXQ=",
        "listen": "0.0.0.0:8080",
        "max_msg_size_bytes": 1048576,
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
        "max_msg_size_bytes": 1048576,
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
        "max_msg_size_bytes": 1048576,
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
        "max_msg_size_bytes": 1048576,
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
        "max_msg_size_bytes": 1048576,
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
