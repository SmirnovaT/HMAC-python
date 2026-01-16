"""Module with config utils"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import base64


@dataclass
class Config:
    """Configuration model"""

    hmac_alg: str
    secret: bytes
    log_level: str
    listen: str
    max_msg_size_bytes: int

    @property
    def host(self) -> str:
        """Extract host from listen string"""
        return self.listen.split(":")[0]

    @property
    def port(self) -> int:
        """Extract port from listen string"""
        return int(self.listen.split(":")[1])


def load_config(config_path: Optional[str] = None) -> Config:
    """Load and validate configuration from JSON file."""
    if config_path is None:
        config_path = Path(__file__).parent.parent / "config.json"
    else:
        config_path = Path(config_path)

    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    if os.name != "nt":
        current_permissions = config_path.stat().st_mode & 0o777
        if current_permissions != 0o600:
            try:
                os.chmod(config_path, 0o600)
            except OSError:
                pass

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in config file: {e}") from e

    required_fields = [
        "hmac_alg",
        "secret",
        "log_level",
        "listen",
        "max_msg_size_bytes",
    ]
    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field in config: {field}")

    if data["hmac_alg"] != "SHA256":
        raise ValueError(f"Unsupported HMAC algorithm: {data['hmac_alg']}")

    secret_str = data["secret"]
    if not isinstance(secret_str, str):
        raise ValueError("Secret must be a string")

    try:
        secret_bytes = base64.b64decode(secret_str, validate=True)
    except Exception as e:
        raise ValueError(f"Invalid base64 secret: {e}") from e

    if len(secret_bytes) == 0:
        raise ValueError("Secret cannot be empty")

    listen = data["listen"]
    if not isinstance(listen, str):
        raise ValueError("Invalid listen format: listen must be a string")
    if ":" not in listen:
        raise ValueError("Invalid listen format: listen must be in format 'host:port'")

    try:
        host, port_str = listen.split(":", 1)
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError("Port must be in range 1-65535")
    except ValueError as e:
        raise ValueError(f"Invalid listen format: {e}") from e

    max_msg_size = data["max_msg_size_bytes"]
    if not isinstance(max_msg_size, int) or max_msg_size <= 0:
        raise ValueError("max_msg_size_bytes must be a positive integer")

    log_level = data["log_level"]
    valid_levels = ["debug", "info", "warning", "error", "critical"]
    if log_level.lower() not in valid_levels:
        raise ValueError(f"Invalid log_level. Must be one of: {valid_levels}")

    return Config(
        hmac_alg=data["hmac_alg"],
        secret=secret_bytes,
        log_level=log_level.lower(),
        listen=listen,
        max_msg_size_bytes=max_msg_size,
    )


_config: Optional[Config] = None


def get_config() -> Config:
    """Get global config instance (singleton)."""
    global _config
    if _config is None:
        _config = load_config()
    return _config
