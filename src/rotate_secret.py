"""Utility for rotating HMAC secret"""

import argparse
import base64
import json
import logging
import os
import secrets
import sys
from pathlib import Path

from constants import HMAC_SHA256_DIGEST_SIZE, SECRET_VISIBLE_CHARS


def generate_secret(length: int = HMAC_SHA256_DIGEST_SIZE) -> bytes:
    """Generate random secret."""
    return secrets.token_bytes(length)


def rotate_secret(
    config_path: str | None = None, secret_length: int = HMAC_SHA256_DIGEST_SIZE
) -> None:
    """Rotate secret in config file."""
    if config_path is None:
        config_path = Path(__file__).parent.parent / "config.json"
    else:
        config_path = Path(config_path)

    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in config file: {e}") from e

    new_secret_bytes = generate_secret(secret_length)
    new_secret_base64 = base64.b64encode(new_secret_bytes).decode("ascii")

    old_secret = data.get("secret", "")
    data["secret"] = new_secret_base64

    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")

        if os.name != "nt":
            os.chmod(config_path, 0o600)

        logger = logging.getLogger("rotate_secret")
        logger.info(f"Secret rotated successfully in {config_path}")
        logger.info(
            f"Old secret (first {SECRET_VISIBLE_CHARS} chars): {old_secret[:SECRET_VISIBLE_CHARS]}..."
        )
        logger.info(
            f"New secret (first {SECRET_VISIBLE_CHARS} chars): {new_secret_base64[:SECRET_VISIBLE_CHARS]}..."
        )
    except Exception as e:
        raise ValueError(f"Failed to write config file: {e}") from e


def main() -> None:
    """Main entry point for rotate-secret utility."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s - %(message)s",
        stream=sys.stdout,
    )

    parser = argparse.ArgumentParser(
        description="Rotate HMAC secret in config.json",
        prog="rotate-secret",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config.json (default: config.json in project root)",
    )
    parser.add_argument(
        "--length",
        type=int,
        default=HMAC_SHA256_DIGEST_SIZE,
        help=f"Secret length in bytes (default: {HMAC_SHA256_DIGEST_SIZE})",
    )

    args = parser.parse_args()

    logger = logging.getLogger("rotate_secret")
    try:
        rotate_secret(args.config, args.length)
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
