"""Module with routes"""

from typing import Annotated
from http import HTTPStatus
from fastapi import APIRouter, Depends, HTTPException

from src.codec import is_valid_base64url
from src.config import Config, get_config
from src.hmac_service import HMACSigner, hmac_service
from src.logger import get_logger, log_error, log_request
from src.models import SignRequest, VerifyRequest, VerifyResponse

router = APIRouter()
logger = get_logger()


def validate_message(msg: str, endpoint: str, config: Config) -> int:
    """Validate message: check for empty string and size limit."""
    if msg == "":
        log_error(logger, endpoint, "invalid_msg", "msg is empty")
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="invalid_msg")

    msg_bytes = msg.encode("utf-8")
    msg_length = len(msg_bytes)

    if msg_length > config.max_msg_size_bytes:
        log_error(
            logger,
            endpoint,
            "Message too large",
            f"size={msg_length}, max={config.max_msg_size_bytes}",
        )
        raise HTTPException(
            status_code=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            detail="Message exceeds max_msg_size_bytes",
        )

    return msg_length


def validate_signature(signature: str, endpoint: str, config: Config) -> None:
    """Validate signature: check size limit and base64url format."""
    signature_length = len(signature.encode("utf-8"))
    if signature_length > config.max_msg_size_bytes:
        log_error(
            logger,
            endpoint,
            "Signature too large",
            f"size={signature_length}, max={config.max_msg_size_bytes}",
        )
        raise HTTPException(
            status_code=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            detail="Signature exceeds max_msg_size_bytes",
        )

    if not is_valid_base64url(signature):
        log_error(
            logger, endpoint, "invalid_signature_format", "Invalid base64url format"
        )
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="invalid_signature_format"
        )


@router.post("/sign", summary="Sign handler", status_code=HTTPStatus.OK)
async def sign(
    request: SignRequest,
    hmac_service: Annotated[HMACSigner, Depends(hmac_service)],
) -> dict[str, str]:
    config = get_config()
    endpoint = "/sign"

    msg_length = validate_message(request.msg, endpoint, config)
    log_request(logger, endpoint, msg_length)

    try:
        signature = hmac_service.sign_base64url(request.msg)
        logger.info(f"Message signed successfully, signature length={len(signature)}")
        return {"signature": signature}
    except Exception as e:
        log_error(logger, endpoint, "internal", str(e))
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail="internal"
        ) from e


@router.post(
    "/verify",
    summary="Verify message with signature handler",
    status_code=HTTPStatus.OK,
)
async def verify(
    request: VerifyRequest,
    hmac_service: Annotated[HMACSigner, Depends(hmac_service)],
) -> VerifyResponse:
    config = get_config()
    endpoint = "/verify"

    msg_length = validate_message(request.msg, endpoint, config)
    validate_signature(request.signature, endpoint, config)
    log_request(logger, endpoint, msg_length)

    try:
        is_valid = hmac_service.verify_base64url(request.msg, request.signature)
        logger.info(f"Signature verification result: {is_valid}")
        return VerifyResponse(ok=is_valid)
    except ValueError as e:
        log_error(logger, endpoint, "invalid_signature_format", str(e))
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="invalid_signature_format"
        ) from e
    except Exception as e:
        log_error(logger, endpoint, "internal", str(e))
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail="internal"
        ) from e
