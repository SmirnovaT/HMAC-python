"""Module with FastAPI application"""

import json

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from src.config import get_config
from src.router import router

app = FastAPI()
app.include_router(router)


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to limit request body size."""

    async def dispatch(self, request: Request, call_next):
        config = get_config()
        content_length = request.headers.get("content-length")

        if content_length:
            try:
                size = int(content_length)
                max_size = config.max_msg_size_bytes * 2
                if size > max_size:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"detail": "Request body too large"},
                    )
            except ValueError:
                pass

        response = await call_next(request)
        return response


app.add_middleware(RequestSizeLimitMiddleware)


@app.exception_handler(json.JSONDecodeError)
async def json_decode_exception_handler(
    request: Request, exc: json.JSONDecodeError
) -> JSONResponse:
    """Handler for JSON parsing errors."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": "invalid_json"},
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    """Handler for Starlette HTTP exceptions."""
    if exc.status_code == 422:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"detail": "invalid_json"},
        )

    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Custom exception handler for validation errors."""
    errors = exc.errors()

    is_json_error = any(
        error.get("type") in ("json_invalid", "value_error.jsondecode")
        for error in errors
    )

    if is_json_error:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"detail": errors},
        )

    for error in errors:
        error_type = error.get("type", "")
        error_loc = error.get("loc", [])

        if len(error_loc) > 0:
            field_name = error_loc[-1]

            is_type_error = "type" in error_type.lower() and (
                "str" in error_type.lower() or error_type == "string_type"
            )

            if field_name == "msg" and is_type_error:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "invalid_msg"},
                )
            elif field_name == "signature" and is_type_error:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "invalid_signature_format"},
                )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": errors},
    )
