"""Standard error handler — consistent error responses across all routes."""

from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..utils.logging import get_logger

logger = get_logger("middleware.error_handler")


def register_error_handlers(app: FastAPI) -> None:
    """Register standard error handlers on the app."""

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        request_id = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": True,
                "status_code": exc.status_code,
                "detail": exc.detail,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": request_id,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        request_id = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=422,
            content={
                "error": True,
                "status_code": 422,
                "detail": "Validation error",
                "errors": exc.errors(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": request_id,
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        request_id = getattr(request.state, "request_id", None)
        logger.error(
            "unhandled_exception",
            error=str(exc),
            request_id=request_id,
            path=str(request.url.path),
            exc_info=True,
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": True,
                "status_code": 500,
                "detail": "Internal server error",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": request_id,
            },
        )
