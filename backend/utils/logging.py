"""Structured JSON logging configuration using structlog with file rotation."""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

import structlog


def setup_logging(
    debug: bool = False,
    log_dir: str = "logs",
    log_max_bytes: int = 10_000_000,
    log_backup_count: int = 5,
) -> None:
    """Configure structured logging for the application.

    Logs to stdout (always) and to a rotating file (production mode).
    In debug mode, uses human-readable console rendering.
    In production mode, uses JSON rendering to both stdout and file.
    """
    log_level = logging.DEBUG if debug else logging.INFO

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer() if not debug else structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure standard library root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear existing handlers to avoid duplicates on reload
    root_logger.handlers.clear()

    # Stdout handler (always)
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(log_level)
    stdout_handler.setFormatter(logging.Formatter("%(message)s"))
    root_logger.addHandler(stdout_handler)

    # Rotating file handler (production and debug)
    try:
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "cereberus.log")
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=log_max_bytes,
            backupCount=log_backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter("%(message)s"))
        root_logger.addHandler(file_handler)
    except OSError:
        # If we can't create log dir/file, continue with stdout only
        pass


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a named structured logger."""
    return structlog.get_logger(name)
