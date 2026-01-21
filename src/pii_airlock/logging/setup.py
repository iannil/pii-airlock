"""Logging configuration for PII-AIRLOCK.

Provides structured JSON logging with request_id correlation.
"""

import logging
import os
import sys
from contextvars import ContextVar
from typing import Any, Optional

from pythonjsonlogger import jsonlogger


# Context variable for request_id correlation
request_id_var: ContextVar[str] = ContextVar("request_id", default="")


class RequestContextFilter(logging.Filter):
    """Filter that adds request_id to log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Add request_id from context to log record."""
        record.request_id = request_id_var.get() or "-"
        return True


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with additional fields."""

    def add_fields(
        self,
        log_record: dict[str, Any],
        record: logging.LogRecord,
        message_dict: dict[str, Any],
    ) -> None:
        """Add custom fields to log record."""
        super().add_fields(log_record, record, message_dict)

        # Rename fields for better compatibility
        if "levelname" in log_record:
            log_record["level"] = log_record.pop("levelname")
        if "asctime" in log_record:
            log_record["timestamp"] = log_record.pop("asctime")

        # Add service name
        log_record["service"] = "pii-airlock"

        # Add request_id if available
        if hasattr(record, "request_id"):
            log_record["request_id"] = record.request_id


def setup_logging(
    level: Optional[str] = None,
    json_format: Optional[bool] = None,
) -> None:
    """Configure application logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR). Defaults to env var
               PII_AIRLOCK_LOG_LEVEL or INFO.
        json_format: Whether to use JSON format. Defaults to env var
                     PII_AIRLOCK_LOG_FORMAT == 'json' or True.
    """
    # Get configuration from environment if not provided
    if level is None:
        level = os.getenv("PII_AIRLOCK_LOG_LEVEL", "INFO").upper()
    if json_format is None:
        log_format = os.getenv("PII_AIRLOCK_LOG_FORMAT", "json").lower()
        json_format = log_format == "json"

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    # Add request context filter
    handler.addFilter(RequestContextFilter())

    # Set formatter
    if json_format:
        formatter = CustomJsonFormatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - [%(request_id)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    # Suppress noisy loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name.

    Args:
        name: Logger name (typically __name__).

    Returns:
        Configured logger instance.
    """
    return logging.getLogger(name)


def set_request_id(request_id: str) -> None:
    """Set the request ID for the current context.

    Args:
        request_id: Unique request identifier.
    """
    request_id_var.set(request_id)


def get_request_id() -> str:
    """Get the current request ID.

    Returns:
        Current request ID or empty string.
    """
    return request_id_var.get()
