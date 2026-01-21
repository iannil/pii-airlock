"""Rate limiting configuration for PII-AIRLOCK.

Provides configurable rate limiting using slowapi.
"""

import os
from typing import Optional

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

from pii_airlock.logging.setup import get_logger

logger = get_logger(__name__)


def get_rate_limit_key(request: Request) -> str:
    """Get the rate limit key for a request.

    Uses X-API-Key header if present, otherwise falls back to IP address.
    This allows for per-client rate limiting when API keys are used.

    Args:
        request: The incoming request.

    Returns:
        Rate limit key (API key or IP address).
    """
    # Try to use API key for rate limiting
    api_key = request.headers.get("X-API-Key")
    if api_key:
        # Use truncated API key for privacy
        return f"api_key:{api_key[:8]}..."

    # Fall back to IP address
    return get_remote_address(request)


# Default rate limit (can be overridden by environment variable)
DEFAULT_RATE_LIMIT = "60/minute"


def get_rate_limit() -> str:
    """Get the configured rate limit.

    Returns:
        Rate limit string (e.g., '60/minute').
    """
    return os.getenv("PII_AIRLOCK_RATE_LIMIT", DEFAULT_RATE_LIMIT)


def is_rate_limit_enabled() -> bool:
    """Check if rate limiting is enabled.

    Returns:
        True if rate limiting is enabled.
    """
    # Rate limiting is enabled by default, can be disabled
    return os.getenv("PII_AIRLOCK_RATE_LIMIT_ENABLED", "true").lower() == "true"


# Create limiter instance
limiter = Limiter(
    key_func=get_rate_limit_key,
    default_limits=[get_rate_limit()] if is_rate_limit_enabled() else [],
    enabled=is_rate_limit_enabled(),
)


def get_limiter() -> Limiter:
    """Get the limiter instance.

    Returns:
        The configured Limiter instance.
    """
    return limiter


def rate_limit_exceeded_handler(request: Request, exc: Exception) -> None:
    """Log rate limit exceeded events.

    Args:
        request: The request that exceeded the rate limit.
        exc: The rate limit exception.
    """
    logger.warning(
        "Rate limit exceeded",
        extra={
            "event": "rate_limit_exceeded",
            "client": get_rate_limit_key(request),
            "path": str(request.url.path),
        },
    )
