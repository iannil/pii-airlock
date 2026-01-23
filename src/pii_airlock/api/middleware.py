"""Request middleware for PII-AIRLOCK.

Provides request logging and metrics middleware.
"""

import hashlib
import time
import uuid
from typing import Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from pii_airlock.logging.setup import get_logger, set_request_id
from pii_airlock.metrics.collectors import (
    ACTIVE_REQUESTS,
    REQUEST_COUNT,
    REQUEST_LATENCY,
)

logger = get_logger(__name__)

# Audit logging (lazy import)
_audit_logger = None


def _get_audit_logger():
    """Lazy import of audit logger."""
    global _audit_logger
    if _audit_logger is None:
        try:
            from pii_airlock.audit import set_audit_context
            _audit_logger = set_audit_context
        except ImportError:
            _audit_logger = False
    return _audit_logger if _audit_logger is not False else None


def _mask_api_key(api_key: str) -> Optional[str]:
    """Mask API key for logging, preserving only prefix and hash suffix.

    SEC-003 FIX: Never log full API keys. Only log a masked version
    consisting of first 4 chars + hash suffix for correlation.

    Args:
        api_key: The full API key.

    Returns:
        Masked API key like "sk-x...a1b2c3" or None if empty.
    """
    if not api_key:
        return None

    # Keep first 4 chars (usually "sk-x" for OpenAI keys)
    prefix = api_key[:4] if len(api_key) >= 4 else api_key

    # Add hash suffix for correlation without exposing the key
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:6]

    return f"{prefix}...{key_hash}"


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for request logging and metrics.

    Adds request_id to all requests and logs request start/completion.
    Also records Prometheus metrics for request latency and count.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        """Process the request with logging and metrics.

        Args:
            request: The incoming request.
            call_next: The next middleware/handler.

        Returns:
            The response from the handler.
        """
        # Generate request ID
        request_id = str(uuid.uuid4())[:8]
        set_request_id(request_id)

        # Store in request state for access by handlers
        request.state.request_id = request_id

        # Get endpoint for metrics
        endpoint = self._get_endpoint(request)
        method = request.method
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        api_key = request.headers.get("authorization", "").replace("Bearer ", "")

        # SEC-003 FIX: Mask API key before logging/audit
        masked_api_key = _mask_api_key(api_key)

        # Set up audit context
        set_audit_fn = _get_audit_logger()
        if set_audit_fn:
            set_audit_fn(
                request_id=request_id,
                source_ip=client_ip,
                user_agent=user_agent,
                api_key=masked_api_key,
            )

        # Track active requests
        ACTIVE_REQUESTS.inc()

        # Log request start
        start_time = time.time()
        logger.info(
            "Request started",
            extra={
                "event": "request_started",
                "method": method,
                "path": str(request.url.path),
                "query": str(request.url.query) if request.url.query else None,
                "client_ip": client_ip,
            },
        )

        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as e:
            status_code = 500
            logger.exception(
                "Request failed with exception",
                extra={
                    "event": "request_error",
                    "error": str(e),
                },
            )

            # Audit error logging
            if set_audit_fn:
                try:
                    from pii_airlock.audit import clear_audit_context
                    clear_audit_context()
                except ImportError:
                    pass
            raise
        finally:
            # Calculate duration
            duration = time.time() - start_time
            duration_ms = round(duration * 1000, 2)

            # Track active requests
            ACTIVE_REQUESTS.dec()

            # Record metrics
            status_str = str(status_code)
            REQUEST_LATENCY.labels(
                method=method,
                endpoint=endpoint,
                status=status_str,
            ).observe(duration)

            REQUEST_COUNT.labels(
                method=method,
                endpoint=endpoint,
                status=status_str,
            ).inc()

            # Log request completion
            logger.info(
                "Request completed",
                extra={
                    "event": "request_completed",
                    "method": method,
                    "path": str(request.url.path),
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                },
            )

            # Clear audit context
            if set_audit_fn:
                try:
                    from pii_airlock.audit import clear_audit_context
                    clear_audit_context()
                except ImportError:
                    pass

        # Add request ID header to response
        response.headers["X-Request-ID"] = request_id

        return response

    def _get_endpoint(self, request: Request) -> str:
        """Get normalized endpoint for metrics.

        Args:
            request: The incoming request.

        Returns:
            Normalized endpoint path.
        """
        path = request.url.path
        # Normalize common endpoints
        if path.startswith("/v1/chat/completions"):
            return "/v1/chat/completions"
        if path.startswith("/api/test"):
            return "/api/test"
        return path

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request.

        Args:
            request: The incoming request.

        Returns:
            Client IP address.
        """
        # Check for forwarded IP
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

        # Check for real IP
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to client host
        if request.client:
            return request.client.host

        return "unknown"
