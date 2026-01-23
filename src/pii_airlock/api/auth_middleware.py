"""Authentication and tenant identification middleware.

This middleware provides:
- Tenant identification from headers or API keys
- API key validation
- Request context injection for tenant and user info
"""

import os
from typing import Optional, Callable

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from pii_airlock.auth.tenant import get_current_tenant, DEFAULT_TENANT_ID, Tenant
from pii_airlock.auth.api_key import validate_api_key, APIKey
from pii_airlock.logging.setup import get_logger

logger = get_logger(__name__)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Middleware for authentication and tenant identification.

    This middleware:
    1. Extracts API key from Authorization header
    2. Validates API key and retrieves associated tenant
    3. Falls back to X-Tenant-ID header if no API key
    4. Injects tenant and API key info into request state

    Example:
        app.add_middleware(AuthenticationMiddleware)
    """

    # Paths that always skip authentication (public endpoints)
    SKIP_AUTH_PATHS = {
        "/health",
        "/docs",
        "/openapi.json",
        "/redoc",
    }

    # Paths that require authentication in production mode
    # Controlled by PII_AIRLOCK_SECURE_ENDPOINTS=true (default in production)
    SENSITIVE_PATHS = {
        "/ui",
        "/debug",
        "/admin",
        "/metrics",
    }

    # Prefixes that require authentication in production mode
    SENSITIVE_PREFIXES = (
        "/api/test",
    )

    # Paths that are management API (require auth but different handling)
    MANAGEMENT_API_PREFIX = "/api/v1"

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Response],
    ) -> Response:
        """Process request with authentication.

        Args:
            request: The incoming request.
            call_next: The next middleware/handler.

        Returns:
            The response from the handler.

        Raises:
            HTTPException: If authentication fails.
        """
        path = request.url.path

        # Check if sensitive endpoints require authentication
        secure_endpoints = os.getenv(
            "PII_AIRLOCK_SECURE_ENDPOINTS", "true"
        ).lower() == "true"

        # Skip auth for always-public endpoints (health, docs)
        if any(
            path == skip_path or path.startswith(skip_path)
            for skip_path in self.SKIP_AUTH_PATHS
        ):
            # Still set default tenant for consistency
            request.state.tenant_id = DEFAULT_TENANT_ID
            request.state.tenant = None
            request.state.api_key = None
            return await call_next(request)

        # Check if this is a sensitive endpoint that needs protection
        is_sensitive = (
            path in self.SENSITIVE_PATHS
            or any(path.startswith(prefix) for prefix in self.SENSITIVE_PREFIXES)
        )

        # In secure mode, sensitive endpoints require authentication
        if secure_endpoints and is_sensitive:
            # Check for authentication
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                logger.warning(
                    "Unauthenticated access to sensitive endpoint blocked",
                    extra={
                        "event": "auth_required",
                        "path": path,
                        "client_ip": self._get_client_ip(request),
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required for this endpoint",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        # Check if multi-tenant is enabled
        multi_tenant_enabled = os.getenv(
            "PII_AIRLOCK_MULTI_TENANT_ENABLED", "false"
        ).lower() == "true"

        # Extract API key from Authorization header
        api_key_value: Optional[str] = None
        auth_header = request.headers.get("Authorization", "")

        if auth_header.startswith("Bearer "):
            api_key_value = auth_header[7:].strip()

        # Extract tenant_id from header
        tenant_id_header = request.headers.get("X-Tenant-ID")

        # Validate API key if provided
        api_key_obj: Optional[APIKey] = None
        tenant: Optional[Tenant] = None

        if api_key_value:
            api_key_obj = validate_api_key(api_key_value)

            if not api_key_obj:
                logger.warning(
                    "Invalid API key provided",
                    extra={
                        "event": "auth_failed",
                        "client_ip": self._get_client_ip(request),
                        "api_key_prefix": api_key_value[:8] + "...",
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid API key",
                )

            # Get tenant from API key
            tenant = get_current_tenant(
                tenant_id=api_key_obj.tenant_id,
                api_key=api_key_value,
            )

            if not tenant:
                logger.warning(
                    "Tenant not found for API key",
                    extra={
                        "event": "auth_failed",
                        "tenant_id": api_key_obj.tenant_id,
                        "api_key_id": api_key_obj.key_id,
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Tenant not found or inactive",
                )

            request.state.tenant_id = tenant.tenant_id
            request.state.api_key = api_key_obj

        elif multi_tenant_enabled and tenant_id_header:
            # No API key, but tenant header provided
            # SEC-002 FIX: Only allow X-Tenant-ID header without API key if explicitly enabled
            # This prevents tenant ID spoofing attacks
            allow_header_tenant = os.getenv(
                "PII_AIRLOCK_ALLOW_HEADER_TENANT", "false"
            ).lower() == "true"

            if not allow_header_tenant:
                logger.warning(
                    "X-Tenant-ID header rejected without API key authentication",
                    extra={
                        "event": "auth_failed",
                        "tenant_id": tenant_id_header,
                        "reason": "header_tenant_disabled",
                        "client_ip": self._get_client_ip(request),
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key required for tenant identification",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            tenant = get_current_tenant(tenant_id=tenant_id_header)

            if not tenant:
                logger.warning(
                    "Invalid tenant ID in header",
                    extra={
                        "event": "auth_failed",
                        "tenant_id": tenant_id_header,
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid tenant ID",
                )

            request.state.tenant_id = tenant.tenant_id
            request.state.api_key = None

        else:
            # No authentication provided, use default
            request.state.tenant_id = DEFAULT_TENANT_ID
            request.state.api_key = None
            tenant = None

        # Store tenant object in state
        request.state.tenant = tenant

        # Log authenticated request
        if tenant:
            logger.debug(
                "Request authenticated",
                extra={
                    "event": "request_authenticated",
                    "tenant_id": tenant.tenant_id,
                    "api_key_id": api_key_obj.key_id if api_key_obj else None,
                },
            )

        return await call_next(request)

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


def get_tenant_id(request: Request) -> str:
    """Get tenant ID from request state.

    This is a FastAPI dependency function.

    Args:
        request: The current request.

    Returns:
        Tenant ID from request state.
    """
    return getattr(request.state, "tenant_id", DEFAULT_TENANT_ID)


def get_tenant(request: Request) -> Optional[Tenant]:
    """Get tenant object from request state.

    This is a FastAPI dependency function.

    Args:
        request: The current request.

    Returns:
        Tenant object or None.
    """
    return getattr(request.state, "tenant", None)


def get_api_key(request: Request) -> Optional[APIKey]:
    """Get API key object from request state.

    This is a FastAPI dependency function.

    Args:
        request: The current request.

    Returns:
        API key object or None.
    """
    return getattr(request.state, "api_key", None)
