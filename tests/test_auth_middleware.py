"""
Tests for authentication middleware (TEST-003).

Tests the authentication and tenant identification middleware including:
- Skip auth paths (health, docs)
- Sensitive endpoint protection
- API key validation
- Tenant identification from API key and header
- Client IP extraction
- Dependency functions
"""

import os
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import Response

from pii_airlock.api.auth_middleware import (
    AuthenticationMiddleware,
    get_tenant_id,
    get_tenant,
    get_api_key,
)
from pii_airlock.auth.tenant import DEFAULT_TENANT_ID


class TestSkipAuthPaths:
    """Test paths that always skip authentication."""

    def test_skip_auth_paths_constant(self):
        """Test SKIP_AUTH_PATHS contains expected paths."""
        assert "/health" in AuthenticationMiddleware.SKIP_AUTH_PATHS
        assert "/docs" in AuthenticationMiddleware.SKIP_AUTH_PATHS
        assert "/openapi.json" in AuthenticationMiddleware.SKIP_AUTH_PATHS
        assert "/redoc" in AuthenticationMiddleware.SKIP_AUTH_PATHS

    @pytest.mark.asyncio
    async def test_health_skips_auth(self):
        """Test /health endpoint skips authentication."""
        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_request = MagicMock()
        mock_request.url.path = "/health"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": ""

        mock_response = MagicMock()
        mock_call_next = AsyncMock(return_value=mock_response)

        result = await middleware.dispatch(mock_request, mock_call_next)

        # Should call next without auth check
        mock_call_next.assert_called_once_with(mock_request)
        assert mock_request.state.tenant_id == DEFAULT_TENANT_ID
        assert mock_request.state.api_key is None

    @pytest.mark.asyncio
    async def test_docs_skips_auth(self):
        """Test /docs endpoint skips authentication."""
        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_request = MagicMock()
        mock_request.url.path = "/docs"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": ""

        mock_response = MagicMock()
        mock_call_next = AsyncMock(return_value=mock_response)

        result = await middleware.dispatch(mock_request, mock_call_next)

        mock_call_next.assert_called_once_with(mock_request)


class TestSensitiveEndpoints:
    """Test sensitive endpoint protection."""

    def test_sensitive_paths_constant(self):
        """Test SENSITIVE_PATHS contains expected paths."""
        assert "/ui" in AuthenticationMiddleware.SENSITIVE_PATHS
        assert "/debug" in AuthenticationMiddleware.SENSITIVE_PATHS
        assert "/admin" in AuthenticationMiddleware.SENSITIVE_PATHS
        assert "/metrics" in AuthenticationMiddleware.SENSITIVE_PATHS

    def test_sensitive_prefixes_constant(self):
        """Test SENSITIVE_PREFIXES contains expected prefixes."""
        assert "/api/test" in AuthenticationMiddleware.SENSITIVE_PREFIXES

    @pytest.mark.asyncio
    async def test_ui_requires_auth_when_secure(self):
        """Test /ui requires authentication in secure mode."""
        from fastapi import HTTPException

        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_request = MagicMock()
        mock_request.url.path = "/ui"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": ""
        mock_request.client = MagicMock(host="127.0.0.1")

        mock_call_next = AsyncMock()

        with patch.dict(os.environ, {"PII_AIRLOCK_SECURE_ENDPOINTS": "true"}):
            with pytest.raises(HTTPException) as exc_info:
                await middleware.dispatch(mock_request, mock_call_next)

            assert exc_info.value.status_code == 401
            assert "Authentication required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_metrics_requires_auth_when_secure(self):
        """Test /metrics requires authentication in secure mode."""
        from fastapi import HTTPException

        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_request = MagicMock()
        mock_request.url.path = "/metrics"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": ""
        mock_request.client = MagicMock(host="127.0.0.1")

        mock_call_next = AsyncMock()

        with patch.dict(os.environ, {"PII_AIRLOCK_SECURE_ENDPOINTS": "true"}):
            with pytest.raises(HTTPException) as exc_info:
                await middleware.dispatch(mock_request, mock_call_next)

            assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_test_api_requires_auth_when_secure(self):
        """Test /api/test/* requires authentication in secure mode."""
        from fastapi import HTTPException

        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_request = MagicMock()
        mock_request.url.path = "/api/test/anonymize"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": ""
        mock_request.client = MagicMock(host="127.0.0.1")

        mock_call_next = AsyncMock()

        with patch.dict(os.environ, {"PII_AIRLOCK_SECURE_ENDPOINTS": "true"}):
            with pytest.raises(HTTPException) as exc_info:
                await middleware.dispatch(mock_request, mock_call_next)

            assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_sensitive_accessible_when_not_secure(self):
        """Test sensitive endpoints accessible when secure mode disabled."""
        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_request = MagicMock()
        mock_request.url.path = "/ui"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": ""

        mock_response = MagicMock()
        mock_call_next = AsyncMock(return_value=mock_response)

        with patch.dict(os.environ, {
            "PII_AIRLOCK_SECURE_ENDPOINTS": "false",
            "PII_AIRLOCK_MULTI_TENANT_ENABLED": "false",
        }):
            result = await middleware.dispatch(mock_request, mock_call_next)

            # Should proceed without auth check
            mock_call_next.assert_called_once_with(mock_request)


class TestAPIKeyValidation:
    """Test API key validation."""

    @pytest.mark.asyncio
    async def test_invalid_api_key_rejected(self):
        """Test invalid API key returns 401."""
        from fastapi import HTTPException

        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_request = MagicMock()
        mock_request.url.path = "/v1/chat/completions"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": {
            "Authorization": "Bearer invalid-key",
        }.get(key, default)
        mock_request.client = MagicMock(host="127.0.0.1")

        mock_call_next = AsyncMock()

        with patch.dict(os.environ, {"PII_AIRLOCK_SECURE_ENDPOINTS": "false"}):
            with patch("pii_airlock.api.auth_middleware.validate_api_key") as mock_validate:
                mock_validate.return_value = None

                with pytest.raises(HTTPException) as exc_info:
                    await middleware.dispatch(mock_request, mock_call_next)

                assert exc_info.value.status_code == 401
                assert "Invalid API key" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_valid_api_key_accepted(self):
        """Test valid API key allows request."""
        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_api_key = MagicMock()
        mock_api_key.tenant_id = "test-tenant"
        mock_api_key.key_id = "key-123"

        mock_tenant = MagicMock()
        mock_tenant.tenant_id = "test-tenant"

        mock_request = MagicMock()
        mock_request.url.path = "/v1/chat/completions"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": {
            "Authorization": "Bearer valid-key",
        }.get(key, default)

        mock_response = MagicMock()
        mock_call_next = AsyncMock(return_value=mock_response)

        with patch.dict(os.environ, {"PII_AIRLOCK_SECURE_ENDPOINTS": "false"}):
            with patch("pii_airlock.api.auth_middleware.validate_api_key") as mock_validate, \
                 patch("pii_airlock.api.auth_middleware.get_current_tenant") as mock_get_tenant:
                mock_validate.return_value = mock_api_key
                mock_get_tenant.return_value = mock_tenant

                result = await middleware.dispatch(mock_request, mock_call_next)

                mock_call_next.assert_called_once_with(mock_request)
                assert mock_request.state.tenant_id == "test-tenant"
                assert mock_request.state.api_key == mock_api_key

    @pytest.mark.asyncio
    async def test_api_key_with_missing_tenant_rejected(self):
        """Test API key with non-existent tenant returns 401."""
        from fastapi import HTTPException

        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_api_key = MagicMock()
        mock_api_key.tenant_id = "missing-tenant"
        mock_api_key.key_id = "key-123"

        mock_request = MagicMock()
        mock_request.url.path = "/v1/chat/completions"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": {
            "Authorization": "Bearer valid-key",
        }.get(key, default)

        mock_call_next = AsyncMock()

        with patch.dict(os.environ, {"PII_AIRLOCK_SECURE_ENDPOINTS": "false"}):
            with patch("pii_airlock.api.auth_middleware.validate_api_key") as mock_validate, \
                 patch("pii_airlock.api.auth_middleware.get_current_tenant") as mock_get_tenant:
                mock_validate.return_value = mock_api_key
                mock_get_tenant.return_value = None

                with pytest.raises(HTTPException) as exc_info:
                    await middleware.dispatch(mock_request, mock_call_next)

                assert exc_info.value.status_code == 401
                assert "Tenant not found" in exc_info.value.detail


class TestTenantHeaderIdentification:
    """Test tenant identification from X-Tenant-ID header."""

    @pytest.mark.asyncio
    async def test_tenant_header_rejected_without_permission(self):
        """Test X-Tenant-ID header rejected when not explicitly allowed."""
        from fastapi import HTTPException

        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_request = MagicMock()
        mock_request.url.path = "/v1/chat/completions"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": {
            "X-Tenant-ID": "test-tenant",
        }.get(key, default)
        mock_request.client = MagicMock(host="127.0.0.1")

        mock_call_next = AsyncMock()

        with patch.dict(os.environ, {
            "PII_AIRLOCK_SECURE_ENDPOINTS": "false",
            "PII_AIRLOCK_MULTI_TENANT_ENABLED": "true",
            "PII_AIRLOCK_ALLOW_HEADER_TENANT": "false",
        }):
            with pytest.raises(HTTPException) as exc_info:
                await middleware.dispatch(mock_request, mock_call_next)

            assert exc_info.value.status_code == 401
            assert "API key required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_tenant_header_accepted_when_allowed(self):
        """Test X-Tenant-ID header accepted when explicitly allowed."""
        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_tenant = MagicMock()
        mock_tenant.tenant_id = "header-tenant"

        mock_request = MagicMock()
        mock_request.url.path = "/v1/chat/completions"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": {
            "X-Tenant-ID": "header-tenant",
        }.get(key, default)

        mock_response = MagicMock()
        mock_call_next = AsyncMock(return_value=mock_response)

        with patch.dict(os.environ, {
            "PII_AIRLOCK_SECURE_ENDPOINTS": "false",
            "PII_AIRLOCK_MULTI_TENANT_ENABLED": "true",
            "PII_AIRLOCK_ALLOW_HEADER_TENANT": "true",
        }):
            with patch("pii_airlock.api.auth_middleware.get_current_tenant") as mock_get_tenant:
                mock_get_tenant.return_value = mock_tenant

                result = await middleware.dispatch(mock_request, mock_call_next)

                mock_call_next.assert_called_once_with(mock_request)
                assert mock_request.state.tenant_id == "header-tenant"

    @pytest.mark.asyncio
    async def test_invalid_tenant_header_rejected(self):
        """Test invalid X-Tenant-ID returns 401."""
        from fastapi import HTTPException

        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_request = MagicMock()
        mock_request.url.path = "/v1/chat/completions"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": {
            "X-Tenant-ID": "invalid-tenant",
        }.get(key, default)

        mock_call_next = AsyncMock()

        with patch.dict(os.environ, {
            "PII_AIRLOCK_SECURE_ENDPOINTS": "false",
            "PII_AIRLOCK_MULTI_TENANT_ENABLED": "true",
            "PII_AIRLOCK_ALLOW_HEADER_TENANT": "true",
        }):
            with patch("pii_airlock.api.auth_middleware.get_current_tenant") as mock_get_tenant:
                mock_get_tenant.return_value = None

                with pytest.raises(HTTPException) as exc_info:
                    await middleware.dispatch(mock_request, mock_call_next)

                assert exc_info.value.status_code == 401
                assert "Invalid tenant ID" in exc_info.value.detail


class TestDefaultTenant:
    """Test default tenant assignment."""

    @pytest.mark.asyncio
    async def test_no_auth_uses_default_tenant(self):
        """Test request without auth uses default tenant."""
        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_request = MagicMock()
        mock_request.url.path = "/v1/chat/completions"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": ""

        mock_response = MagicMock()
        mock_call_next = AsyncMock(return_value=mock_response)

        with patch.dict(os.environ, {
            "PII_AIRLOCK_SECURE_ENDPOINTS": "false",
            "PII_AIRLOCK_MULTI_TENANT_ENABLED": "false",
        }):
            result = await middleware.dispatch(mock_request, mock_call_next)

            mock_call_next.assert_called_once_with(mock_request)
            assert mock_request.state.tenant_id == DEFAULT_TENANT_ID
            assert mock_request.state.api_key is None


class TestDependencyFunctions:
    """Test FastAPI dependency functions."""

    def test_get_tenant_id_returns_default(self):
        """Test get_tenant_id returns default when no state."""
        mock_request = MagicMock()
        mock_request.state = MagicMock(spec=[])

        result = get_tenant_id(mock_request)
        assert result == DEFAULT_TENANT_ID

    def test_get_tenant_id_returns_state(self):
        """Test get_tenant_id returns value from state."""
        mock_request = MagicMock()
        mock_request.state.tenant_id = "custom-tenant"

        result = get_tenant_id(mock_request)
        assert result == "custom-tenant"

    def test_get_tenant_returns_none(self):
        """Test get_tenant returns None when no tenant."""
        mock_request = MagicMock()
        mock_request.state = MagicMock(spec=[])

        result = get_tenant(mock_request)
        assert result is None

    def test_get_tenant_returns_tenant(self):
        """Test get_tenant returns tenant from state."""
        mock_tenant = MagicMock()
        mock_request = MagicMock()
        mock_request.state.tenant = mock_tenant

        result = get_tenant(mock_request)
        assert result is mock_tenant

    def test_get_api_key_returns_none(self):
        """Test get_api_key returns None when no key."""
        mock_request = MagicMock()
        mock_request.state = MagicMock(spec=[])

        result = get_api_key(mock_request)
        assert result is None

    def test_get_api_key_returns_key(self):
        """Test get_api_key returns key from state."""
        mock_key = MagicMock()
        mock_request = MagicMock()
        mock_request.state.api_key = mock_key

        result = get_api_key(mock_request)
        assert result is mock_key


class TestClientIPExtraction:
    """Test client IP extraction."""

    def test_get_client_ip_from_forwarded(self):
        """Test IP extraction from X-Forwarded-For header."""
        middleware = AuthenticationMiddleware(app=MagicMock())
        mock_request = MagicMock()
        mock_request.headers.get = lambda key, default=None: {
            "X-Forwarded-For": "1.2.3.4, 5.6.7.8",
        }.get(key, default)
        mock_request.client = None

        ip = middleware._get_client_ip(mock_request)
        assert ip == "1.2.3.4"

    def test_get_client_ip_from_real_ip(self):
        """Test IP extraction from X-Real-IP header."""
        middleware = AuthenticationMiddleware(app=MagicMock())
        mock_request = MagicMock()
        mock_request.headers.get = lambda key, default=None: {
            "X-Real-IP": "10.20.30.40",
        }.get(key, default)
        mock_request.client = None

        ip = middleware._get_client_ip(mock_request)
        assert ip == "10.20.30.40"

    def test_get_client_ip_from_client(self):
        """Test IP extraction from request client."""
        middleware = AuthenticationMiddleware(app=MagicMock())
        mock_request = MagicMock()
        mock_request.headers.get = lambda key, default=None: None
        mock_request.client.host = "192.168.1.1"

        ip = middleware._get_client_ip(mock_request)
        assert ip == "192.168.1.1"

    def test_get_client_ip_unknown(self):
        """Test IP extraction returns unknown when no source."""
        middleware = AuthenticationMiddleware(app=MagicMock())
        mock_request = MagicMock()
        mock_request.headers.get = lambda key, default=None: None
        mock_request.client = None

        ip = middleware._get_client_ip(mock_request)
        assert ip == "unknown"


class TestBearerTokenParsing:
    """Test Bearer token parsing."""

    @pytest.mark.asyncio
    async def test_bearer_token_extracted(self):
        """Test Bearer token is correctly extracted from header."""
        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_api_key = MagicMock()
        mock_api_key.tenant_id = "test-tenant"
        mock_api_key.key_id = "key-123"

        mock_tenant = MagicMock()
        mock_tenant.tenant_id = "test-tenant"

        mock_request = MagicMock()
        mock_request.url.path = "/v1/chat/completions"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": {
            "Authorization": "Bearer   my-api-key-12345  ",  # Extra spaces
        }.get(key, default)

        mock_response = MagicMock()
        mock_call_next = AsyncMock(return_value=mock_response)

        with patch.dict(os.environ, {"PII_AIRLOCK_SECURE_ENDPOINTS": "false"}):
            with patch("pii_airlock.api.auth_middleware.validate_api_key") as mock_validate, \
                 patch("pii_airlock.api.auth_middleware.get_current_tenant") as mock_get_tenant:
                mock_validate.return_value = mock_api_key
                mock_get_tenant.return_value = mock_tenant

                await middleware.dispatch(mock_request, mock_call_next)

                # Check that the key was extracted and trimmed correctly
                mock_validate.assert_called_once_with("my-api-key-12345")

    @pytest.mark.asyncio
    async def test_non_bearer_auth_ignored(self):
        """Test non-Bearer auth header is ignored."""
        middleware = AuthenticationMiddleware(app=MagicMock())

        mock_request = MagicMock()
        mock_request.url.path = "/v1/chat/completions"
        mock_request.state = MagicMock()
        mock_request.headers.get = lambda key, default="": {
            "Authorization": "Basic dXNlcjpwYXNz",  # Basic auth
        }.get(key, default)

        mock_response = MagicMock()
        mock_call_next = AsyncMock(return_value=mock_response)

        with patch.dict(os.environ, {
            "PII_AIRLOCK_SECURE_ENDPOINTS": "false",
            "PII_AIRLOCK_MULTI_TENANT_ENABLED": "false",
        }):
            with patch("pii_airlock.api.auth_middleware.validate_api_key") as mock_validate:
                await middleware.dispatch(mock_request, mock_call_next)

                # validate_api_key should not be called for Basic auth
                mock_validate.assert_not_called()
                # Should use default tenant
                assert mock_request.state.tenant_id == DEFAULT_TENANT_ID


class TestManagementAPIPrefix:
    """Test management API prefix constant."""

    def test_management_api_prefix(self):
        """Test MANAGEMENT_API_PREFIX is correctly set."""
        assert AuthenticationMiddleware.MANAGEMENT_API_PREFIX == "/api/v1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
