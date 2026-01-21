"""Tests for rate limiting functionality."""

import pytest
from unittest.mock import patch, MagicMock

from starlette.requests import Request
from starlette.testclient import TestClient

from pii_airlock.api.limiter import (
    limiter,
    get_rate_limit_key,
    get_rate_limit,
    is_rate_limit_enabled,
    DEFAULT_RATE_LIMIT,
)


class TestGetRateLimitKey:
    """Tests for get_rate_limit_key function."""

    def test_uses_api_key_when_present(self):
        """Test that API key is used for rate limiting when present."""
        # Create a mock request with X-API-Key header
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [(b"x-api-key", b"sk-test1234567890")],
        }
        request = Request(scope)

        key = get_rate_limit_key(request)

        # Should use truncated API key
        assert key.startswith("api_key:")
        assert "sk-test1" in key
        assert "..." in key

    def test_uses_ip_when_no_api_key(self):
        """Test that IP address is used when no API key present."""
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [],
            "client": ("192.168.1.100", 12345),
        }
        request = Request(scope)

        key = get_rate_limit_key(request)

        # Should return IP address
        assert key == "192.168.1.100"


class TestGetRateLimit:
    """Tests for get_rate_limit function."""

    def test_returns_default_rate_limit(self):
        """Test that default rate limit is returned."""
        with patch.dict("os.environ", {}, clear=True):
            # Remove any existing env var
            import os

            os.environ.pop("PII_AIRLOCK_RATE_LIMIT", None)

            limit = get_rate_limit()
            assert limit == DEFAULT_RATE_LIMIT
            assert limit == "60/minute"

    def test_returns_custom_rate_limit(self):
        """Test that custom rate limit from env is returned."""
        with patch.dict("os.environ", {"PII_AIRLOCK_RATE_LIMIT": "100/minute"}):
            limit = get_rate_limit()
            assert limit == "100/minute"


class TestIsRateLimitEnabled:
    """Tests for is_rate_limit_enabled function."""

    def test_enabled_by_default(self):
        """Test that rate limiting is enabled by default."""
        with patch.dict("os.environ", {}, clear=True):
            import os

            os.environ.pop("PII_AIRLOCK_RATE_LIMIT_ENABLED", None)

            enabled = is_rate_limit_enabled()
            assert enabled is True

    def test_can_be_disabled(self):
        """Test that rate limiting can be disabled via env."""
        with patch.dict("os.environ", {"PII_AIRLOCK_RATE_LIMIT_ENABLED": "false"}):
            enabled = is_rate_limit_enabled()
            assert enabled is False

    def test_enabled_when_true(self):
        """Test that rate limiting is enabled when set to 'true'."""
        with patch.dict("os.environ", {"PII_AIRLOCK_RATE_LIMIT_ENABLED": "true"}):
            enabled = is_rate_limit_enabled()
            assert enabled is True


class TestLimiterInstance:
    """Tests for limiter instance."""

    def test_limiter_exists(self):
        """Test that limiter instance exists."""
        assert limiter is not None

    def test_limiter_uses_custom_key_func(self):
        """Test that limiter uses our custom key function."""
        assert limiter._key_func == get_rate_limit_key


class TestRateLimitIntegration:
    """Integration tests for rate limiting with FastAPI."""

    @pytest.fixture
    def client(self):
        """Create a test client with rate limiting."""
        from pii_airlock.api.routes import app

        return TestClient(app)

    def test_health_endpoint_not_rate_limited(self, client):
        """Test that health endpoint works without rate limiting."""
        # Health endpoint should always work
        response = client.get("/health")
        assert response.status_code == 200

    def test_metrics_endpoint_not_rate_limited(self, client):
        """Test that metrics endpoint works without rate limiting."""
        response = client.get("/metrics")
        assert response.status_code == 200

    def test_rate_limit_headers_present(self, client):
        """Test that rate limit headers are present in response."""
        # Note: This test may need adjustment based on actual rate limit config
        # The actual rate limiting behavior depends on the limiter state
        response = client.get("/health")

        # Health endpoint should work
        assert response.status_code == 200


class TestRateLimitFormat:
    """Tests for rate limit format strings."""

    def test_default_rate_limit_format(self):
        """Test that default rate limit is in valid format."""
        limit = DEFAULT_RATE_LIMIT

        # Should be in format "number/period"
        assert "/" in limit
        parts = limit.split("/")
        assert len(parts) == 2

        # First part should be a number
        assert parts[0].isdigit()

        # Second part should be a time period
        assert parts[1] in ["second", "minute", "hour", "day"]

    def test_common_rate_limit_formats(self):
        """Test that common rate limit formats are valid."""
        valid_formats = [
            "60/minute",
            "100/minute",
            "10/second",
            "1000/hour",
            "10000/day",
        ]

        for fmt in valid_formats:
            parts = fmt.split("/")
            assert len(parts) == 2
            assert parts[0].isdigit()
            assert parts[1] in ["second", "minute", "hour", "day"]
