"""Tests for Prometheus metrics."""

import pytest
from prometheus_client import REGISTRY

from pii_airlock.metrics.collectors import (
    REQUEST_LATENCY,
    REQUEST_COUNT,
    PII_DETECTED,
    UPSTREAM_LATENCY,
    UPSTREAM_ERRORS,
    ACTIVE_REQUESTS,
    MAPPING_STORE_SIZE,
    MAPPING_STORE_EXPIRED,
)


class TestMetricsDefinition:
    """Tests for metrics definition."""

    def test_request_latency_exists(self):
        """Test that REQUEST_LATENCY histogram exists."""
        assert REQUEST_LATENCY is not None
        assert REQUEST_LATENCY._name == "pii_airlock_request_duration_seconds"

    def test_request_count_exists(self):
        """Test that REQUEST_COUNT counter exists."""
        assert REQUEST_COUNT is not None
        # Prometheus counters internally use _name without _total suffix
        assert "pii_airlock_requests" in REQUEST_COUNT._name

    def test_pii_detected_exists(self):
        """Test that PII_DETECTED counter exists."""
        assert PII_DETECTED is not None
        assert "pii_airlock_pii_detected" in PII_DETECTED._name

    def test_upstream_latency_exists(self):
        """Test that UPSTREAM_LATENCY histogram exists."""
        assert UPSTREAM_LATENCY is not None
        assert UPSTREAM_LATENCY._name == "pii_airlock_upstream_duration_seconds"

    def test_upstream_errors_exists(self):
        """Test that UPSTREAM_ERRORS counter exists."""
        assert UPSTREAM_ERRORS is not None
        assert "pii_airlock_upstream_errors" in UPSTREAM_ERRORS._name

    def test_active_requests_exists(self):
        """Test that ACTIVE_REQUESTS gauge exists."""
        assert ACTIVE_REQUESTS is not None
        assert ACTIVE_REQUESTS._name == "pii_airlock_active_requests"

    def test_mapping_store_size_exists(self):
        """Test that MAPPING_STORE_SIZE gauge exists."""
        assert MAPPING_STORE_SIZE is not None
        assert MAPPING_STORE_SIZE._name == "pii_airlock_mapping_store_size"

    def test_mapping_store_expired_exists(self):
        """Test that MAPPING_STORE_EXPIRED counter exists."""
        assert MAPPING_STORE_EXPIRED is not None
        assert "pii_airlock_mapping_store_expired" in MAPPING_STORE_EXPIRED._name


class TestMetricsLabels:
    """Tests for metrics label configurations."""

    def test_request_latency_labels(self):
        """Test REQUEST_LATENCY has correct labels."""
        labels = REQUEST_LATENCY._labelnames
        assert "method" in labels
        assert "endpoint" in labels
        assert "status" in labels

    def test_request_count_labels(self):
        """Test REQUEST_COUNT has correct labels."""
        labels = REQUEST_COUNT._labelnames
        assert "method" in labels
        assert "endpoint" in labels
        assert "status" in labels

    def test_pii_detected_labels(self):
        """Test PII_DETECTED has correct labels."""
        labels = PII_DETECTED._labelnames
        assert "entity_type" in labels

    def test_upstream_latency_labels(self):
        """Test UPSTREAM_LATENCY has correct labels."""
        labels = UPSTREAM_LATENCY._labelnames
        assert "model" in labels

    def test_upstream_errors_labels(self):
        """Test UPSTREAM_ERRORS has correct labels."""
        labels = UPSTREAM_ERRORS._labelnames
        assert "error_type" in labels


class TestMetricsOperations:
    """Tests for metrics operations."""

    def test_request_latency_observation(self):
        """Test observing request latency."""
        # This should not raise
        REQUEST_LATENCY.labels(method="POST", endpoint="/test", status="200").observe(
            0.5
        )

    def test_request_count_increment(self):
        """Test incrementing request count."""
        # This should not raise
        REQUEST_COUNT.labels(method="GET", endpoint="/health", status="200").inc()

    def test_pii_detected_increment(self):
        """Test incrementing PII detection counter."""
        # This should not raise
        PII_DETECTED.labels(entity_type="PERSON").inc()
        PII_DETECTED.labels(entity_type="EMAIL").inc(5)

    def test_upstream_latency_observation(self):
        """Test observing upstream latency."""
        # This should not raise
        UPSTREAM_LATENCY.labels(model="gpt-4").observe(1.5)

    def test_upstream_errors_increment(self):
        """Test incrementing upstream errors."""
        # This should not raise
        UPSTREAM_ERRORS.labels(error_type="http_error").inc()

    def test_active_requests_gauge(self):
        """Test active requests gauge operations."""
        # This should not raise
        ACTIVE_REQUESTS.inc()
        ACTIVE_REQUESTS.dec()
        ACTIVE_REQUESTS.set(5)

    def test_mapping_store_size_gauge(self):
        """Test mapping store size gauge."""
        # This should not raise
        MAPPING_STORE_SIZE.set(10)
        MAPPING_STORE_SIZE.set(0)

    def test_mapping_store_expired_counter(self):
        """Test mapping store expired counter."""
        # This should not raise
        MAPPING_STORE_EXPIRED.inc()
        MAPPING_STORE_EXPIRED.inc(3)


class TestHistogramBuckets:
    """Tests for histogram bucket configurations."""

    def test_request_latency_buckets(self):
        """Test REQUEST_LATENCY has appropriate buckets."""
        # Request latency buckets: 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
        buckets = REQUEST_LATENCY._kwargs.get("buckets", REQUEST_LATENCY._upper_bounds)
        assert 0.01 in buckets or any(b <= 0.01 for b in buckets)
        assert 10.0 in buckets or any(b >= 10.0 for b in buckets)

    def test_upstream_latency_buckets(self):
        """Test UPSTREAM_LATENCY has appropriate buckets for LLM calls."""
        # Upstream latency buckets: 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0
        buckets = UPSTREAM_LATENCY._kwargs.get(
            "buckets", UPSTREAM_LATENCY._upper_bounds
        )
        # LLM calls can be slow, so we need larger buckets
        assert 60.0 in buckets or any(b >= 60.0 for b in buckets)
