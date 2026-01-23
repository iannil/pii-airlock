"""Prometheus metrics collectors for PII-AIRLOCK.

Defines all application metrics for monitoring and observability.
"""

from prometheus_client import Counter, Gauge, Histogram

# Request metrics
REQUEST_LATENCY = Histogram(
    "pii_airlock_request_duration_seconds",
    "Request latency in seconds",
    ["method", "endpoint", "status"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

REQUEST_COUNT = Counter(
    "pii_airlock_requests_total",
    "Total request count",
    ["method", "endpoint", "status"],
)

# PII detection metrics
PII_DETECTED = Counter(
    "pii_airlock_pii_detected_total",
    "Total PII entities detected",
    ["entity_type"],
)

# Upstream API metrics
UPSTREAM_LATENCY = Histogram(
    "pii_airlock_upstream_duration_seconds",
    "Upstream API latency",
    ["model"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
)

UPSTREAM_ERRORS = Counter(
    "pii_airlock_upstream_errors_total",
    "Upstream API errors",
    ["error_type"],
)

# Active connections
ACTIVE_REQUESTS = Gauge(
    "pii_airlock_active_requests",
    "Currently processing requests",
)

# Mapping store metrics
MAPPING_STORE_SIZE = Gauge(
    "pii_airlock_mapping_store_size",
    "Number of active mappings in store",
)

MAPPING_STORE_EXPIRED = Counter(
    "pii_airlock_mapping_store_expired_total",
    "Total expired mappings cleaned up",
)

# Quota metrics
QUOTA_EXCEEDED = Counter(
    "pii_airlock_quota_exceeded_total",
    "Total quota limit violations",
    ["tenant_id", "quota_type"],
)

# Secret scanning metrics
SECRET_DETECTED = Counter(
    "pii_airlock_secret_detected_total",
    "Total secrets detected in requests",
    ["secret_type", "risk_level"],
)

SECRET_BLOCKED = Counter(
    "pii_airlock_secret_blocked_total",
    "Total requests blocked due to secrets",
    ["secret_type"],
)

# OPS-006: Local processing latency
ANONYMIZATION_DURATION = Histogram(
    "pii_airlock_anonymization_duration_seconds",
    "Anonymization processing latency",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)

DEANONYMIZATION_DURATION = Histogram(
    "pii_airlock_deanonymization_duration_seconds",
    "Deanonymization processing latency",
    buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1],
)

SECRET_SCAN_DURATION = Histogram(
    "pii_airlock_secret_scan_duration_seconds",
    "Secret scanning latency",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
)
