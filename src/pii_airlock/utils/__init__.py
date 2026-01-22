"""Utility functions and validators."""

# Text processing utilities
from pii_airlock.utils.text import (
    clean_whitespace,
    contains_chinese,
    count_words,
    extract_pii_placeholders,
    normalize_text,
    sanitize_for_logging,
    split_text_preserve_pii,
    truncate_text,
)

# Validation utilities
from pii_airlock.utils.validators import (
    is_chinese_text,
    sanitize_input,
    validate_chinese_id_card,
    validate_chinese_id_card_with_checksum,
    validate_credit_card,
    validate_email,
    validate_ip_address,
    validate_phone,
    validate_phone_international,
    validate_postal_code,
    validate_ssn,
    validate_url,
)

# Performance utilities
from pii_airlock.utils.performance import (
    PerformanceMetrics,
    RateLimiter,
    TimedExecution,
    cached_result,
    retry_on_failure,
    timed_execution,
)

__all__ = [
    # Text processing
    "normalize_text",
    "truncate_text",
    "count_words",
    "split_text_preserve_pii",
    "clean_whitespace",
    "contains_chinese",
    "extract_pii_placeholders",
    "sanitize_for_logging",
    # Validation
    "validate_email",
    "validate_phone",
    "validate_phone_international",
    "validate_chinese_id_card",
    "validate_chinese_id_card_with_checksum",
    "validate_credit_card",
    "validate_ip_address",
    "validate_url",
    "validate_ssn",
    "validate_postal_code",
    "is_chinese_text",
    "sanitize_input",
    # Performance
    "TimedExecution",
    "timed_execution",
    "PerformanceMetrics",
    "RateLimiter",
    "cached_result",
    "retry_on_failure",
]
