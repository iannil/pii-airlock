"""Tests for utility functions."""

import pytest

from pii_airlock.utils import (
    cached_result,
    clean_whitespace,
    contains_chinese,
    count_words,
    extract_pii_placeholders,
    is_chinese_text,
    normalize_text,
    PerformanceMetrics,
    RateLimiter,
    sanitize_for_logging,
    sanitize_input,
    split_text_preserve_pii,
    TimedExecution,
    timed_execution,
    truncate_text,
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


class TestTextProcessing:
    """Tests for text processing functions."""

    def test_normalize_text_empty(self) -> None:
        assert normalize_text("") == ""
        assert normalize_text(None) == ""  # type: ignore

    def test_normalize_text_whitespace(self) -> None:
        assert normalize_text("  hello  world  ") == "hello world"
        assert normalize_text("hello\tworld\ntest") == "hello world test"

    def test_normalize_text_unicode(self) -> None:
        # Unicode NFKC normalization
        assert normalize_text("Hello\u00a0World") == "Hello World"

    def test_truncate_text_no_truncation(self) -> None:
        assert truncate_text("short", 20) == "short"

    def test_truncate_text_with_truncation(self) -> None:
        assert truncate_text("This is a long text", 10) == "This is..."
        # max_length=3 is less than suffix length (3), so it should just be the suffix
        # Actually, 3 >= 3, so it should return "..." (no room for text)
        assert truncate_text("Hello", 3) == "..."
        assert truncate_text("Hello", 5) == "Hello"  # No truncation needed
        assert truncate_text("Hello World", 8) == "Hello..."

    def test_truncate_text_custom_suffix(self) -> None:
        assert truncate_text("Long text here", 10, suffix="---") == "Long te---"

    def test_truncate_text_invalid_length(self) -> None:
        with pytest.raises(ValueError):
            truncate_text("test", 2, suffix="...")

    def test_count_words_english(self) -> None:
        assert count_words("Hello world") == 2
        assert count_words("  Multiple   spaces  ") == 2

    def test_count_words_chinese(self) -> None:
        # Chinese counts characters
        assert count_words("你好世界") == 4

    def test_count_words_mixed(self) -> None:
        # Mixed English and Chinese
        # "Hello" = 1 English word, "你好" = 2 Chinese characters
        assert count_words("Hello 你好") == 3  # 1 English word + 2 Chinese chars

    def test_clean_whitespace(self) -> None:
        assert clean_whitespace("  hello   world  ") == "hello world"
        assert clean_whitespace("hello\n\nworld", preserve_newlines=True) == "hello\n\nworld"

    def test_contains_chinese(self) -> None:
        assert contains_chinese("Hello 世界") is True
        assert contains_chinese("Hello world") is False
        assert contains_chinese("") is False

    def test_extract_pii_placeholders(self) -> None:
        result = extract_pii_placeholders("Hello <PERSON_1>, call <PHONE_1>")
        assert result == ["PERSON_1", "PHONE_1"]

        result = extract_pii_placeholders("No placeholders here")
        assert result == []

    def test_sanitize_for_logging(self) -> None:
        result = sanitize_for_logging("Long text here " * 20, 20)
        assert len(result) <= 23  # 20 + "..."

    def test_split_text_preserve_pii(self) -> None:
        # The function splits at chunk boundaries, result may vary
        result = split_text_preserve_pii("Hello <PERSON_1> world", 15)
        # The key is that placeholder should not be split
        assert any("<PERSON_1>" in chunk for chunk in result)
        # All original text should be present
        assert "".join(result) == "Hello <PERSON_1> world"


class TestValidators:
    """Tests for validation functions."""

    def test_validate_email_valid(self) -> None:
        assert validate_email("user@example.com") is True
        assert validate_email("test+tag@domain.co.uk") is True
        assert validate_email("user123@test-domain.com") is True

    def test_validate_email_invalid(self) -> None:
        assert validate_email("invalid.email") is False
        assert validate_email("") is False
        assert validate_email("@example.com") is False

    def test_validate_phone_valid(self) -> None:
        assert validate_phone("13800138000") is True
        assert validate_phone("15912345678") is True
        assert validate_phone("  13800138000  ") is True  # With spaces

    def test_validate_phone_invalid(self) -> None:
        assert validate_phone("12345678901") is False
        assert validate_phone("1380013800") is False  # Too short
        assert validate_phone("") is False

    def test_validate_phone_international(self) -> None:
        assert validate_phone_international("+8613800138000") is True
        assert validate_phone_international("+14155552671") is True
        assert validate_phone_international("13800138000") is False  # No +

    def test_validate_chinese_id_card_valid(self) -> None:
        assert validate_chinese_id_card("110101199003077758") is True
        assert validate_chinese_id_card("310104198007137514") is True

    def test_validate_chinese_id_card_invalid(self) -> None:
        assert validate_chinese_id_card("123456789012345678") is False
        assert validate_chinese_id_card("") is False

    def test_validate_chinese_id_card_checksum(self) -> None:
        assert validate_chinese_id_card_with_checksum("110101199003077758") is True

    def test_validate_credit_card_valid(self) -> None:
        # Test card numbers (Luhn valid)
        assert validate_credit_card("4111111111111111") is True  # Visa test
        assert validate_credit_card("4242 4242 4242 4242") is True  # Stripe test

    def test_validate_credit_card_invalid(self) -> None:
        assert validate_credit_card("1234567890123456") is False
        assert validate_credit_card("") is False

    def test_validate_ip_address_ipv4(self) -> None:
        assert validate_ip_address("192.168.1.1") is True
        assert validate_ip_address("8.8.8.8") is True

    def test_validate_ip_address_ipv6(self) -> None:
        assert validate_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

    def test_validate_ip_address_invalid(self) -> None:
        assert validate_ip_address("256.256.256.256") is False
        assert validate_ip_address("") is False

    def test_validate_url_valid(self) -> None:
        assert validate_url("https://example.com") is True
        assert validate_url("http://test.org/path") is True
        assert validate_url("ftp://files.example.com") is True

    def test_validate_url_invalid(self) -> None:
        assert validate_url("not a url") is False
        assert validate_url("") is False

    def test_validate_ssn_valid(self) -> None:
        assert validate_ssn("123-45-6789") is True
        assert validate_ssn("123456789") is True

    def test_validate_ssn_invalid(self) -> None:
        assert validate_ssn("000-00-0000") is False
        assert validate_ssn("666-12-3456") is False
        assert validate_ssn("900-12-3456") is False

    def test_validate_postal_code_china(self) -> None:
        assert validate_postal_code("100000") is True  # Beijing
        assert validate_postal_code("200000") is True  # Shanghai

    def test_validate_postal_code_us(self) -> None:
        assert validate_postal_code("90210", country="US") is True
        assert validate_postal_code("12345-6789", country="US") is True

    def test_is_chinese_text(self) -> None:
        assert is_chinese_text("你好世界") is True
        assert is_chinese_text("Hello world") is False
        assert is_chinese_text("Hello 世界", threshold=0.2) is True

    def test_sanitize_input_valid(self) -> None:
        is_valid, result = sanitize_input("Hello world", 100)
        assert is_valid is True
        assert result == "Hello world"

    def test_sanitize_input_empty(self) -> None:
        is_valid, result = sanitize_input("", 100)
        assert is_valid is False
        assert "empty" in result.lower()

    def test_sanitize_input_too_long(self) -> None:
        is_valid, result = sanitize_input("a" * 10001, 10000)
        assert is_valid is False
        assert "exceeds" in result.lower()

    def test_sanitize_input_malicious(self) -> None:
        is_valid, result = sanitize_input("<script>alert('xss')</script>", 1000)
        assert is_valid is False
        assert "malicious" in result.lower()


class TestPerformanceUtils:
    """Tests for performance utilities."""

    def test_timed_execution_context(self) -> None:
        with TimedExecution("test_operation") as timer:
            assert timer.operation_name == "test_operation"
        assert timer.elapsed_ms >= 0

    def test_timed_execution_decorator(self) -> None:
        @timed_execution
        def test_func():
            return "result"

        result = test_func()
        assert result == "result"

    def test_performance_metrics(self) -> None:
        metrics = PerformanceMetrics()

        metrics.record(50.0)
        metrics.record(100.0)
        metrics.record(150.0)

        assert metrics.count == 3
        assert metrics.min_ms == 50.0
        assert metrics.max_ms == 150.0
        assert metrics.avg_ms == 100.0

    def test_performance_metrics_percentiles(self) -> None:
        metrics = PerformanceMetrics()

        for i in range(100):
            metrics.record(float(i))

        assert metrics.p50_ms == pytest.approx(49.5, abs=1)
        assert metrics.p95_ms == pytest.approx(94.0, abs=2)

    def test_performance_metrics_summary(self) -> None:
        metrics = PerformanceMetrics()
        metrics.record(100.0)

        summary = metrics.get_summary()
        assert "count" in summary
        assert "avg_ms" in summary

    def test_performance_metrics_reset(self) -> None:
        metrics = PerformanceMetrics()
        metrics.record(100.0)
        metrics.reset()

        assert metrics.count == 0

    def test_rate_limiter(self) -> None:
        limiter = RateLimiter(rate=10, burst=5)

        # Should allow up to burst
        for _ in range(5):
            assert limiter.try_acquire() is True

        # Should reject after burst
        assert limiter.try_acquire() is False

    def test_cached_result(self) -> None:
        call_count = 0

        @cached_result(ttl_seconds=1.0)
        def expensive_func(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        # First call
        assert expensive_func(5) == 10
        assert call_count == 1

        # Cached call
        assert expensive_func(5) == 10
        assert call_count == 1

        # Different argument
        assert expensive_func(3) == 6
        assert call_count == 2
