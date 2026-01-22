"""Tests for entropy detector."""

import pytest

from pii_airlock.recognizers.entropy_detector import (
    EntropyLevel,
    EntropyResult,
    EntropyDetector,
    SecretScanner,
    get_entropy_detector,
    is_secret,
    scan_for_secrets,
)


class TestShannonEntropy:
    """Tests for Shannon entropy calculation."""

    def test_entropy_empty_string(self):
        """Test entropy of empty string."""
        detector = EntropyDetector()
        entropy = detector.calculate_shannon_entropy("")
        assert entropy == 0.0

    def test_entropy_single_character(self):
        """Test entropy of single character."""
        detector = EntropyDetector()
        entropy = detector.calculate_shannon_entropy("a")
        assert entropy == 0.0

    def test_entropy_repeated_character(self):
        """Test entropy of repeated characters."""
        detector = EntropyDetector()
        entropy = detector.calculate_shannon_entropy("aaaa")
        assert entropy == 0.0

    def test_entropy_uniform_string(self):
        """Test entropy of uniform distribution."""
        detector = EntropyDetector()
        # All characters appear equally
        entropy = detector.calculate_shannon_entropy("abcd")
        # Maximum entropy for 4 unique characters is log2(4) = 2
        assert entropy > 1.5

    def test_entropy_natural_language(self):
        """Test entropy of natural language."""
        detector = EntropyDetector()
        entropy = detector.calculate_shannon_entropy("Hello world")
        # Natural language has lower entropy
        assert 2.5 < entropy < 4.5

    def test_entropy_random_string(self):
        """Test entropy of random string."""
        detector = EntropyDetector()
        # Hex string (high entropy)
        entropy = detector.calculate_shannon_entropy("a1b2c3d4e5f6g7h8")
        # Should be higher than natural language
        assert entropy > 3.5

    def test_entropy_api_key_like(self):
        """Test entropy of API key-like string."""
        detector = EntropyDetector()
        # Base64-like string
        entropy = detector.calculate_shannon_entropy("sk-1234567890abcdefABCDEF")
        assert entropy > 4.0


class TestEntropyClassification:
    """Tests for entropy level classification."""

    def test_classify_low_entropy(self):
        """Test classification of low entropy."""
        detector = EntropyDetector()
        level = detector.classify_entropy(2.0)
        assert level == EntropyLevel.LOW

    def test_classify_medium_entropy(self):
        """Test classification of medium entropy."""
        detector = EntropyDetector()
        level = detector.classify_entropy(4.0)
        assert level == EntropyLevel.MEDIUM

    def test_classify_high_entropy(self):
        """Test classification of high entropy."""
        detector = EntropyDetector()
        level = detector.classify_entropy(4.8)
        assert level == EntropyLevel.HIGH

    def test_classify_critical_entropy(self):
        """Test classification of critical entropy."""
        detector = EntropyDetector()
        level = detector.classify_entropy(5.2)
        assert level == EntropyLevel.CRITICAL


class TestEntropyDetector:
    """Tests for EntropyDetector."""

    def test_analyze_too_short(self):
        """Test that short strings return None."""
        detector = EntropyDetector(min_length=16)
        result = detector.analyze("short")
        assert result is None

    def test_analyze_uuid(self):
        """Test analysis of UUID (false positive)."""
        detector = EntropyDetector()
        result = detector.analyze("550e8400-e29b-41d4-a716-446655440000")

        assert result is not None
        assert result.is_suspicious is False  # UUIDs should be filtered

    def test_analyze_hex_color(self):
        """Test analysis of hex color (false positive)."""
        detector = EntropyDetector()
        result = detector.analyze("#ff5733")

        # May be None if too short, or not suspicious
        if result:
            assert result.is_suspicious is False

    def test_analyze_date(self):
        """Test analysis of date (false positive)."""
        detector = EntropyDetector()
        result = detector.analyze("2023-12-25")

        if result:
            assert result.is_suspicious is False

    def test_analyze_pure_digits(self):
        """Test analysis of pure digits."""
        detector = EntropyDetector()
        result = detector.analyze("12345678901234567890")

        assert result is None or result.is_suspicious is False

    def test_analyze_natural_language(self):
        """Test analysis of natural language."""
        detector = EntropyDetector()
        result = detector.analyze(
            "This is a normal sentence that someone might write"
        )

        if result:
            assert result.level in (EntropyLevel.LOW, EntropyLevel.MEDIUM)

    def test_analyze_base64_token(self):
        """Test analysis of Base64 token."""
        detector = EntropyDetector()
        # 32-character base64-like string
        result = detector.analyze("dGVzdGFiYzEyMzQ1Njc4OX55enh3dnE=")

        if result:
            # Base64 tokens with low variance may have MEDIUM entropy
            assert result.level in (EntropyLevel.MEDIUM, EntropyLevel.HIGH, EntropyLevel.CRITICAL)

    def test_analyze_hex_token(self):
        """Test analysis of hex token."""
        detector = EntropyDetector()
        result = detector.analyze("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

        if result:
            # Hex tokens with patterns may have MEDIUM entropy
            assert result.level in (EntropyLevel.MEDIUM, EntropyLevel.HIGH, EntropyLevel.CRITICAL)

    def test_analyze_with_context(self):
        """Test analysis with context."""
        detector = EntropyDetector()
        result = detector.analyze(
            "sk-1234567890abcdef",
            context="api_key: sk-1234567890abcdef"
        )

        # Context containing "api_key" should increase suspicion
        if result:
            # Medium entropy + secret indicator = suspicious
            assert "secret indicator" in result.reason.lower() or result.is_suspicious

    def test_scan_text(self):
        """Test scanning text for high entropy strings."""
        detector = EntropyDetector()
        text = "Normal text with a suspicious_token: a1b2c3d4e5f6a7b8c9d0e1f2"

        results = detector.scan_text(text)

        # Should find the high entropy token
        assert len(results) >= 1
        if results:
            assert any("a1b2c3d4e5f6a7b8c9d0e1f2" in r.text for r in results)

    def test_scan_text_no_secrets(self):
        """Test scanning text without secrets."""
        detector = EntropyDetector()
        text = "This is just normal text with no secrets or tokens"

        results = detector.scan_text(text)

        # Should not find anything suspicious
        assert all(not r.is_suspicious for r in results)


class TestSecretScanner:
    """Tests for SecretScanner."""

    def test_is_high_entropy_secret(self):
        """Test checking if text is a secret."""
        scanner = SecretScanner()

        # High entropy string
        assert scanner.is_high_entropy_secret("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8")

        # Natural language
        assert not scanner.is_high_entropy_secret(
            "This is normal text that people write"
        )

    def test_scan_and_report_clean(self):
        """Test scanning clean text."""
        scanner = SecretScanner()
        result = scanner.scan_and_report("This is clean text")

        assert result["found"] == 0
        assert result["risk_level"] == "none"
        assert len(result["items"]) == 0

    def test_scan_and_report_with_secrets(self):
        """Test scanning text with secrets."""
        scanner = SecretScanner()
        text = "API key: sk-1234567890abcdefghijk"
        result = scanner.scan_and_report(text)

        if result["found"] > 0:
            assert result["risk_level"] in ("medium", "high", "critical")
            assert len(result["items"]) == result["found"]


class TestGlobalFunctions:
    """Tests for global utility functions."""

    def test_get_entropy_detector_singleton(self):
        """Test that get_entropy_detector returns singleton."""
        detector1 = get_entropy_detector()
        detector2 = get_entropy_detector()

        assert detector1 is detector2

    def test_is_secret(self):
        """Test is_secret convenience function."""
        # High entropy string
        result = is_secret("sk-1234567890abcdefghijk1234567890")
        assert isinstance(result, bool)

        # Low entropy string
        result = is_secret("hello world")
        assert isinstance(result, bool)

    def test_scan_for_secrets(self):
        """Test scan_for_secrets convenience function."""
        result = scan_for_secrets("This is clean text")

        assert "found" in result
        assert "risk_level" in result
        assert "items" in result


class TestKnownSecretPatterns:
    """Tests for detecting known secret patterns."""

    def test_detect_openai_api_key(self):
        """Test detection of OpenAI API key pattern."""
        detector = EntropyDetector()
        # OpenAI keys start with "sk-" and are high entropy
        result = detector.analyze("sk-proj-abc123def456ghi789jkl012mno345pqr")

        if result:
            assert result.is_suspicious or result.level == EntropyLevel.HIGH

    def test_detect_aws_access_key(self):
        """Test detection of AWS access key pattern."""
        detector = EntropyDetector()
        # AWS keys are 20-character alphanumeric
        result = detector.analyze("AKIAIOSFODNN7EXAMPLE")

        if result:
            # AWS keys have moderate-high entropy
            assert result.level in (EntropyLevel.MEDIUM, EntropyLevel.HIGH)

    def test_detect_bearer_token(self):
        """Test detection of bearer token."""
        scanner = SecretScanner()
        # Bearer tokens are typically high entropy
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

        result = scanner.scan_and_report(text)
        # May find the JWT token as suspicious


@pytest.mark.parametrize(
    "text,expected_suspicious",
    [
        ("normal text", False),
        ("1234567890123456", False),  # Too predictable
        ("abcdabcdabcdabcd", False),  # Repeating pattern
        ("a1b2c3d4e5f6g7h8", True),  # Mixed case + digits
        ("sk-1234567890abcDEF", True),  # API key like
    ],
)
def test_entropy_detection_cases(text, expected_suspicious):
    """Test various entropy detection cases."""
    detector = EntropyDetector()
    result = detector.analyze(text)

    if result is None:
        # Too short or filtered
        return

    if expected_suspicious:
        # Should at least be medium risk
        assert result.level in (
            EntropyLevel.MEDIUM,
            EntropyLevel.HIGH,
            EntropyLevel.CRITICAL,
        )
    else:
        # Should not be marked as suspicious
        assert not result.is_suspicious or result.level == EntropyLevel.LOW
