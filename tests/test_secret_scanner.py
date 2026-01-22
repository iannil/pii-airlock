"""Tests for the secret scanner module."""

import pytest
import string

from pii_airlock.core.secret_scanner.patterns import (
    SecretPattern,
    SecretType,
    get_predefined_patterns,
    get_pattern_by_type,
)
from pii_airlock.core.secret_scanner.scanner import (
    SecretMatch,
    SecretScanResult,
    SecretScanner,
    quick_scan,
    get_secret_scanner,
)
from pii_airlock.core.secret_scanner.interceptor import (
    InterceptResult,
    SecretInterceptor,
    get_secret_interceptor,
)


class TestSecretPatterns:
    """Tests for predefined secret patterns."""

    def test_get_predefined_patterns_all(self):
        """Test getting all predefined patterns."""
        patterns = get_predefined_patterns()

        assert len(patterns) > 20
        assert all(isinstance(p, SecretPattern) for p in patterns)

    def test_get_predefined_patterns_filtered(self):
        """Test filtering patterns by type."""
        patterns = get_predefined_patterns(types=[SecretType.OPENAI_API_KEY])

        assert len(patterns) == 1
        assert patterns[0].type == SecretType.OPENAI_API_KEY

    def test_get_predefined_patterns_min_risk(self):
        """Test filtering by minimum risk level."""
        patterns = get_predefined_patterns(min_risk_level="critical")

        assert all(p.risk_level == "critical" for p in patterns)

    def test_get_pattern_by_type(self):
        """Test getting pattern by type."""
        pattern = get_pattern_by_type(SecretType.OPENAI_API_KEY)

        assert pattern is not None
        assert pattern.type == SecretType.OPENAI_API_KEY
        assert pattern.risk_level == "critical"

    def test_get_pattern_by_type_not_found(self):
        """Test getting non-existent pattern."""
        pattern = get_pattern_by_type("nonexistent")

        assert pattern is None


class TestSecretScanner:
    """Tests for SecretScanner."""

    def test_scan_openai_key(self):
        """Test scanning OpenAI API key."""
        scanner = SecretScanner()
        # OpenAI API key: sk- + 48 chars
        key_suffix = string.ascii_letters * 2 + string.digits * 2  # 72 chars, take first 48
        key = "sk-" + key_suffix[:48]
        text = f"My key: {key}"
        result = scanner.scan(text)

        assert result.total_count == 1
        assert result.matches[0].secret_type == SecretType.OPENAI_API_KEY

    def test_scan_anthropic_key(self):
        """Test scanning Anthropic API key."""
        scanner = SecretScanner()
        # Anthropic key: sk-ant-api03- + 95 chars
        chars = string.ascii_letters + string.digits + "_-"
        key_suffix = (chars * 3)[:95]
        key = "sk-ant-api03-" + key_suffix
        text = f"Claude key: {key}"
        result = scanner.scan(text)

        assert result.total_count == 1
        assert result.matches[0].secret_type == SecretType.ANTHROPIC_API_KEY

    def test_scan_aws_key(self):
        """Test scanning AWS access key."""
        scanner = SecretScanner()
        text = "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
        result = scanner.scan(text)

        assert result.total_count == 1
        assert result.matches[0].secret_type == SecretType.AWS_ACCESS_KEY

    def test_scan_github_token(self):
        """Test scanning GitHub token."""
        scanner = SecretScanner()
        # GitHub token: ghp_ + 36 chars
        token = "ghp_" + string.ascii_lowercase * 2  # 52 chars, take first 36
        text = f"GITHUB_TOKEN={token[:40]}"  # ghp_ + 36 = 40 total
        result = scanner.scan(text)

        assert result.total_count >= 1

    def test_scan_jwt(self):
        """Test scanning JWT token."""
        scanner = SecretScanner()
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = scanner.scan(text)

        assert result.total_count == 1
        assert result.matches[0].secret_type == SecretType.JWT_TOKEN

    def test_scan_database_url(self):
        """Test scanning database URL."""
        scanner = SecretScanner()
        text = "postgresql://user:password@localhost:5432/dbname"
        result = scanner.scan(text)

        assert result.total_count >= 1

    def test_scan_private_key(self):
        """Test scanning private key header."""
        scanner = SecretScanner()
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"""
        result = scanner.scan(text)

        assert result.total_count == 1
        assert result.matches[0].secret_type == SecretType.PRIVATE_KEY

    def test_scan_no_secrets(self):
        """Test scanning text with no secrets."""
        scanner = SecretScanner()
        text = "这是一段普通的文本，没有任何敏感信息。"
        result = scanner.scan(text)

        assert result.total_count == 0
        assert not result.should_block

    def test_scan_multiple_secrets(self):
        """Test scanning multiple secrets in one text."""
        scanner = SecretScanner()
        openai_key = "sk-" + (string.ascii_letters * 2 + string.digits * 2)[:48]
        text = f"""
        OpenAI key: {openai_key}
        AWS key: AKIAIOSFODNN7EXAMPLE
        JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc
        """
        result = scanner.scan(text)

        assert result.total_count >= 3
        assert result.has_critical is True

    def test_should_block_critical(self):
        """Test blocking on critical secrets."""
        scanner = SecretScanner()
        key = "sk-" + (string.ascii_letters * 2 + string.digits * 2)[:48]
        text = f"API key: {key}"
        result = scanner.scan(text)

        assert result.should_block is True
        assert result.has_critical is True

    def test_add_custom_pattern(self):
        """Test adding custom pattern."""
        import re
        scanner = SecretScanner()
        custom_pattern = SecretPattern(
            name="Custom Key",
            type=SecretType.GENERIC_API_KEY,
            pattern=re.compile(r'(CUSTOM_[A-Z0-9]{32})'),
            description="Custom API key",
            risk_level="high",
            examples=["CUSTOM_1234567890ABCDEFGHIJKLMNOPQRSTUV"],
        )
        scanner.add_pattern(custom_pattern)

        text = "Key is CUSTOM_1234567890ABCDEFGHIJKLMNOPQRSTUV"
        result = scanner.scan(text)

        assert result.total_count >= 1

    def test_remove_pattern_by_type(self):
        """Test removing pattern by type."""
        scanner = SecretScanner()
        original_count = scanner.get_pattern_count()

        removed = scanner.remove_pattern_by_type(SecretType.OPENAI_API_KEY)

        assert removed == 1
        assert scanner.get_pattern_count() == original_count - 1

    def test_scan_json(self):
        """Test scanning JSON data."""
        scanner = SecretScanner()
        key = "sk-" + (string.ascii_letters * 2 + string.digits * 2)[:48]
        data = {
            "api_key": key,
            "model": "gpt-4",
        }
        result = scanner.scan_json(data)

        assert result.total_count == 1

    def test_scan_performance(self):
        """Test scanning performance."""
        scanner = SecretScanner()
        key = "sk-" + (string.ascii_letters * 2 + string.digits * 2)[:48]
        text = "正常文本 " * 1000 + f" {key} " + "正常文本 " * 1000

        result = scanner.scan(text)

        assert result.scan_time_ms < 1000  # Should be fast
        assert result.total_count == 1


class TestSecretScanResult:
    """Tests for SecretScanResult."""

    def test_critical_count(self):
        """Test counting critical secrets."""
        result = SecretScanResult(
            matches=[
                SecretMatch(
                    secret_type=SecretType.OPENAI_API_KEY,
                    pattern_name="OpenAI API Key",
                    matched_text="sk-abc",
                    start=0,
                    end=6,
                    risk_level="critical",
                ),
                SecretMatch(
                    secret_type=SecretType.GENERIC_API_KEY,
                    pattern_name="Generic Key",
                    matched_text="key-xyz",
                    start=10,
                    end=16,
                    risk_level="medium",
                ),
            ],
            text_length=20,
            scan_time_ms=10,
        )

        assert result.total_count == 2
        assert result.critical_count == 1
        assert result.high_count == 0

    def test_get_by_type(self):
        """Test filtering by type."""
        result = SecretScanResult(
            matches=[
                SecretMatch(
                    secret_type=SecretType.OPENAI_API_KEY,
                    pattern_name="OpenAI API Key",
                    matched_text="sk-abc",
                    start=0,
                    end=6,
                    risk_level="critical",
                ),
                SecretMatch(
                    secret_type=SecretType.JWT_TOKEN,
                    pattern_name="JWT",
                    matched_text="eyJ...",
                    start=10,
                    end=20,
                    risk_level="high",
                ),
            ],
            text_length=20,
            scan_time_ms=10,
        )

        openai_matches = result.get_by_type(SecretType.OPENAI_API_KEY)
        assert len(openai_matches) == 1
        assert openai_matches[0].secret_type == SecretType.OPENAI_API_KEY

    def test_get_by_risk_level(self):
        """Test filtering by risk level."""
        result = SecretScanResult(
            matches=[
                SecretMatch(
                    secret_type=SecretType.OPENAI_API_KEY,
                    pattern_name="OpenAI API Key",
                    matched_text="sk-abc",
                    start=0,
                    end=6,
                    risk_level="critical",
                ),
                SecretMatch(
                    secret_type=SecretType.JWT_TOKEN,
                    pattern_name="JWT",
                    matched_text="eyJ...",
                    start=10,
                    end=20,
                    risk_level="high",
                ),
            ],
            text_length=20,
            scan_time_ms=10,
        )

        critical_matches = result.get_by_risk_level("critical")
        assert len(critical_matches) == 1


class TestSecretMatch:
    """Tests for SecretMatch."""

    def test_redacted(self):
        """Test redacted display."""
        match = SecretMatch(
            secret_type=SecretType.OPENAI_API_KEY,
            pattern_name="OpenAI API Key",
            matched_text="sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF",
            start=0,
            end=50,
            risk_level="critical",
        )

        redacted = match.redacted()
        assert "sk-" in redacted
        assert "****" in redacted

    def test_redacted_short(self):
        """Test redacted display for short secrets."""
        match = SecretMatch(
            secret_type=SecretType.PASSWORD,
            pattern_name="Password",
            matched_text="pass",
            start=0,
            end=4,
            risk_level="high",
        )

        redacted = match.redacted()
        assert redacted == "****"


class TestSecretInterceptor:
    """Tests for SecretInterceptor."""

    def test_check_safe_content(self):
        """Test checking safe content."""
        interceptor = SecretInterceptor()
        result = interceptor.check("这是一段安全的文本。")

        assert result.safe_to_proceed is True
        assert result.should_block is False

    def test_check_dangerous_content(self):
        """Test checking content with secrets."""
        interceptor = SecretInterceptor()
        key = "sk-" + (string.ascii_letters * 2 + string.digits * 2)[:48]
        text = f"API key: {key}"
        result = interceptor.check(text)

        assert result.safe_to_proceed is False
        assert result.should_block is True
        assert result.blocked_matches is not None
        assert len(result.blocked_matches) == 1
        assert result.reason is not None

    def test_check_dict(self):
        """Test checking dict data."""
        interceptor = SecretInterceptor()
        key = "sk-" + (string.ascii_letters * 2 + string.digits * 2)[:48]
        data = {
            "prompt": "Help me",
            "api_key": key,
        }
        result = interceptor.check_dict(data)

        assert result.should_block is True

    def test_check_messages(self):
        """Test checking chat messages."""
        interceptor = SecretInterceptor()
        key = "sk-" + (string.ascii_letters * 2 + string.digits * 2)[:48]
        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "user", "content": f"Key: {key}"},
        ]
        result = interceptor.check_messages(messages)

        assert result.should_block is True

    def test_sanitize(self):
        """Test sanitizing content."""
        interceptor = SecretInterceptor()
        key = "sk-" + (string.ascii_letters * 2 + string.digits * 2)[:48]
        content = f"My key {key} is here"
        result = interceptor.check(content)

        if result.scan_result.total_count > 0:
            sanitized = interceptor.sanitize(content, result.scan_result)
            assert "[REDACTED:" in sanitized
            assert key not in sanitized

    def test_sanitize_no_secrets(self):
        """Test sanitizing content with no secrets."""
        interceptor = SecretInterceptor()
        content = "This is safe content"
        sanitized = interceptor.sanitize(content)

        assert sanitized == content

    def test_get_stats(self):
        """Test getting interceptor stats."""
        interceptor = SecretInterceptor()
        key = "sk-" + (string.ascii_letters * 2 + string.digits * 2)[:48]
        interceptor.check("safe text")
        interceptor.check(f"unsafe {key}")

        stats = interceptor.get_stats()
        assert stats["total_scans"] == 2
        assert stats["total_blocks"] == 1

    def test_reset_stats(self):
        """Test resetting stats."""
        interceptor = SecretInterceptor()
        interceptor.check("test")

        interceptor.reset_stats()
        stats = interceptor.get_stats()
        assert stats["total_scans"] == 0


class TestGlobalInstances:
    """Tests for global instances."""

    def test_get_secret_scanner_singleton(self):
        """Test global scanner singleton."""
        scanner1 = get_secret_scanner()
        scanner2 = get_secret_scanner()

        assert scanner1 is scanner2

    def test_get_secret_interceptor_singleton(self):
        """Test global interceptor singleton."""
        interceptor1 = get_secret_interceptor()
        interceptor2 = get_secret_interceptor()

        assert interceptor1 is interceptor2

    def test_quick_scan(self):
        """Test quick scan function."""
        key = "sk-" + (string.ascii_letters * 2 + string.digits * 2)[:48]
        matches = quick_scan(f"My key: {key}")

        assert len(matches) >= 1
        assert isinstance(matches[0], SecretMatch)


class TestSecretPatternEdgeCases:
    """Tests for edge cases."""

    def test_empty_text(self):
        """Test scanning empty text."""
        scanner = SecretScanner()
        result = scanner.scan("")

        assert result.total_count == 0

    def test_very_long_text(self):
        """Test scanning very long text."""
        scanner = SecretScanner()
        text = "normal " * 10000
        result = scanner.scan(text)

        assert result.total_count == 0
        assert result.scan_time_ms < 5000

    def test_unicode_text(self):
        """Test scanning Unicode text."""
        scanner = SecretScanner()
        key = "sk-" + (string.ascii_letters * 2 + string.digits * 2)[:48]
        text = f"中文文本 {key} 混合"
        result = scanner.scan(text)

        assert result.total_count == 1

    def test_multiline_text(self):
        """Test scanning multiline text."""
        scanner = SecretScanner()
        key = "sk-" + (string.ascii_letters * 2 + string.digits * 2)[:48]
        text = f"""Line 1
Line 2: {key}
Line 3
"""
        result = scanner.scan(text)

        assert result.total_count == 1
