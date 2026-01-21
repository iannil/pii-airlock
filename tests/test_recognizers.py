"""Unit tests for custom recognizers."""

import pytest
from pii_airlock.recognizers.zh_id_card import (
    ChineseIdCardRecognizer,
    validate_chinese_id_card,
)
from pii_airlock.recognizers.zh_phone import ChinesePhoneRecognizer


class TestChineseIdCardRecognizer:
    """Tests for Chinese ID card recognizer."""

    @pytest.fixture
    def recognizer(self):
        """Create recognizer instance."""
        return ChineseIdCardRecognizer()

    def test_valid_id_card(self, recognizer):
        """Test validation of valid ID cards."""
        # These are test numbers with valid checksums
        # Formula: sum(digit[i] * weight[i]) % 11 -> checksum map
        # 110101199003077715 is valid (Beijing, 1990-03-07)
        assert recognizer.validate_result("110101199003077715") is True

    def test_invalid_checksum(self, recognizer):
        """Test detection of invalid checksum."""
        # Change last digit to make checksum invalid
        assert recognizer.validate_result("110101199003077711") is False

    def test_invalid_length(self, recognizer):
        """Test rejection of wrong length."""
        assert recognizer.validate_result("1234567890") is False
        assert recognizer.validate_result("12345678901234567890") is False

    def test_lowercase_x(self, recognizer):
        """Test that lowercase x is accepted."""
        # If uppercase X is valid, lowercase should be too
        # 11010119900307109X has valid checksum (mod 11 = 2 -> X)
        result_upper = recognizer.validate_result("11010119900307109X")
        result_lower = recognizer.validate_result("11010119900307109x")
        assert result_upper == result_lower
        assert result_upper is True


class TestValidateChineseIdCard:
    """Tests for standalone validation function."""

    def test_valid_id(self):
        """Test valid ID card."""
        assert validate_chinese_id_card("110101199003077715") is True

    def test_invalid_id(self):
        """Test invalid ID card."""
        assert validate_chinese_id_card("110101199003077710") is False


class TestChinesePhoneRecognizer:
    """Tests for Chinese phone recognizer."""

    @pytest.fixture
    def recognizer(self):
        """Create recognizer instance."""
        return ChinesePhoneRecognizer()

    def test_patterns_exist(self, recognizer):
        """Test that patterns are defined."""
        assert len(recognizer.patterns) > 0

    def test_context_words_exist(self, recognizer):
        """Test that context words are defined."""
        assert len(recognizer.context) > 0
        assert "电话" in recognizer.context
        assert "手机" in recognizer.context
