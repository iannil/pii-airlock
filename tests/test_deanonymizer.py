"""Unit tests for the Deanonymizer module."""

import pytest
from pii_airlock.core.deanonymizer import Deanonymizer, DeanonymizationResult
from pii_airlock.core.mapping import PIIMapping


class TestDeanonymizerBasic:
    """Basic deanonymization tests."""

    @pytest.fixture
    def deanonymizer(self):
        """Create deanonymizer instance."""
        return Deanonymizer()

    @pytest.fixture
    def sample_mapping(self):
        """Create sample mapping."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")
        mapping.add("PHONE", "13800138000", "<PHONE_1>")
        mapping.add("EMAIL", "test@example.com", "<EMAIL_1>")
        return mapping

    def test_empty_text(self, deanonymizer, sample_mapping):
        """Empty text should return unchanged."""
        result = deanonymizer.deanonymize("", sample_mapping)
        assert result.text == ""
        assert result.replaced_count == 0

    def test_no_placeholders(self, deanonymizer, sample_mapping):
        """Text without placeholders should return unchanged."""
        text = "今天天气很好"
        result = deanonymizer.deanonymize(text, sample_mapping)
        assert result.text == text
        assert result.replaced_count == 0

    def test_simple_replace(self, deanonymizer, sample_mapping):
        """Simple placeholder replacement."""
        result = deanonymizer.deanonymize("<PERSON_1>您好", sample_mapping)
        assert result.text == "张三您好"
        assert result.is_complete
        assert result.replaced_count == 1

    def test_multiple_placeholders(self, deanonymizer, sample_mapping):
        """Multiple placeholders in text."""
        result = deanonymizer.deanonymize(
            "<PERSON_1>的电话是<PHONE_1>，邮箱是<EMAIL_1>", sample_mapping
        )
        assert result.text == "张三的电话是13800138000，邮箱是test@example.com"
        assert result.replaced_count == 3
        assert result.is_complete

    def test_same_placeholder_twice(self, deanonymizer, sample_mapping):
        """Same placeholder appearing twice."""
        result = deanonymizer.deanonymize(
            "<PERSON_1>说<PERSON_1>很忙", sample_mapping
        )
        assert result.text == "张三说张三很忙"
        assert result.replaced_count == 2

    def test_unknown_placeholder(self, deanonymizer, sample_mapping):
        """Unknown placeholder should remain unchanged."""
        result = deanonymizer.deanonymize(
            "<PERSON_1>和<PERSON_2>", sample_mapping
        )
        assert "张三" in result.text
        assert "<PERSON_2>" in result.text
        assert not result.is_complete
        assert "<PERSON_2>" in result.unresolved


class TestDeanonymizerFuzzy:
    """Fuzzy matching tests for LLM hallucinations."""

    @pytest.fixture
    def deanonymizer(self):
        """Create deanonymizer with fuzzy matching."""
        return Deanonymizer(enable_fuzzy_matching=True)

    @pytest.fixture
    def sample_mapping(self):
        """Create sample mapping."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")
        mapping.add("PHONE", "13800138000", "<PHONE_1>")
        return mapping

    def test_fuzzy_space(self, deanonymizer, sample_mapping):
        """Handle space instead of underscore."""
        result = deanonymizer.deanonymize("<PERSON 1>您好", sample_mapping)
        assert "张三" in result.text

    def test_fuzzy_lowercase(self, deanonymizer, sample_mapping):
        """Handle lowercase type names."""
        result = deanonymizer.deanonymize("<person 1>您好", sample_mapping)
        assert "张三" in result.text

    def test_fuzzy_brackets(self, deanonymizer, sample_mapping):
        """Handle square brackets."""
        result = deanonymizer.deanonymize("[PERSON_1]您好", sample_mapping)
        assert "张三" in result.text

    def test_fuzzy_curly_braces(self, deanonymizer, sample_mapping):
        """Handle double curly braces."""
        result = deanonymizer.deanonymize("{{PERSON_1}}您好", sample_mapping)
        assert "张三" in result.text

    def test_fuzzy_hyphen(self, deanonymizer, sample_mapping):
        """Handle hyphen instead of underscore."""
        result = deanonymizer.deanonymize("<PERSON-1>您好", sample_mapping)
        assert "张三" in result.text

    def test_fuzzy_disabled(self, sample_mapping):
        """Fuzzy matching disabled."""
        deanonymizer = Deanonymizer(enable_fuzzy_matching=False)
        result = deanonymizer.deanonymize("<PERSON 1>您好", sample_mapping)
        # Should NOT replace fuzzy matches
        assert "张三" not in result.text
        assert "<PERSON 1>" in result.text


class TestDeanonymizerUtilities:
    """Test utility methods."""

    @pytest.fixture
    def deanonymizer(self):
        return Deanonymizer()

    def test_extract_placeholders(self, deanonymizer):
        """Test placeholder extraction."""
        text = "致<PERSON_1>：您的<PHONE_2>已验证"
        placeholders = deanonymizer.extract_placeholders(text)

        assert ("PERSON", "1") in placeholders
        assert ("PHONE", "2") in placeholders

    def test_has_placeholders_true(self, deanonymizer):
        """Test has_placeholders returns True."""
        assert deanonymizer.has_placeholders("Hello <PERSON_1>")

    def test_has_placeholders_false(self, deanonymizer):
        """Test has_placeholders returns False."""
        assert not deanonymizer.has_placeholders("Hello World")
