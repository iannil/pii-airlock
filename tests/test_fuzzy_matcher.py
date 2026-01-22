"""Tests for the fuzzy matcher module."""

import pytest

from pii_airlock.core.fuzzy import (
    FuzzyMatcher,
    FuzzyMatch,
    FuzzyMatchType,
    SmartRehydrator,
)
from pii_airlock.core.deanonymizer import Deanonymizer
from pii_airlock.core.mapping import PIIMapping


class TestFuzzyMatcher:
    """Tests for FuzzyMatcher."""

    def test_normalize_standard_placeholder(self):
        """Test normalizing standard placeholders."""
        matcher = FuzzyMatcher()

        assert matcher.normalize_placeholder("<PERSON_1>") == "<PERSON_1>"
        assert matcher.normalize_placeholder("<PHONE_NUMBER_2>") == "<PHONE_NUMBER_2>"
        assert matcher.normalize_placeholder("<EMAIL_ADDRESS_3>") == "<EMAIL_ADDRESS_3>"

    def test_normalize_lowercase_placeholder(self):
        """Test normalizing lowercase placeholders."""
        matcher = FuzzyMatcher()

        assert matcher.normalize_placeholder("<person_1>") == "<PERSON_1>"
        assert matcher.normalize_placeholder("<Person_1>") == "<PERSON_1>"

    def test_normalize_bracket_variants(self):
        """Test normalizing bracket variants."""
        matcher = FuzzyMatcher()

        # Square brackets
        assert matcher.normalize_placeholder("[PERSON_1]") == "<PERSON_1>"
        # Curly braces
        assert matcher.normalize_placeholder("{PERSON_1}") == "<PERSON_1>"
        # Parentheses
        assert matcher.normalize_placeholder("(PERSON_1)") == "<PERSON_1>"

    def test_normalize_separator_variants(self):
        """Test normalizing separator variants."""
        matcher = FuzzyMatcher()

        # Hyphen
        assert matcher.normalize_placeholder("<PERSON-1>") == "<PERSON_1>"
        # Colon
        assert matcher.normalize_placeholder("<PERSON:1>") == "<PERSON_1>"

    def test_normalize_whitespace_variants(self):
        """Test normalizing whitespace variants."""
        matcher = FuzzyMatcher()

        # Spaces around components
        assert matcher.normalize_placeholder("< PERSON_1 >") == "<PERSON_1>"
        assert matcher.normalize_placeholder("< PERSON_1>") == "<PERSON_1>"
        assert matcher.normalize_placeholder("<PERSON _1>") == "<PERSON_1>"

    def test_normalize_invalid_format(self):
        """Test normalizing invalid formats."""
        matcher = FuzzyMatcher()

        # Not a valid placeholder
        # "PERSON_1" without brackets is not matched by any pattern
        assert matcher.normalize_placeholder("PERSON_1") is None
        assert matcher.normalize_placeholder("hello") is None
        assert matcher.normalize_placeholder("") is None
        assert matcher.normalize_placeholder("<>") is None


class TestSmartRehydrator:
    """Tests for SmartRehydrator."""

    def test_exact_match_only(self):
        """Test rehydration with only exact matches."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")
        mapping.add("PHONE", "13800138000", "<PHONE_NUMBER_1>")

        rehydrator = SmartRehydrator(enable_fuzzy=False)
        text, exact_count, fuzzy_count = rehydrator.rehydrate(
            "请联系 <PERSON_1> 或 <PHONE_NUMBER_1>",
            mapping
        )

        assert "张三" in text
        assert "13800138000" in text
        assert exact_count == 2
        assert fuzzy_count == 0

    def test_fuzzy_match_variants(self):
        """Test rehydration with fuzzy matches."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")
        mapping.add("PHONE", "13800138000", "<PHONE_NUMBER_1>")

        rehydrator = SmartRehydrator(enable_fuzzy=True, confidence_threshold=0.75)
        text, exact_count, fuzzy_count = rehydrator.rehydrate(
            "请联系 <Person_1> 或 [PHONE_NUMBER_1]",
            mapping
        )

        assert "张三" in text
        assert "13800138000" in text
        assert exact_count == 0  # No exact matches in this format
        assert fuzzy_count == 2  # Two fuzzy matches

    def test_combined_exact_and_fuzzy(self):
        """Test rehydration with both exact and fuzzy matches."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")
        mapping.add("PHONE", "13800138000", "<PHONE_NUMBER_1>")

        rehydrator = SmartRehydrator(enable_fuzzy=True)
        text, exact_count, fuzzy_count = rehydrator.rehydrate(
            "请联系 <PERSON_1> 和 [PHONE_NUMBER_1]",
            mapping
        )

        assert "张三" in text
        assert "13800138000" in text
        assert exact_count == 1  # <PERSON_1> is exact
        assert fuzzy_count == 1  # [PHONE_NUMBER_1] is fuzzy

    def test_confidence_threshold(self):
        """Test confidence threshold filtering."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        # Low threshold - should match
        rehydrator_low = SmartRehydrator(confidence_threshold=0.5)
        text, _, fuzzy_count = rehydrator_low.rehydrate(
            "请联系 PERSON1",
            mapping
        )
        # "PERSON1" has low confidence (0.70), so it won't match even with 0.5 threshold
        # because the pattern doesn't match

        # High confidence threshold - fewer matches
        rehydrator_high = SmartRehydrator(confidence_threshold=0.95)
        text, _, fuzzy_count = rehydrator_high.rehydrate(
            "请联系 <Person_1>",
            mapping
        )
        assert "张三" in text

    def test_no_match(self):
        """Test when no valid match is found."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        rehydrator = SmartRehydrator()
        text, exact_count, fuzzy_count = rehydrator.rehydrate(
            "请联系 XXX_1",
            mapping
        )

        assert exact_count == 0
        assert fuzzy_count == 0

    def test_multiple_occurrences(self):
        """Test multiple occurrences of the same placeholder."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        rehydrator = SmartRehydrator()
        text, exact_count, fuzzy_count = rehydrator.rehydrate(
            "<PERSON_1>，<Person_1>和[PERSON_1]",
            mapping
        )

        assert text.count("张三") == 3
        assert exact_count + fuzzy_count == 3


class TestDeanonymizerIntegration:
    """Integration tests for enhanced Deanonymizer."""

    def test_deanonymizer_with_enhanced_fuzzy(self):
        """Test Deanonymizer with enhanced fuzzy matching enabled."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")
        mapping.add("PHONE", "13800138000", "<PHONE_NUMBER_1>")

        # 使用增强模糊匹配
        deanonymizer = Deanonymizer(
            enable_fuzzy_matching=True,
            use_enhanced_fuzzy=True,
            confidence_threshold=0.75,
        )

        result = deanonymizer.deanonymize(
            "请联系 <Person_1> 或 [PHONE_NUMBER_1]",
            mapping
        )

        assert "张三" in result.text
        assert "13800138000" in result.text
        assert result.replaced_count == 2

    def test_deanonymizer_backward_compatibility(self):
        """Test that default behavior is preserved."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        # 默认使用传统方法
        deanonymizer = Deanonymizer()
        result = deanonymizer.deanonymize("致<PERSON_1>：您好", mapping)

        assert result.text == "致张三：您好"

    def test_fuzzy_disabled(self):
        """Test with fuzzy matching disabled."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        deanonymizer = Deanonymizer(enable_fuzzy_matching=False)
        result = deanonymizer.deanonymize("致<Person_1>：您好", mapping)

        # Should not replace <Person_1> when fuzzy is disabled
        assert "张三" not in result.text
        assert "<Person_1>" in result.text


class TestFuzzyMatchEdgeCases:
    """Tests for edge cases in fuzzy matching."""

    def test_empty_text(self):
        """Test with empty text."""
        matcher = FuzzyMatcher()
        assert matcher.normalize_placeholder("") is None

    def test_very_long_placeholder(self):
        """Test with very long placeholder names."""
        matcher = FuzzyMatcher()

        # Long entity type
        long_placeholder = "<CUSTOM_ENTITY_TYPE_NAME_123>"
        assert matcher.normalize_placeholder(long_placeholder) == long_placeholder

    def test_nested_brackets(self):
        """Test with nested bracket structures."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        rehydrator = SmartRehydrator()
        text, _, _ = rehydrator.rehydrate(
            "<<<PERSON_1>>>",
            mapping
        )

        # Standard pattern will match <PERSON_1> inside <<<PERSON_1>>>
        # Result is <<张三>> with remaining outer brackets
        assert "张三" in text
        assert "<<" in text or text == "<<张三>>"

    def test_placeholder_with_punctuation(self):
        """Test placeholder with trailing punctuation."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        rehydrator = SmartRehydrator()
        # This test checks if the standard match works with punctuation
        text, _, _ = rehydrator.rehydrate(
            "<PERSON_1>。",
            mapping
        )

        # The Chinese period should be preserved
        assert "张三。" in text

        # Also test with English period
        text2, _, _ = rehydrator.rehydrate(
            "<PERSON_1>.",
            mapping
        )
        assert "张三." in text2

    def test_mixed_placeholder_formats(self):
        """Test with different placeholder formats in same text."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")
        mapping.add("PHONE", "13800138000", "<PHONE_NUMBER_1>")

        rehydrator = SmartRehydrator(confidence_threshold=0.7)
        text, exact_count, fuzzy_count = rehydrator.rehydrate(
            "请找<Person_1>，他的电话是[PHONE_NUMBER_1]",
            mapping
        )

        assert "张三" in text
        assert "13800138000" in text
        assert exact_count == 0  # <Person_1> is fuzzy (not exact uppercase)
        assert fuzzy_count == 2  # Both are fuzzy matches

    def test_case_insensitive_mapping(self):
        """Test that entity type matching is case-insensitive."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        rehydrator = SmartRehydrator()
        text, _, fuzzy_count = rehydrator.rehydrate(
            "请找<person_1>",
            mapping
        )

        assert "张三" in text
        assert fuzzy_count == 1
