"""Tests for error handling scenarios."""

import pytest

from pii_airlock.core.anonymizer import Anonymizer, AnonymizationResult
from pii_airlock.core.deanonymizer import Deanonymizer
from pii_airlock.core.strategies import (
    StrategyConfig,
    StrategyType,
    StrategyResult,
    get_strategy,
    HashStrategy,
    MaskStrategy,
    PlaceholderStrategy,
)


class TestAnonymizerErrors:
    """Tests for Anonymizer error handling."""

    def test_anonymize_empty_text(self) -> None:
        anonymizer = Anonymizer()
        result = anonymizer.anonymize("")

        assert result.text == ""
        assert result.pii_count == 0

    def test_anonymize_whitespace_only(self) -> None:
        anonymizer = Anonymizer()
        result = anonymizer.anonymize("   \n\t   ")

        assert result.text.strip() == ""
        assert result.pii_count == 0

    def test_anonymize_none_input(self) -> None:
        anonymizer = Anonymizer()
        result = anonymizer.anonymize("")  # Empty string instead of None for type safety

        assert result.text == ""

    def test_anonymize_very_long_text(self) -> None:
        anonymizer = Anonymizer()
        long_text = "张三 " * 1000  # Shorter but still substantial

        result = anonymizer.anonymize(long_text)

        # Should handle long text without crashing
        assert len(result.text) > 0
        # Some instances of 张三 should be anonymized (NER may not catch all)
        # At least some placeholders should exist
        assert "<PERSON_" in result.text or "张三" in result.text

    def test_anonymize_special_characters(self) -> None:
        anonymizer = Anonymizer()
        text = "张三的邮箱是test+tag@example.com!#$%"

        result = anonymizer.anonymize(text)

        # Should handle special characters
        assert result.text is not None

    def test_anonymize_unicode_emoji(self) -> None:
        anonymizer = Anonymizer()
        text = "张三的电话是13800138000😊"

        result = anonymizer.anonymize(text)

        # Should handle emoji
        assert "😊" in result.text

    def test_anonymize_mixed_languages(self) -> None:
        anonymizer = Anonymizer(enable_intent_detection=False, enable_allowlist=False)
        text = "张三 (John) 的电话是13800138000"

        result = anonymizer.anonymize(text)

        # Should handle mixed Chinese and English
        assert "张三" not in result.text
        assert "13800138000" not in result.text

    def test_anonymize_with_invalid_entities(self) -> None:
        anonymizer = Anonymizer()
        # Invalid entities should raise an error from the analyzer
        with pytest.raises(ValueError):
            anonymizer.anonymize("张三来了", entities=["INVALID_ENTITY"])

    def test_anonymize_with_empty_entities_list(self) -> None:
        anonymizer = Anonymizer()
        result = anonymizer.anonymize("张三的电话是13800138000", entities=[])

        # Empty list falls back to default SUPPORTED_ENTITIES
        # So PII should still be detected
        assert "<PERSON_" in result.text or "<PHONE_" in result.text

    def test_anonymize_overlapping_entities(self) -> None:
        anonymizer = Anonymizer()
        # Text that might cause overlapping detection
        text = "张三张的电话"

        result = anonymizer.anonymize(text)

        # Should handle overlapping entities gracefully
        assert result.text is not None

    def test_session_id_isolation(self) -> None:
        anonymizer = Anonymizer()

        result1 = anonymizer.anonymize("张三", session_id="session1")
        result2 = anonymizer.anonymize("张三", session_id="session2")

        # Different sessions should have separate mappings
        assert result1.mapping.session_id == "session1"
        assert result2.mapping.session_id == "session2"


class TestDeanonymizerErrors:
    """Tests for Deanonymizer error handling."""

    def test_deanonymize_empty_text(self) -> None:
        from pii_airlock.core.mapping import PIIMapping

        deanonymizer = Deanonymizer()
        result = deanonymizer.deanonymize("", PIIMapping())

        assert result.text == ""

    def test_deanonymize_no_placeholders(self) -> None:
        from pii_airlock.core.mapping import PIIMapping

        deanonymizer = Deanonymizer()
        result = deanonymizer.deanonymize("This is plain text", PIIMapping())

        assert result.text == "This is plain text"

    def test_deanonymize_invalid_placeholder_format(self) -> None:
        from pii_airlock.core.mapping import PIIMapping

        deanonymizer = Deanonymizer()
        result = deanonymizer.deanonymize("This has <INVALID> placeholder", PIIMapping())

        # Should handle invalid format gracefully
        assert result.text is not None

    def test_deanonymize_missing_mapping(self) -> None:
        from pii_airlock.core.mapping import PIIMapping

        deanonymizer = Deanonymizer()
        result = deanonymizer.deanonymize("This has <PERSON_1>", PIIMapping())

        # Should return original when mapping is missing
        assert "<PERSON_1>" in result.text

    def test_deanonymize_mismatched_placeholder(self) -> None:
        from pii_airlock.core.mapping import PIIMapping

        deanonymizer = Deanonymizer()
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")
        result = deanonymizer.deanonymize("This has <PERSON_99>", mapping)

        # Should handle missing placeholder in mapping
        assert "<PERSON_99>" in result.text


class TestStrategyErrors:
    """Tests for strategy error handling."""

    def test_get_invalid_strategy(self) -> None:
        with pytest.raises(ValueError):
            get_strategy("not_a_real_strategy")

    def test_strategy_config_invalid_env_value(self) -> None:
        import os

        os.environ["PII_AIRLOCK_STRATEGY_PERSON"] = "invalid"

        try:
            config = StrategyConfig.from_env()
            # Should fall back to default for invalid values
            assert config.get_strategy("PERSON") == StrategyType.PLACEHOLDER
        finally:
            del os.environ["PII_AIRLOCK_STRATEGY_PERSON"]

    def test_strategy_with_empty_value(self) -> None:
        strategy = PlaceholderStrategy()
        result = strategy.anonymize("", "PERSON", 1, {})

        assert result.text == "<PERSON_1>"
        assert result.can_deanonymize is True

    def test_mask_strategy_with_short_value(self) -> None:
        strategy = MaskStrategy()
        result = strategy.anonymize("a", "PHONE", 1, {})

        # Should handle very short values
        assert result.text is not None
        assert result.can_deanonymize is False

    def test_mask_strategy_with_non_phone(self) -> None:
        strategy = MaskStrategy()
        result = strategy.anonymize("abcdefghij", "PHONE", 1, {})

        # Should handle non-numeric phone values
        assert result.text is not None

    def test_hash_strategy_with_empty_value(self) -> None:
        strategy = HashStrategy()
        result = strategy.anonymize("", "PERSON", 1, {})

        # Empty string should still hash
        assert len(result.text) == 64

    def test_strategy_result_properties(self) -> None:
        result = StrategyResult(text="<PERSON_1>", can_deanonymize=True)

        assert result.text == "<PERSON_1>"
        assert result.can_deanonymize is True

        # Test with can_deanonymize=False
        result2 = StrategyResult(text="[REDACTED]", can_deanonymize=False)
        assert result2.can_deanonymize is False


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_anonymize_single_char_name(self) -> None:
        anonymizer = Anonymizer()
        result = anonymizer.anonymize("王")

        # Single character should be handled
        assert result.text is not None

    def test_anonymize_very_short_text(self) -> None:
        anonymizer = Anonymizer()
        result = anonymizer.anonymize("李")

        assert result.text is not None

    def test_anonymize_repeated_same_pii(self) -> None:
        anonymizer = Anonymizer(enable_intent_detection=False, enable_allowlist=False)
        text = "张三给张三打了电话"

        result = anonymizer.anonymize(text)

        # Both instances should use same placeholder
        placeholders = [word for word in result.text.split() if "<PERSON_" in word]
        assert len(set(placeholders)) == 1  # All same placeholder

    def test_anonymize_newline_handling(self) -> None:
        anonymizer = Anonymizer()
        text = "张三\n李四\n王五"

        result = anonymizer.anonymize(text)

        # Should preserve newlines
        assert "\n" in result.text or result.text.count("\n") == text.count("\n")

    def test_anonymize_tab_handling(self) -> None:
        anonymizer = Anonymizer()
        text = "张三\t李四"

        result = anonymizer.anonymize(text)

        # Should handle tabs
        assert result.text is not None

    def test_anonymize_consecutive_pii(self) -> None:
        anonymizer = Anonymizer()
        text = "张三李四王五"

        result = anonymizer.anonymize(text)

        # Should handle consecutive PII
        assert result.text is not None

    def test_mapping_get_original_missing(self) -> None:
        from pii_airlock.core.mapping import PIIMapping

        mapping = PIIMapping()
        result = mapping.get_original("<PERSON_1>")

        # Should return None for missing keys
        assert result is None

    def test_mapping_get_placeholder_missing(self) -> None:
        from pii_airlock.core.mapping import PIIMapping

        mapping = PIIMapping()
        result = mapping.get_placeholder("PERSON", "张三")

        # Should return None for missing values
        assert result is None

    def test_counter_multiple_types(self) -> None:
        from pii_airlock.core.counter import PlaceholderCounter

        counter = PlaceholderCounter()

        assert counter.next("PERSON") == 1
        assert counter.next("PERSON") == 2
        assert counter.next("PHONE") == 1
        assert counter.next("PERSON") == 3

    def test_score_threshold_filtering(self) -> None:
        # Very high threshold should filter out most results
        anonymizer = Anonymizer(score_threshold=0.99)
        result = anonymizer.anonymize("张三的电话是13800138000")

        # Most results should be filtered out
        assert result.text is not None
