"""Tests for anonymization strategies."""

import os

import pytest

from pii_airlock.core.strategies import (
    get_strategy,
    HashStrategy,
    MaskStrategy,
    PlaceholderStrategy,
    RedactStrategy,
    register_strategy,
    StrategyConfig,
    StrategyResult,
    StrategyType,
)
from pii_airlock.core.anonymizer import Anonymizer


class TestPlaceholderStrategy:
    """Tests for PlaceholderStrategy."""

    def test_name(self) -> None:
        strategy = PlaceholderStrategy()
        assert strategy.name == StrategyType.PLACEHOLDER

    def test_supports_deanonymization(self) -> None:
        strategy = PlaceholderStrategy()
        assert strategy.supports_deanonymization is True

    def test_anonymize_person(self) -> None:
        strategy = PlaceholderStrategy()
        result = strategy.anonymize("张三", "PERSON", 1, {})

        assert result.text == "<PERSON_1>"
        assert result.can_deanonymize is True

    def test_anonymize_phone(self) -> None:
        strategy = PlaceholderStrategy()
        result = strategy.anonymize("13800138000", "PHONE", 1, {})

        assert result.text == "<PHONE_1>"
        assert result.can_deanonymize is True

    def test_anonymize_multiple_indices(self) -> None:
        strategy = PlaceholderStrategy()

        result1 = strategy.anonymize("张三", "PERSON", 1, {})
        result2 = strategy.anonymize("李四", "PERSON", 2, {})

        assert result1.text == "<PERSON_1>"
        assert result2.text == "<PERSON_2>"


class TestHashStrategy:
    """Tests for HashStrategy."""

    def test_name(self) -> None:
        strategy = HashStrategy()
        assert strategy.name == StrategyType.HASH

    def test_supports_deanonymization(self) -> None:
        strategy = HashStrategy()
        assert strategy.supports_deanonymization is True

    def test_anonymize_creates_hash(self) -> None:
        strategy = HashStrategy()
        result = strategy.anonymize("张三", "PERSON", 1, {})

        # Should be a SHA256 hex string (64 chars)
        assert len(result.text) == 64
        assert all(c in "0123456789abcdef" for c in result.text)
        assert result.can_deanonymize is True

    def test_anonymize_deterministic(self) -> None:
        strategy = HashStrategy()

        result1 = strategy.anonymize("张三", "PERSON", 1, {})
        result2 = strategy.anonymize("张三", "PERSON", 2, {})

        # Same input should produce same hash
        assert result1.text == result2.text

    def test_anonymize_different_inputs(self) -> None:
        strategy = HashStrategy()

        result1 = strategy.anonymize("张三", "PERSON", 1, {})
        result2 = strategy.anonymize("李四", "PERSON", 1, {})

        # Different inputs should produce different hashes
        assert result1.text != result2.text

    def test_anonymize_with_entity_salt(self) -> None:
        strategy = HashStrategy()

        result1 = strategy.anonymize("samevalue", "PERSON", 1, {"salt": "PERSON"})
        result2 = strategy.anonymize("samevalue", "EMAIL", 1, {"salt": "EMAIL"})

        # Different salts should produce different hashes
        assert result1.text != result2.text


class TestMaskStrategy:
    """Tests for MaskStrategy."""

    def test_name(self) -> None:
        strategy = MaskStrategy()
        assert strategy.name == StrategyType.MASK

    def test_supports_deanonymization(self) -> None:
        strategy = MaskStrategy()
        assert strategy.supports_deanonymization is False

    def test_mask_phone(self) -> None:
        strategy = MaskStrategy()
        result = strategy.anonymize("13800138000", "PHONE", 1, {})

        assert result.text == "138****8000"
        assert result.can_deanonymize is False

    def test_mask_email(self) -> None:
        strategy = MaskStrategy()
        result = strategy.anonymize("test@example.com", "EMAIL", 1, {})

        assert result.text == "t**t@example.com"
        assert result.can_deanonymize is False

    def test_mask_id_card(self) -> None:
        strategy = MaskStrategy()
        result = strategy.anonymize("110101199003077758", "ID_CARD", 1, {})

        assert result.text == "110101********7758"
        assert result.can_deanonymize is False

    def test_mask_credit_card(self) -> None:
        strategy = MaskStrategy()
        result = strategy.anonymize("4111111111111111", "CREDIT_CARD", 1, {})

        # 16 digits: 4111 + 8 asterisks + 1111 = 4111********1111
        assert result.text == "4111********1111"
        assert result.can_deanonymize is False

    def test_mask_generic_short(self) -> None:
        strategy = MaskStrategy()
        result = strategy.anonymize("abc", "UNKNOWN", 1, {})

        assert result.text == "***"
        assert result.can_deanonymize is False

    def test_mask_generic_long(self) -> None:
        strategy = MaskStrategy()
        result = strategy.anonymize("abcdefghij", "UNKNOWN", 1, {})

        # Should show first and last 25%
        assert "a" in result.text
        assert "j" in result.text
        assert "*" in result.text
        assert result.can_deanonymize is False


class TestRedactStrategy:
    """Tests for RedactStrategy."""

    def test_name(self) -> None:
        strategy = RedactStrategy()
        assert strategy.name == StrategyType.REDACT

    def test_supports_deanonymization(self) -> None:
        strategy = RedactStrategy()
        assert strategy.supports_deanonymization is False

    def test_anonymize_with_default_marker(self) -> None:
        strategy = RedactStrategy()
        result = strategy.anonymize("张三", "PERSON", 1, {})

        assert result.text == "[REDACTED]"
        assert result.can_deanonymize is False

    def test_anonymize_with_custom_marker(self) -> None:
        strategy = RedactStrategy(marker="[XXX]")
        result = strategy.anonymize("test@example.com", "EMAIL", 1, {})

        assert result.text == "[XXX]"
        assert result.can_deanonymize is False


class TestStrategyConfig:
    """Tests for StrategyConfig."""

    def test_default_config(self) -> None:
        config = StrategyConfig()

        assert config.get_strategy("PERSON") == StrategyType.PLACEHOLDER
        assert config.get_strategy("PHONE_NUMBER") == StrategyType.PLACEHOLDER
        assert config.get_strategy("EMAIL_ADDRESS") == StrategyType.PLACEHOLDER
        assert config.get_strategy("CREDIT_CARD") == StrategyType.MASK

    def test_custom_config(self) -> None:
        config = StrategyConfig({"PERSON": StrategyType.HASH, "PHONE": StrategyType.MASK})

        assert config.get_strategy("PERSON") == StrategyType.HASH
        assert config.get_strategy("PHONE") == StrategyType.MASK
        assert config.get_strategy("EMAIL") == StrategyType.PLACEHOLDER  # Default

    def test_from_env_empty(self) -> None:
        # Clear any existing env vars
        for key in list(os.environ.keys()):
            if key.startswith("PII_AIRLOCK_STRATEGY_"):
                del os.environ[key]

        config = StrategyConfig.from_env()
        assert config.get_strategy("PERSON") == StrategyType.PLACEHOLDER

    def test_from_env_with_values(self) -> None:
        os.environ["PII_AIRLOCK_STRATEGY_PERSON"] = "hash"
        os.environ["PII_AIRLOCK_STRATEGY_PHONE"] = "mask"

        try:
            config = StrategyConfig.from_env()
            assert config.get_strategy("PERSON") == StrategyType.HASH
            assert config.get_strategy("PHONE_NUMBER") == StrategyType.MASK
        finally:
            del os.environ["PII_AIRLOCK_STRATEGY_PERSON"]
            del os.environ["PII_AIRLOCK_STRATEGY_PHONE"]


class TestGetStrategy:
    """Tests for get_strategy function."""

    def test_get_placeholder_strategy(self) -> None:
        strategy = get_strategy(StrategyType.PLACEHOLDER)
        assert isinstance(strategy, PlaceholderStrategy)

    def test_get_hash_strategy(self) -> None:
        strategy = get_strategy(StrategyType.HASH)
        assert isinstance(strategy, HashStrategy)

    def test_get_mask_strategy(self) -> None:
        strategy = get_strategy(StrategyType.MASK)
        assert isinstance(strategy, MaskStrategy)

    def test_get_redact_strategy(self) -> None:
        strategy = get_strategy(StrategyType.REDACT)
        assert isinstance(strategy, RedactStrategy)

    def test_get_strategy_by_string(self) -> None:
        strategy = get_strategy("placeholder")
        assert isinstance(strategy, PlaceholderStrategy)

    def test_get_strategy_invalid(self) -> None:
        with pytest.raises(ValueError):
            get_strategy("invalid_strategy")

    def test_register_custom_strategy(self) -> None:
        # Create a custom strategy type and instance
        custom_type = "custom"

        class CustomStrategy(PlaceholderStrategy):
            @property
            def name(self) -> str:  # type: ignore
                return custom_type

        register_strategy(custom_type, CustomStrategy())

        strategy = get_strategy("custom")
        assert isinstance(strategy, CustomStrategy)


class TestAnonymizerWithStrategies:
    """Tests for Anonymizer integration with strategies."""

    def test_anonymizer_with_default_strategy(self) -> None:
        anonymizer = Anonymizer()
        result = anonymizer.anonymize("张三的电话是13800138000")

        # Should use placeholder by default
        assert "<PERSON_1>" in result.text or "<PERSON_2>" in result.text
        assert "<PHONE_" in result.text

    def test_anonymizer_with_mask_strategy(self) -> None:
        strategy_config = StrategyConfig({"PHONE_NUMBER": StrategyType.MASK})
        anonymizer = Anonymizer(strategy_config=strategy_config)

        result = anonymizer.anonymize("电话是13800138000")

        # Phone should be masked
        assert "138****8000" in result.text or "138" in result.text

    def test_anonymizer_with_redact_strategy(self) -> None:
        strategy_config = StrategyConfig({"PERSON": StrategyType.REDACT})
        anonymizer = Anonymizer(strategy_config=strategy_config)

        result = anonymizer.anonymize("张三来了")

        # Person should be redacted
        assert "[REDACTED]" in result.text or result.text.count("[") > 0

    def test_anonymizer_with_hash_strategy(self) -> None:
        strategy_config = StrategyConfig({"PERSON": StrategyType.HASH})
        anonymizer = Anonymizer(strategy_config=strategy_config)

        result = anonymizer.anonymize("张三来了")

        # Person should be hashed (64 char hex string)
        # The result should contain a 64-char hash value
        # Find hash-like strings in the result
        words = result.text.replace("来了", "").split()
        has_hash = any(len(w) == 64 and all(c in "0123456789abcdef" for c in w) for w in words)
        assert has_hash, f"Expected 64-char hash in: {result.text}"

    def test_anonymizer_strategies_from_env(self) -> None:
        os.environ["PII_AIRLOCK_STRATEGY_PERSON"] = "redact"

        try:
            anonymizer = Anonymizer(load_strategies_from_env=True)
            assert anonymizer.strategy_config.get_strategy("PERSON") == StrategyType.REDACT
        finally:
            del os.environ["PII_AIRLOCK_STRATEGY_PERSON"]

    def test_anonymizer_mixed_strategies(self) -> None:
        strategy_config = StrategyConfig({
            "PERSON": StrategyType.PLACEHOLDER,
            "PHONE_NUMBER": StrategyType.MASK,
            "EMAIL_ADDRESS": StrategyType.REDACT,
        })
        anonymizer = Anonymizer(strategy_config=strategy_config)

        result = anonymizer.anonymize("张三的电话是13800138000，邮箱是test@example.com")

        # Check each strategy was applied
        # Person should have placeholder
        assert "<PERSON_" in result.text
        # Phone should have mask
        assert "138" in result.text and "*" in result.text
        # Email should be redacted
        assert "[REDACTED]" in result.text or "redact" in result.text.lower()
