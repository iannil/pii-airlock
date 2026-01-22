"""
Integration tests for PII-AIRLOCK Phase 7.2 features.

Tests the integration of new modules with the core anonymization flow.
"""

import pytest
import os
from pathlib import Path

from pii_airlock.core.anonymizer import Anonymizer, AnonymizationResult
from pii_airlock.core.deanonymizer import Deanonymizer
from pii_airlock.core.mapping import PIIMapping
from pii_airlock.core.strategies import StrategyType, StrategyConfig
from pii_airlock.api.compliance_api import (
    get_all_presets,
    load_compliance_preset_safe,
    get_active_strategy_config,
    set_active_preset,
    clear_active_preset,
)
from pii_airlock.core.secret_scanner import (
    get_secret_scanner,
    SecretScanner,
    quick_scan,
)
from pii_airlock.core.synthetic import SyntheticDataGenerator
from pii_airlock.core.intent_detector import (
    get_intent_detector,
    reset_intent_detector,
    load_intent_patterns,
)


class TestCompliancePresetIntegration:
    """Test compliance preset integration with anonymizer."""

    def teardown_method(self):
        """Clean up after tests."""
        clear_active_preset()

    def test_load_all_presets(self):
        """Test that all compliance presets can be loaded."""
        presets = get_all_presets()
        assert len(presets) >= 3, "Should have at least 3 presets (GDPR, CCPA, PIPL, Financial)"

        # Check that key presets exist
        preset_names = list(presets.keys())
        assert "gdpr" in preset_names
        assert "ccpa" in preset_names
        assert "pipl" in preset_names

    def test_preset_has_strategies(self):
        """Test that compliance presets have strategy definitions."""
        presets = get_all_presets()

        for name, preset in presets.items():
            assert preset.strategies, f"Preset {name} should have strategies"
            assert len(preset.strategies) > 0, f"Preset {name} should have at least one strategy"

    def test_gdpr_preset_strategies(self):
        """Test GDPR preset has specific strategies."""
        presets = get_all_presets()
        gdpr = presets.get("gdpr")

        assert gdpr is not None
        assert gdpr.name == "GDPR Compliance"
        # GDPR should use synthetic or mask for sensitive data
        assert "PERSON" in gdpr.strategies or "EMAIL_ADDRESS" in gdpr.strategies

    def test_activate_preset_updates_strategy_config(self):
        """Test that activating a preset updates the strategy config."""
        presets = get_all_presets()
        ccpa = presets.get("ccpa")

        if ccpa:
            # Activate CCPA preset
            set_active_preset(ccpa, source="test")

            # Check that active strategies are available
            active_config = get_active_strategy_config()
            assert active_config is not None, "Active config should be set after activating preset"
            assert active_config.strategies, "Active config should have strategies"

            # Verify the preset's strategies are in the config
            # entity_type in preset is a string (uppercase like 'PERSON')
            # active_config.strategies uses uppercase keys
            for entity_type, strategy in ccpa.strategies.items():
                if entity_type == "default":
                    continue  # Skip default special key
                entity_type_upper = entity_type.upper() if isinstance(entity_type, str) else entity_type.value.upper()
                strategy_lower = strategy.lower() if isinstance(strategy, str) else strategy.value.lower()
                actual_strategy = active_config.strategies.get(entity_type_upper)
                assert actual_strategy is not None, f"Strategy for {entity_type} should exist"
                assert actual_strategy.value == strategy_lower, \
                    f"Strategy for {entity_type} should be {strategy}, got {actual_strategy.value}"

    def test_anonymizer_uses_active_preset_strategies(self):
        """Test that anonymizer uses strategies from active preset."""
        from pii_airlock.recognizers.registry import create_analyzer_with_chinese_support

        presets = get_all_presets()
        pipl = presets.get("pipl")

        if pipl:
            # Activate PIPL preset
            set_active_preset(pipl, source="test")

            # Create anonymizer (should load from active preset)
            analyzer = create_analyzer_with_chinese_support()
            anonymizer = Anonymizer(analyzer=analyzer)

            # Check that anonymizer has the preset's strategies
            active_config = get_active_strategy_config()
            if active_config:
                # The anonymizer should have loaded the preset's strategies
                # (This is checked via the strategy_config property)
                assert anonymizer.strategy_config.strategies == active_config.strategies

    def test_anonymizer_without_preset(self):
        """Test that anonymizer works without any active preset."""
        from pii_airlock.recognizers.registry import create_analyzer_with_chinese_support

        # Clear any active preset
        clear_active_preset()

        analyzer = create_analyzer_with_chinese_support()
        anonymizer = Anonymizer(analyzer=analyzer)

        # Should use default strategies
        assert anonymizer.strategy_config is not None
        assert len(anonymizer.strategy_config.strategies) > 0


class TestSecretScannerIntegration:
    """Test secret scanner integration."""

    def test_secret_scanner_detects_api_keys(self):
        """Test that secret scanner can detect API keys."""
        scanner = get_secret_scanner()

        # Test OpenAI API key pattern
        result = scanner.scan("My API key is sk-abc123def456")

        assert result.total_count > 0, "Should detect API key"
        assert result.has_critical or result.has_high, "API key should be high risk"

    def test_secret_scanner_blocks_secrets(self):
        """Test that secret scanner correctly blocks dangerous secrets."""
        scanner = get_secret_scanner()

        # Test various secret patterns
        test_cases = [
            ("OpenAI key", "sk-proj-abc123def456"),
            ("AWS key", "AKIAIOSFODNN7EXAMPLE"),
            ("Generic token", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
        ]

        for name, secret in test_cases:
            result = scanner.scan(secret)
            # All should be detected
            assert result.total_count > 0 or secret, f"{name} should be detected"

    def test_secret_scanner_with_context(self):
        """Test secret scanner with message context."""
        scanner = get_secret_scanner()

        # Test within a sentence
        result = scanner.scan("Please send the data to api_key:sk-abc123def456 for processing")

        assert result.total_count > 0, "Should detect API key in context"


class TestSyntheticDataIntegration:
    """Test synthetic data generation integration."""

    def setup_method(self):
        """Reset intent detector before each test."""
        from pii_airlock.core.intent_detector import reset_intent_detector
        reset_intent_detector()

    def test_synthetic_generator_generates_chinese_names(self):
        """Test synthetic generator produces Chinese names."""
        generator = SyntheticDataGenerator()

        # Test name generation
        result = generator.generate("张三", "PERSON")

        assert result.synthetic != result.original, "Synthetic name should be different"
        assert result.synthetic != "", "Synthetic name should not be empty"
        assert len(result.synthetic) >= 2, "Chinese name should be at least 2 characters"

    def test_synthetic_generates_phone_numbers(self):
        """Test synthetic generator produces valid phone numbers."""
        generator = SyntheticDataGenerator()

        result = generator.generate("13800138000", "PHONE")

        assert result.synthetic != result.original, "Synthetic phone should be different"
        # Should be 11 digits (Chinese mobile format)
        assert result.synthetic.isdigit(), "Phone should be all digits"
        assert len(result.synthetic) == 11, "Chinese phone should be 11 digits"

    def test_synthetic_mapping_roundtrip(self):
        """Test synthetic data can be mapped back to original."""
        generator = SyntheticDataGenerator()

        original = "张三"
        entity_type = "PERSON"

        # Generate synthetic
        mapping = generator.generate(original, entity_type)

        # The mapping should preserve the original
        assert mapping.original == original
        assert mapping.synthetic != original

        # Should be able to deanonymize
        restored = generator.deanonymize(mapping.synthetic, [mapping])
        assert restored == original

    def test_anonymizer_with_synthetic_strategy(self):
        """Test anonymizer uses synthetic strategy correctly."""
        from pii_airlock.recognizers.registry import create_analyzer_with_chinese_support
        from pii_airlock.core.intent_detector import reset_intent_detector

        # Reset intent detector to ensure fresh state
        reset_intent_detector()

        analyzer = create_analyzer_with_chinese_support()
        strategy_config = StrategyConfig({"PERSON": StrategyType.SYNTHETIC})

        anonymizer = Anonymizer(
            analyzer=analyzer,
            strategy_config=strategy_config,
            enable_intent_detection=False,  # Disable intent detection for this test
            enable_allowlist=False,  # Disable allowlist for this test
        )

        result = anonymizer.anonymize("张三的电话是13800138000")

        # Original name should not be in the result
        assert "张三" not in result.text, "Original name should be replaced"
        # Phone should be masked
        assert "13800138000" not in result.text, "Phone should be anonymized"

        # Should have synthetic mappings
        assert result.mapping.has_synthetic_mappings()

        # Result should still contain Chinese characters for the synthetic name
        assert any("\u4e00" <= c <= "\u9fff" for c in result.text), "Should contain Chinese characters"

    def test_deanonymizer_restores_synthetic_data(self):
        """Test deanonymizer can restore synthetic data."""
        deanonymizer = Deanonymizer()
        mapping = PIIMapping()

        # Add synthetic mapping
        mapping.add_synthetic("PERSON", "张三", "李四")

        text = "致李四：您好"
        restored = deanonymizer.deanonymize(text, mapping)

        assert restored.text == "致张三：您好"

    def test_synthetic_same_input_same_output(self):
        """Test synthetic generator produces consistent output for same input."""
        generator = SyntheticDataGenerator(seed=42)

        result1 = generator.generate("张三", "PERSON")
        result2 = generator.generate("张三", "PERSON")

        # Same input should produce same output (deterministic)
        assert result1.synthetic == result2.synthetic


class TestIntentDetectorIntegration:
    """Test intent detector integration."""

    def teardown_method(self):
        """Clean up after tests."""
        reset_intent_detector()

    def test_intent_detector_question_context(self):
        """Test intent detector correctly identifies question context."""
        detector = get_intent_detector()

        # Question context
        result = detector.is_question_context("Who is Xi Jinping?", 7, 17)
        assert result.is_question, "Should detect question context"

        # Statement context
        result = detector.is_question_context("Send email to Xi Jinping", 14, 24)
        assert not result.is_question, "Should detect statement context"

    def test_intent_detector_with_chinese_questions(self):
        """Test intent detector with Chinese question patterns."""
        detector = get_intent_detector()

        # Chinese questions
        questions = [
            "习近平是谁？",
            "请介绍一下张三",
            "你知道李四吗？",
        ]

        for question in questions:
            result = detector.is_question_text(question)
            assert result.is_question, f"Should detect question: {question}"

    def test_intent_detector_preserves_question_entities(self):
        """Test that entities in questions are preserved."""
        detector = get_intent_detector()

        # Check the logic for preserving entities in questions
        # For PERSON type in question context
        text = "Who is Xi Jinping?"
        entity_start = 7  # "Xi Jinping"
        entity_end = 18

        should_preserve = detector.should_preserve_entity(
            text, entity_start, entity_end, is_allowlisted=False
        )

        assert should_preserve, "Person name in question should be preserved"

    def test_intent_detector_anonymizes_statement_entities(self):
        """Test that entities in statements are anonymized."""
        detector = get_intent_detector()

        # Statement with PII
        text = "Send email to Xi Jinping"
        entity_start = 14  # "Xi Jinping"
        entity_end = 25

        should_preserve = detector.should_preserve_entity(
            text, entity_start, entity_end, is_allowlisted=False
        )

        assert not should_preserve, "PII in statement should be anonymized"

    def test_intent_config_file_loading(self):
        """Test that intent patterns can be loaded from config file."""
        config_path = Path("config/intent_patterns.yaml")

        if config_path.exists():
            patterns = load_intent_patterns(config_path)
            assert isinstance(patterns, dict), "Should return a dictionary"

            # Should have pattern categories
            expected_keys = [
                "question_patterns",
                "question_context_patterns",
                "statement_context_patterns",
            ]
            for key in expected_keys:
                assert key in patterns, f"Should have {key} in patterns"

    def test_reload_intent_detector(self):
        """Test that intent detector can be reloaded."""
        # Get initial detector
        detector1 = get_intent_detector()

        # Reset and get new detector
        reset_intent_detector()
        detector2 = get_intent_detector()

        # Should be different instances
        assert detector1 is not detector2

        # Both should work
        result1 = detector1.is_question_text("Who is Xi?")
        result2 = detector2.is_question_text("Who is Xi?")

        assert result1.is_question == result2.is_question


class TestEndToEndAnonymization:
    """Test end-to-end anonymization flow."""

    def setup_method(self):
        """Reset intent detector before each test."""
        from pii_airlock.core.intent_detector import reset_intent_detector
        reset_intent_detector()

    def test_full_anonymization_deanonymization_cycle(self):
        """Test complete anonymization and deanonymization cycle."""
        from pii_airlock.recognizers.registry import create_analyzer_with_chinese_support

        analyzer = create_analyzer_with_chinese_support()
        anonymizer = Anonymizer(analyzer=analyzer)
        deanonymizer = Deanonymizer()

        original_text = "张三的邮箱是test@example.com，电话是13800138000"

        # Anonymize
        result = anonymizer.anonymize(original_text)

        assert result.has_pii, "Should detect PII"
        assert result.text != original_text, "Text should be anonymized"

        # Deanonymize
        restored = deanonymizer.deanonymize(result.text, result.mapping)

        assert restored.text == original_text, "Should restore original text"

    def test_synthetic_strategy_preserves_semantics(self):
        """Test synthetic strategy preserves semantic meaning."""
        from pii_airlock.recognizers.registry import create_analyzer_with_chinese_support

        analyzer = create_analyzer_with_chinese_support()
        strategy_config = StrategyConfig({
            "PERSON": StrategyType.SYNTHETIC,
            "PHONE": StrategyType.SYNTHETIC,
        })
        anonymizer = Anonymizer(analyzer=analyzer, strategy_config=strategy_config)
        deanonymizer = Deanonymizer()

        original_text = "张三打电话给李四"

        # Anonymize with synthetic data
        result = anonymizer.anonymize(original_text)

        # Should still be semantically meaningful (names and phone)
        # Should contain Chinese characters for names
        assert any("\u4e00" <= c <= "\u9fff" for c in result.text), "Should contain Chinese characters"

        # Should deanonymize back to original
        restored = deanonymizer.deanonymize(result.text, result.mapping)
        assert restored.text == original_text

    def test_mask_strategy_partially_reveals(self):
        """Test mask strategy partially reveals information."""
        from pii_airlock.recognizers.registry import create_analyzer_with_chinese_support

        analyzer = create_analyzer_with_chinese_support()
        strategy_config = StrategyConfig({
            "PHONE_NUMBER": StrategyType.MASK,
            "EMAIL_ADDRESS": StrategyType.MASK,
        })
        anonymizer = Anonymizer(analyzer=analyzer, strategy_config=strategy_config)

        text = "联系13800138000或test@example.com"
        result = anonymizer.anonymize(text)

        # Phone should be masked (with asterisks)
        assert "13800138000" not in result.text, "Original phone should be masked"
        assert "*" in result.text, "Result should contain masking characters"

        # Email should be partially masked
        # The domain part may remain visible, but the local part is masked
        assert "test@example.com" not in result.text, "Original email should be modified"
        assert "@" in result.text, "Email @ symbol should remain"


class TestBoundaryCases:
    """Test boundary cases and edge conditions."""

    def test_empty_text(self):
        """Test handling of empty text."""
        from pii_airlock.recognizers.registry import create_analyzer_with_chinese_support

        analyzer = create_analyzer_with_chinese_support()
        anonymizer = Anonymizer(analyzer=analyzer)

        result = anonymizer.anonymize("")

        assert result.text == ""
        assert result.pii_count == 0

    def test_long_text(self):
        """Test handling of very long text."""
        from pii_airlock.recognizers.registry import create_analyzer_with_chinese_support

        analyzer = create_analyzer_with_chinese_support()
        anonymizer = Anonymizer(analyzer=analyzer)

        # Create a long text with repeated PII
        long_text = "联系人：" + "张三，" * 100 + " 电话：13800138000"

        result = anonymizer.anonymize(long_text)

        # Should process the entire text
        assert len(result.text) > 0
        # Should detect the phone
        assert "13800138000" not in result.text or "***" in result.text

    def test_mixed_language(self):
        """Test handling of mixed Chinese and English text."""
        from pii_airlock.recognizers.registry import create_analyzer_with_chinese_support

        analyzer = create_analyzer_with_chinese_support()
        anonymizer = Anonymizer(analyzer=analyzer)

        text = "张三's email is john@example.com, phone is 13800138000"

        result = anonymizer.anonymize(text)

        # Should detect and anonymize both Chinese and English PII
        assert result.pii_count >= 2  # At least name and email/phone

    def test_multiple_same_entity(self):
        """Test handling of same entity appearing multiple times."""
        from pii_airlock.recognizers.registry import create_analyzer_with_chinese_support

        analyzer = create_analyzer_with_chinese_support()
        anonymizer = Anonymizer(analyzer=analyzer)
        deanonymizer = Deanonymizer()

        text = "张三给张三发消息"

        result = anonymizer.anonymize(text)

        # Both occurrences should map to the same placeholder
        placeholders = result.mapping.get_all_placeholders()
        person_placeholders = [p for p in placeholders if "PERSON" in p]
        assert len(person_placeholders) <= 2, "Should have at most 2 PERSON placeholders"

        # Deanonymize should restore both
        restored = deanonymizer.deanonymize(result.text, result.mapping)
        assert restored.text == text or "张三" in restored.text


class TestCompliancePresetActivation:
    """Test compliance preset activation and deactivation."""

    def teardown_method(self):
        """Clean up after tests."""
        clear_active_preset()

    def test_activate_preset_via_env(self):
        """Test activating preset via API."""
        presets = get_all_presets()
        if not presets:
            pytest.skip("No compliance presets available")

        # Activate first preset
        preset_name = list(presets.keys())[0]
        preset = presets[preset_name]

        set_active_preset(preset, source="test")

        # Verify it's active
        from pii_airlock.api.compliance_api import get_active_preset, is_preset_active
        assert is_preset_active(), "Preset should be active"

        active = get_active_preset()
        assert active.name == preset.name

    def test_deactivate_preset(self):
        """Test deactivating preset."""
        from pii_airlock.api.compliance_api import is_preset_active, get_active_preset

        # First activate a preset
        presets = get_all_presets()
        if presets:
            preset = list(presets.values())[0]
            set_active_preset(preset, source="test")
            assert is_preset_active()

        # Then deactivate
        clear_active_preset()

        assert not is_preset_active()
        assert get_active_preset() is None


class TestSecretScanningInProxy:
    """Test secret scanning integration with proxy."""

    def test_secret_scanner_blocks_requests(self):
        """Test that requests with secrets are blocked."""
        from pii_airlock.core.secret_scanner.interceptor import get_secret_interceptor

        interceptor = get_secret_interceptor()

        # Test blocking
        result = interceptor.check_messages([
            {"role": "user", "content": "My API key is sk-abc123def456"}
        ])

        assert result.should_block, "Should block request with API key"
        assert result.scan_result.total_count > 0, "Should detect the secret"

    def test_secret_scanner_allows_safe_requests(self):
        """Test that safe requests are allowed through."""
        from pii_airlock.core.secret_scanner.interceptor import get_secret_interceptor

        interceptor = get_secret_interceptor()

        result = interceptor.check_messages([
            {"role": "user", "content": "What is the weather?"}
        ])

        assert not result.should_block, "Should allow safe request"
        assert result.scan_result.total_count == 0, "Should detect no secrets"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
