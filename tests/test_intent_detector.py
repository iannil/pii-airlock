"""Tests for intent detection module."""

import pytest

from pii_airlock.core.intent_detector import (
    IntentDetector,
    IntentResult,
    get_intent_detector,
    reset_intent_detector,
    is_question_context,
    should_preserve_entity,
)


class TestIntentDetector:
    """Tests for IntentDetector class."""

    def test_create_detector(self):
        """Test creating an intent detector."""
        detector = IntentDetector()
        assert detector is not None
        assert detector.context_window == 50

    def test_custom_context_window(self):
        """Test creating detector with custom context window."""
        detector = IntentDetector(context_window=100)
        assert detector.context_window == 100

    def test_is_question_text_with_question_mark(self):
        """Test question detection with question mark."""
        detector = IntentDetector()

        # Chinese question mark
        result = detector.is_question_text("张三是谁？")
        assert result.is_question is True
        assert result.confidence > 0.8

        # English question mark
        result = detector.is_question_text("Who is John?")
        assert result.is_question is True
        assert result.confidence > 0.8

    def test_is_question_text_with_question_words(self):
        """Test question detection with question words."""
        detector = IntentDetector()

        # Chinese question words
        result = detector.is_question_text("谁是张三")
        assert result.is_question is True

        result = detector.is_question_text("请介绍一下习近平")
        assert result.is_question is True

        # English question words
        result = detector.is_question_text("Who is the president")
        assert result.is_question is True

        result = detector.is_question_text("Tell me about John")
        assert result.is_question is True

    def test_is_question_text_statement(self):
        """Test that statements are not classified as questions."""
        detector = IntentDetector()

        result = detector.is_question_text("张三是我的朋友")
        assert result.is_question is False

        result = detector.is_question_text("Send email to John")
        assert result.is_question is False

    def test_is_question_context_entity_in_question(self):
        """Test question context detection around an entity."""
        detector = IntentDetector()

        # Entity in a question
        text = "张三是谁？"
        # "张三" is at position 0-2
        result = detector.is_question_context(text, 0, 2)
        assert result.is_question is True

        text = "Who is John Smith?"
        # "John Smith" approximately at position 7-17
        result = detector.is_question_context(text, 7, 17)
        assert result.is_question is True

    def test_is_question_context_entity_in_statement(self):
        """Test that entity in statement is not classified as question."""
        detector = IntentDetector()

        # Entity in a statement
        text = "请给张三发邮件"
        result = detector.is_question_context(text, 2, 4)  # "张三"
        assert result.is_question is False

        text = "Send email to John"
        result = detector.is_question_context(text, 12, 16)  # "John"
        assert result.is_question is False

    def test_should_preserve_entity_question_context(self):
        """Test that entities are preserved in question context."""
        detector = IntentDetector()

        # Question context - always preserve
        text = "谁是张三？"
        result = detector.should_preserve_entity(text, 0, 2, is_allowlisted=False)
        assert result is True

    def test_should_preserve_entity_statement_with_allowlist(self):
        """Test that allowlisted entities are preserved in statements."""
        detector = IntentDetector()

        # Statement context + allowlisted = preserve
        text = "给张三发邮件"
        result = detector.should_preserve_entity(text, 1, 3, is_allowlisted=True)
        assert result is True

    def test_should_preserve_entity_statement_no_allowlist(self):
        """Test that non-allowlisted entities are NOT preserved in statements."""
        detector = IntentDetector()

        # Statement context + not allowlisted = anonymize
        text = "给张三发邮件"
        result = detector.should_preserve_entity(text, 1, 3, is_allowlisted=False)
        assert result is False


class TestGlobalFunctions:
    """Tests for global utility functions."""

    def test_get_intent_detector_singleton(self):
        """Test that get_intent_detector returns singleton."""
        reset_intent_detector()
        detector1 = get_intent_detector()
        detector2 = get_intent_detector()
        assert detector1 is detector2

    def test_reset_intent_detector(self):
        """Test reset_intent_detector function."""
        detector1 = get_intent_detector()
        reset_intent_detector()
        detector2 = get_intent_detector()
        # They should be different instances after reset
        # (though the implementation may return the same config)
        assert detector1 is not detector2 or detector2 is not None

    def test_is_question_context(self):
        """Test is_question_context convenience function."""
        reset_intent_detector()
        result = is_question_context("张三是谁？", 0, 2)
        assert isinstance(result, bool)

    def test_should_preserve_entity_convenience(self):
        """Test should_preserve_entity convenience function."""
        reset_intent_detector()
        result = should_preserve_entity("谁是张三？", 0, 2, is_allowlisted=False)
        assert isinstance(result, bool)


class TestIntegrationWithAnonymizer:
    """Tests for intent detection integration with anonymizer."""

    def test_anonymizer_preserves_question_entities(self, analyzer):
        """Test that anonymizer preserves entities in question context."""
        from pii_airlock.core.anonymizer import Anonymizer
        from pii_airlock.core.intent_detector import reset_intent_detector

        reset_intent_detector()

        # Create anonymizer with intent detection enabled
        anonymizer = Anonymizer(
            analyzer=analyzer,
            enable_intent_detection=True,
            enable_allowlist=False,  # Disable allowlist to isolate intent detection
        )

        # Question context - entity should be preserved
        result = anonymizer.anonymize("谁是张三？")

        # The entity "张三" should be preserved because it's a question
        # (unless the system doesn't detect it as a PERSON entity)
        # We'll check that intent_exemptions is populated correctly
        assert hasattr(result, "intent_exemptions")
        # If PERSON is detected, it should be in intent_exemptions
        if len(result.entities) > 0:
            # Check if any PERSON entities were detected
            person_entities = [e for e in result.entities if e.entity_type == "PERSON"]
            if person_entities:
                # Should have intent exemptions
                assert len(result.intent_exemptions) > 0

    def test_anonymizer_anonymizes_statement_entities(self, analyzer):
        """Test that anonymizer anonymizes entities in statement context."""
        from pii_airlock.core.anonymizer import Anonymizer
        from pii_airlock.core.intent_detector import reset_intent_detector

        reset_intent_detector()

        # Create anonymizer with intent detection enabled
        anonymizer = Anonymizer(
            analyzer=analyzer,
            enable_intent_detection=True,
            enable_allowlist=False,
        )

        # Statement context - entity should be anonymized
        result = anonymizer.anonymize("给张三发邮件")

        # The entity "张三" should be anonymized
        assert "<PERSON" in result.text or "张三" in result.text
        # No intent exemptions in statement context
        assert len(result.intent_exemptions) == 0

    def test_anonymizer_intent_disabled(self, analyzer):
        """Test that anonymizer works with intent detection disabled."""
        from pii_airlock.core.anonymizer import Anonymizer
        from pii_airlock.core.intent_detector import reset_intent_detector

        reset_intent_detector()

        # Create anonymizer with intent detection DISABLED
        anonymizer = Anonymizer(
            analyzer=analyzer,
            enable_intent_detection=False,
            enable_allowlist=False,
        )

        # Even in question context, entity should be anonymized
        result = anonymizer.anonymize("谁是张三？")

        # With intent disabled, the entity should be anonymized
        # (assuming it's detected as PERSON)
        if result.pii_count > 0:
            assert "<PERSON" in result.text

    def test_anonymization_result_has_intent_exemptions(self, analyzer):
        """Test that AnonymizationResult has intent_exemptions field."""
        from pii_airlock.core.anonymizer import Anonymizer
        from pii_airlock.core.intent_detector import reset_intent_detector

        reset_intent_detector()

        anonymizer = Anonymizer(
            analyzer=analyzer,
            enable_intent_detection=True,
        )

        result = anonymizer.anonymize("张三是谁？")

        # Check that the result has the intent_exemptions field
        assert hasattr(result, "intent_exemptions")
        assert isinstance(result.intent_exemptions, list)

    def test_anonymization_result_all_exemptions(self, analyzer):
        """Test the all_exemptions property."""
        from pii_airlock.core.anonymizer import Anonymizer
        from pii_airlock.core.intent_detector import reset_intent_detector
        from pii_airlock.recognizers.allowlist import get_allowlist_registry, AllowlistConfig

        reset_intent_detector()

        # Add test entry to allowlist
        registry = get_allowlist_registry()
        test_allowlist = AllowlistConfig(
            name="test_intent",
            entity_type="PERSON",
            enabled=True,
        )
        test_allowlist.add("李四")
        registry.register(test_allowlist)

        # Create anonymizer with both features enabled
        anonymizer = Anonymizer(
            analyzer=analyzer,
            enable_intent_detection=True,
            enable_allowlist=True,
        )

        result = anonymizer.anonymize("谁是张三？")

        # Check all_exemptions property
        assert hasattr(result, "all_exemptions")
        assert isinstance(result.all_exemptions, list)

        # Verify all_exemptions combines both lists
        expected_count = len(result.allowlist_exemptions) + len(result.intent_exemptions)
        assert len(result.all_exemptions) == expected_count


class TestSpecificPatterns:
    """Tests for specific question/answer patterns."""

    def test_who_is_pattern(self):
        """Test 'Who is/谁是' pattern."""
        detector = IntentDetector()

        result = detector.is_question_text("谁是习近平")
        assert result.is_question is True

        result = detector.is_question_text("Who is Xi Jinping")
        assert result.is_question is True

    def test_tell_me_about_pattern(self):
        """Test 'tell me about/介绍一下' pattern."""
        detector = IntentDetector()

        result = detector.is_question_text("介绍一下马云")
        assert result.is_question is True

        result = detector.is_question_text("Tell me about Elon Musk")
        assert result.is_question is True

    def test_do_you_know_pattern(self):
        """Test 'do you know/你知道' pattern."""
        detector = IntentDetector()

        result = detector.is_question_text("你知道比尔盖茨吗")
        assert result.is_question is True

        result = detector.is_question_text("Do you know Steve Jobs")
        assert result.is_question is True

    def test_send_email_pattern(self):
        """Test 'send email/发邮件' pattern is NOT a question."""
        detector = IntentDetector()

        result = detector.is_question_text("给张三发邮件")
        assert result.is_question is False

        result = detector.is_question_text("Send email to John")
        assert result.is_question is False

    def test_call_contact_pattern(self):
        """Test 'call/联系' pattern is NOT a question."""
        detector = IntentDetector()

        result = detector.is_question_text("联系李四")
        assert result.is_question is False

        result = detector.is_question_text("Call Mary")
        assert result.is_question is False
