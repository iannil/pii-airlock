"""
Intent Detection for PII Anonymization

This module provides functionality to detect the intent of text
(question vs statement) to help decide whether PII entities should
be anonymized or preserved.

The key insight is that when users ASK about public figures or
entities, they want the AI to know who/what they're asking about.
When users STATE information containing PII, it should be anonymized.

Example:
    "Who is Xi Jinping?" -> Question context, preserve "Xi Jinping"
    "Send email to Xi Jinping" -> Statement context, anonymize "Xi Jinping"
"""

import re
import os
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union, List, Set


# CORE-002 FIX: Environment variable for configurable question favoring types
# Default includes PERSON, ORG, LOCATION. Add PHONE, EMAIL etc. if needed.
# Example: PII_AIRLOCK_QUESTION_FAVORING_TYPES="PERSON,ORGANIZATION,LOCATION,PHONE,EMAIL"
DEFAULT_QUESTION_FAVORING_TYPES = {"PERSON", "ORGANIZATION", "LOCATION"}

def _get_question_favoring_types() -> Set[str]:
    """Get question favoring types from environment or default."""
    env_value = os.getenv("PII_AIRLOCK_QUESTION_FAVORING_TYPES", "")
    if env_value.strip():
        return {t.strip().upper() for t in env_value.split(",") if t.strip()}
    return DEFAULT_QUESTION_FAVORING_TYPES.copy()


# Default question patterns (Chinese and English)
DEFAULT_QUESTION_PATTERNS = [
    # Chinese question patterns - Must match actual characters at the start
    r"^[\s]*(\?|？|谁|何人|哪位|哪些|什么叫|什么是|请问|如何|怎么|多少|几|是不是|能否|可以)",
    r"(是誰|是谁|是什么|怎么样|如何|吗\?|呢\?|吗？|呢？)$",
    r"^[\s]*(请| kindly)?(告诉我|介绍一下|讲讲|说说|描述一下|解释一下)",
    r"(你知道|你知道.*吗|听说过|听说过.*吗)",
    r"(查一下|查查|搜索|找一下|找找)",
    # English question patterns
    r"^[\s]*(Who|What|Where|When|Why|How|Which|Whose|Whom|Is|Are|Do|Does|Can|Could|Would|Should|Will|Would)\b",
    r"\?[\s]*$",
    r"(tell me|describe|explain|introduce)",
    r"(do you know|have you heard)",
]

# Patterns that indicate the entity is being asked ABOUT
QUESTION_CONTEXT_PATTERNS = [
    r"(是哪|是誰|是谁|叫什么|叫啥|what is|who is)",
    r"(介绍|描述|explain|describe|introduce|tell me about)",
]

# Patterns that indicate the entity is being used in a statement
STATEMENT_CONTEXT_PATTERNS = [
    r"(联系|呼叫|发邮件|发送|写信|给|告诉|通知|提醒|call|email|text|send|write|notify)",
    r"(的电话|的邮箱|的地址|的身份证|的手机|'s phone|'s email|'s address)",
]


@dataclass
class IntentResult:
    """Result of intent detection.

    Attributes:
        is_question: Whether the text is in question context.
        confidence: Confidence score (0.0 to 1.0).
        reason: Reason for the classification.
        matched_pattern: The pattern that matched (if any).
    """

    is_question: bool
    confidence: float
    reason: str
    matched_pattern: Optional[str] = None


class IntentDetector:
    """Detects whether text is in question or statement context.

    This helps decide whether to preserve PII entities:
    - Question context: Preserve entity names (so AI knows what's being asked)
    - Statement context: Anonymize entities (to protect privacy)
    """

    def __init__(
        self,
        question_patterns: Optional[List[str]] = None,
        question_context_patterns: Optional[List[str]] = None,
        statement_context_patterns: Optional[List[str]] = None,
        context_window: int = 50,
        config_path: Optional[Union[Path, str]] = None,
    ):
        """Initialize the intent detector.

        Args:
            question_patterns: Custom regex patterns for question detection.
            question_context_patterns: Patterns for questions about entities.
            statement_context_patterns: Patterns for statements using PII.
            context_window: Number of characters around entity to check for context.
            config_path: Path to YAML configuration file with patterns.
        """
        self.config_path = config_path
        self.context_window = context_window

        # Load patterns from config if provided, otherwise use defaults
        if config_path:
            config = load_intent_patterns(config_path)
            self.question_patterns = config.get("question_patterns", DEFAULT_QUESTION_PATTERNS)
            self._question_context_patterns = config.get("question_context_patterns", QUESTION_CONTEXT_PATTERNS)
            self._statement_context_patterns = config.get("statement_context_patterns", STATEMENT_CONTEXT_PATTERNS)
            self._always_anonymize = set(config.get("always_anonymize_in_statements", []))
            self._question_favoring = set(config.get("question_favoring_entities", []))
        else:
            self.question_patterns = question_patterns or DEFAULT_QUESTION_PATTERNS
            self._question_context_patterns = question_context_patterns or QUESTION_CONTEXT_PATTERNS
            self._statement_context_patterns = statement_context_patterns or STATEMENT_CONTEXT_PATTERNS
            self._always_anonymize = set()
            # CORE-002 FIX: Use environment variable for question favoring types
            self._question_favoring = _get_question_favoring_types()

        # Compile patterns for better performance
        self._compiled_question = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.question_patterns
        ]
        self._compiled_question_context = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self._question_context_patterns
        ]
        self._compiled_statement_context = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self._statement_context_patterns
        ]

    @property
    def question_favoring_types(self) -> Set[str]:
        """Get the set of entity types that favor question context.

        CORE-002 FIX: Expose question favoring types for use by anonymizer.
        These entity types will be preserved (not anonymized) when detected
        in question context.

        Returns:
            Set of entity type names (e.g., {"PERSON", "ORGANIZATION", "LOCATION"}).
        """
        return self._question_favoring

    def is_question_text(self, text: str) -> IntentResult:
        """Check if the entire text is a question.

        Args:
            text: The text to analyze.

        Returns:
            IntentResult with classification details.
        """
        if not text or not text.strip():
            return IntentResult(
                is_question=False,
                confidence=0.0,
                reason="Empty text",
            )

        text = text.strip()

        # Check for question marks at the end
        if text.endswith("?") or text.endswith("？"):
            return IntentResult(
                is_question=True,
                confidence=0.9,
                reason="Ends with question mark",
                matched_pattern="?",
            )

        # Check against question patterns
        for i, pattern in enumerate(self._compiled_question):
            if pattern.search(text):
                return IntentResult(
                    is_question=True,
                    confidence=0.85,
                    reason=f"Matches question pattern {i}",
                    matched_pattern=self.question_patterns[i],
                )

        return IntentResult(
            is_question=False,
            confidence=0.7,
            reason="No question pattern matched",
        )

    def is_question_context(
        self,
        text: str,
        entity_start: int,
        entity_end: int,
    ) -> IntentResult:
        """Check if an entity is in question context.

        This looks at the context around the entity to determine
        if it's being asked ABOUT (question) or used (statement).

        Args:
            text: The full text containing the entity.
            entity_start: Start position of the entity.
            entity_end: End position of the entity.

        Returns:
            IntentResult with classification details.
        """
        if not text or entity_start < 0 or entity_end > len(text):
            return IntentResult(
                is_question=False,
                confidence=0.0,
                reason="Invalid position",
            )

        # Extract context around the entity
        start = max(0, entity_start - self.context_window)
        end = min(len(text), entity_end + self.context_window)
        context = text[start:end]

        # First, check if the whole text is a question
        whole_text_result = self.is_question_text(text)
        if whole_text_result.is_question and whole_text_result.confidence > 0.8:
            return IntentResult(
                is_question=True,
                confidence=0.95,
                reason="Whole text is a question",
                matched_pattern=whole_text_result.matched_pattern,
            )

        # Check for question context patterns around the entity
        for i, pattern in enumerate(self._compiled_question_context):
            if pattern.search(context):
                return IntentResult(
                    is_question=True,
                    confidence=0.85,
                    reason=f"Entity in question context pattern {i}",
                    matched_pattern=QUESTION_CONTEXT_PATTERNS[i],
                )

        # Check for statement context patterns
        for i, pattern in enumerate(self._compiled_statement_context):
            if pattern.search(context):
                return IntentResult(
                    is_question=False,
                    confidence=0.9,
                    reason=f"Entity in statement context pattern {i}",
                    matched_pattern=STATEMENT_CONTEXT_PATTERNS[i],
                )

        # Default: treat as statement (safer for privacy)
        return IntentResult(
            is_question=False,
            confidence=0.5,
            reason="No clear context detected, defaulting to statement",
        )

    def should_preserve_entity(
        self,
        text: str,
        entity_start: int,
        entity_end: int,
        is_allowlisted: bool = False,
    ) -> bool:
        """Decide whether to preserve an entity (not anonymize).

        Decision logic:
        1. Question context + allowlisted -> Preserve (ask about public figure)
        2. Question context + not allowlisted -> Preserve (ask about someone)
        3. Statement context + allowlisted -> Preserve (public figure reference)
        4. Statement context + not allowlisted -> Anonymize (private PII)

        Args:
            text: The full text containing the entity.
            entity_start: Start position of the entity.
            entity_end: End position of the entity.
            is_allowlisted: Whether the entity is in the allowlist.

        Returns:
            True if entity should be preserved, False if should be anonymized.
        """
        intent = self.is_question_context(text, entity_start, entity_end)

        # Question context: always preserve entity name
        if intent.is_question:
            return True

        # Statement context with allowlist: preserve
        if is_allowlisted:
            return True

        # Statement context without allowlist: anonymize
        return False


# Global singleton
_global_detector: Optional[IntentDetector] = None


def get_intent_detector(config_path: Optional[Union[Path, str]] = None) -> IntentDetector:
    """Get the global intent detector instance.

    Creates and initializes the detector on first call.
    Checks for config file at default location if not provided.

    Args:
        config_path: Optional path to YAML configuration file.

    Returns:
        IntentDetector instance.
    """
    global _global_detector

    if _global_detector is None:
        # Use default config path if not provided and file exists
        if config_path is None:
            default_paths = [
                Path("config/intent_patterns.yaml"),
                Path("/etc/pii_airlock/intent_patterns.yaml"),
            ]
            for path in default_paths:
                if path.exists():
                    config_path = path
                    break

        _global_detector = IntentDetector(config_path=config_path)

    return _global_detector


def load_intent_patterns(config_path: Union[Path, str]) -> dict:
    """Load intent detection patterns from YAML configuration.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        Dictionary with pattern lists.
    """
    config_path = Path(config_path)

    if not config_path.exists():
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            return {}

        patterns = {
            "question_patterns": [],
            "question_context_patterns": [],
            "statement_context_patterns": [],
            "always_anonymize_in_statements": [],
            "question_favoring_entities": [],
        }

        # Extract patterns from YAML structure
        for pattern_type, key in [
            ("question_patterns", "question_patterns"),
            ("question_context_patterns", "question_context_patterns"),
            ("statement_context_patterns", "statement_context_patterns"),
        ]:
            if key in data:
                for item in data[key]:
                    if isinstance(item, dict) and "pattern" in item:
                        patterns[pattern_type].append(item["pattern"])
                    elif isinstance(item, str):
                        patterns[pattern_type].append(item)

        # Extract entity type lists
        if "always_anonymize_in_statements" in data:
            patterns["always_anonymize_in_statements"] = data["always_anonymize_in_statements"]
        if "question_favoring_entities" in data:
            patterns["question_favoring_entities"] = data["question_favoring_entities"]

        return patterns

    except (yaml.YAMLError, IOError, ValueError) as e:
        # Silently fail and return empty patterns
        return {}


def reset_intent_detector() -> None:
    """Reset the global intent detector instance.

    This is primarily useful for testing or reloading configuration.
    """
    global _global_detector
    _global_detector = None


def is_question_context(
    text: str,
    entity_start: int,
    entity_end: int,
) -> bool:
    """Convenience function to check if entity is in question context.

    Args:
        text: The full text containing the entity.
        entity_start: Start position of the entity.
        entity_end: End position of the entity.

    Returns:
        True if entity is in question context.
    """
    detector = get_intent_detector()
    return detector.is_question_context(text, entity_start, entity_end).is_question


def should_preserve_entity(
    text: str,
    entity_start: int,
    entity_end: int,
    is_allowlisted: bool = False,
) -> bool:
    """Convenience function to decide whether to preserve an entity.

    Args:
        text: The full text containing the entity.
        entity_start: Start position of the entity.
        entity_end: End position of the entity.
        is_allowlisted: Whether the entity is in the allowlist.

    Returns:
        True if entity should be preserved (not anonymized).
    """
    detector = get_intent_detector()
    return detector.should_preserve_entity(
        text, entity_start, entity_end, is_allowlisted
    )
