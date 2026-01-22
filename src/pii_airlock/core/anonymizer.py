"""
PII Anonymization Engine

This module provides the core anonymization functionality, transforming
text containing PII into sanitized text with type-preserving placeholders.

Example:
    >>> from pii_airlock.core.anonymizer import Anonymizer
    >>> anonymizer = Anonymizer()
    >>> result = anonymizer.anonymize("张三的电话是13800138000")
    >>> print(result.text)
    <PERSON_1>的电话是<PHONE_1>
"""

import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig, OperatorResult

from pii_airlock.core.mapping import PIIMapping
from pii_airlock.core.counter import PlaceholderCounter
from pii_airlock.core.strategies import StrategyConfig, StrategyType, get_strategy
from pii_airlock.recognizers.registry import create_analyzer_with_chinese_support
from pii_airlock.recognizers.allowlist import is_allowlisted


# Global singleton for shared AnalyzerEngine (heavy to initialize)
_global_analyzer: Optional[AnalyzerEngine] = None
_analyzer_lock = threading.Lock()
_analyzer_config: dict = {}  # Store config to detect changes


def get_shared_analyzer(
    language: str = "zh",
    spacy_model: str = "zh_core_web_sm",
    config_path: Optional[Union[Path, str]] = None,
) -> AnalyzerEngine:
    """Get or create a shared AnalyzerEngine instance.

    This function provides a singleton AnalyzerEngine to avoid the overhead
    of repeatedly loading spaCy models and initializing recognizers.
    The analyzer is thread-safe and can be shared across requests.

    Args:
        language: Language code for NLP analysis.
        spacy_model: spaCy model to use.
        config_path: Optional path to custom patterns configuration.

    Returns:
        Shared AnalyzerEngine instance.

    Note:
        If called with different configuration parameters after the
        analyzer has been initialized, the existing analyzer is returned.
        To use different configurations, create separate Anonymizer
        instances with explicit analyzer parameter.
    """
    global _global_analyzer, _analyzer_config

    if _global_analyzer is None:
        with _analyzer_lock:
            # Double-check locking pattern
            if _global_analyzer is None:
                _global_analyzer = create_analyzer_with_chinese_support(
                    language=language,
                    spacy_model=spacy_model,
                    config_path=config_path,
                )
                _analyzer_config = {
                    "language": language,
                    "spacy_model": spacy_model,
                    "config_path": str(config_path) if config_path else None,
                }

    return _global_analyzer


def reset_shared_analyzer() -> None:
    """Reset the shared analyzer instance.

    This is primarily useful for testing or when you need to
    reinitialize the analyzer with different configuration.
    """
    global _global_analyzer, _analyzer_config
    with _analyzer_lock:
        _global_analyzer = None
        _analyzer_config = {}


@dataclass
class AnonymizationResult:
    """Result of anonymization operation.

    Attributes:
        text: The anonymized text with placeholders.
        mapping: Bidirectional mapping between original values and placeholders.
        entities: List of detected PII entities with their locations.
        allowlist_exemptions: List of entities that were exempted from anonymization
            because they were in the allowlist.
        intent_exemptions: List of entities that were exempted from anonymization
            because they were in a question context (e.g., "Who is...?").
    """

    text: str
    mapping: PIIMapping
    entities: list[RecognizerResult] = field(default_factory=list)
    allowlist_exemptions: list[dict] = field(default_factory=list)
    intent_exemptions: list[dict] = field(default_factory=list)

    @property
    def all_exemptions(self) -> list[dict]:
        """Get all exemptions (allowlist + intent)."""
        return self.allowlist_exemptions + self.intent_exemptions

    @property
    def has_pii(self) -> bool:
        """Check if any PII was detected."""
        return len(self.entities) > 0

    @property
    def pii_count(self) -> int:
        """Get count of detected PII entities."""
        return len(self.entities)


class Anonymizer:
    """Main PII anonymization engine.

    This class orchestrates PII detection and replacement with
    type-preserving placeholders like <PERSON_1>, <PHONE_2>, etc.
    Also supports multiple anonymization strategies via StrategyConfig.

    Attributes:
        language: Primary language for NLP analysis.
        score_threshold: Minimum confidence score for PII detection.
        strategy_config: Configuration for anonymization strategies.

    Example:
        >>> anonymizer = Anonymizer()
        >>> result = anonymizer.anonymize("张三的邮箱是test@example.com")
        >>> print(result.text)
        <PERSON_1>的邮箱是<EMAIL_1>
        >>> print(result.mapping.get_original("<PERSON_1>"))
        张三

        # With custom patterns:
        >>> anonymizer = Anonymizer(config_path="config/custom_patterns.yaml")

        # With mask strategy for phone numbers:
        >>> from pii_airlock.core.strategies import StrategyConfig, StrategyType
        >>> strategy_config = StrategyConfig({"PHONE_NUMBER": StrategyType.MASK})
        >>> anonymizer = Anonymizer(strategy_config=strategy_config)
        >>> result = anonymizer.anonymize("电话是13800138000")
        >>> print(result.text)
        电话是138****8000
    """

    # Default supported entities
    DEFAULT_ENTITIES: list[str] = [
        "PERSON",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "CREDIT_CARD",
        "ZH_ID_CARD",
        "IP_ADDRESS",
    ]

    # Default mapping from Presidio entity types to our placeholder types
    DEFAULT_ENTITY_TYPE_MAP: dict[str, str] = {
        "PERSON": "PERSON",
        "PHONE_NUMBER": "PHONE",
        "EMAIL_ADDRESS": "EMAIL",
        "CREDIT_CARD": "CREDIT_CARD",
        "ZH_ID_CARD": "ID_CARD",
        "IP_ADDRESS": "IP",
    }

    def __init__(
        self,
        language: str = "zh",
        score_threshold: float = 0.5,
        spacy_model: str = "zh_core_web_sm",
        analyzer: Optional[AnalyzerEngine] = None,
        config_path: Optional[Union[Path, str]] = None,
        custom_entity_types: Optional[dict[str, str]] = None,
        use_shared_analyzer: bool = True,
        strategy_config: Optional[StrategyConfig] = None,
        load_strategies_from_env: bool = False,
        enable_allowlist: Optional[bool] = None,
        enable_intent_detection: Optional[bool] = None,
    ) -> None:
        """Initialize the anonymizer.

        Args:
            language: Language code for NLP analysis (default: "zh" for Chinese).
            score_threshold: Minimum confidence score for PII detection.
            spacy_model: spaCy model to use (default: zh_core_web_sm).
            analyzer: Optional pre-configured AnalyzerEngine.
            config_path: Path to YAML configuration file with custom patterns.
            custom_entity_types: Additional entity type mappings for custom patterns.
                Maps from Presidio entity type to placeholder type.
                Example: {"EMPLOYEE_ID": "EMPLOYEE", "PROJECT_CODE": "PROJECT"}
            use_shared_analyzer: If True and no analyzer is provided, use the
                shared singleton analyzer for better performance. Default: True.
            strategy_config: Configuration for anonymization strategies per entity type.
            load_strategies_from_env: If True, load strategy configuration from
                environment variables (PII_AIRLOCK_STRATEGY_*).
            enable_allowlist: If True, entities in the allowlist will not be anonymized.
                If None, reads from PII_AIRLOCK_ALLOWLIST_ENABLED env var (default: True).
            enable_intent_detection: If True, uses intent detection to preserve entities
                in question contexts (e.g., "Who is Xi Jinping?"). If None, reads from
                PII_AIRLOCK_INTENT_DETECTION_ENABLED env var (default: True).
        """
        self.language = language
        self.score_threshold = score_threshold

        # Initialize allowlist setting
        if enable_allowlist is None:
            self.enable_allowlist = os.getenv("PII_AIRLOCK_ALLOWLIST_ENABLED", "true").lower() == "true"
        else:
            self.enable_allowlist = enable_allowlist

        # Initialize intent detection setting
        if enable_intent_detection is None:
            self.enable_intent_detection = os.getenv("PII_AIRLOCK_INTENT_DETECTION_ENABLED", "true").lower() == "true"
        else:
            self.enable_intent_detection = enable_intent_detection

        # Lazy initialize intent detector only if needed
        self._intent_detector = None

        # Initialize strategy configuration
        # Priority: explicit strategy_config > env vars > compliance preset > default
        if strategy_config:
            self.strategy_config = strategy_config
        elif load_strategies_from_env:
            self.strategy_config = StrategyConfig.from_env()
        else:
            # Check if there's an active compliance preset with strategy config
            preset_config = self._get_compliance_preset_strategy_config()
            if preset_config:
                self.strategy_config = preset_config
            else:
                self.strategy_config = StrategyConfig()

        # Initialize entity mappings (copy defaults to avoid mutating class attributes)
        self.SUPPORTED_ENTITIES = list(self.DEFAULT_ENTITIES)
        self.ENTITY_TYPE_MAP = dict(self.DEFAULT_ENTITY_TYPE_MAP)

        # Add custom entity types
        if custom_entity_types:
            self.ENTITY_TYPE_MAP.update(custom_entity_types)
            for entity_type in custom_entity_types.keys():
                if entity_type not in self.SUPPORTED_ENTITIES:
                    self.SUPPORTED_ENTITIES.append(entity_type)

        # Load custom patterns from YAML and add their entity types
        if config_path:
            self._load_custom_entity_types(config_path)

        # Initialize Presidio engines
        if analyzer:
            self._analyzer = analyzer
        elif use_shared_analyzer:
            # Use shared singleton for better performance
            self._analyzer = get_shared_analyzer(
                language=language,
                spacy_model=spacy_model,
                config_path=config_path,
            )
        else:
            # Create a new analyzer instance
            self._analyzer = create_analyzer_with_chinese_support(
                language=language,
                spacy_model=spacy_model,
                config_path=config_path,
            )

        self._anonymizer_engine = AnonymizerEngine()

    def _load_custom_entity_types(self, config_path: Union[Path, str]) -> None:
        """Load custom entity types from YAML configuration.

        Args:
            config_path: Path to the YAML configuration file.
        """
        from pii_airlock.config.pattern_loader import load_patterns_from_yaml_safe

        patterns, error = load_patterns_from_yaml_safe(config_path)
        if not error:
            for pattern in patterns:
                entity_type = pattern.entity_type
                if entity_type not in self.SUPPORTED_ENTITIES:
                    self.SUPPORTED_ENTITIES.append(entity_type)
                # For custom patterns, use the entity type as placeholder type by default
                if entity_type not in self.ENTITY_TYPE_MAP:
                    self.ENTITY_TYPE_MAP[entity_type] = entity_type

    def anonymize(
        self,
        text: str,
        entities: Optional[list[str]] = None,
        session_id: Optional[str] = None,
    ) -> AnonymizationResult:
        """Anonymize PII in the given text.

        Args:
            text: Input text potentially containing PII.
            entities: Specific entity types to detect. If None, detect all supported.
            session_id: Optional session identifier for mapping isolation.

        Returns:
            AnonymizationResult containing anonymized text and mapping.

        Example:
            >>> result = anonymizer.anonymize("张三的邮箱是test@example.com")
            >>> print(result.text)
            <PERSON_1>的邮箱是<EMAIL_1>
        """
        if not text or not text.strip():
            return AnonymizationResult(text=text, mapping=PIIMapping(session_id=session_id))

        entities_to_detect = entities or self.SUPPORTED_ENTITIES

        # Step 1: Detect PII entities
        analyzer_results = self._analyzer.analyze(
            text=text,
            language=self.language,
            entities=entities_to_detect,
            score_threshold=self.score_threshold,
        )

        if not analyzer_results:
            return AnonymizationResult(
                text=text,
                mapping=PIIMapping(session_id=session_id),
            )

        # Step 2: Filter overlapping entities (keep highest score)
        filtered_results = self._remove_overlapping_entities(analyzer_results)

        # Step 3: Create mapping and counter for this operation
        mapping = PIIMapping(session_id=session_id)
        counter = PlaceholderCounter()

        # Step 4: Sort results by position (reverse order for replacement)
        sorted_results = sorted(filtered_results, key=lambda x: x.start, reverse=True)

        # Step 5: Track exemptions for audit logging
        allowlist_exemptions: list[dict] = []
        intent_exemptions: list[dict] = []

        # Step 6: Replace PII using configured strategies (from end to start to preserve positions)
        anonymized_text = text
        for result in sorted_results:
            original_value = text[result.start : result.end]
            placeholder_type = self.ENTITY_TYPE_MAP.get(result.entity_type, result.entity_type)

            # Check 1: Intent detection - preserve entities in question context
            if self.enable_intent_detection:
                is_question, exemption_reason = self._check_intent_context(
                    text, result.start, result.end, result.entity_type
                )
                if is_question:
                    intent_exemptions.append({
                        "entity_type": result.entity_type,
                        "original_value": original_value,
                        "start": result.start,
                        "end": result.end,
                        "reason": exemption_reason,
                    })
                    continue

            # Check 2: Allowlist - if entity is allowlisted, skip anonymization
            if self.enable_allowlist and is_allowlisted(
                result.entity_type, original_value, default=False
            ):
                allowlist_exemptions.append({
                    "entity_type": result.entity_type,
                    "original_value": original_value,
                    "start": result.start,
                    "end": result.end,
                })
                continue

            # Get the strategy for this entity type
            strategy_type = self.strategy_config.get_strategy(result.entity_type)
            strategy = get_strategy(strategy_type)

            # Check if this exact value already has a placeholder/hash/synthetic
            existing = mapping.get_placeholder(placeholder_type, original_value)
            if existing:
                replacement = existing
            else:
                # Check for fuzzy match - normalized value might already exist
                normalized_value = self._normalize_pii_value(original_value, placeholder_type)
                fuzzy_placeholder = mapping.get_placeholder(placeholder_type + "_normalized", normalized_value)
                if fuzzy_placeholder:
                    # Use the same replacement for fuzzy match
                    replacement = mapping.get_original(fuzzy_placeholder)
                else:
                    # For synthetic strategy, check if we already have a synthetic value
                    if strategy_type == StrategyType.SYNTHETIC:
                        existing_synthetic = mapping.get_synthetic(original_value)
                        if existing_synthetic:
                            replacement = existing_synthetic
                        else:
                            # Check fuzzy synthetic match
                            normalized_synthetic = mapping.get_synthetic(normalized_value)
                            if normalized_synthetic:
                                replacement = normalized_synthetic
                            else:
                                # Generate new synthetic value
                                index = counter.next(placeholder_type)
                                strategy_result = strategy.anonymize(
                                    value=original_value,
                                    entity_type=placeholder_type,
                                    index=index,
                                    context={},
                                )
                                replacement = strategy_result.text

                                # Store as synthetic mapping
                                mapping.add_synthetic(placeholder_type, original_value, replacement)
                                # Also store normalized mapping for fuzzy matching
                                if normalized_value != original_value:
                                    mapping.add_synthetic(placeholder_type + "_normalized", normalized_value, replacement)
                    else:
                        # Apply the strategy to generate replacement
                        index = counter.next(placeholder_type)
                        strategy_result = strategy.anonymize(
                            value=original_value,
                            entity_type=placeholder_type,
                            index=index,
                            context={"salt": result.entity_type},
                        )
                        replacement = strategy_result.text

                        # Only add to mapping if the strategy supports deanonymization
                        if strategy_result.can_deanonymize:
                            mapping.add(placeholder_type, original_value, replacement)
                            # Also store normalized mapping for fuzzy matching
                            if normalized_value != original_value:
                                mapping.add(placeholder_type + "_normalized", normalized_value, replacement)

            # Replace in text
            anonymized_text = (
                anonymized_text[: result.start] + replacement + anonymized_text[result.end :]
            )

        result = AnonymizationResult(
            text=anonymized_text,
            mapping=mapping,
            entities=list(analyzer_results),
            allowlist_exemptions=allowlist_exemptions,
            intent_exemptions=intent_exemptions,
        )

        # Log exemptions for audit trail
        if allowlist_exemptions:
            self._log_allowlist_exemptions(allowlist_exemptions, session_id)
        if intent_exemptions:
            self._log_intent_exemptions(intent_exemptions, session_id)

        return result

    def get_supported_entities(self) -> list[str]:
        """Get list of supported entity types.

        Returns:
            List of entity type strings.
        """
        return list(self.SUPPORTED_ENTITIES)

    def _log_allowlist_exemptions(
        self, exemptions: list[dict], session_id: Optional[str]
    ) -> None:
        """Log allowlist exemptions for audit trail.

        Args:
            exemptions: List of exempted entities with their details.
            session_id: Optional session identifier.
        """
        try:
            from pii_airlock.audit.logger import get_audit_logger
            import logging

            logger = get_audit_logger()
            if not logger.enabled:
                return

            # Log each exemption
            for exemption in exemptions:
                # Use sync logging to avoid async issues in sync context
                logging.info(
                    "Allowlist exemption: %s (%s)",
                    exemption.get("original_value"),
                    exemption.get("entity_type"),
                )

                # Try to schedule async logging if event loop is running
                try:
                    import asyncio

                    try:
                        loop = asyncio.get_running_loop()
                        # Schedule async log as a task (fire and forget)
                        asyncio.create_task(
                            logger.log(
                                event_type="allowlist_exempt",
                                entity_type=exemption.get("entity_type"),
                                metadata={
                                    "original_value": exemption.get("original_value"),
                                    "session_id": session_id,
                                    "exemption_reason": "allowlist_match",
                                },
                            )
                        )
                    except RuntimeError:
                        # No event loop running, skip async logging
                        pass
                except Exception:
                    # Skip async logging if it fails
                    pass
        except Exception:
            # Silently fail if audit logging is not available
            pass

    def _log_intent_exemptions(
        self, exemptions: list[dict], session_id: Optional[str]
    ) -> None:
        """Log intent exemptions for audit trail.

        Args:
            exemptions: List of exempted entities with their details.
            session_id: Optional session identifier.
        """
        try:
            import logging

            # Log each exemption
            for exemption in exemptions:
                logging.info(
                    "Intent exemption: %s (%s) - reason: %s",
                    exemption.get("original_value"),
                    exemption.get("entity_type"),
                    exemption.get("reason", "question_context"),
                )
        except Exception:
            # Silently fail if logging fails
            pass

    @property
    def intent_detector(self):
        """Get or create the intent detector instance."""
        if self._intent_detector is None:
            from pii_airlock.core.intent_detector import get_intent_detector
            self._intent_detector = get_intent_detector()
        return self._intent_detector

    def _check_intent_context(
        self,
        text: str,
        entity_start: int,
        entity_end: int,
        entity_type: str,
    ) -> tuple[bool, str]:
        """Check if an entity is in question context.

        Args:
            text: The full text containing the entity.
            entity_start: Start position of the entity.
            entity_end: End position of the entity.
            entity_type: The type of entity (PERSON, PHONE, etc).

        Returns:
            Tuple of (should_preserve, reason).
        """
        # Only check intent for certain entity types
        # (PII types like phone, email, etc should always be anonymized in statements)
        question_favoring_types = {"PERSON", "ORGANIZATION", "LOCATION"}

        if entity_type not in question_favoring_types:
            return (False, "entity_type_not_favoring")

        try:
            intent_result = self.intent_detector.is_question_context(
                text, entity_start, entity_end
            )
            return (intent_result.is_question, intent_result.reason)
        except Exception:
            # If intent detection fails, default to False (anonymize)
            return (False, "intent_detection_failed")

    def _remove_overlapping_entities(
        self,
        results: list[RecognizerResult],
    ) -> list[RecognizerResult]:
        """Remove overlapping entities, keeping the highest-scoring one.

        When two entities overlap, we keep the one with the higher confidence
        score. If scores are equal, we keep the longer (more specific) entity.

        Args:
            results: List of detected entities.

        Returns:
            Filtered list with no overlapping entities.
        """
        if not results:
            return results

        # Sort by start position, then by score (descending), then by length (descending)
        sorted_results = sorted(
            results,
            key=lambda x: (x.start, -x.score, -(x.end - x.start)),
        )

        filtered: list[RecognizerResult] = []
        for result in sorted_results:
            # Check if this result overlaps with any already-accepted result
            overlaps = False
            for accepted in filtered:
                # Check for overlap: ranges overlap if one starts before the other ends
                if not (result.end <= accepted.start or result.start >= accepted.end):
                    overlaps = True
                    break

            if not overlaps:
                filtered.append(result)

        return filtered

    def _get_compliance_preset_strategy_config(self) -> Optional[StrategyConfig]:
        """Get strategy configuration from the active compliance preset.

        Returns:
            StrategyConfig from the active preset, or None if no preset is active.
        """
        try:
            from pii_airlock.api.compliance_api import get_active_strategy_config
            return get_active_strategy_config()
        except ImportError:
            return None
        except Exception:
            return None

    def _normalize_pii_value(self, value: str, entity_type: str) -> str:
        """Normalize a PII value for fuzzy matching.

        Removes common formatting variations to detect equivalent values.
        For example:
        - Phone: "138-0013-8000" -> "13800138000"
        - Phone: "138 0013 8000" -> "13800138000"
        - ID Card: "110101 19900307 7758" -> "110101199003077758"

        Args:
            value: The PII value to normalize.
            entity_type: The type of PII entity.

        Returns:
            Normalized value for comparison.
        """
        import re

        entity_upper = entity_type.upper()

        # Remove all whitespace
        normalized = re.sub(r'\s+', '', value)

        # For phone numbers, remove common separators
        if "PHONE" in entity_upper:
            normalized = re.sub(r'[-—–\(\)]', '', normalized)

        # For ID cards, remove spaces and dashes
        if "ID_CARD" in entity_upper or "IDCARD" in entity_upper:
            normalized = re.sub(r'[-—–\s]', '', normalized)

        # For credit cards, remove spaces and dashes
        if "CREDIT_CARD" in entity_upper:
            normalized = re.sub(r'[-—–\s]', '', normalized)

        # For email, convert to lowercase for comparison
        if "EMAIL" in entity_upper:
            normalized = normalized.lower()

        return normalized
