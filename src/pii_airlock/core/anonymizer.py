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
    """

    text: str
    mapping: PIIMapping
    entities: list[RecognizerResult] = field(default_factory=list)

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
        """
        self.language = language
        self.score_threshold = score_threshold

        # Initialize strategy configuration
        if load_strategies_from_env:
            self.strategy_config = StrategyConfig.from_env()
        elif strategy_config:
            self.strategy_config = strategy_config
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

        # Step 4: Replace PII using configured strategies (from end to start to preserve positions)
        anonymized_text = text
        for result in sorted_results:
            original_value = text[result.start : result.end]
            placeholder_type = self.ENTITY_TYPE_MAP.get(result.entity_type, result.entity_type)

            # Get the strategy for this entity type
            strategy_type = self.strategy_config.get_strategy(result.entity_type)
            strategy = get_strategy(strategy_type)

            # Check if this exact value already has a placeholder/hash
            existing = mapping.get_placeholder(placeholder_type, original_value)
            if existing:
                replacement = existing
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

            # Replace in text
            anonymized_text = (
                anonymized_text[: result.start] + replacement + anonymized_text[result.end :]
            )

        return AnonymizationResult(
            text=anonymized_text,
            mapping=mapping,
            entities=list(analyzer_results),
        )

    def get_supported_entities(self) -> list[str]:
        """Get list of supported entity types.

        Returns:
            List of entity type strings.
        """
        return list(self.SUPPORTED_ENTITIES)

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
