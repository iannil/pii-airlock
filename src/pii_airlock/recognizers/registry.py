"""
Custom Recognizer Registry

Sets up Presidio with Chinese language support and custom recognizers.
"""

from pathlib import Path
from typing import Optional, Union

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

from pii_airlock.recognizers.zh_id_card import ChineseIdCardRecognizer
from pii_airlock.recognizers.zh_phone import ChinesePhoneRecognizer
from pii_airlock.recognizers.zh_person import ChinesePersonRecognizer


def create_analyzer_with_chinese_support(
    language: str = "zh",
    spacy_model: str = "zh_core_web_sm",
    custom_recognizers: Optional[list] = None,
    config_path: Optional[Union[Path, str]] = None,
) -> AnalyzerEngine:
    """Create an AnalyzerEngine configured for Chinese PII detection.

    Args:
        language: Language code (default: "zh").
        spacy_model: spaCy model to use for Chinese NLP (default: zh_core_web_sm).
        custom_recognizers: Additional recognizers to register.
        config_path: Path to YAML configuration file with custom patterns.

    Returns:
        Configured AnalyzerEngine instance.

    Example:
        >>> analyzer = create_analyzer_with_chinese_support()
        >>> results = analyzer.analyze("张三的身份证号是xxx", language="zh")

        # With custom patterns from YAML:
        >>> analyzer = create_analyzer_with_chinese_support(
        ...     config_path="config/custom_patterns.yaml"
        ... )
    """
    # Configure NLP engine for Chinese
    nlp_configuration = {
        "nlp_engine_name": "spacy",
        "models": [
            {"lang_code": language, "model_name": spacy_model},
        ],
    }

    nlp_engine = NlpEngineProvider(nlp_configuration=nlp_configuration).create_engine()

    # Create registry
    registry = RecognizerRegistry()

    # Add Chinese-specific recognizers
    registry.add_recognizer(ChineseIdCardRecognizer(supported_language=language))
    registry.add_recognizer(ChinesePhoneRecognizer(supported_language=language))
    registry.add_recognizer(ChinesePersonRecognizer(supported_language=language))

    # Load predefined recognizers (email, credit card, etc.)
    registry.load_predefined_recognizers(nlp_engine=nlp_engine, languages=[language])

    # Add any custom recognizers
    if custom_recognizers:
        for recognizer in custom_recognizers:
            registry.add_recognizer(recognizer)

    # Load custom patterns from YAML configuration
    if config_path:
        from pii_airlock.config.pattern_loader import load_patterns_from_yaml_safe
        from pii_airlock.recognizers.custom_pattern import create_recognizer_from_config

        config_path = Path(config_path)
        patterns, error = load_patterns_from_yaml_safe(config_path)

        if error:
            import warnings

            warnings.warn(f"Failed to load custom patterns: {error}")
        else:
            for pattern in patterns:
                recognizer = create_recognizer_from_config(pattern, language)
                registry.add_recognizer(recognizer)

    return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)


def get_supported_entities() -> list[str]:
    """Get list of all supported PII entity types.

    Returns:
        List of entity type strings.
    """
    return [
        "PERSON",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "CREDIT_CARD",
        "ZH_ID_CARD",
        "IP_ADDRESS",
        "URL",
    ]
