"""Dynamic pattern recognizer factory.

This module creates Presidio PatternRecognizer instances from configuration,
allowing custom PII patterns to be loaded at runtime.
"""

from presidio_analyzer import Pattern, PatternRecognizer

from pii_airlock.config.pattern_loader import PatternConfig


def create_recognizer_from_config(
    config: PatternConfig,
    language: str = "zh",
) -> PatternRecognizer:
    """Create a PatternRecognizer from a PatternConfig.

    Args:
        config: The pattern configuration.
        language: Language code for the recognizer (default: "zh").

    Returns:
        A configured PatternRecognizer instance.

    Example:
        >>> config = PatternConfig(
        ...     name="employee_id",
        ...     entity_type="EMPLOYEE_ID",
        ...     regex="EMP[A-Z]\\d{6}",
        ...     score=0.85,
        ... )
        >>> recognizer = create_recognizer_from_config(config)
        >>> recognizer.analyze("员工编号: EMPA123456", entities=["EMPLOYEE_ID"])
    """
    pattern = Pattern(
        name=config.name,
        regex=config.regex,
        score=config.score,
    )

    # Generate a class-like name for the recognizer
    # e.g., "employee_id" -> "CustomEmployeeIdRecognizer"
    name_parts = config.name.split("_")
    class_name = "Custom" + "".join(part.title() for part in name_parts) + "Recognizer"

    return PatternRecognizer(
        supported_entity=config.entity_type,
        patterns=[pattern],
        context=config.context or [],
        supported_language=language,
        name=class_name,
    )


def create_recognizers_from_configs(
    configs: list[PatternConfig],
    language: str = "zh",
) -> list[PatternRecognizer]:
    """Create multiple recognizers from a list of configurations.

    Args:
        configs: List of pattern configurations.
        language: Language code for the recognizers.

    Returns:
        List of configured PatternRecognizer instances.

    Example:
        >>> configs = load_patterns_from_yaml("config/patterns.yaml")
        >>> recognizers = create_recognizers_from_configs(configs)
        >>> print(f"Created {len(recognizers)} custom recognizers")
    """
    return [create_recognizer_from_config(config, language) for config in configs]
