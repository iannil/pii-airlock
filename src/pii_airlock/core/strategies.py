"""
Anonymization strategies for PII data.

This module provides multiple strategies for anonymizing PII:
- placeholder: Replace with type-based placeholders (e.g., <PERSON_1>)
- hash: Replace with SHA256 hash
- mask: Replace partial content with asterisks (e.g., 138****8000)
- redact: Replace completely with [REDACTED]

Strategies can be configured per entity type.
"""

import hashlib
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pii_airlock.config.pattern_loader import load_patterns_from_yaml_safe


class StrategyType(str, Enum):
    """Supported anonymization strategy types."""

    PLACEHOLDER = "placeholder"
    HASH = "hash"
    MASK = "mask"
    REDACT = "redact"
    SYNTHETIC = "synthetic"  # 使用语义相似的假数据替换


@dataclass
class StrategyResult:
    """Result of applying an anonymization strategy.

    Attributes:
        text: The anonymized text.
        can_deanonymize: Whether this result can be deanonymized.
            Placeholder and hash strategies support deanonymization,
            while mask and redact do not.
    """

    text: str
    can_deanonymize: bool = True


class AnonymizationStrategy(ABC):
    """Base class for anonymization strategies."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Get the strategy name."""

    @property
    def supports_deanonymization(self) -> bool:
        """Check if this strategy supports deanonymization."""
        return True

    @abstractmethod
    def anonymize(
        self,
        value: str,
        entity_type: str,
        index: int,
        context: dict[str, Any],
    ) -> StrategyResult:
        """Anonymize a value using this strategy.

        Args:
            value: The original value to anonymize.
            entity_type: The type of PII entity (e.g., PERSON, PHONE).
            index: The index of this value for the entity type.
            context: Additional context for the anonymization.

        Returns:
            StrategyResult containing the anonymized text.
        """


class PlaceholderStrategy(AnonymizationStrategy):
    """Replace PII with type-based placeholders.

    Example: "张三" -> "<PERSON_1>"
    """

    @property
    def name(self) -> str:
        return StrategyType.PLACEHOLDER

    def anonymize(
        self,
        value: str,
        entity_type: str,
        index: int,
        context: dict[str, Any],
    ) -> StrategyResult:
        """Replace value with placeholder."""
        placeholder = f"<{entity_type}_{index}>"
        return StrategyResult(text=placeholder, can_deanonymize=True)


class HashStrategy(AnonymizationStrategy):
    """Replace PII with a hash of the original value.

    Uses SHA256 for hashing. The hash is deterministic, so the same
    input will always produce the same hash, enabling deanonymization
    with the original hash mapping.

    Example: "张三" -> "a1b2c3d4e5f6..."
    """

    @property
    def name(self) -> str:
        return StrategyType.HASH

    def anonymize(
        self,
        value: str,
        entity_type: str,
        index: int,
        context: dict[str, Any],
    ) -> StrategyResult:
        """Replace value with SHA256 hash."""
        # Use entity_type as salt for domain-specific hashing
        salt = context.get("salt", entity_type)
        hash_input = f"{salt}:{value}"
        hash_hex = hashlib.sha256(hash_input.encode()).hexdigest()
        return StrategyResult(text=hash_hex, can_deanonymize=True)


class MaskStrategy(AnonymizationStrategy):
    """Partially mask PII while preserving format.

    Shows first and last portions, masks the middle with asterisks.
    The exact masking pattern depends on the entity type.

    Examples:
        Phone: "13800138000" -> "138****8000"
        Email: "test@example.com" -> "t**t@example.com"
        ID Card: "110101199003077758" -> "110101********7758"
    """

    @property
    def name(self) -> str:
        return StrategyType.MASK

    @property
    def supports_deanonymization(self) -> bool:
        return False

    def anonymize(
        self,
        value: str,
        entity_type: str,
        index: int,
        context: dict[str, Any],
    ) -> StrategyResult:
        """Partially mask the value."""
        masked = self._mask_value(value, entity_type)
        return StrategyResult(text=masked, can_deanonymize=False)

    def _mask_value(self, value: str, entity_type: str) -> str:
        """Apply appropriate masking based on entity type."""
        entity_upper = entity_type.upper()

        if "PHONE" in entity_upper:
            return self._mask_phone(value)
        elif "EMAIL" in entity_upper:
            return self._mask_email(value)
        elif "ID_CARD" in entity_upper or "IDCARD" in entity_upper:
            return self._mask_id_card(value)
        elif "CREDIT_CARD" in entity_upper:
            return self._mask_credit_card(value)
        else:
            return self._mask_generic(value)

    def _mask_phone(self, phone: str) -> str:
        """Mask phone number: show first 3 and last 4 digits."""
        # Remove non-digits
        digits = "".join(c for c in phone if c.isdigit())
        if len(digits) >= 7:
            return f"{digits[:3]}****{digits[-4:]}"
        return "*" * len(phone)

    def _mask_email(self, email: str) -> str:
        """Mask email: show first and last char of local part."""
        if "@" not in email:
            return "*" * len(email)
        local, domain = email.split("@", 1)
        if len(local) <= 2:
            masked_local = "*" * len(local)
        else:
            masked_local = f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}"
        return f"{masked_local}@{domain}"

    def _mask_id_card(self, id_card: str) -> str:
        """Mask Chinese ID card: show first 6 and last 4 digits."""
        digits = "".join(c for c in id_card if c.isdigit() or c.upper() == "X")
        if len(digits) >= 10:
            return f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}"
        return "*" * len(id_card)

    def _mask_credit_card(self, card: str) -> str:
        """Mask credit card: show first 4 and last 4 digits."""
        digits = "".join(c for c in card if c.isdigit())
        if len(digits) >= 8:
            return f"{digits[:4]}{'*' * (len(digits) - 8)}{digits[-4:]}"
        return "*" * len(card)

    def _mask_generic(self, value: str) -> str:
        """Generic masking: show first and last 25% of characters."""
        if len(value) <= 4:
            return "*" * len(value)
        show_chars = max(1, len(value) // 4)
        return f"{value[:show_chars]}{'*' * (len(value) - 2 * show_chars)}{value[-show_chars:]}"


class RedactStrategy(AnonymizationStrategy):
    """Completely redact PII with a fixed marker.

    This strategy provides maximum privacy by completely removing
    the original value and replacing it with a marker.

    Example: "test@example.com" -> "[REDACTED]"
    """

    @property
    def name(self) -> str:
        return StrategyType.REDACT

    @property
    def supports_deanonymization(self) -> bool:
        return False

    def __init__(self, marker: str = "[REDACTED]") -> None:
        """Initialize the redact strategy.

        Args:
            marker: The marker text to use for redaction.
        """
        self._marker = marker

    def anonymize(
        self,
        value: str,
        entity_type: str,
        index: int,
        context: dict[str, Any],
    ) -> StrategyResult:
        """Redact the value completely."""
        return StrategyResult(text=self._marker, can_deanonymize=False)


class SyntheticStrategy(AnonymizationStrategy):
    """Replace PII with semantically similar synthetic data.

    This strategy generates realistic fake data that preserves the
    semantic characteristics of the original PII, allowing LLMs
    to maintain context while protecting privacy.

    Example:
        - "张三" -> "李四"
        - "13800138000" -> "13912345678"
        - "test@example.com" -> "user@163.com"

    This strategy supports deanonymization through the mapping metadata.
    """

    @property
    def name(self) -> str:
        return StrategyType.SYNTHETIC

    @property
    def supports_deanonymization(self) -> bool:
        return True

    def __init__(self, seed: int = 42, **kwargs) -> None:
        """Initialize the synthetic strategy.

        Args:
            seed: Random seed for deterministic generation.
            **kwargs: Additional parameters passed to generators.
        """
        self._seed = seed
        self._generator = None  # Lazy initialization

    def _get_generator(self):
        """Get or create the synthetic data generator."""
        if self._generator is None:
            from pii_airlock.core.synthetic.generator import SyntheticDataGenerator
            self._generator = SyntheticDataGenerator(seed=self._seed)
        return self._generator

    def anonymize(
        self,
        value: str,
        entity_type: str,
        index: int,
        context: dict[str, Any],
    ) -> StrategyResult:
        """Generate synthetic replacement for the PII value."""
        generator = self._get_generator()
        mapping = generator.generate(value, entity_type)

        # Store mapping in context for deanonymization
        if "synthetic_mappings" not in context:
            context["synthetic_mappings"] = []
        context["synthetic_mappings"].append(mapping)

        return StrategyResult(
            text=mapping.synthetic,
            can_deanonymize=True,
        )


# Strategy registry
_STRATEGIES: dict[StrategyType, AnonymizationStrategy] = {
    StrategyType.PLACEHOLDER: PlaceholderStrategy(),
    StrategyType.HASH: HashStrategy(),
    StrategyType.MASK: MaskStrategy(),
    StrategyType.REDACT: RedactStrategy(),
    StrategyType.SYNTHETIC: SyntheticStrategy(),
}


def get_strategy(strategy_type: StrategyType | str) -> AnonymizationStrategy:
    """Get a strategy instance by type.

    Args:
        strategy_type: The strategy type to retrieve.

    Returns:
        An instance of the requested strategy.

    Raises:
        ValueError: If the strategy type is not supported.
    """
    # First, try to convert to enum if it's a known type
    if isinstance(strategy_type, str):
        strategy_key = strategy_type.lower()
        # Check if it's a direct match in _STRATEGIES
        if strategy_key in _STRATEGIES:
            return _STRATEGIES[strategy_key]
        # Try to convert to StrategyType enum
        try:
            strategy_type = StrategyType(strategy_key)
        except ValueError:
            raise ValueError(f"Unknown strategy type: {strategy_key}")

    if strategy_type not in _STRATEGIES:
        raise ValueError(f"Strategy not implemented: {strategy_type}")

    return _STRATEGIES[strategy_type]


def register_strategy(strategy_type: StrategyType | str, strategy: AnonymizationStrategy) -> None:
    """Register a custom strategy.

    Args:
        strategy_type: The strategy type identifier.
        strategy: The strategy instance to register.
    """
    _STRATEGIES[strategy_type] = strategy


class StrategyConfig:
    """Configuration for anonymization strategies.

    Maps entity types to their anonymization strategies.
    """

    # Default strategy mapping (class constant)
    DEFAULT_STRATEGIES: dict[str, StrategyType] = {
        "PERSON": StrategyType.PLACEHOLDER,
        "PHONE": StrategyType.PLACEHOLDER,
        "PHONE_NUMBER": StrategyType.PLACEHOLDER,
        "EMAIL": StrategyType.PLACEHOLDER,
        "EMAIL_ADDRESS": StrategyType.PLACEHOLDER,
        "CREDIT_CARD": StrategyType.MASK,
        "ID_CARD": StrategyType.MASK,
        "ZH_ID_CARD": StrategyType.MASK,
        "IP": StrategyType.MASK,
        "IP_ADDRESS": StrategyType.MASK,
    }

    def __init__(self, strategies: dict[str, StrategyType] | None = None) -> None:
        """Initialize strategy configuration.

        Args:
            strategies: Custom strategy mapping. If None, uses defaults.
        """
        self.strategies: dict[str, StrategyType] = {**self.DEFAULT_STRATEGIES}
        if strategies:
            self.strategies.update(strategies)

    def get_strategy(self, entity_type: str) -> StrategyType:
        """Get the strategy for an entity type.

        Args:
            entity_type: The entity type to look up.

        Returns:
            The strategy type for this entity. Defaults to PLACEHOLDER.
        """
        return self.strategies.get(entity_type, StrategyType.PLACEHOLDER)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "StrategyConfig":
        """Load strategy configuration from a YAML file.

        YAML format:
            strategies:
              PERSON: placeholder
              PHONE_NUMBER: mask
              EMAIL_ADDRESS: redact

        Args:
            path: Path to the YAML configuration file.

        Returns:
            StrategyConfig with loaded configuration.
        """
        patterns, error = load_patterns_from_yaml_safe(path)

        if error:
            return cls()  # Return default config on error

        # Extract strategy configurations from custom patterns
        strategies: dict[str, StrategyType] = {}
        for pattern in patterns:
            if hasattr(pattern, "strategy") and pattern.strategy:
                try:
                    strategies[pattern.entity_type] = StrategyType(pattern.strategy)
                except ValueError:
                    pass  # Skip invalid strategy names

        return cls(strategies)

    @classmethod
    def from_env(cls) -> "StrategyConfig":
        """Load strategy configuration from environment variables.

        Environment variables:
            PII_AIRLOCK_STRATEGY_PERSON: Strategy for PERSON entities
            PII_AIRLOCK_STRATEGY_PHONE: Strategy for PHONE entities
            PII_AIRLOCK_STRATEGY_EMAIL: Strategy for EMAIL entities
            etc.

        Returns:
            StrategyConfig with loaded configuration.
        """
        strategies: dict[str, StrategyType] = {}

        # Mapping of entity types to env var suffixes
        entity_env_map = {
            "PERSON": "PERSON",
            "PHONE": "PHONE",
            "PHONE_NUMBER": "PHONE",
            "EMAIL": "EMAIL",
            "EMAIL_ADDRESS": "EMAIL",
            "CREDIT_CARD": "CREDIT_CARD",
            "ID_CARD": "ID_CARD",
            "ZH_ID_CARD": "ID_CARD",
            "IP": "IP",
            "IP_ADDRESS": "IP",
        }

        for entity_type, env_suffix in entity_env_map.items():
            env_value = os.getenv(f"PII_AIRLOCK_STRATEGY_{env_suffix}")
            if env_value:
                try:
                    strategies[entity_type] = StrategyType(env_value.lower())
                except ValueError:
                    pass  # Skip invalid strategy names

        return cls(strategies)
