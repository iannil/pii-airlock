"""Configuration module for PII-AIRLOCK."""

from pii_airlock.config.pattern_loader import (
    PatternConfig,
    load_patterns_from_yaml,
)

__all__ = [
    "PatternConfig",
    "load_patterns_from_yaml",
]
