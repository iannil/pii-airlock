"""Core modules for PII anonymization and deanonymization."""

from pii_airlock.core.anonymizer import (
    Anonymizer,
    AnonymizationResult,
    get_shared_analyzer,
    reset_shared_analyzer,
)
from pii_airlock.core.deanonymizer import Deanonymizer, DeanonymizationResult
from pii_airlock.core.mapping import PIIMapping
from pii_airlock.core.counter import PlaceholderCounter

__all__ = [
    "Anonymizer",
    "AnonymizationResult",
    "Deanonymizer",
    "DeanonymizationResult",
    "PIIMapping",
    "PlaceholderCounter",
    "get_shared_analyzer",
    "reset_shared_analyzer",
]
