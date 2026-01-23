"""
PII-AIRLOCK: Make Public LLMs Private

A middleware/reverse proxy for protecting sensitive personal information
when using public LLM APIs.
"""

# DOC-001 FIX: Version unified with pyproject.toml
__version__ = "1.1.0"

from pii_airlock.core.anonymizer import Anonymizer, AnonymizationResult
from pii_airlock.core.deanonymizer import Deanonymizer, DeanonymizationResult
from pii_airlock.core.mapping import PIIMapping

__all__ = [
    "Anonymizer",
    "AnonymizationResult",
    "Deanonymizer",
    "DeanonymizationResult",
    "PIIMapping",
]
