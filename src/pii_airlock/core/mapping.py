"""
PII Mapping Manager

Manages bidirectional mappings between original PII values and placeholders.
Designed for thread-safe operation and easy serialization.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import threading
import json


@dataclass
class MappingEntry:
    """A single mapping entry."""

    entity_type: str
    original_value: str
    placeholder: str
    created_at: datetime = field(default_factory=datetime.now)
    strategy: Optional[str] = None  # "placeholder", "hash", "synthetic", etc.


@dataclass
class SyntheticMapping:
    """A synthetic data mapping entry.

    Maps synthetic values back to original values for deanonymization.
    Used with the "synthetic" anonymization strategy.
    """

    entity_type: str
    original_value: str
    synthetic_value: str
    created_at: datetime = field(default_factory=datetime.now)


class PIIMapping:
    """Bidirectional mapping manager for PII anonymization.

    This class maintains mappings between original PII values and
    their placeholder representations, supporting lookup in both directions.

    Thread Safety:
        This implementation uses locks for thread-safe operation,
        suitable for concurrent request handling.

    Example:
        >>> mapping = PIIMapping()
        >>> mapping.add("PERSON", "张三", "<PERSON_1>")
        >>> mapping.get_original("<PERSON_1>")
        '张三'
        >>> mapping.get_placeholder("PERSON", "张三")
        '<PERSON_1>'

        >>> # Synthetic data mapping
        >>> mapping.add_synthetic("PERSON", "张三", "李四")
        >>> mapping.get_original_from_synthetic("李四")
        '张三'
    """

    def __init__(self, session_id: Optional[str] = None) -> None:
        """Initialize the mapping manager.

        Args:
            session_id: Optional session identifier for isolation.
        """
        self.session_id = session_id
        self._lock = threading.RLock()

        # Forward mapping: {entity_type: {original_value: placeholder}}
        self._forward: dict[str, dict[str, str]] = {}

        # Reverse mapping: {placeholder: original_value}
        self._reverse: dict[str, str] = {}

        # Full entries for metadata
        self._entries: list[MappingEntry] = []

        # Synthetic mappings: {synthetic_value: SyntheticMapping}
        self._synthetic_mappings: dict[str, SyntheticMapping] = {}

        # Reverse synthetic mappings: {original_value: synthetic_value}
        # For quick lookup to avoid generating the same synthetic value twice
        self._synthetic_reverse: dict[str, str] = {}

    def add(
        self,
        entity_type: str,
        original_value: str,
        placeholder: str,
    ) -> None:
        """Add a new mapping entry.

        Args:
            entity_type: The PII type (PERSON, PHONE, etc.).
            original_value: The original PII text.
            placeholder: The placeholder string.
        """
        with self._lock:
            if entity_type not in self._forward:
                self._forward[entity_type] = {}

            self._forward[entity_type][original_value] = placeholder
            self._reverse[placeholder] = original_value
            self._entries.append(
                MappingEntry(
                    entity_type=entity_type,
                    original_value=original_value,
                    placeholder=placeholder,
                )
            )

    def get_placeholder(
        self,
        entity_type: str,
        original_value: str,
    ) -> Optional[str]:
        """Get placeholder for an original value.

        Args:
            entity_type: The PII type.
            original_value: The original text.

        Returns:
            The placeholder string, or None if not found.
        """
        with self._lock:
            return self._forward.get(entity_type, {}).get(original_value)

    def get_original(self, placeholder: str) -> Optional[str]:
        """Get original value for a placeholder.

        Args:
            placeholder: The placeholder string.

        Returns:
            The original PII value, or None if not found.
        """
        with self._lock:
            return self._reverse.get(placeholder)

    def get_all_placeholders(self) -> list[str]:
        """Get all placeholder strings.

        Returns:
            List of all placeholders in this mapping.
        """
        with self._lock:
            return list(self._reverse.keys())

    def get_entries_by_type(self, entity_type: str) -> list[MappingEntry]:
        """Get all entries for a specific entity type.

        Args:
            entity_type: The PII type to filter by.

        Returns:
            List of MappingEntry objects for the given type.
        """
        with self._lock:
            return [e for e in self._entries if e.entity_type == entity_type]

    def to_dict(self) -> dict:
        """Serialize mapping to dictionary.

        Returns:
            Dictionary representation suitable for JSON serialization.
        """
        with self._lock:
            return {
                "session_id": self.session_id,
                "mappings": {
                    entity_type: dict(values)
                    for entity_type, values in self._forward.items()
                },
            }

    @classmethod
    def from_dict(cls, data: dict) -> "PIIMapping":
        """Deserialize mapping from dictionary.

        Args:
            data: Dictionary from to_dict().

        Returns:
            Reconstructed PIIMapping instance.
        """
        mapping = cls(session_id=data.get("session_id"))
        for entity_type, values in data.get("mappings", {}).items():
            for original, placeholder in values.items():
                mapping.add(entity_type, original, placeholder)
        return mapping

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str) -> "PIIMapping":
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def clear(self) -> None:
        """Clear all mappings."""
        with self._lock:
            self._forward.clear()
            self._reverse.clear()
            self._entries.clear()
            self._synthetic_mappings.clear()
            self._synthetic_reverse.clear()

    def __len__(self) -> int:
        """Return total number of mappings."""
        with self._lock:
            return len(self._reverse) + len(self._synthetic_mappings)

    def __contains__(self, placeholder: str) -> bool:
        """Check if placeholder exists."""
        with self._lock:
            return placeholder in self._reverse or placeholder in self._synthetic_mappings

    def __repr__(self) -> str:
        """Return string representation."""
        with self._lock:
            return f"PIIMapping(session_id={self.session_id}, entries={len(self._entries)}, synthetic={len(self._synthetic_mappings)})"

    # Synthetic mapping methods

    def add_synthetic(
        self,
        entity_type: str,
        original_value: str,
        synthetic_value: str,
    ) -> None:
        """Add a synthetic data mapping entry.

        Args:
            entity_type: The PII type (PERSON, PHONE, etc.).
            original_value: The original PII text.
            synthetic_value: The synthetic replacement text.
        """
        with self._lock:
            mapping = SyntheticMapping(
                entity_type=entity_type,
                original_value=original_value,
                synthetic_value=synthetic_value,
            )
            self._synthetic_mappings[synthetic_value] = mapping
            self._synthetic_reverse[original_value] = synthetic_value

    def get_synthetic(self, original_value: str) -> Optional[str]:
        """Get synthetic value for an original value.

        Args:
            original_value: The original PII text.

        Returns:
            The synthetic value, or None if not found.
        """
        with self._lock:
            return self._synthetic_reverse.get(original_value)

    def get_original_from_synthetic(self, synthetic_value: str) -> Optional[str]:
        """Get original value for a synthetic value.

        Args:
            synthetic_value: The synthetic replacement text.

        Returns:
            The original PII value, or None if not found.
        """
        with self._lock:
            mapping = self._synthetic_mappings.get(synthetic_value)
            return mapping.original_value if mapping else None

    def get_synthetic_mapping(self, synthetic_value: str) -> Optional[SyntheticMapping]:
        """Get the full synthetic mapping entry.

        Args:
            synthetic_value: The synthetic replacement text.

        Returns:
            The SyntheticMapping entry, or None if not found.
        """
        with self._lock:
            return self._synthetic_mappings.get(synthetic_value)

    def has_synthetic_mappings(self) -> bool:
        """Check if this mapping has any synthetic entries."""
        with self._lock:
            return len(self._synthetic_mappings) > 0
