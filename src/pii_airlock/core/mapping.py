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

    def __len__(self) -> int:
        """Return total number of mappings."""
        with self._lock:
            return len(self._reverse)

    def __contains__(self, placeholder: str) -> bool:
        """Check if placeholder exists."""
        with self._lock:
            return placeholder in self._reverse

    def __repr__(self) -> str:
        """Return string representation."""
        with self._lock:
            return f"PIIMapping(session_id={self.session_id}, entries={len(self._entries)})"
