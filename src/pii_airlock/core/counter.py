"""
Placeholder Counter Management

Manages sequential numbering for type-preserving placeholders.
"""

from threading import Lock
from typing import Optional


class PlaceholderCounter:
    """Thread-safe counter for generating placeholder indices.

    Generates sequential numbers for each entity type,
    ensuring unique placeholders like <PERSON_1>, <PERSON_2>, etc.

    Example:
        >>> counter = PlaceholderCounter()
        >>> counter.next("PERSON")
        1
        >>> counter.next("PERSON")
        2
        >>> counter.next("PHONE")
        1
    """

    def __init__(self) -> None:
        """Initialize the counter."""
        self._counters: dict[str, int] = {}
        self._lock = Lock()

    def next(self, entity_type: str) -> int:
        """Get the next index for an entity type.

        Args:
            entity_type: The PII type (PERSON, PHONE, etc.).

        Returns:
            The next sequential number (1-based).
        """
        with self._lock:
            current = self._counters.get(entity_type, 0)
            self._counters[entity_type] = current + 1
            return current + 1

    def current(self, entity_type: str) -> int:
        """Get the current count for an entity type.

        Args:
            entity_type: The PII type.

        Returns:
            Current count (0 if never used).
        """
        with self._lock:
            return self._counters.get(entity_type, 0)

    def reset(self, entity_type: Optional[str] = None) -> None:
        """Reset counter(s).

        Args:
            entity_type: Specific type to reset, or None to reset all.
        """
        with self._lock:
            if entity_type:
                self._counters[entity_type] = 0
            else:
                self._counters.clear()

    def __repr__(self) -> str:
        """Return string representation."""
        with self._lock:
            return f"PlaceholderCounter({self._counters})"
