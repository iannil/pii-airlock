"""Allowlist recognizer for PII exemption.

This module provides functionality to maintain allowlists of entities
that should NOT be anonymized, such as public figures, common locations,
and well-known organizations.

Allowlists are loaded from text files in the config/allowlists directory.
"""

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional, Set


@dataclass
class AllowlistConfig:
    """Configuration for a single allowlist.

    Attributes:
        name: Unique identifier for the allowlist.
        entity_type: The PII entity type this allowlist applies to.
        entries: Set of allowlisted entries.
        enabled: Whether this allowlist is active.
        case_sensitive: Whether matching is case-sensitive.
    """

    name: str
    entity_type: str
    entries: Set[str] = field(default_factory=set)
    enabled: bool = True
    case_sensitive: bool = False

    def add(self, entry: str) -> None:
        """Add an entry to the allowlist."""
        if self.case_sensitive:
            self.entries.add(entry)
        else:
            self.entries.add(entry.lower())

    def remove(self, entry: str) -> None:
        """Remove an entry from the allowlist."""
        if self.case_sensitive:
            self.entries.discard(entry)
        else:
            self.entries.discard(entry.lower())

    def contains(self, entry: str) -> bool:
        """Check if an entry is in the allowlist."""
        if self.case_sensitive:
            return entry in self.entries
        return entry.lower() in self.entries

    @property
    def entry_count(self) -> int:
        """Get the number of entries in the allowlist."""
        return len(self.entries)

    def load_from_file(self, path: Path | str) -> int:
        """Load entries from a text file.

        Args:
            path: Path to the text file with one entry per line.

        Returns:
            Number of entries loaded.
        """
        path = Path(path)
        if not path.exists():
            return 0

        count = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue
                self.add(line)
                count += 1

        return count


class AllowlistRegistry:
    """Registry for managing multiple allowlists.

    This class manages all allowlists and provides methods to check
    if entities should be exempted from anonymization.
    """

    def __init__(self, allowlists_dir: Optional[Path | str] = None):
        """Initialize the allowlist registry.

        Args:
            allowlists_dir: Directory containing allowlist text files.
        """
        self._allowlists: dict[str, AllowlistConfig] = {}
        self._allowlists_dir = Path(allowlists_dir) if allowlists_dir else None

    def register(self, allowlist: AllowlistConfig) -> None:
        """Register an allowlist."""
        self._allowlists[allowlist.name] = allowlist

    def get(self, name: str) -> Optional[AllowlistConfig]:
        """Get an allowlist by name."""
        return self._allowlists.get(name)

    def is_allowed(
        self, entity_type: str, text: str, default: bool = False
    ) -> bool:
        """Check if an entity should be exempted from anonymization.

        Args:
            entity_type: The PII entity type (e.g., PERSON, LOCATION).
            text: The text to check.
            default: Default value if no matching allowlist is found.

        Returns:
            True if the entity should be exempted (allowlisted), False otherwise.
        """
        # Check entity-type-specific allowlists
        for allowlist in self._allowlists.values():
            if not allowlist.enabled:
                continue
            if allowlist.entity_type == entity_type or allowlist.entity_type == "*":
                if allowlist.contains(text):
                    return True

        return default

    def load_from_directory(self, directory: Path | str) -> int:
        """Load all allowlists from a directory.

        Args:
            directory: Directory containing allowlist text files.

        Returns:
            Number of allowlists loaded.
        """
        directory = Path(directory)
        if not directory.exists():
            return 0

        count = 0
        for txt_file in directory.glob("*.txt"):
            # Create allowlist from filename
            name = txt_file.stem
            entity_type = self._infer_entity_type(name)

            allowlist = AllowlistConfig(
                name=name,
                entity_type=entity_type,
                enabled=True,
                case_sensitive=False,
            )
            entry_count = allowlist.load_from_file(txt_file)

            if entry_count > 0:
                self.register(allowlist)
                count += 1

        return count

    def _infer_entity_type(self, name: str) -> str:
        """Infer entity type from allowlist name."""
        name_lower = name.lower()

        if "person" in name_lower or "figure" in name_lower:
            return "PERSON"
        if "location" in name_lower or "place" in name_lower or "city" in name_lower:
            return "LOCATION"
        if "org" in name_lower or "company" in name_lower:
            return "ORG"
        if "email" in name_lower:
            return "EMAIL_ADDRESS"

        return "*"

    def reload(self) -> int:
        """Reload all allowlists from the configured directory.

        Returns:
            Number of allowlists reloaded.
        """
        self._allowlists.clear()

        if self._allowlists_dir:
            return self.load_from_directory(self._allowlists_dir)

        return 0

    def list_allowlists(self) -> list[dict]:
        """List all registered allowlists with metadata."""
        return [
            {
                "name": alist.name,
                "entity_type": alist.entity_type,
                "enabled": alist.enabled,
                "entry_count": len(alist.entries),
                "case_sensitive": alist.case_sensitive,
            }
            for alist in self._allowlists.values()
        ]


# Global registry instance
_registry: Optional[AllowlistRegistry] = None


def get_allowlist_registry() -> AllowlistRegistry:
    """Get the global allowlist registry instance.

    Creates and initializes the registry on first call.
    """
    global _registry

    if _registry is None:
        # Determine allowlists directory
        project_root = Path(__file__).parent.parent.parent.parent
        default_dir = project_root / "config" / "allowlists"

        # Allow override via environment variable
        env_dir = os.getenv("PII_AIRLOCK_ALLOWLISTS_DIR")

        _registry = AllowlistRegistry(allowlists_dir=env_dir or default_dir)

        # Load allowlists from directory
        if default_dir.exists() or (env_dir and Path(env_dir).exists()):
            _registry.reload()

    return _registry


def is_allowlisted(entity_type: str, text: str, default: bool = False) -> bool:
    """Check if an entity should be exempted from anonymization.

    This is a convenience function that uses the global registry.

    Args:
        entity_type: The PII entity type (e.g., PERSON, LOCATION).
        text: The text to check.
        default: Default value if no matching allowlist is found.

    Returns:
        True if the entity should be exempted, False otherwise.
    """
    registry = get_allowlist_registry()
    return registry.is_allowed(entity_type, text, default=default)


def reload_allowlists() -> int:
    """Reload all allowlists from disk.

    Returns:
        Number of allowlists reloaded.
    """
    registry = get_allowlist_registry()
    return registry.reload()


@lru_cache(maxsize=10000)
def is_public_figure(name: str) -> bool:
    """Check if a name matches a public figure in the allowlist.

    This function is cached for performance.

    Args:
        name: The name to check.

    Returns:
        True if the name is a public figure, False otherwise.
    """
    return is_allowlisted("PERSON", name, default=False)


@lru_cache(maxsize=10000)
def is_common_location(location: str) -> bool:
    """Check if a location is in the common locations allowlist.

    This function is cached for performance.

    Args:
        location: The location to check.

    Returns:
        True if the location is common, False otherwise.
    """
    return is_allowlisted("LOCATION", location, default=False)


def clear_caches() -> None:
    """Clear all allowlist caches."""
    is_public_figure.cache_clear()
    is_common_location.cache_clear()


class AllowlistFilter:
    """Filter for removing allowlisted entities from PII results.

    This class can be used with Presidio's recognizer registry
    to filter out allowlisted entities.
    """

    def __init__(self, registry: Optional[AllowlistRegistry] = None):
        """Initialize the filter.

        Args:
            registry: Allowlist registry to use. If None, uses global registry.
        """
        self._registry = registry or get_allowlist_registry()

    def should_filter(self, entity_type: str, text: str) -> bool:
        """Check if an entity should be filtered (exempted from anonymization).

        Args:
            entity_type: The PII entity type.
            text: The entity text.

        Returns:
            True if the entity should be filtered, False otherwise.
        """
        return self._registry.is_allowed(entity_type, text, default=False)

    def filter_entities(
        self, entities: list[dict]
    ) -> list[dict]:
        """Filter a list of recognized entities.

        Args:
            entities: List of entity dicts with 'entity_type' and 'text' keys.

        Returns:
            Filtered list with allowlisted entities removed.
        """
        return [
            entity
            for entity in entities
            if not self.should_filter(
                entity.get("entity_type", ""), entity.get("text", "")
            )
        ]


def get_allowlist_filter() -> AllowlistFilter:
    """Get a global allowlist filter instance."""
    return AllowlistFilter()
