"""API key management for PII-AIRLOCK.

This module provides secure API key generation, validation, and lifecycle management.

API Key Format:
    piiak_{tenant}_{random}

    Example: piiak_team-a_a1b2c3d4e5f6g7h8

Key States:
    - Active: Key is valid for authentication
    - Disabled: Key is temporarily disabled
    - Revoked: Key is permanently revoked
"""

import secrets
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, List
import threading

from pii_airlock.logging.setup import get_logger

logger = get_logger(__name__)


class KeyStatus(str, Enum):
    """API key status values."""

    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"


@dataclass
class APIKey:
    """An API key for authentication.

    Attributes:
        key_id: Unique key identifier (short hash).
        key_prefix: First few characters for identification.
        tenant_id: Associated tenant ID.
        name: Human-readable name for the key.
        status: Current status.
        created_at: Creation timestamp.
        last_used: Last usage timestamp.
        expires_at: Optional expiration timestamp.
        scopes: List of permission scopes.
    """

    key_id: str
    key_prefix: str
    tenant_id: str
    name: str
    status: KeyStatus = KeyStatus.ACTIVE
    created_at: float = field(default_factory=time.time)
    last_used: Optional[float] = None
    expires_at: Optional[float] = None
    scopes: List[str] = field(default_factory=list)
    # Rate limit override (e.g., "1000/hour")
    rate_limit: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        """Check if key is valid and not expired."""
        if self.status != KeyStatus.ACTIVE:
            return False
        if self.expires_at and time.time() > self.expires_at:
            return False
        return True

    @property
    def created_at_datetime(self) -> datetime:
        """Get creation time as datetime."""
        return datetime.fromtimestamp(self.created_at)

    @property
    def expires_at_datetime(self) -> Optional[datetime]:
        """Get expiration time as datetime."""
        if self.expires_at:
            return datetime.fromtimestamp(self.expires_at)
        return None


class APIKeyStore:
    """Storage backend for API keys.

    Thread-safe in-memory storage. For production, use Redis-based storage.
    """

    def __init__(self) -> None:
        """Initialize the API key store."""
        self._keys: Dict[str, APIKey] = {}  # key_id -> APIKey
        self._full_keys: Dict[str, APIKey] = {}  # full_key_hash -> APIKey
        self._tenant_keys: Dict[str, List[str]] = {}  # tenant_id -> list[key_id]
        self._lock = threading.RLock()

    def create_key(
        self,
        tenant_id: str,
        name: str,
        scopes: Optional[List[str]] = None,
        expires_in_days: Optional[int] = None,
        rate_limit: Optional[str] = None,
    ) -> tuple[str, APIKey]:
        """Create a new API key.

        Args:
            tenant_id: Associated tenant ID.
            name: Human-readable name.
            scopes: Permission scopes (default: ["llm:use", "metrics:view"]).
            expires_in_days: Days until expiration (None = never expires).
            rate_limit: Rate limit override.

        Returns:
            Tuple of (full_key, APIKey metadata).
        """
        # Generate random key
        random_part = secrets.token_urlsafe(16)
        full_key = f"piiak_{tenant_id}_{random_part}"

        # Create key metadata
        key_id = hashlib.sha256(full_key.encode()).hexdigest()[:16]
        key_prefix = full_key[:12]  # First 12 chars for display

        now = time.time()
        expires_at = None
        if expires_in_days:
            expires_at = now + (expires_in_days * 86400)

        api_key = APIKey(
            key_id=key_id,
            key_prefix=key_prefix,
            tenant_id=tenant_id,
            name=name,
            status=KeyStatus.ACTIVE,
            created_at=now,
            expires_at=expires_at,
            scopes=scopes or ["llm:use", "metrics:view"],
            rate_limit=rate_limit,
        )

        with self._lock:
            self._keys[key_id] = api_key
            # Store hash of full key for validation
            key_hash = hashlib.sha256(full_key.encode()).hexdigest()
            self._full_keys[key_hash] = api_key

            # Update tenant index
            if tenant_id not in self._tenant_keys:
                self._tenant_keys[tenant_id] = []
            self._tenant_keys[tenant_id].append(key_id)

        logger.info(
            "API key created",
            extra={
                "event": "api_key_created",
                "key_id": key_id,
                "tenant_id": tenant_id,
                "name": name,
            },
        )

        return full_key, api_key

    def get_key(self, key_id: str) -> Optional[APIKey]:
        """Get key by ID.

        Args:
            key_id: The key identifier.

        Returns:
            APIKey if found, None otherwise.
        """
        with self._lock:
            return self._keys.get(key_id)

    def validate_key(self, full_key: str) -> Optional[APIKey]:
        """Validate an API key.

        Args:
            full_key: The full API key string.

        Returns:
            APIKey if valid, None otherwise.
        """
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()

        with self._lock:
            api_key = self._full_keys.get(key_hash)

        if not api_key:
            return None

        if not api_key.is_valid:
            logger.warning(
                "Invalid API key used",
                extra={
                    "event": "api_key_invalid",
                    "key_id": api_key.key_id,
                    "status": api_key.status,
                },
            )
            return None

        # Update last used
        with self._lock:
            api_key.last_used = time.time()

        return api_key

    def revoke_key(self, key_id: str) -> bool:
        """Revoke an API key.

        Args:
            key_id: The key identifier.

        Returns:
            True if revoked, False if not found.
        """
        with self._lock:
            api_key = self._keys.get(key_id)
            if not api_key:
                return False

            api_key.status = KeyStatus.REVOKED

            logger.info(
                "API key revoked",
                extra={
                    "event": "api_key_revoked",
                    "key_id": key_id,
                    "tenant_id": api_key.tenant_id,
                },
            )

            return True

    def disable_key(self, key_id: str) -> bool:
        """Disable an API key temporarily.

        Args:
            key_id: The key identifier.

        Returns:
            True if disabled, False if not found.
        """
        with self._lock:
            api_key = self._keys.get(key_id)
            if not api_key:
                return False

            api_key.status = KeyStatus.DISABLED

            logger.info(
                "API key disabled",
                extra={
                    "event": "api_key_disabled",
                    "key_id": key_id,
                    "tenant_id": api_key.tenant_id,
                },
            )

            return True

    def enable_key(self, key_id: str) -> bool:
        """Enable a previously disabled API key.

        Args:
            key_id: The key identifier.

        Returns:
            True if enabled, False if not found.
        """
        with self._lock:
            api_key = self._keys.get(key_id)
            if not api_key:
                return False

            api_key.status = KeyStatus.ACTIVE

            logger.info(
                "API key enabled",
                extra={
                    "event": "api_key_enabled",
                    "key_id": key_id,
                    "tenant_id": api_key.tenant_id,
                },
            )

            return True

    def list_keys(
        self,
        tenant_id: Optional[str] = None,
        status: Optional[KeyStatus] = None,
    ) -> List[APIKey]:
        """List API keys, optionally filtered.

        Args:
            tenant_id: Filter by tenant ID.
            status: Filter by status.

        Returns:
            List of API keys.
        """
        with self._lock:
            keys = list(self._keys.values())

            if tenant_id:
                keys = [k for k in keys if k.tenant_id == tenant_id]

            if status:
                keys = [k for k in keys if k.status == status]

            return keys

    def delete_key(self, key_id: str) -> bool:
        """Permanently delete an API key.

        Args:
            key_id: The key identifier.

        Returns:
            True if deleted, False if not found.
        """
        with self._lock:
            api_key = self._keys.pop(key_id, None)
            if not api_key:
                return False

            # Remove from full keys index
            # We need to find and remove the hash
            to_remove = [
                hash_key
                for hash_key, key in self._full_keys.items()
                if key.key_id == key_id
            ]
            for hash_key in to_remove:
                del self._full_keys[hash_key]

            # Update tenant index
            if api_key.tenant_id in self._tenant_keys:
                self._tenant_keys[api_key.tenant_id].remove(key_id)

            logger.info(
                "API key deleted",
                extra={
                    "event": "api_key_deleted",
                    "key_id": key_id,
                    "tenant_id": api_key.tenant_id,
                },
            )

            return True


# Global API key store (singleton-like)
_api_key_store: Optional[APIKeyStore] = None
_store_lock = threading.Lock()


def get_api_key_store() -> APIKeyStore:
    """Get the global API key store.

    Returns:
        Global APIKeyStore instance.
    """
    global _api_key_store

    with _store_lock:
        if _api_key_store is None:
            _api_key_store = APIKeyStore()

    return _api_key_store


def reset_api_key_store() -> None:
    """Reset the global API key store (for testing)."""
    global _api_key_store
    with _store_lock:
        _api_key_store = None


def validate_api_key(api_key: str) -> Optional[APIKey]:
    """Validate an API key using the global store.

    Args:
        api_key: The full API key string.

    Returns:
        APIKey if valid, None otherwise.
    """
    store = get_api_key_store()
    return store.validate_key(api_key)
