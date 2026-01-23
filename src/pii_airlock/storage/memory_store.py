"""
Memory-based storage for PII mappings.

Used for development and testing without Redis dependency.
Supports tenant isolation for multi-tenant deployments.
"""

import os
import threading
import time
from typing import Optional

from pii_airlock.core.mapping import PIIMapping
from pii_airlock.metrics.collectors import MAPPING_STORE_SIZE, MAPPING_STORE_EXPIRED

# SEC-005 FIX: Default tenant ID for single-tenant mode
# This ensures all mappings have a namespace prefix to avoid collisions
DEFAULT_STORAGE_TENANT = os.getenv("PII_AIRLOCK_DEFAULT_TENANT", "_default_")


class MemoryStore:
    """In-memory storage for PII mappings with TTL support.

    This store is useful for development, testing, and single-instance
    deployments where Redis is not available.

    Features:
    - Thread-safe operations
    - Automatic TTL expiration
    - Optional background cleanup thread
    - Prometheus metrics for monitoring
    - Tenant isolation for multi-tenant deployments

    Example:
        >>> store = MemoryStore(default_ttl=300)
        >>> mapping = PIIMapping()
        >>> mapping.add("PERSON", "张三", "<PERSON_1>")
        >>> store.save("request-123", mapping)
        >>> retrieved = store.get("request-123")
        >>> # With tenant isolation
        >>> store.save("request-123", mapping, tenant_id="team-a")
    """

    def __init__(
        self,
        default_ttl: int = 300,
        cleanup_interval: int = 60,
        enable_background_cleanup: bool = True,
    ) -> None:
        """Initialize the memory store.

        Args:
            default_ttl: Default time-to-live in seconds (default: 300 = 5 minutes).
            cleanup_interval: Interval between background cleanup runs in seconds (default: 60).
            enable_background_cleanup: Whether to start background cleanup thread (default: True).
        """
        self.default_ttl = default_ttl
        self._cleanup_interval = cleanup_interval
        self._store: dict[str, tuple[PIIMapping, float]] = {}
        self._lock = threading.RLock()

        # Background cleanup
        self._shutdown_event = threading.Event()
        self._cleanup_thread: Optional[threading.Thread] = None

        if enable_background_cleanup:
            self._start_background_cleanup()

    def _start_background_cleanup(self) -> None:
        """Start the background cleanup thread."""
        self._cleanup_thread = threading.Thread(
            target=self._background_cleanup_loop,
            daemon=True,
            name="MemoryStore-cleanup",
        )
        self._cleanup_thread.start()

    def _background_cleanup_loop(self) -> None:
        """Background thread that periodically cleans up expired mappings."""
        while not self._shutdown_event.is_set():
            # Wait for the cleanup interval or shutdown signal
            if self._shutdown_event.wait(timeout=self._cleanup_interval):
                # Shutdown was signaled
                break

            # Run cleanup
            removed = self.cleanup_expired()

            # Update metrics
            with self._lock:
                MAPPING_STORE_SIZE.set(len(self._store))

    def shutdown(self) -> None:
        """Shutdown the background cleanup thread gracefully.

        This method signals the background thread to stop and waits for it
        to finish. Call this when shutting down the application.
        """
        self._shutdown_event.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5.0)

    def _make_key(self, request_id: str, tenant_id: Optional[str] = None) -> str:
        """Generate storage key for a request ID.

        SEC-005 FIX: Always use tenant prefix for namespace isolation.
        Uses DEFAULT_STORAGE_TENANT when no tenant_id is provided.

        Args:
            request_id: Unique request identifier.
            tenant_id: Optional tenant ID for multi-tenant isolation.

        Returns:
            Storage key string with tenant prefix.
        """
        effective_tenant = tenant_id or DEFAULT_STORAGE_TENANT
        return f"{effective_tenant}:{request_id}"

    def save(
        self,
        request_id: str,
        mapping: PIIMapping,
        ttl: Optional[int] = None,
        tenant_id: Optional[str] = None,
    ) -> None:
        """Save a mapping with TTL.

        Args:
            request_id: Unique identifier for the request.
            mapping: The PIIMapping to store.
            ttl: Optional TTL override in seconds.
            tenant_id: Optional tenant ID for multi-tenant isolation.
        """
        key = self._make_key(request_id, tenant_id)
        expiry = time.time() + (ttl or self.default_ttl)
        with self._lock:
            self._store[key] = (mapping, expiry)
            MAPPING_STORE_SIZE.set(len(self._store))

    def get(self, request_id: str, tenant_id: Optional[str] = None) -> Optional[PIIMapping]:
        """Retrieve a mapping by request ID.

        Args:
            request_id: The request identifier.
            tenant_id: Optional tenant ID for multi-tenant isolation.

        Returns:
            The PIIMapping if found and not expired, None otherwise.
        """
        key = self._make_key(request_id, tenant_id)
        with self._lock:
            if key not in self._store:
                return None

            mapping, expiry = self._store[key]

            if time.time() > expiry:
                del self._store[key]
                MAPPING_STORE_SIZE.set(len(self._store))
                MAPPING_STORE_EXPIRED.inc()
                return None

            return mapping

    def delete(self, request_id: str, tenant_id: Optional[str] = None) -> bool:
        """Delete a mapping.

        Args:
            request_id: The request identifier.
            tenant_id: Optional tenant ID for multi-tenant isolation.

        Returns:
            True if deleted, False if not found.
        """
        key = self._make_key(request_id, tenant_id)
        with self._lock:
            if key in self._store:
                del self._store[key]
                MAPPING_STORE_SIZE.set(len(self._store))
                return True
            return False

    def extend_ttl(
        self,
        request_id: str,
        ttl: Optional[int] = None,
        tenant_id: Optional[str] = None,
    ) -> bool:
        """Extend the TTL of an existing mapping.

        SEC-008 FIX: Allow extending TTL for long-running streaming requests
        to prevent mapping expiration during stream processing.

        Args:
            request_id: The request identifier.
            ttl: New TTL in seconds. If None, uses default_ttl.
            tenant_id: Optional tenant ID for multi-tenant isolation.

        Returns:
            True if TTL was extended, False if mapping not found or expired.
        """
        key = self._make_key(request_id, tenant_id)
        with self._lock:
            if key not in self._store:
                return False

            mapping, expiry = self._store[key]

            # Check if already expired
            if time.time() > expiry:
                del self._store[key]
                MAPPING_STORE_SIZE.set(len(self._store))
                MAPPING_STORE_EXPIRED.inc()
                return False

            # Extend TTL
            new_expiry = time.time() + (ttl or self.default_ttl)
            self._store[key] = (mapping, new_expiry)
            return True

    def delete_tenant_keys(self, tenant_id: str) -> int:
        """Delete all keys for a specific tenant.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            Number of keys deleted.
        """
        prefix = f"{tenant_id}:"
        count = 0
        with self._lock:
            keys_to_delete = [k for k in self._store if k.startswith(prefix)]
            for key in keys_to_delete:
                del self._store[key]
                count += 1
            if count:
                MAPPING_STORE_SIZE.set(len(self._store))
        return count

    def cleanup_expired(self) -> int:
        """Remove all expired mappings.

        Returns:
            Number of mappings removed.
        """
        now = time.time()
        removed = 0

        with self._lock:
            expired_keys = [
                key for key, (_, expiry) in self._store.items() if now > expiry
            ]
            for key in expired_keys:
                del self._store[key]
                removed += 1

            if removed > 0:
                MAPPING_STORE_SIZE.set(len(self._store))
                MAPPING_STORE_EXPIRED.inc(removed)

        return removed

    def clear(self) -> None:
        """Clear all mappings."""
        with self._lock:
            self._store.clear()
            MAPPING_STORE_SIZE.set(0)

    def __len__(self) -> int:
        """Return number of stored mappings (including expired)."""
        with self._lock:
            return len(self._store)

    def __del__(self) -> None:
        """Cleanup on garbage collection."""
        self.shutdown()
