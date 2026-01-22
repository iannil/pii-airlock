"""LLM response caching for PII-AIRLOCK.

This module provides caching of LLM responses to reduce:
- API costs (fewer calls to upstream LLM)
- Latency (cached responses are instant)
- Rate limiting impact (fewer upstream requests)

Cache Key:
    Based on SHA256 hash of:
    - Model name
    - Anonymized messages content
    - Temperature and other key parameters

Cache Strategy:
    - Cache is applied AFTER anonymization
    - Cache hit returns cached deanonymized response
    - Cache miss stores response after deanonymization
"""

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, AsyncIterator
import threading

from pii_airlock.logging.setup import get_logger
from pii_airlock.metrics.collectors import Counter, Gauge, Histogram

logger = get_logger(__name__)

# Cache metrics
CACHE_HITS = Counter(
    "pii_airlock_cache_hits_total",
    "Total cache hits",
    ["tenant_id", "model"],
)

CACHE_MISSES = Counter(
    "pii_airlock_cache_misses_total",
    "Total cache misses",
    ["tenant_id", "model"],
)

CACHE_SIZE = Gauge(
    "pii_airlock_cache_size",
    "Number of cached responses",
    ["tenant_id"],
)

CACHE_LATENCY = Histogram(
    "pii_airlock_cache_lookup_duration_seconds",
    "Cache lookup latency",
    ["tenant_id"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
)


@dataclass
class CacheEntry:
    """A cached LLM response.

    Attributes:
        key: Cache key.
        tenant_id: Tenant identifier.
        model: Model name.
        response_data: Cached response JSON.
        created_at: Creation timestamp.
        expires_at: Expiration timestamp.
        hit_count: Number of times this entry was accessed.
        size_bytes: Size of cached data in bytes.
    """

    key: str
    tenant_id: str
    model: str
    response_data: Dict[str, Any]
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    hit_count: int = 0
    size_bytes: int = 0

    @property
    def is_expired(self) -> bool:
        """Check if entry has expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    @property
    def age_seconds(self) -> float:
        """Get age of entry in seconds."""
        return time.time() - self.created_at


def get_cache_key(
    tenant_id: str,
    model: str,
    anonymized_messages: list[Dict[str, Any]],
    temperature: Optional[float] = None,
    **kwargs,
) -> str:
    """Generate cache key for a request.

    Args:
        tenant_id: Tenant identifier.
        model: Model name.
        anonymized_messages: List of anonymized message dicts.
        temperature: Temperature parameter.
        **kwargs: Other parameters to include in key.

    Returns:
        SHA256 hash string for cache key.
    """
    # Build canonical representation
    key_data = {
        "tenant": tenant_id,
        "model": model,
        "messages": anonymized_messages,
        "temperature": temperature,
    }

    # Add significant parameters
    for param in ["top_p", "max_tokens", "presence_penalty", "frequency_penalty"]:
        if param in kwargs and kwargs[param] is not None:
            key_data[param] = kwargs[param]

    # Serialize to JSON with sorted keys
    key_json = json.dumps(key_data, sort_keys=True, ensure_ascii=False)

    # Hash
    return hashlib.sha256(key_json.encode()).hexdigest()


class LLMCache:
    """Cache for LLM responses.

    Thread-safe in-memory storage with TTL support.
    For production, use Redis-based implementation.

    Example:
        >>> cache = LLMCache(default_ttl=3600)
        >>> cache.put("key123", response_data, "tenant-a", "gpt-4")
        >>> entry = cache.get("key123")
        >>> if entry:
        ...     return entry.response_data
    """

    def __init__(
        self,
        default_ttl: int = 3600,
        max_size: int = 10000,
        cleanup_interval: int = 300,
    ) -> None:
        """Initialize the cache.

        Args:
            default_ttl: Default TTL in seconds (default: 1 hour).
            max_size: Maximum number of cached entries.
            cleanup_interval: Seconds between cleanup runs.
        """
        self.default_ttl = default_ttl
        self.max_size = max_size
        self._cleanup_interval = cleanup_interval
        self._store: Dict[str, CacheEntry] = {}
        self._tenant_index: Dict[str, set] = {}  # tenant_id -> set of keys
        self._lock = threading.RLock()
        self._shutdown = False

        # Start cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="LLMCache-cleanup",
        )
        self._cleanup_thread.start()

        logger.info(
            "LLM cache initialized",
            extra={
                "event": "cache_initialized",
                "default_ttl": default_ttl,
                "max_size": max_size,
            },
        )

    def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while not self._shutdown:
            time.sleep(self._cleanup_interval)
            self.cleanup_expired()

    def _make_internal_key(self, key: str, tenant_id: str) -> str:
        """Create internal storage key including tenant.

        This ensures tenant isolation in the cache store.

        Args:
            key: External cache key.
            tenant_id: Tenant identifier.

        Returns:
            Internal storage key.
        """
        return f"{tenant_id}:{key}"

    def get(self, key: str, tenant_id: Optional[str] = None) -> Optional[CacheEntry]:
        """Get cached entry by key.

        Args:
            key: Cache key.
            tenant_id: Optional tenant ID for validation.

        Returns:
            CacheEntry if found and valid, None otherwise.
        """
        start_time = time.time()

        # Build internal key - tenant_id is required for proper isolation
        internal_key = self._make_internal_key(key, tenant_id or "default")

        with self._lock:
            entry = self._store.get(internal_key)

            if entry is None:
                CACHE_MISSES.labels(
                    tenant_id=tenant_id or "unknown",
                    model="unknown",
                ).inc()
                return None

            # Check expiration
            if entry.is_expired:
                # Remove expired entry
                del self._store[internal_key]
                self._remove_from_tenant_index(entry.tenant_id, internal_key)
                CACHE_MISSES.labels(
                    tenant_id=tenant_id or entry.tenant_id,
                    model=entry.model,
                ).inc()
                return None

            # Validate tenant
            if tenant_id and entry.tenant_id != tenant_id:
                CACHE_MISSES.labels(
                    tenant_id=tenant_id,
                    model="unknown",
                ).inc()
                return None

            # Update hit count
            entry.hit_count += 1

            # Record metrics
            duration = time.time() - start_time
            CACHE_HITS.labels(
                tenant_id=entry.tenant_id,
                model=entry.model,
            ).inc()
            CACHE_LATENCY.labels(tenant_id=entry.tenant_id).observe(duration)

            logger.debug(
                "Cache hit",
                extra={
                    "event": "cache_hit",
                    "tenant_id": entry.tenant_id,
                    "model": entry.model,
                    "key": key[:16] + "...",
                    "hit_count": entry.hit_count,
                },
            )

            return entry

    def put(
        self,
        key: str,
        response_data: Dict[str, Any],
        tenant_id: str,
        model: str,
        ttl: Optional[int] = None,
    ) -> CacheEntry:
        """Store response in cache.

        Args:
            key: Cache key.
            response_data: Response JSON to cache.
            tenant_id: Tenant identifier.
            model: Model name.
            ttl: TTL in seconds (uses default if not specified).

        Returns:
            Created CacheEntry.
        """
        # Calculate size
        response_json = json.dumps(response_data, ensure_ascii=False)
        size_bytes = len(response_json.encode())

        # Calculate expiration
        now = time.time()
        effective_ttl = ttl if ttl is not None else self.default_ttl
        expires_at = now + effective_ttl if effective_ttl is not None else None

        # Create internal key with tenant isolation
        internal_key = self._make_internal_key(key, tenant_id)

        entry = CacheEntry(
            key=key,
            tenant_id=tenant_id,
            model=model,
            response_data=response_data,
            created_at=now,
            expires_at=expires_at,
            hit_count=0,
            size_bytes=size_bytes,
        )

        with self._lock:
            # Enforce max size by evicting oldest entries
            while len(self._store) >= self.max_size and internal_key not in self._store:
                # Find oldest entry
                oldest_key = min(
                    self._store.keys(),
                    key=lambda k: self._store[k].created_at,
                )
                oldest = self._store.pop(oldest_key)
                self._remove_from_tenant_index(oldest.tenant_id, oldest_key)

            # Store entry
            self._store[internal_key] = entry

            # Update tenant index
            if tenant_id not in self._tenant_index:
                self._tenant_index[tenant_id] = set()
            self._tenant_index[tenant_id].add(internal_key)

            # Update metrics
            self._update_tenant_metrics()

        logger.debug(
            "Cache entry stored",
            extra={
                "event": "cache_stored",
                "tenant_id": tenant_id,
                "model": model,
                "key": key[:16] + "...",
                "size_bytes": size_bytes,
            },
        )

        return entry

    def delete(self, key: str, tenant_id: Optional[str] = None) -> bool:
        """Delete entry from cache.

        Args:
            key: Cache key.
            tenant_id: Optional tenant ID for key construction.

        Returns:
            True if deleted, False if not found.
        """
        internal_key = self._make_internal_key(key, tenant_id or "default")
        with self._lock:
            entry = self._store.pop(internal_key, None)
            if entry:
                self._remove_from_tenant_index(entry.tenant_id, internal_key)
                self._update_tenant_metrics()
                return True
            return False

    def invalidate_tenant(self, tenant_id: str) -> int:
        """Invalidate all cache entries for a tenant.

        Args:
            tenant_id: Tenant identifier.

        Returns:
            Number of entries invalidated.
        """
        with self._lock:
            keys = self._tenant_index.get(tenant_id, set()).copy()
            count = 0
            for key in keys:
                if key in self._store:
                    del self._store[key]
                    self._tenant_index[tenant_id].discard(key)
                    count += 1

            self._update_tenant_metrics()

            logger.info(
                "Tenant cache invalidated",
                extra={
                    "event": "cache_tenant_invalidated",
                    "tenant_id": tenant_id,
                    "count": count,
                },
            )

            return count

    def cleanup_expired(self) -> int:
        """Remove all expired entries.

        Returns:
            Number of entries removed.
        """
        now = time.time()
        removed = 0

        with self._lock:
            expired_keys = [
                key for key, entry in self._store.items()
                if entry.is_expired
            ]

            for key in expired_keys:
                entry = self._store.pop(key)
                self._remove_from_tenant_index(entry.tenant_id, key)
                removed += 1

            if removed:
                self._update_tenant_metrics()

        return removed

    def get_stats(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Get cache statistics.

        Args:
            tenant_id: Optional tenant ID to filter by.

        Returns:
            Dictionary of cache statistics.
        """
        with self._lock:
            if tenant_id:
                keys = self._tenant_index.get(tenant_id, set())
                entries = [self._store[k] for k in keys if k in self._store]
            else:
                entries = list(self._store.values())

            total_size = sum(e.size_bytes for e in entries)
            total_hits = sum(e.hit_count for e in entries)
            avg_age = (
                sum(e.age_seconds for e in entries) / len(entries)
                if entries else 0
            )

            return {
                "entry_count": len(entries),
                "total_size_bytes": total_size,
                "total_hits": total_hits,
                "avg_age_seconds": avg_age,
                "entries": [
                    {
                        "key": e.key[:16] + "...",
                        "model": e.model,
                        "created_at": e.created_at,
                        "hit_count": e.hit_count,
                        "size_bytes": e.size_bytes,
                    }
                    for e in entries[:10]  # First 10 entries
                ],
            }

    def _remove_from_tenant_index(self, tenant_id: str, key: str) -> None:
        """Remove key from tenant index."""
        if tenant_id in self._tenant_index:
            self._tenant_index[tenant_id].discard(key)
            if not self._tenant_index[tenant_id]:
                del self._tenant_index[tenant_id]

    def _update_tenant_metrics(self) -> None:
        """Update Prometheus metrics for tenant cache sizes."""
        # Clear existing metrics
        for tenant in list(self._tenant_index.keys()):
            CACHE_SIZE.labels(tenant_id=tenant).set(
                len(self._tenant_index.get(tenant, set()))
            )

    def shutdown(self) -> None:
        """Shutdown the cache cleanup thread."""
        self._shutdown = True
        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5.0)

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._store.clear()
            self._tenant_index.clear()

        logger.info(
            "Cache cleared",
            extra={"event": "cache_cleared"},
        )


# Global cache instance (singleton-like)
_cache: Optional[LLMCache] = None
_cache_lock = threading.Lock()


def get_llm_cache() -> LLMCache:
    """Get the global LLM cache instance.

    Returns:
        Global LLMCache instance.
    """
    global _cache

    with _cache_lock:
        if _cache is None:
            import os

            ttl = int(os.getenv("PII_AIRLOCK_CACHE_TTL", "3600"))
            max_size = int(os.getenv("PII_AIRLOCK_CACHE_MAX_SIZE", "10000"))

            # Check if cache is enabled
            enabled = os.getenv("PII_AIRLOCK_CACHE_ENABLED", "false").lower() == "true"

            if enabled:
                _cache = LLMCache(default_ttl=ttl, max_size=max_size)
            else:
                # Create disabled cache (no-op)
                _cache = LLMCache(default_ttl=0, max_size=0)

    return _cache


def reset_llm_cache() -> None:
    """Reset the global LLM cache (for testing)."""
    global _cache
    with _cache_lock:
        if _cache:
            _cache.shutdown()
        _cache = None
