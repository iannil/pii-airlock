"""
Redis-based storage for PII mappings.

Production-ready storage with automatic TTL expiration.
Supports tenant isolation for multi-tenant deployments.
"""

import json
from typing import Optional

from pii_airlock.core.mapping import PIIMapping


class RedisStore:
    """Redis storage for PII mappings with TTL support.

    This store is designed for production deployments where
    multiple instances need to share mapping state.

    Supports multi-tenant isolation by prefixing keys with tenant_id.

    Example:
        >>> import redis
        >>> client = redis.Redis(host='localhost', port=6379)
        >>> store = RedisStore(client)
        >>> mapping = PIIMapping()
        >>> mapping.add("PERSON", "张三", "<PERSON_1>")
        >>> store.save("request-123", mapping)
        >>> # With tenant isolation
        >>> store.save("request-123", mapping, tenant_id="team-a")
    """

    KEY_PREFIX = "pii_airlock:mapping:"

    def __init__(
        self,
        redis_client,
        default_ttl: int = 300,
    ) -> None:
        """Initialize the Redis store.

        Args:
            redis_client: Redis client instance (redis.Redis or compatible).
            default_ttl: Default time-to-live in seconds (default: 300 = 5 minutes).
        """
        self._client = redis_client
        self.default_ttl = default_ttl

    def _make_key(self, request_id: str, tenant_id: Optional[str] = None) -> str:
        """Generate Redis key for a request ID.

        Args:
            request_id: Unique request identifier.
            tenant_id: Optional tenant ID for multi-tenant isolation.

        Returns:
            Redis key string with tenant prefix if provided.
        """
        if tenant_id:
            return f"{self.KEY_PREFIX}{tenant_id}:{request_id}"
        return f"{self.KEY_PREFIX}{request_id}"

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
        data = mapping.to_json()
        self._client.setex(key, ttl or self.default_ttl, data)

    def get(self, request_id: str, tenant_id: Optional[str] = None) -> Optional[PIIMapping]:
        """Retrieve a mapping by request ID.

        Args:
            request_id: The request identifier.
            tenant_id: Optional tenant ID for multi-tenant isolation.

        Returns:
            The PIIMapping if found, None otherwise.
        """
        key = self._make_key(request_id, tenant_id)
        data = self._client.get(key)

        if data is None:
            return None

        # Handle bytes from Redis
        if isinstance(data, bytes):
            data = data.decode("utf-8")

        return PIIMapping.from_json(data)

    def delete(self, request_id: str, tenant_id: Optional[str] = None) -> bool:
        """Delete a mapping.

        Args:
            request_id: The request identifier.
            tenant_id: Optional tenant ID for multi-tenant isolation.

        Returns:
            True if deleted, False if not found.
        """
        key = self._make_key(request_id, tenant_id)
        return self._client.delete(key) > 0

    def extend_ttl(self, request_id: str, ttl: Optional[int] = None, tenant_id: Optional[str] = None) -> bool:
        """Extend the TTL of a mapping.

        Args:
            request_id: The request identifier.
            ttl: New TTL in seconds.
            tenant_id: Optional tenant ID for multi-tenant isolation.

        Returns:
            True if extended, False if not found.
        """
        key = self._make_key(request_id, tenant_id)
        return self._client.expire(key, ttl or self.default_ttl)

    def exists(self, request_id: str, tenant_id: Optional[str] = None) -> bool:
        """Check if a mapping exists.

        Args:
            request_id: The request identifier.
            tenant_id: Optional tenant ID for multi-tenant isolation.

        Returns:
            True if exists, False otherwise.
        """
        key = self._make_key(request_id, tenant_id)
        return self._client.exists(key) > 0

    def delete_tenant_keys(self, tenant_id: str) -> int:
        """Delete all keys for a specific tenant.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            Number of keys deleted.
        """
        pattern = f"{self.KEY_PREFIX}{tenant_id}:*"
        keys = list(self._client.scan_iter(match=pattern))
        if keys:
            return self._client.delete(*keys)
        return 0
