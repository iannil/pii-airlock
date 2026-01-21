"""
Redis-based storage for PII mappings.

Production-ready storage with automatic TTL expiration.
"""

import json
from typing import Optional

from pii_airlock.core.mapping import PIIMapping


class RedisStore:
    """Redis storage for PII mappings with TTL support.

    This store is designed for production deployments where
    multiple instances need to share mapping state.

    Example:
        >>> import redis
        >>> client = redis.Redis(host='localhost', port=6379)
        >>> store = RedisStore(client)
        >>> mapping = PIIMapping()
        >>> mapping.add("PERSON", "张三", "<PERSON_1>")
        >>> store.save("request-123", mapping)
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

    def _make_key(self, request_id: str) -> str:
        """Generate Redis key for a request ID."""
        return f"{self.KEY_PREFIX}{request_id}"

    def save(
        self,
        request_id: str,
        mapping: PIIMapping,
        ttl: Optional[int] = None,
    ) -> None:
        """Save a mapping with TTL.

        Args:
            request_id: Unique identifier for the request.
            mapping: The PIIMapping to store.
            ttl: Optional TTL override in seconds.
        """
        key = self._make_key(request_id)
        data = mapping.to_json()
        self._client.setex(key, ttl or self.default_ttl, data)

    def get(self, request_id: str) -> Optional[PIIMapping]:
        """Retrieve a mapping by request ID.

        Args:
            request_id: The request identifier.

        Returns:
            The PIIMapping if found, None otherwise.
        """
        key = self._make_key(request_id)
        data = self._client.get(key)

        if data is None:
            return None

        # Handle bytes from Redis
        if isinstance(data, bytes):
            data = data.decode("utf-8")

        return PIIMapping.from_json(data)

    def delete(self, request_id: str) -> bool:
        """Delete a mapping.

        Args:
            request_id: The request identifier.

        Returns:
            True if deleted, False if not found.
        """
        key = self._make_key(request_id)
        return self._client.delete(key) > 0

    def extend_ttl(self, request_id: str, ttl: Optional[int] = None) -> bool:
        """Extend the TTL of a mapping.

        Args:
            request_id: The request identifier.
            ttl: New TTL in seconds.

        Returns:
            True if extended, False if not found.
        """
        key = self._make_key(request_id)
        return self._client.expire(key, ttl or self.default_ttl)

    def exists(self, request_id: str) -> bool:
        """Check if a mapping exists.

        Args:
            request_id: The request identifier.

        Returns:
            True if exists, False otherwise.
        """
        key = self._make_key(request_id)
        return self._client.exists(key) > 0
