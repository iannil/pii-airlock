"""Tests for LLM response caching."""

import time
import pytest

from pii_airlock.cache.llm_cache import (
    LLMCache,
    CacheEntry,
    get_cache_key,
    get_llm_cache,
    reset_llm_cache,
)


class TestGetCacheKey:
    """Tests for get_cache_key function."""

    def test_cache_key_generation(self):
        """Test generating cache key from request parameters."""
        messages = [
            {"role": "user", "content": "Hello <PERSON_1>"},
            {"role": "assistant", "content": "Hi there!"},
        ]

        key1 = get_cache_key(
            tenant_id="tenant-1",
            model="gpt-4",
            anonymized_messages=messages,
            temperature=0.7,
        )

        key2 = get_cache_key(
            tenant_id="tenant-1",
            model="gpt-4",
            anonymized_messages=messages,
            temperature=0.7,
        )

        # Same inputs should produce same key
        assert key1 == key2

        # Different temperature should produce different key
        key3 = get_cache_key(
            tenant_id="tenant-1",
            model="gpt-4",
            anonymized_messages=messages,
            temperature=0.5,
        )

        assert key1 != key3

    def test_cache_key_includes_tenant(self):
        """Test that cache key includes tenant_id."""
        messages = [{"role": "user", "content": "Hello"}]

        key1 = get_cache_key(
            tenant_id="tenant-a",
            model="gpt-4",
            anonymized_messages=messages,
        )

        key2 = get_cache_key(
            tenant_id="tenant-b",
            model="gpt-4",
            anonymized_messages=messages,
        )

        # Different tenants should produce different keys
        assert key1 != key2


class TestCacheEntry:
    """Tests for CacheEntry dataclass."""

    def test_cache_entry_creation(self):
        """Test creating a cache entry."""
        entry = CacheEntry(
            key="test-key",
            tenant_id="tenant-1",
            model="gpt-4",
            response_data={"choices": [{"message": {"content": "Hello"}}]},
            created_at=time.time(),
        )

        assert entry.key == "test-key"
        assert entry.tenant_id == "tenant-1"
        assert entry.model == "gpt-4"
        assert entry.is_expired is False

    def test_cache_entry_expiration(self):
        """Test cache entry expiration."""
        # Non-expiring entry
        entry_no_expiry = CacheEntry(
            key="no-expiry",
            tenant_id="tenant-1",
            model="gpt-4",
            response_data={},
            expires_at=None,
        )
        assert entry_no_expiry.is_expired is False

        # Expired entry
        entry_expired = CacheEntry(
            key="expired",
            tenant_id="tenant-1",
            model="gpt-4",
            response_data={},
            expires_at=time.time() - 100,
        )
        assert entry_expired.is_expired is True

        # Not yet expired
        entry_valid = CacheEntry(
            key="valid",
            tenant_id="tenant-1",
            model="gpt-4",
            response_data={},
            expires_at=time.time() + 100,
        )
        assert entry_valid.is_expired is False

    def test_cache_entry_age(self):
        """Test cache entry age calculation."""
        created = time.time() - 10  # Created 10 seconds ago

        entry = CacheEntry(
            key="test",
            tenant_id="tenant-1",
            model="gpt-4",
            response_data={},
            created_at=created,
        )

        age = entry.age_seconds
        assert age >= 10
        assert age < 11  # Should be close to 10 seconds


class TestLLMCache:
    """Tests for LLMCache."""

    def setup_method(self):
        """Reset cache before each test."""
        reset_llm_cache()

    def test_cache_put_and_get(self):
        """Test storing and retrieving cache entries."""
        cache = LLMCache(default_ttl=3600, max_size=100)

        response_data = {
            "id": "chatcmpl-123",
            "choices": [{"message": {"content": "Hello!"}}],
        }

        cache.put(
            key="test-key",
            response_data=response_data,
            tenant_id="tenant-1",
            model="gpt-4",
        )

        entry = cache.get("test-key", tenant_id="tenant-1")
        assert entry is not None
        assert entry.response_data == response_data
        assert entry.hit_count == 1

    def test_cache_miss(self):
        """Test cache miss scenario."""
        cache = LLMCache()

        entry = cache.get("nonexistent", tenant_id="tenant-1")
        assert entry is None

    def test_cache_tenant_isolation(self):
        """Test that cache is isolated by tenant."""
        cache = LLMCache()

        response_a = {"response": "A"}
        response_b = {"response": "B"}

        cache.put("key", response_a, "tenant-a", "gpt-4")
        cache.put("key", response_b, "tenant-b", "gpt-4")

        # Each tenant should get their own response
        entry_a = cache.get("key", "tenant-a")
        entry_b = cache.get("key", "tenant-b")

        assert entry_a.response_data == response_a
        assert entry_b.response_data == response_b

    def test_cache_tenant_validation(self):
        """Test that cache validates tenant on retrieval."""
        cache = LLMCache()

        cache.put("key", {"data": "value"}, "tenant-a", "gpt-4")

        # Correct tenant - should succeed
        entry = cache.get("key", "tenant-a")
        assert entry is not None

        # Wrong tenant - should fail
        entry = cache.get("key", "tenant-b")
        assert entry is None

    def test_cache_expiration(self):
        """Test cache entry expiration."""
        cache = LLMCache(default_ttl=0)  # Immediate expiration

        cache.put("key", {"data": "value"}, "tenant-1", "gpt-4")

        # Should expire immediately
        entry = cache.get("key", "tenant-1")
        assert entry is None

    def test_cache_max_size_eviction(self):
        """Test that cache evicts oldest entries when full."""
        cache = LLMCache(max_size=3)

        cache.put("key1", {"d": 1}, "tenant", "gpt-4")
        cache.put("key2", {"d": 2}, "tenant", "gpt-4")
        cache.put("key3", {"d": 3}, "tenant", "gpt-4")

        # All should fit
        assert cache.get("key1", "tenant") is not None

        # Adding one more should evict key1
        cache.put("key4", {"d": 4}, "tenant", "gpt-4")

        assert cache.get("key1", "tenant") is None
        assert cache.get("key2", "tenant") is not None
        assert cache.get("key3", "tenant") is not None
        assert cache.get("key4", "tenant") is not None

    def test_cache_hit_count_increments(self):
        """Test that hit count increments on each retrieval."""
        cache = LLMCache()

        cache.put("key", {"data": "value"}, "tenant-1", "gpt-4")

        cache.get("key", "tenant-1")
        cache.get("key", "tenant-1")
        cache.get("key", "tenant-1")

        entry = cache.get("key", "tenant-1")
        assert entry.hit_count == 4

    def test_cache_invalidate_tenant(self):
        """Test invalidating all cache entries for a tenant."""
        cache = LLMCache()

        cache.put("key1", {"d": 1}, "tenant-a", "gpt-4")
        cache.put("key2", {"d": 2}, "tenant-a", "gpt-4")
        cache.put("key3", {"d": 3}, "tenant-b", "gpt-4")

        # Invalidate tenant-a
        count = cache.invalidate_tenant("tenant-a")
        assert count == 2

        # Tenant-a entries should be gone
        assert cache.get("key1", "tenant-a") is None
        assert cache.get("key2", "tenant-a") is None

        # Tenant-b entry should remain
        assert cache.get("key3", "tenant-b") is not None

    def test_cache_delete(self):
        """Test deleting a specific cache entry."""
        cache = LLMCache()

        cache.put("key", {"data": "value"}, "tenant-1", "gpt-4")

        # Verify it exists
        assert cache.get("key", "tenant-1") is not None

        # Delete it (need to provide tenant_id for proper isolation)
        success = cache.delete("key", "tenant-1")
        assert success is True

        # Verify it's gone
        assert cache.get("key", "tenant-1") is None

    def test_cache_stats(self):
        """Test getting cache statistics."""
        cache = LLMCache()

        cache.put("key1", {"d": 1}, "tenant-1", "gpt-4")
        cache.put("key2", {"d": 2}, "tenant-1", "gpt-4")
        cache.get("key1", "tenant-1")  # One hit

        stats = cache.get_stats("tenant-1")

        assert stats["entry_count"] == 2
        assert stats["total_hits"] == 1

    def test_cache_cleanup_expired(self):
        """Test cleanup of expired entries."""
        cache = LLMCache(default_ttl=0, max_size=100)

        cache.put("key1", {"d": 1}, "tenant-1", "gpt-4")
        cache.put("key2", {"d": 2}, "tenant-1", "gpt-4")

        # Both should be expired
        removed = cache.cleanup_expired()
        assert removed == 2

        # Stats should show no entries
        stats = cache.get_stats("tenant-1")
        assert stats["entry_count"] == 0


class TestGlobalLLMCache:
    """Tests for global LLM cache functions."""

    def setup_method(self):
        """Reset cache before each test."""
        reset_llm_cache()

    def test_get_llm_cache_singleton(self):
        """Test that get_llm_cache returns same instance."""
        cache1 = get_llm_cache()
        cache2 = get_llm_cache()

        assert cache1 is cache2
