"""Edge case tests for PII-AIRLOCK.

This module contains tests for boundary conditions and edge cases:
- TEST-008: Empty PII mapping handling
- TEST-009: Very long text (>100KB) processing
- TEST-010: Concurrent access to mapping store
- TEST-011: Cache expiration boundary conditions
- TEST-012: Quota threshold edge cases
"""

import time
import threading
import concurrent.futures
import pytest

from pii_airlock.core.mapping import PIIMapping
from pii_airlock.core.anonymizer import Anonymizer
from pii_airlock.core.deanonymizer import Deanonymizer
from pii_airlock.storage.memory_store import MemoryStore
from pii_airlock.cache.llm_cache import LLMCache, reset_llm_cache
from pii_airlock.auth.quota import (
    QuotaStore,
    QuotaConfig,
    QuotaLimit,
    QuotaType,
    QuotaPeriod,
    reset_quota_store,
)


# =============================================================================
# TEST-008: Empty PII Mapping Handling
# =============================================================================

class TestEmptyPIIMapping:
    """Tests for handling empty PII mappings."""

    def test_empty_mapping_creation(self):
        """Test creating an empty mapping."""
        mapping = PIIMapping()
        assert len(mapping) == 0
        assert mapping.get_all_placeholders() == []

    def test_empty_mapping_serialization(self):
        """Test serializing and deserializing empty mapping."""
        mapping = PIIMapping(session_id="test-session")

        # Serialize
        data = mapping.to_dict()
        assert data["session_id"] == "test-session"
        assert data["mappings"] == {}

        # Deserialize
        restored = PIIMapping.from_dict(data)
        assert restored.session_id == "test-session"
        assert len(restored) == 0

    def test_empty_mapping_json(self):
        """Test JSON serialization of empty mapping."""
        mapping = PIIMapping()
        json_str = mapping.to_json()

        restored = PIIMapping.from_json(json_str)
        assert len(restored) == 0

    def test_deanonymize_with_empty_mapping(self):
        """Test deanonymization with empty mapping."""
        deanonymizer = Deanonymizer()
        mapping = PIIMapping()

        text = "Hello <PERSON_1>, your phone is <PHONE_1>"
        result = deanonymizer.deanonymize(text, mapping)

        # Placeholders should remain unchanged
        assert result.text == text
        assert result.replaced_count == 0

    def test_store_empty_mapping(self):
        """Test storing and retrieving empty mapping."""
        store = MemoryStore(default_ttl=300, enable_background_cleanup=False)
        mapping = PIIMapping(session_id="empty-test")

        store.save("request-1", mapping, tenant_id="tenant-1")
        retrieved = store.get("request-1", tenant_id="tenant-1")

        assert retrieved is not None
        assert len(retrieved) == 0
        assert retrieved.session_id == "empty-test"

        store.shutdown()

    def test_anonymize_text_without_pii(self):
        """Test anonymizing text that contains no PII."""
        anonymizer = Anonymizer()

        text = "这是一段没有任何个人信息的普通文本。"
        result = anonymizer.anonymize(text)

        assert result.text == text
        assert len(result.mapping) == 0
        assert len(result.entities) == 0


# =============================================================================
# TEST-009: Very Long Text Processing
# =============================================================================

class TestLongTextProcessing:
    """Tests for processing very long text (>100KB)."""

    def test_long_text_without_pii(self):
        """Test processing long text without PII."""
        anonymizer = Anonymizer()

        # Generate 100KB of text without PII
        base_text = "这是一段普通文本，没有任何敏感信息。" * 100
        long_text = base_text * 50  # Approximately 100KB

        assert len(long_text.encode('utf-8')) > 100000  # > 100KB

        result = anonymizer.anonymize(long_text)

        assert result.text == long_text
        assert len(result.mapping) == 0

    def test_long_text_with_scattered_pii(self):
        """Test processing long text with PII scattered throughout."""
        anonymizer = Anonymizer()
        deanonymizer = Deanonymizer()

        # Create long text with PII at beginning, middle, and end
        filler = "这是普通文本。" * 1000  # ~15KB per block

        long_text = (
            "张三的电话是13800138000。" +
            filler +
            "李四的邮箱是lisi@example.com。" +
            filler +
            "王五的身份证是110101199003077516。"
        )

        assert len(long_text.encode('utf-8')) > 30000  # > 30KB

        # Anonymize
        result = anonymizer.anonymize(long_text)

        # Should detect all PII
        assert len(result.mapping) >= 3  # At least 3 PII entities

        # Verify placeholders are present
        assert "<PERSON_" in result.text or "<PHONE_" in result.text

        # Verify deanonymization works
        restored = deanonymizer.deanonymize(result.text, result.mapping)
        assert "13800138000" in restored.text or "张三" in restored.text

    def test_long_text_memory_efficiency(self):
        """Test that long text processing doesn't cause memory issues."""
        anonymizer = Anonymizer()

        # Generate 200KB text
        long_text = "张三的电话是13800138000。普通文本。" * 10000

        import sys
        initial_size = sys.getsizeof(long_text)

        result = anonymizer.anonymize(long_text)

        # Result should be similar size (not significantly larger)
        result_size = sys.getsizeof(result.text)
        assert result_size < initial_size * 2  # Should not double in size

    def test_mapping_with_many_entries(self):
        """Test mapping with many PII entries."""
        mapping = PIIMapping(session_id="large-test")

        # Add 1000 entries
        for i in range(1000):
            mapping.add(
                f"PERSON",
                f"Person_{i}",
                f"<PERSON_{i}>"
            )

        assert len(mapping) == 1000

        # Serialization should work
        data = mapping.to_dict()
        restored = PIIMapping.from_dict(data)
        assert len(restored) == 1000

        # Lookup should still be fast
        import time
        start = time.time()
        for i in range(100):
            mapping.get_original(f"<PERSON_{i}>")
        elapsed = time.time() - start
        assert elapsed < 0.1  # Should be very fast


# =============================================================================
# TEST-010: Concurrent Access to Mapping Store
# =============================================================================

class TestConcurrentMappingAccess:
    """Tests for concurrent access to mapping store."""

    def test_concurrent_save_different_keys(self):
        """Test concurrent saves with different keys."""
        store = MemoryStore(default_ttl=300, enable_background_cleanup=False)

        def save_mapping(i):
            mapping = PIIMapping(session_id=f"session-{i}")
            mapping.add("PERSON", f"Person_{i}", f"<PERSON_{i}>")
            store.save(f"request-{i}", mapping, tenant_id="tenant-1")
            return i

        # Concurrent saves
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(save_mapping, i) for i in range(100)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == 100

        # Verify all entries were saved
        for i in range(100):
            retrieved = store.get(f"request-{i}", tenant_id="tenant-1")
            assert retrieved is not None
            assert retrieved.session_id == f"session-{i}"

        store.shutdown()

    def test_concurrent_save_same_key(self):
        """Test concurrent saves to the same key."""
        store = MemoryStore(default_ttl=300, enable_background_cleanup=False)

        results = []
        lock = threading.Lock()

        def save_mapping(i):
            mapping = PIIMapping(session_id=f"session-{i}")
            mapping.add("PERSON", f"Person_{i}", f"<PERSON_1>")
            store.save("shared-key", mapping, tenant_id="tenant-1")
            with lock:
                results.append(i)

        threads = [threading.Thread(target=save_mapping, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 50

        # Final value should be one of the written values
        retrieved = store.get("shared-key", tenant_id="tenant-1")
        assert retrieved is not None

        store.shutdown()

    def test_concurrent_read_write(self):
        """Test concurrent reads and writes."""
        store = MemoryStore(default_ttl=300, enable_background_cleanup=False)

        # Pre-populate
        for i in range(10):
            mapping = PIIMapping(session_id=f"session-{i}")
            store.save(f"request-{i}", mapping, tenant_id="tenant-1")

        read_count = [0]
        write_count = [0]
        lock = threading.Lock()

        def reader():
            for _ in range(100):
                for i in range(10):
                    store.get(f"request-{i}", tenant_id="tenant-1")
                    with lock:
                        read_count[0] += 1

        def writer():
            for j in range(100):
                mapping = PIIMapping(session_id=f"new-session-{j}")
                store.save(f"new-request-{j}", mapping, tenant_id="tenant-1")
                with lock:
                    write_count[0] += 1

        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=reader),
            threading.Thread(target=writer),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert read_count[0] == 2000  # 2 readers * 100 iterations * 10 reads
        assert write_count[0] == 100

        store.shutdown()

    def test_concurrent_delete(self):
        """Test concurrent delete operations."""
        store = MemoryStore(default_ttl=300, enable_background_cleanup=False)

        # Pre-populate
        for i in range(100):
            mapping = PIIMapping()
            store.save(f"request-{i}", mapping, tenant_id="tenant-1")

        deleted = []
        lock = threading.Lock()

        def delete_mapping(i):
            result = store.delete(f"request-{i}", tenant_id="tenant-1")
            with lock:
                if result:
                    deleted.append(i)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(delete_mapping, i) for i in range(100)]
            concurrent.futures.wait(futures)

        # All should be deleted
        assert len(deleted) == 100
        assert len(store) == 0

        store.shutdown()

    def test_concurrent_extend_ttl(self):
        """Test concurrent TTL extension."""
        store = MemoryStore(default_ttl=1, enable_background_cleanup=False)

        mapping = PIIMapping(session_id="test")
        store.save("request-1", mapping, tenant_id="tenant-1")

        extend_results = []
        lock = threading.Lock()

        def extend_ttl():
            for _ in range(50):
                result = store.extend_ttl("request-1", ttl=10, tenant_id="tenant-1")
                with lock:
                    extend_results.append(result)
                time.sleep(0.001)

        threads = [threading.Thread(target=extend_ttl) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Most extensions should succeed
        assert extend_results.count(True) > 200

        # Mapping should still exist
        retrieved = store.get("request-1", tenant_id="tenant-1")
        assert retrieved is not None

        store.shutdown()


# =============================================================================
# TEST-011: Cache Expiration Boundary Conditions
# =============================================================================

class TestCacheExpirationBoundary:
    """Tests for cache expiration edge cases."""

    def setup_method(self):
        """Reset cache before each test."""
        reset_llm_cache()

    def test_cache_exact_expiration_time(self):
        """Test cache behavior at exact expiration boundary."""
        cache = LLMCache(default_ttl=1)  # 1 second TTL

        cache.put("key", {"data": "value"}, "tenant-1", "gpt-4")

        # Should exist immediately
        entry = cache.get("key", "tenant-1")
        assert entry is not None

        # Wait for expiration
        time.sleep(1.1)

        # Should be expired
        entry = cache.get("key", "tenant-1")
        assert entry is None

    def test_cache_zero_ttl(self):
        """Test cache with zero TTL (immediate expiration)."""
        cache = LLMCache(default_ttl=0)

        cache.put("key", {"data": "value"}, "tenant-1", "gpt-4")

        # Should be expired immediately
        entry = cache.get("key", "tenant-1")
        assert entry is None

    def test_cache_very_long_ttl(self):
        """Test cache with very long TTL."""
        cache = LLMCache(default_ttl=86400 * 365)  # 1 year

        cache.put("key", {"data": "value"}, "tenant-1", "gpt-4")

        entry = cache.get("key", "tenant-1")
        assert entry is not None
        assert entry.is_expired is False

    def test_cache_expiration_during_retrieval(self):
        """Test handling of entries expiring during retrieval."""
        cache = LLMCache(default_ttl=1)

        # Store multiple entries
        for i in range(10):
            cache.put(f"key-{i}", {"data": i}, "tenant-1", "gpt-4")

        # Wait for expiration
        time.sleep(1.1)

        # All should be expired
        for i in range(10):
            entry = cache.get(f"key-{i}", "tenant-1")
            assert entry is None

    def test_cache_cleanup_timing(self):
        """Test cleanup of expired entries."""
        cache = LLMCache(default_ttl=0, max_size=100)

        # Add expired entries
        for i in range(50):
            cache.put(f"key-{i}", {"data": i}, "tenant-1", "gpt-4")

        # Cleanup
        removed = cache.cleanup_expired()
        assert removed == 50

        # Stats should reflect cleanup
        stats = cache.get_stats("tenant-1")
        assert stats["entry_count"] == 0

    def test_cache_entry_refresh_before_expiration(self):
        """Test refreshing cache entry before expiration."""
        cache = LLMCache(default_ttl=2)

        cache.put("key", {"version": 1}, "tenant-1", "gpt-4")

        time.sleep(1)  # Wait 1 second

        # Refresh with new value
        cache.put("key", {"version": 2}, "tenant-1", "gpt-4")

        time.sleep(1.5)  # Would have expired if not refreshed

        entry = cache.get("key", "tenant-1")
        assert entry is not None
        assert entry.response_data["version"] == 2

    def test_cache_max_size_with_expiration(self):
        """Test max size eviction with expiring entries."""
        cache = LLMCache(default_ttl=0, max_size=5)

        # All entries will be expired
        for i in range(10):
            cache.put(f"key-{i}", {"data": i}, "tenant-1", "gpt-4")

        # All should be expired
        for i in range(10):
            assert cache.get(f"key-{i}", "tenant-1") is None


# =============================================================================
# TEST-012: Quota Threshold Edge Cases
# =============================================================================

class TestQuotaThresholdEdgeCases:
    """Tests for quota threshold boundary conditions."""

    def setup_method(self):
        """Reset quota store before each test."""
        reset_quota_store()

    def test_quota_exact_limit(self):
        """Test quota at exact limit."""
        store = QuotaStore()

        config = QuotaConfig(
            tenant_id="tenant-1",
            limits=[
                QuotaLimit(
                    quota_type=QuotaType.REQUESTS,
                    period=QuotaPeriod.HOURLY,
                    limit=10,
                )
            ]
        )
        store.set_quota(config)

        # Use 9 requests
        for _ in range(9):
            store.record_usage("tenant-1", QuotaType.REQUESTS, 1)

        # 10th request should be allowed
        allowed, _ = store.check_quota("tenant-1", QuotaType.REQUESTS, 1)
        assert allowed is True

        store.record_usage("tenant-1", QuotaType.REQUESTS, 1)

        # 11th request should be denied
        allowed, _ = store.check_quota("tenant-1", QuotaType.REQUESTS, 1)
        assert allowed is False

    def test_quota_one_over_limit(self):
        """Test quota one over limit."""
        store = QuotaStore()

        config = QuotaConfig(
            tenant_id="tenant-1",
            limits=[
                QuotaLimit(
                    quota_type=QuotaType.REQUESTS,
                    period=QuotaPeriod.HOURLY,
                    limit=5,
                )
            ]
        )
        store.set_quota(config)

        # Use exactly 5
        for _ in range(5):
            store.record_usage("tenant-1", QuotaType.REQUESTS, 1)

        # Next should be denied
        allowed, limit = store.check_quota("tenant-1", QuotaType.REQUESTS, 1)
        assert allowed is False
        assert limit is not None
        assert limit.limit == 5

    def test_quota_soft_limit_warning(self):
        """Test soft limit warning threshold."""
        store = QuotaStore()

        config = QuotaConfig(
            tenant_id="tenant-1",
            limits=[
                QuotaLimit(
                    quota_type=QuotaType.REQUESTS,
                    period=QuotaPeriod.HOURLY,
                    limit=100,
                    soft_limit_percent=80.0,
                )
            ]
        )
        store.set_quota(config)

        # Soft limit is 80
        limit = config.limits[0]
        assert limit.soft_limit == 80

        # Use 79 requests (under soft limit)
        for _ in range(79):
            store.record_usage("tenant-1", QuotaType.REQUESTS, 1)

        # 80th request crosses soft limit but is still allowed
        allowed, _ = store.check_quota("tenant-1", QuotaType.REQUESTS, 1)
        assert allowed is True

    def test_quota_zero_limit(self):
        """Test quota with zero limit (block all)."""
        store = QuotaStore()

        config = QuotaConfig(
            tenant_id="tenant-1",
            limits=[
                QuotaLimit(
                    quota_type=QuotaType.REQUESTS,
                    period=QuotaPeriod.HOURLY,
                    limit=0,
                )
            ]
        )
        store.set_quota(config)

        # First request should be denied
        allowed, _ = store.check_quota("tenant-1", QuotaType.REQUESTS, 1)
        assert allowed is False

    def test_quota_large_single_request(self):
        """Test large single request against quota."""
        store = QuotaStore()

        config = QuotaConfig(
            tenant_id="tenant-1",
            limits=[
                QuotaLimit(
                    quota_type=QuotaType.TOKENS,
                    period=QuotaPeriod.DAILY,
                    limit=1000,
                )
            ]
        )
        store.set_quota(config)

        # Request that would exceed limit in one go
        allowed, _ = store.check_quota("tenant-1", QuotaType.TOKENS, 1001)
        assert allowed is False

        # Request exactly at limit should be allowed
        allowed, _ = store.check_quota("tenant-1", QuotaType.TOKENS, 1000)
        assert allowed is True

    def test_quota_no_config_allows_all(self):
        """Test that no quota config allows unlimited usage."""
        store = QuotaStore()

        # No config set
        for _ in range(1000):
            allowed, limit = store.check_quota("tenant-1", QuotaType.REQUESTS, 1)
            assert allowed is True
            assert limit is None

    def test_quota_multiple_periods(self):
        """Test quota enforcement across multiple periods."""
        store = QuotaStore()

        config = QuotaConfig(
            tenant_id="tenant-1",
            limits=[
                QuotaLimit(
                    quota_type=QuotaType.REQUESTS,
                    period=QuotaPeriod.HOURLY,
                    limit=10,
                ),
                QuotaLimit(
                    quota_type=QuotaType.REQUESTS,
                    period=QuotaPeriod.DAILY,
                    limit=100,
                ),
            ]
        )
        store.set_quota(config)

        # Use 10 requests (hits hourly limit)
        for _ in range(10):
            store.record_usage("tenant-1", QuotaType.REQUESTS, 1)

        # Next request should hit hourly limit
        allowed, limit = store.check_quota("tenant-1", QuotaType.REQUESTS, 1)
        assert allowed is False
        assert limit.period == QuotaPeriod.HOURLY

    def test_quota_usage_summary(self):
        """Test getting accurate usage summary."""
        store = QuotaStore()

        config = QuotaConfig(
            tenant_id="tenant-1",
            limits=[
                QuotaLimit(
                    quota_type=QuotaType.REQUESTS,
                    period=QuotaPeriod.HOURLY,
                    limit=100,
                ),
                QuotaLimit(
                    quota_type=QuotaType.TOKENS,
                    period=QuotaPeriod.DAILY,
                    limit=10000,
                ),
            ]
        )
        store.set_quota(config)

        # Record some usage
        store.record_usage("tenant-1", QuotaType.REQUESTS, 25)
        store.record_usage("tenant-1", QuotaType.TOKENS, 500)

        summary = store.get_usage_summary("tenant-1")

        assert QuotaType.REQUESTS.value in summary
        assert QuotaType.TOKENS.value in summary

    def test_quota_concurrent_access(self):
        """Test concurrent quota checks and updates."""
        store = QuotaStore()

        config = QuotaConfig(
            tenant_id="tenant-1",
            limits=[
                QuotaLimit(
                    quota_type=QuotaType.REQUESTS,
                    period=QuotaPeriod.HOURLY,
                    limit=1000,
                )
            ]
        )
        store.set_quota(config)

        results = []
        lock = threading.Lock()

        def check_and_record():
            for _ in range(100):
                allowed, _ = store.check_quota("tenant-1", QuotaType.REQUESTS, 1)
                if allowed:
                    store.record_usage("tenant-1", QuotaType.REQUESTS, 1)
                    with lock:
                        results.append(True)

        threads = [threading.Thread(target=check_and_record) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 1000 requests should have succeeded
        assert len(results) == 1000


# =============================================================================
# Additional Edge Cases
# =============================================================================

class TestAdditionalEdgeCases:
    """Additional edge case tests."""

    def test_mapping_special_characters(self):
        """Test mapping with special characters in values."""
        mapping = PIIMapping()

        # Special characters in names
        mapping.add("PERSON", "张三\n李四", "<PERSON_1>")
        mapping.add("EMAIL", "test+alias@example.com", "<EMAIL_1>")
        mapping.add("PHONE", "+86-138-0013-8000", "<PHONE_1>")

        assert mapping.get_original("<PERSON_1>") == "张三\n李四"
        assert mapping.get_original("<EMAIL_1>") == "test+alias@example.com"

        # JSON serialization should handle special chars
        json_str = mapping.to_json()
        restored = PIIMapping.from_json(json_str)
        assert restored.get_original("<PERSON_1>") == "张三\n李四"

    def test_mapping_unicode_normalization(self):
        """Test mapping with different unicode forms."""
        mapping = PIIMapping()

        # Chinese characters
        mapping.add("PERSON", "张三", "<PERSON_1>")
        mapping.add("LOCATION", "北京市朝阳区", "<LOCATION_1>")

        assert mapping.get_original("<PERSON_1>") == "张三"
        assert mapping.get_original("<LOCATION_1>") == "北京市朝阳区"

    def test_store_tenant_isolation_edge_cases(self):
        """Test tenant isolation with similar IDs."""
        store = MemoryStore(default_ttl=300, enable_background_cleanup=False)

        # Similar tenant IDs
        mapping1 = PIIMapping(session_id="session-1")
        mapping2 = PIIMapping(session_id="session-2")

        store.save("request", mapping1, tenant_id="tenant")
        store.save("request", mapping2, tenant_id="tenant-1")

        # Should be isolated
        r1 = store.get("request", tenant_id="tenant")
        r2 = store.get("request", tenant_id="tenant-1")

        assert r1.session_id == "session-1"
        assert r2.session_id == "session-2"

        store.shutdown()

    def test_cache_large_response(self):
        """Test caching large response data."""
        cache = LLMCache(default_ttl=300)

        # Large response (simulate multi-choice, large content)
        large_response = {
            "id": "chatcmpl-123",
            "choices": [
                {"message": {"content": "x" * 100000}}  # 100KB content
                for _ in range(5)
            ],
            "usage": {"total_tokens": 50000}
        }

        cache.put("large-key", large_response, "tenant-1", "gpt-4")

        entry = cache.get("large-key", "tenant-1")
        assert entry is not None
        assert len(entry.response_data["choices"]) == 5
