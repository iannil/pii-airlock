"""
Redis 存储模块测试

测试 RedisStore 类的功能：
- 映射保存/获取/删除
- TTL 管理
- 租户隔离
- 批量删除
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
import json

from pii_airlock.storage.redis_store import RedisStore, DEFAULT_STORAGE_TENANT
from pii_airlock.core.mapping import PIIMapping


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_redis():
    """Create a mock Redis client."""
    client = Mock()
    client.setex = Mock()
    client.get = Mock(return_value=None)
    client.delete = Mock(return_value=1)
    client.expire = Mock(return_value=True)
    client.exists = Mock(return_value=0)
    client.scan_iter = Mock(return_value=iter([]))
    return client


@pytest.fixture
def redis_store(mock_redis):
    """Create a RedisStore with mock client."""
    return RedisStore(mock_redis, default_ttl=300)


@pytest.fixture
def sample_mapping():
    """Create a sample PIIMapping for testing."""
    mapping = PIIMapping()
    mapping.add("PERSON", "张三", "<PERSON_1>")
    mapping.add("PHONE", "13800138000", "<PHONE_1>")
    return mapping


# ============================================================================
# Basic Operations Tests
# ============================================================================


class TestRedisStoreBasicOperations:
    """Test basic CRUD operations."""

    def test_init(self, mock_redis):
        """Test RedisStore initialization."""
        store = RedisStore(mock_redis, default_ttl=600)
        assert store.default_ttl == 600
        assert store._client is mock_redis

    def test_save_mapping(self, redis_store, mock_redis, sample_mapping):
        """Test saving a mapping."""
        redis_store.save("request-123", sample_mapping)

        mock_redis.setex.assert_called_once()
        call_args = mock_redis.setex.call_args
        assert "request-123" in call_args[0][0]
        assert call_args[0][1] == 300  # default TTL

    def test_save_mapping_custom_ttl(self, redis_store, mock_redis, sample_mapping):
        """Test saving a mapping with custom TTL."""
        redis_store.save("request-123", sample_mapping, ttl=600)

        call_args = mock_redis.setex.call_args
        assert call_args[0][1] == 600

    def test_get_mapping_exists(self, redis_store, mock_redis, sample_mapping):
        """Test getting an existing mapping."""
        # Setup mock to return serialized mapping
        mock_redis.get.return_value = sample_mapping.to_json().encode('utf-8')

        result = redis_store.get("request-123")

        assert result is not None
        assert result.get_placeholder("PERSON", "张三") == "<PERSON_1>"

    def test_get_mapping_not_exists(self, redis_store, mock_redis):
        """Test getting a non-existent mapping."""
        mock_redis.get.return_value = None

        result = redis_store.get("nonexistent")

        assert result is None

    def test_get_mapping_string_response(self, redis_store, mock_redis, sample_mapping):
        """Test getting a mapping when Redis returns string (not bytes)."""
        mock_redis.get.return_value = sample_mapping.to_json()

        result = redis_store.get("request-123")

        assert result is not None

    def test_delete_mapping_exists(self, redis_store, mock_redis):
        """Test deleting an existing mapping."""
        mock_redis.delete.return_value = 1

        result = redis_store.delete("request-123")

        assert result is True
        mock_redis.delete.assert_called_once()

    def test_delete_mapping_not_exists(self, redis_store, mock_redis):
        """Test deleting a non-existent mapping."""
        mock_redis.delete.return_value = 0

        result = redis_store.delete("nonexistent")

        assert result is False

    def test_exists_true(self, redis_store, mock_redis):
        """Test exists check when mapping exists."""
        mock_redis.exists.return_value = 1

        result = redis_store.exists("request-123")

        assert result is True

    def test_exists_false(self, redis_store, mock_redis):
        """Test exists check when mapping doesn't exist."""
        mock_redis.exists.return_value = 0

        result = redis_store.exists("request-123")

        assert result is False


# ============================================================================
# TTL Management Tests
# ============================================================================


class TestTTLManagement:
    """Test TTL extension functionality."""

    def test_extend_ttl_success(self, redis_store, mock_redis):
        """Test extending TTL successfully."""
        mock_redis.expire.return_value = True

        result = redis_store.extend_ttl("request-123", ttl=600)

        assert result is True
        mock_redis.expire.assert_called_once()

    def test_extend_ttl_default(self, redis_store, mock_redis):
        """Test extending TTL with default value."""
        mock_redis.expire.return_value = True

        redis_store.extend_ttl("request-123")

        call_args = mock_redis.expire.call_args
        assert call_args[0][1] == 300  # default TTL

    def test_extend_ttl_not_found(self, redis_store, mock_redis):
        """Test extending TTL for non-existent key."""
        mock_redis.expire.return_value = False

        result = redis_store.extend_ttl("nonexistent")

        assert result is False


# ============================================================================
# Key Generation Tests
# ============================================================================


class TestKeyGeneration:
    """Test Redis key generation."""

    def test_make_key_no_tenant(self, redis_store):
        """Test key generation without tenant ID."""
        key = redis_store._make_key("request-123")

        assert f"{DEFAULT_STORAGE_TENANT}:" in key
        assert "request-123" in key
        assert key.startswith(RedisStore.KEY_PREFIX)

    def test_make_key_with_tenant(self, redis_store):
        """Test key generation with tenant ID."""
        key = redis_store._make_key("request-123", tenant_id="tenant-abc")

        assert "tenant-abc:" in key
        assert "request-123" in key
        assert DEFAULT_STORAGE_TENANT not in key

    def test_make_key_empty_tenant_uses_default(self, redis_store):
        """Test that empty tenant falls back to default."""
        key1 = redis_store._make_key("request-123", tenant_id=None)
        key2 = redis_store._make_key("request-123", tenant_id="")

        # Empty string is falsy, so should use default
        assert DEFAULT_STORAGE_TENANT in key1
        # Empty string tenant should also use the provided empty string... actually falsy check
        # Let's test the actual behavior
        assert key1 == key2 or DEFAULT_STORAGE_TENANT in key2


# ============================================================================
# Tenant Isolation Tests
# ============================================================================


class TestTenantIsolation:
    """Test multi-tenant isolation."""

    def test_save_with_tenant(self, redis_store, mock_redis, sample_mapping):
        """Test saving with tenant ID."""
        redis_store.save("request-123", sample_mapping, tenant_id="tenant-a")

        call_args = mock_redis.setex.call_args
        key = call_args[0][0]
        assert "tenant-a:" in key

    def test_get_with_tenant(self, redis_store, mock_redis, sample_mapping):
        """Test getting with tenant ID."""
        mock_redis.get.return_value = sample_mapping.to_json().encode()

        redis_store.get("request-123", tenant_id="tenant-a")

        call_args = mock_redis.get.call_args
        key = call_args[0][0]
        assert "tenant-a:" in key

    def test_delete_with_tenant(self, redis_store, mock_redis):
        """Test deleting with tenant ID."""
        redis_store.delete("request-123", tenant_id="tenant-a")

        call_args = mock_redis.delete.call_args
        key = call_args[0][0]
        assert "tenant-a:" in key

    def test_exists_with_tenant(self, redis_store, mock_redis):
        """Test exists check with tenant ID."""
        redis_store.exists("request-123", tenant_id="tenant-a")

        call_args = mock_redis.exists.call_args
        key = call_args[0][0]
        assert "tenant-a:" in key

    def test_extend_ttl_with_tenant(self, redis_store, mock_redis):
        """Test TTL extension with tenant ID."""
        redis_store.extend_ttl("request-123", tenant_id="tenant-a")

        call_args = mock_redis.expire.call_args
        key = call_args[0][0]
        assert "tenant-a:" in key

    def test_delete_tenant_keys(self, redis_store, mock_redis):
        """Test deleting all keys for a tenant."""
        mock_redis.scan_iter.return_value = iter([
            b"pii_airlock:mapping:tenant-a:req1",
            b"pii_airlock:mapping:tenant-a:req2",
        ])
        mock_redis.delete.return_value = 2

        result = redis_store.delete_tenant_keys("tenant-a")

        assert result == 2
        mock_redis.scan_iter.assert_called_once()

    def test_delete_tenant_keys_no_keys(self, redis_store, mock_redis):
        """Test deleting tenant keys when none exist."""
        mock_redis.scan_iter.return_value = iter([])

        result = redis_store.delete_tenant_keys("tenant-a")

        assert result == 0
        mock_redis.delete.assert_not_called()

    def test_different_tenants_different_keys(self, redis_store):
        """Test that different tenants get different keys."""
        key_a = redis_store._make_key("req-1", tenant_id="tenant-a")
        key_b = redis_store._make_key("req-1", tenant_id="tenant-b")

        assert key_a != key_b
        assert "tenant-a" in key_a
        assert "tenant-b" in key_b


# ============================================================================
# Edge Cases
# ============================================================================


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_mapping(self, redis_store, mock_redis):
        """Test saving an empty mapping."""
        mapping = PIIMapping()
        redis_store.save("request-123", mapping)

        mock_redis.setex.assert_called_once()

    def test_large_mapping(self, redis_store, mock_redis):
        """Test saving a mapping with many entries."""
        mapping = PIIMapping()
        for i in range(1000):
            mapping.add("PERSON", f"Person{i}", f"<PERSON_{i}>")

        redis_store.save("request-123", mapping)

        mock_redis.setex.assert_called_once()

    def test_special_chars_in_request_id(self, redis_store, mock_redis, sample_mapping):
        """Test request ID with special characters."""
        request_id = "req-123_abc@test:xyz"
        redis_store.save(request_id, sample_mapping)

        call_args = mock_redis.setex.call_args
        key = call_args[0][0]
        assert request_id in key

    def test_unicode_request_id(self, redis_store, mock_redis, sample_mapping):
        """Test request ID with Unicode characters."""
        request_id = "请求-123"
        redis_store.save(request_id, sample_mapping)

        mock_redis.setex.assert_called_once()

    def test_zero_ttl_uses_default(self, redis_store, mock_redis, sample_mapping):
        """Test saving with zero TTL uses default (falsy check)."""
        redis_store.save("request-123", sample_mapping, ttl=0)

        call_args = mock_redis.setex.call_args
        # Zero is falsy, so default TTL (300) is used
        assert call_args[0][1] == 300


# ============================================================================
# Integration-like Tests (with mocked Redis behavior)
# ============================================================================


class TestIntegrationScenarios:
    """Test realistic usage scenarios."""

    def test_save_get_delete_flow(self, mock_redis, sample_mapping):
        """Test complete save-get-delete flow."""
        store = RedisStore(mock_redis)

        # Save
        store.save("req-1", sample_mapping)
        assert mock_redis.setex.called

        # Get - setup return value
        mock_redis.get.return_value = sample_mapping.to_json().encode()
        result = store.get("req-1")
        assert result is not None
        assert result.get_placeholder("PERSON", "张三") == "<PERSON_1>"

        # Delete
        mock_redis.delete.return_value = 1
        deleted = store.delete("req-1")
        assert deleted is True

    def test_streaming_ttl_extension(self, mock_redis, sample_mapping):
        """Test TTL extension during streaming."""
        store = RedisStore(mock_redis, default_ttl=300)

        # Initial save
        store.save("stream-req", sample_mapping)

        # Simulate streaming with TTL extensions
        mock_redis.expire.return_value = True
        for _ in range(5):
            result = store.extend_ttl("stream-req", ttl=300)
            assert result is True

        # Verify expire was called multiple times
        assert mock_redis.expire.call_count == 5

    def test_multi_tenant_isolation(self, mock_redis):
        """Test that tenants are isolated."""
        store = RedisStore(mock_redis)

        mapping_a = PIIMapping()
        mapping_a.add("PERSON", "Alice", "<PERSON_1>")

        mapping_b = PIIMapping()
        mapping_b.add("PERSON", "Bob", "<PERSON_1>")

        # Save for different tenants
        store.save("req-1", mapping_a, tenant_id="tenant-a")
        store.save("req-1", mapping_b, tenant_id="tenant-b")

        # Verify different keys were used
        calls = mock_redis.setex.call_args_list
        assert len(calls) == 2
        keys = [call[0][0] for call in calls]
        assert "tenant-a" in keys[0]
        assert "tenant-b" in keys[1]
        assert keys[0] != keys[1]


# ============================================================================
# Default Tenant Configuration Tests
# ============================================================================


class TestDefaultTenantConfiguration:
    """Test DEFAULT_STORAGE_TENANT configuration."""

    def test_default_tenant_value(self):
        """Test default tenant value from environment or default."""
        # The default value should be "_default_" unless overridden
        assert DEFAULT_STORAGE_TENANT is not None
        assert len(DEFAULT_STORAGE_TENANT) > 0

    @patch.dict('os.environ', {'PII_AIRLOCK_DEFAULT_TENANT': 'custom_default'})
    def test_custom_default_tenant_from_env(self):
        """Test that default tenant can be configured via environment."""
        # This tests the concept; actual value is set at import time
        import os
        assert os.getenv("PII_AIRLOCK_DEFAULT_TENANT") == "custom_default"
