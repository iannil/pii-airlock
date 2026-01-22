"""Tests for API key management."""

import pytest

from pii_airlock.auth.api_key import (
    APIKey,
    APIKeyStore,
    KeyStatus,
    get_api_key_store,
    reset_api_key_store,
    validate_api_key,
)


class TestAPIKey:
    """Tests for APIKey dataclass."""

    def test_api_key_creation(self):
        """Test creating an API key."""
        key = APIKey(
            key_id="test-key-id",
            key_prefix="piiak_test_",
            tenant_id="tenant-1",
            name="Test Key",
            status=KeyStatus.ACTIVE,
            scopes=["llm:use"],
        )

        assert key.key_id == "test-key-id"
        assert key.tenant_id == "tenant-1"
        assert key.is_valid is True

    def test_api_key_expiration(self):
        """Test API key expiration."""
        import time

        # Expired key
        expired_key = APIKey(
            key_id="expired",
            key_prefix="piiak_",
            tenant_id="tenant",
            name="Expired",
            status=KeyStatus.ACTIVE,
            expires_at=time.time() - 100,
        )
        assert expired_key.is_valid is False

        # Valid key
        valid_key = APIKey(
            key_id="valid",
            key_prefix="piiak_",
            tenant_id="tenant",
            name="Valid",
            status=KeyStatus.ACTIVE,
            expires_at=time.time() + 3600,
        )
        assert valid_key.is_valid is True

    def test_api_key_disabled(self):
        """Test disabled API key."""
        key = APIKey(
            key_id="disabled",
            key_prefix="piiak_",
            tenant_id="tenant",
            name="Disabled",
            status=KeyStatus.DISABLED,
        )
        assert key.is_valid is False

    def test_api_key_revoked(self):
        """Test revoked API key."""
        key = APIKey(
            key_id="revoked",
            key_prefix="piiak_",
            tenant_id="tenant",
            name="Revoked",
            status=KeyStatus.REVOKED,
        )
        assert key.is_valid is False


class TestAPIKeyStore:
    """Tests for APIKeyStore."""

    def setup_method(self):
        """Reset store before each test."""
        reset_api_key_store()

    def test_create_key(self):
        """Test creating a new API key."""
        store = get_api_key_store()

        full_key, key_obj = store.create_key(
            tenant_id="tenant-1",
            name="Test Key",
            scopes=["llm:use"],
        )

        assert full_key.startswith("piiak_tenant-1_")
        assert key_obj.tenant_id == "tenant-1"
        assert key_obj.name == "Test Key"
        assert key_obj.scopes == ["llm:use"]
        assert key_obj.status == KeyStatus.ACTIVE

    def test_validate_key(self):
        """Test validating an API key."""
        store = get_api_key_store()

        full_key, _ = store.create_key(
            tenant_id="tenant-1",
            name="Test Key",
        )

        # Valid key
        validated = store.validate_key(full_key)
        assert validated is not None
        assert validated.tenant_id == "tenant-1"

        # Invalid key
        invalid = store.validate_key("invalid_key")
        assert invalid is None

    def test_revoke_key(self):
        """Test revoking an API key."""
        store = get_api_key_store()

        full_key, key_obj = store.create_key(
            tenant_id="tenant-1",
            name="Test Key",
        )

        # Key should be valid initially
        validated = store.validate_key(full_key)
        assert validated is not None

        # Revoke the key
        success = store.revoke_key(key_obj.key_id)
        assert success is True

        # Key should no longer be valid
        validated = store.validate_key(full_key)
        assert validated is None

    def test_disable_and_enable_key(self):
        """Test disabling and enabling an API key."""
        store = get_api_key_store()

        full_key, key_obj = store.create_key(
            tenant_id="tenant-1",
            name="Test Key",
        )

        # Disable key
        success = store.disable_key(key_obj.key_id)
        assert success is True

        validated = store.validate_key(full_key)
        assert validated is None

        # Enable key
        success = store.enable_key(key_obj.key_id)
        assert success is True

        validated = store.validate_key(full_key)
        assert validated is not None

    def test_list_keys_by_tenant(self):
        """Test listing keys by tenant."""
        store = get_api_key_store()

        store.create_key(tenant_id="tenant-a", name="Key A1")
        store.create_key(tenant_id="tenant-a", name="Key A2")
        store.create_key(tenant_id="tenant-b", name="Key B1")

        keys_a = store.list_keys(tenant_id="tenant-a")
        assert len(keys_a) == 2

        keys_b = store.list_keys(tenant_id="tenant-b")
        assert len(keys_b) == 1

    def test_list_keys_by_status(self):
        """Test listing keys by status."""
        store = get_api_key_store()

        _, key1 = store.create_key(tenant_id="tenant", name="Key 1")
        _, key2 = store.create_key(tenant_id="tenant", name="Key 2")

        store.disable_key(key2.key_id)

        active_keys = store.list_keys(status=KeyStatus.ACTIVE)
        disabled_keys = store.list_keys(status=KeyStatus.DISABLED)

        assert len(active_keys) == 1
        assert len(disabled_keys) == 1

    def test_delete_key(self):
        """Test permanently deleting a key."""
        store = get_api_key_store()

        _, key_obj = store.create_key(
            tenant_id="tenant-1",
            name="Test Key",
        )

        # Key exists
        retrieved = store.get_key(key_obj.key_id)
        assert retrieved is not None

        # Delete key
        success = store.delete_key(key_obj.key_id)
        assert success is True

        # Key is gone
        retrieved = store.get_key(key_obj.key_id)
        assert retrieved is None

    def test_key_last_used_tracking(self):
        """Test that key last_used is updated on validation."""
        import time

        store = get_api_key_store()

        full_key, key_obj = store.create_key(
            tenant_id="tenant-1",
            name="Test Key",
        )

        # Initially no last_used
        assert key_obj.last_used is None

        # Validate key - should update last_used
        time.sleep(0.01)  # Small delay to ensure timestamp difference
        validated = store.validate_key(full_key)
        assert validated is not None
        assert validated.last_used is not None
        assert validated.last_used > key_obj.created_at


class TestGlobalValidateAPIKey:
    """Tests for global validate_api_key function."""

    def setup_method(self):
        """Reset store before each test."""
        reset_api_key_store()

    def test_validate_api_key_function(self):
        """Test the global validate_api_key function."""
        store = get_api_key_store()

        full_key, _ = store.create_key(
            tenant_id="tenant-1",
            name="Test Key",
        )

        # Valid key through global function
        validated = validate_api_key(full_key)
        assert validated is not None
        assert validated.tenant_id == "tenant-1"

        # Invalid key
        validated = validate_api_key("invalid")
        assert validated is None
