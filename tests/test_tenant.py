"""Tests for multi-tenant support."""

import pytest

from pii_airlock.auth.tenant import (
    Tenant,
    TenantConfig,
    TenantStatus,
    get_current_tenant,
    get_tenant_config,
    reset_tenant_config,
    DEFAULT_TENANT_ID,
)


class TestTenant:
    """Tests for Tenant dataclass."""

    def test_tenant_creation(self):
        """Test creating a tenant."""
        tenant = Tenant(
            tenant_id="test-tenant",
            name="Test Tenant",
            status=TenantStatus.ACTIVE,
            api_keys=["key1", "key2"],
            rate_limit="100/minute",
            max_ttl=600,
        )

        assert tenant.tenant_id == "test-tenant"
        assert tenant.name == "Test Tenant"
        assert tenant.status == TenantStatus.ACTIVE
        assert tenant.is_active is True
        assert tenant.rate_limit == "100/minute"
        assert tenant.max_ttl == 600

    def test_tenant_status_checks(self):
        """Test tenant status property."""
        active_tenant = Tenant(
            tenant_id="active", name="Active", status=TenantStatus.ACTIVE
        )
        disabled_tenant = Tenant(
            tenant_id="disabled", name="Disabled", status=TenantStatus.DISABLED
        )
        suspended_tenant = Tenant(
            tenant_id="suspended", name="Suspended", status=TenantStatus.SUSPENDED
        )

        assert active_tenant.is_active is True
        assert disabled_tenant.is_active is False
        assert suspended_tenant.is_active is False


class TestTenantConfig:
    """Tests for TenantConfig."""

    def test_add_and_get_tenant(self):
        """Test adding and retrieving tenants."""
        config = TenantConfig()

        tenant = Tenant(
            tenant_id="test-1", name="Test 1", status=TenantStatus.ACTIVE
        )
        config.add_tenant(tenant)

        retrieved = config.get_tenant("test-1")
        assert retrieved is not None
        assert retrieved.tenant_id == "test-1"
        assert retrieved.name == "Test 1"

    def test_get_nonexistent_tenant(self):
        """Test getting a tenant that doesn't exist."""
        config = TenantConfig()
        retrieved = config.get_tenant("nonexistent")
        assert retrieved is None

    def test_list_tenants(self):
        """Test listing all tenants."""
        config = TenantConfig()

        config.add_tenant(
            Tenant(tenant_id="a", name="A", status=TenantStatus.ACTIVE)
        )
        config.add_tenant(
            Tenant(tenant_id="b", name="B", status=TenantStatus.DISABLED)
        )

        all_tenants = config.list_tenants()
        assert len(all_tenants) == 2

        active_only = config.list_tenants(status=TenantStatus.ACTIVE)
        assert len(active_only) == 1
        assert active_only[0].tenant_id == "a"

    def test_remove_tenant(self):
        """Test removing a tenant."""
        config = TenantConfig()

        config.add_tenant(
            Tenant(tenant_id="to-remove", name="To Remove", status=TenantStatus.ACTIVE)
        )

        assert config.get_tenant("to-remove") is not None

        result = config.remove_tenant("to-remove")
        assert result is True

        assert config.get_tenant("to-remove") is None

    def test_api_key_index(self):
        """Test API key indexing."""
        config = TenantConfig()

        tenant = Tenant(
            tenant_id="test-tenant",
            name="Test",
            api_keys=["piiak_test_key1", "piiak_test_key2"],
        )
        config.add_tenant(tenant)

        # Lookup by API key
        found = config.get_tenant_by_api_key("piiak_test_key1")
        assert found is not None
        assert found.tenant_id == "test-tenant"

        # Lookup by prefix
        found = config.get_tenant_by_api_key("piiak_test_randomsuffix")
        assert found is not None
        assert found.tenant_id == "test-tenant"

        # Non-existent key
        found = config.get_tenant_by_api_key("piiak_other_key")
        assert found is None


class TestGetCurrentTenant:
    """Tests for get_current_tenant function."""

    def setup_method(self):
        """Reset config before each test."""
        reset_tenant_config()

    def test_default_tenant_when_multi_tenant_disabled(self, monkeypatch):
        """Test that default tenant is returned when multi-tenant is disabled."""
        monkeypatch.setenv("PII_AIRLOCK_MULTI_TENANT_ENABLED", "false")

        tenant = get_current_tenant()
        assert tenant is not None
        assert tenant.tenant_id == DEFAULT_TENANT_ID

    def test_tenant_lookup_by_id(self, monkeypatch):
        """Test tenant lookup by tenant_id."""
        monkeypatch.setenv("PII_AIRLOCK_MULTI_TENANT_ENABLED", "true")

        config = get_tenant_config()
        config.add_tenant(
            Tenant(tenant_id="test-tenant", name="Test", status=TenantStatus.ACTIVE)
        )

        tenant = get_current_tenant(tenant_id="test-tenant")
        assert tenant is not None
        assert tenant.tenant_id == "test-tenant"

    def test_tenant_lookup_by_api_key(self, monkeypatch):
        """Test tenant lookup by API key."""
        monkeypatch.setenv("PII_AIRLOCK_MULTI_TENANT_ENABLED", "true")

        config = get_tenant_config()
        tenant = Tenant(
            tenant_id="test-tenant",
            name="Test",
            api_keys=["piiak_test_secret"],
        )
        config.add_tenant(tenant)

        found = get_current_tenant(api_key="piiak_test_secret")
        assert found is not None
        assert found.tenant_id == "test-tenant"

    def test_disabled_tenant_not_returned(self, monkeypatch):
        """Test that disabled tenants are not returned."""
        monkeypatch.setenv("PII_AIRLOCK_MULTI_TENANT_ENABLED", "true")

        config = get_tenant_config()
        config.add_tenant(
            Tenant(tenant_id="disabled-tenant", name="Disabled", status=TenantStatus.DISABLED)
        )

        tenant = get_current_tenant(tenant_id="disabled-tenant")
        assert tenant is None
