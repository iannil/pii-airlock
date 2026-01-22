"""Multi-tenant support for PII-AIRLOCK.

This module provides tenant isolation for enterprise deployments where
multiple departments or projects need to share the same PII-AIRLOCK instance.

Tenants can be identified via:
1. X-Tenant-ID header
2. API key prefix (piiak_{tenant}_{key})
3. Query parameter (for testing only)

Each tenant has:
- Unique tenant_id
- Name for display
- Associated API keys
- Custom PII patterns configuration
- Rate limit settings
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, List
import threading

import yaml

from pii_airlock.logging.setup import get_logger

logger = get_logger(__name__)


class TenantStatus(str, Enum):
    """Tenant status values."""

    ACTIVE = "active"
    DISABLED = "disabled"
    SUSPENDED = "suspended"


@dataclass
class Tenant:
    """A tenant configuration.

    Attributes:
        tenant_id: Unique tenant identifier.
        name: Human-readable name.
        status: Current status (active, disabled, suspended).
        api_keys: List of API key prefixes associated with this tenant.
        config_path: Path to tenant-specific PII patterns.
        rate_limit: Rate limit string (e.g., "100/minute").
        max_ttl: Maximum mapping TTL in seconds.
    """

    tenant_id: str
    name: str
    status: TenantStatus = TenantStatus.ACTIVE
    api_keys: List[str] = field(default_factory=list)
    config_path: Optional[str] = None
    rate_limit: str = "60/minute"
    max_ttl: int = 300
    # Custom settings
    settings: Dict = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        """Check if tenant is active."""
        return self.status == TenantStatus.ACTIVE


@dataclass
class TenantConfig:
    """Configuration for multi-tenant support.

    Manages tenant lookup and configuration loading.
    Thread-safe for concurrent access.
    """

    tenants: Dict[str, Tenant] = field(default_factory=dict)
    api_key_index: Dict[str, str] = field(default_factory=dict)  # key -> tenant_id
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant by ID.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            Tenant if found, None otherwise.
        """
        with self._lock:
            return self.tenants.get(tenant_id)

    def get_tenant_by_api_key(self, api_key: str) -> Optional[Tenant]:
        """Get tenant by API key.

        Args:
            api_key: The API key (full key or prefix).

        Returns:
            Tenant if found, None otherwise.
        """
        with self._lock:
            # Try exact match first
            tenant_id = self.api_key_index.get(api_key)
            if tenant_id:
                return self.tenants.get(tenant_id)

            # Try prefix match for piiak_{tenant}_* format
            if api_key.startswith("piiak_"):
                parts = api_key.split("_", 2)
                if len(parts) >= 2:
                    tenant_id = parts[1]
                    return self.tenants.get(tenant_id)

            return None

    def add_tenant(self, tenant: Tenant) -> None:
        """Add a tenant to the configuration.

        Args:
            tenant: The tenant to add.
        """
        with self._lock:
            self.tenants[tenant.tenant_id] = tenant
            for key in tenant.api_keys:
                self.api_key_index[key] = tenant.tenant_id

            logger.info(
                "Tenant added to configuration",
                extra={
                    "event": "tenant_added",
                    "tenant_id": tenant.tenant_id,
                    "tenant_name": tenant.name,
                },
            )

    def remove_tenant(self, tenant_id: str) -> bool:
        """Remove a tenant from the configuration.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            True if removed, False if not found.
        """
        with self._lock:
            tenant = self.tenants.pop(tenant_id, None)
            if tenant:
                for key in tenant.api_keys:
                    self.api_key_index.pop(key, None)

                logger.info(
                    "Tenant removed from configuration",
                    extra={
                        "event": "tenant_removed",
                        "tenant_id": tenant_id,
                    },
                )
                return True
            return False

    def list_tenants(self, status: Optional[TenantStatus] = None) -> List[Tenant]:
        """List all tenants, optionally filtered by status.

        Args:
            status: Optional status filter.

        Returns:
            List of tenants.
        """
        with self._lock:
            tenants = list(self.tenants.values())
            if status:
                tenants = [t for t in tenants if t.status == status]
            return tenants

    @classmethod
    def from_yaml(cls, path: Path | str) -> "TenantConfig":
        """Load tenant configuration from YAML file.

        Args:
            path: Path to tenants.yaml file.

        Returns:
            TenantConfig instance.

        Example YAML:
            tenants:
              - tenant_id: "team-a"
                name: "Team A"
                status: "active"
                api_keys: ["piiak_team-a_key1", "piiak_team-a_key2"]
                rate_limit: "100/minute"
                max_ttl: 600
        """
        path = Path(path)

        if not path.exists():
            logger.warning(f"Tenant configuration file not found: {path}")
            return cls()

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if data is None:
            return cls()

        config = cls()

        for tenant_data in data.get("tenants", []):
            # Parse status
            status_str = tenant_data.get("status", "active")
            try:
                status = TenantStatus(status_str.lower())
            except ValueError:
                status = TenantStatus.ACTIVE

            tenant = Tenant(
                tenant_id=tenant_data["tenant_id"],
                name=tenant_data["name"],
                status=status,
                api_keys=tenant_data.get("api_keys", []),
                config_path=tenant_data.get("config_path"),
                rate_limit=tenant_data.get("rate_limit", "60/minute"),
                max_ttl=tenant_data.get("max_ttl", 300),
                settings=tenant_data.get("settings", {}),
            )
            config.add_tenant(tenant)

        logger.info(
            f"Loaded {len(config.tenants)} tenants from configuration",
            extra={
                "event": "tenants_loaded",
                "source": str(path),
                "count": len(config.tenants),
            },
        )

        return config


# Global tenant configuration (singleton-like)
_tenant_config: Optional[TenantConfig] = None
_tenant_config_lock = threading.Lock()


def get_tenant_config() -> TenantConfig:
    """Get the global tenant configuration.

    Loads from PII_AIRLOCK_TENANT_CONFIG_PATH if set.

    Returns:
        Global TenantConfig instance.
    """
    global _tenant_config

    with _tenant_config_lock:
        if _tenant_config is None:
            import os

            config_path = os.getenv("PII_AIRLOCK_TENANT_CONFIG_PATH")
            if config_path:
                _tenant_config = TenantConfig.from_yaml(config_path)
            else:
                # Create default single-tenant config
                _tenant_config = TenantConfig()

    return _tenant_config


def reset_tenant_config() -> None:
    """Reset the global tenant configuration (for testing)."""
    global _tenant_config
    with _tenant_config_lock:
        _tenant_config = None


# Default tenant for backward compatibility
DEFAULT_TENANT_ID = "default"


def get_current_tenant(
    tenant_id: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Optional[Tenant]:
    """Get the current tenant from request context.

    Args:
        tenant_id: Optional tenant_id from X-Tenant-ID header.
        api_key: Optional API key from Authorization header.

    Returns:
        Tenant if found and active, None otherwise.

    The resolution order is:
    1. If api_key provided, lookup tenant by API key
    2. If tenant_id provided, lookup tenant by ID
    3. If multi-tenant disabled, return default tenant
    """
    import os

    # Check if multi-tenant is enabled
    multi_tenant_enabled = os.getenv("PII_AIRLOCK_MULTI_TENANT_ENABLED", "false").lower() == "true"

    if not multi_tenant_enabled:
        # Return default tenant for backward compatibility
        return Tenant(
            tenant_id=DEFAULT_TENANT_ID,
            name="Default Tenant",
            status=TenantStatus.ACTIVE,
        )

    config = get_tenant_config()

    # Try API key lookup first
    if api_key:
        tenant = config.get_tenant_by_api_key(api_key)
        if tenant and tenant.is_active:
            return tenant

    # Try tenant_id lookup
    if tenant_id:
        tenant = config.get_tenant(tenant_id)
        if tenant and tenant.is_active:
            return tenant

    # No valid tenant found
    logger.warning(
        "No valid tenant found for request",
        extra={
            "event": "tenant_not_found",
            "tenant_id": tenant_id,
            "api_key_prefix": api_key[:8] + "..." if api_key else None,
        },
    )

    return None
