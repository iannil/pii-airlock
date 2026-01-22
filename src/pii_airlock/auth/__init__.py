"""Authentication and authorization module for PII-AIRLOCK.

This module provides:
- Multi-tenant support (tenant.py)
- API key management (api_key.py)
- Role-based access control (rbac.py)
- Quota management (quota.py)
"""

from pii_airlock.auth.tenant import Tenant, TenantConfig, get_current_tenant
from pii_airlock.auth.api_key import APIKey, APIKeyStore, validate_api_key
from pii_airlock.auth.rbac import Role, Permission, check_permission, has_role
from pii_airlock.auth.quota import QuotaConfig, QuotaStore, check_quota

__all__ = [
    "Tenant",
    "TenantConfig",
    "get_current_tenant",
    "APIKey",
    "APIKeyStore",
    "validate_api_key",
    "Role",
    "Permission",
    "check_permission",
    "has_role",
    "QuotaConfig",
    "QuotaStore",
    "check_quota",
]
