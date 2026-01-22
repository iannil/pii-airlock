"""Role-Based Access Control (RBAC) for PII-AIRLOCK.

This module provides role and permission management for authorization.

Roles:
    - Admin: Full access to all resources
    - Operator: Can use LLM API and view metrics
    - Viewer: Read-only access to metrics and logs
    - User: Can only use the LLM API

Permissions:
    - llm.use: Call LLM endpoints
    - metrics.view: View Prometheus metrics
    - audit.view: View audit logs
    - tenant.manage: Manage tenants
    - key.manage: Manage API keys
    - quota.view: View quota usage
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set, Optional
import threading

from pii_airlock.logging.setup import get_logger

logger = get_logger(__name__)


class Permission(str, Enum):
    """Permission types."""

    LLM_USE = "llm.use"
    METRICS_VIEW = "metrics.view"
    AUDIT_VIEW = "audit.view"
    TENANT_MANAGE = "tenant.manage"
    KEY_MANAGE = "key.manage"
    QUOTA_VIEW = "quota.view"
    ADMIN_ALL = "admin.all"


class Role(str, Enum):
    """User roles."""

    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    USER = "user"


# Default permissions for each role
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {
        Permission.LLM_USE,
        Permission.METRICS_VIEW,
        Permission.AUDIT_VIEW,
        Permission.TENANT_MANAGE,
        Permission.KEY_MANAGE,
        Permission.QUOTA_VIEW,
        Permission.ADMIN_ALL,
    },
    Role.OPERATOR: {
        Permission.LLM_USE,
        Permission.METRICS_VIEW,
        Permission.QUOTA_VIEW,
    },
    Role.VIEWER: {
        Permission.METRICS_VIEW,
        Permission.AUDIT_VIEW,
        Permission.QUOTA_VIEW,
    },
    Role.USER: {
        Permission.LLM_USE,
    },
}


@dataclass
class User:
    """A user with roles and permissions.

    Attributes:
        user_id: Unique user identifier.
        name: Human-readable name.
        email: Email address.
        roles: List of assigned roles.
        tenant_id: Associated tenant ID.
        is_active: Whether the user is active.
    """

    user_id: str
    name: str
    email: str
    roles: List[Role] = field(default_factory=lambda: [Role.USER])
    tenant_id: Optional[str] = None
    is_active: bool = True

    @property
    def permissions(self) -> Set[Permission]:
        """Get all permissions from assigned roles."""
        perms: Set[Permission] = set()
        for role in self.roles:
            perms.update(ROLE_PERMISSIONS.get(role, set()))
        return perms

    def has_permission(self, permission: Permission) -> bool:
        """Check if user has a specific permission."""
        return permission in self.permissions or Permission.ADMIN_ALL in self.permissions

    def has_role(self, role: Role) -> bool:
        """Check if user has a specific role."""
        return role in self.roles


class UserStore:
    """Storage backend for users.

    Thread-safe in-memory storage.
    """

    def __init__(self) -> None:
        """Initialize the user store."""
        self._users: Dict[str, User] = {}  # user_id -> User
        self._email_index: Dict[str, str] = {}  # email -> user_id
        self._lock = threading.RLock()

    def create_user(
        self,
        user_id: str,
        name: str,
        email: str,
        roles: Optional[List[Role]] = None,
        tenant_id: Optional[str] = None,
    ) -> User:
        """Create a new user.

        Args:
            user_id: Unique user identifier.
            name: Human-readable name.
            email: Email address.
            roles: List of roles (default: [USER]).
            tenant_id: Associated tenant ID.

        Returns:
            Created User instance.
        """
        user = User(
            user_id=user_id,
            name=name,
            email=email,
            roles=roles or [Role.USER],
            tenant_id=tenant_id,
            is_active=True,
        )

        with self._lock:
            self._users[user_id] = user
            self._email_index[email] = user_id

        logger.info(
            "User created",
            extra={
                "event": "user_created",
                "user_id": user_id,
                "email": email,
                "roles": [r.value for r in user.roles],
            },
        )

        return user

    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID.

        Args:
            user_id: The user identifier.

        Returns:
            User if found, None otherwise.
        """
        with self._lock:
            return self._users.get(user_id)

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email.

        Args:
            email: The email address.

        Returns:
            User if found, None otherwise.
        """
        with self._lock:
            user_id = self._email_index.get(email)
            return self._users.get(user_id) if user_id else None

    def update_user_roles(self, user_id: str, roles: List[Role]) -> Optional[User]:
        """Update user roles.

        Args:
            user_id: The user identifier.
            roles: New list of roles.

        Returns:
            Updated User if found, None otherwise.
        """
        with self._lock:
            user = self._users.get(user_id)
            if not user:
                return None

            user.roles = roles

        logger.info(
            "User roles updated",
            extra={
                "event": "user_roles_updated",
                "user_id": user_id,
                "roles": [r.value for r in roles],
            },
        )

        return user

    def deactivate_user(self, user_id: str) -> bool:
        """Deactivate a user.

        Args:
            user_id: The user identifier.

        Returns:
            True if deactivated, False if not found.
        """
        with self._lock:
            user = self._users.get(user_id)
            if not user:
                return False

            user.is_active = False

        logger.info(
            "User deactivated",
            extra={
                "event": "user_deactivated",
                "user_id": user_id,
            },
        )

        return True

    def list_users(
        self,
        tenant_id: Optional[str] = None,
        role: Optional[Role] = None,
    ) -> List[User]:
        """List users, optionally filtered.

        Args:
            tenant_id: Filter by tenant ID.
            role: Filter by role.

        Returns:
            List of users.
        """
        with self._lock:
            users = list(self._users.values())

            if tenant_id:
                users = [u for u in users if u.tenant_id == tenant_id]

            if role:
                users = [u for u in users if role in u.roles]

            return users


# Global user store (singleton-like)
_user_store: Optional[UserStore] = None
_user_store_lock = threading.Lock()


def get_user_store() -> UserStore:
    """Get the global user store.

    Returns:
        Global UserStore instance.
    """
    global _user_store

    with _user_store_lock:
        if _user_store is None:
            _user_store = UserStore()
            # Create default admin user
            _user_store.create_user(
                user_id="admin",
                name="Default Admin",
                email="admin@pii-airlock.local",
                roles=[Role.ADMIN],
            )

    return _user_store


def reset_user_store() -> None:
    """Reset the global user store (for testing)."""
    global _user_store
    with _user_store_lock:
        _user_store = None


def check_permission(user: User, permission: Permission) -> bool:
    """Check if a user has a specific permission.

    Args:
        user: The user to check.
        permission: The required permission.

    Returns:
        True if user has permission, False otherwise.
    """
    return user.has_permission(permission)


def has_role(user: User, role: Role) -> bool:
    """Check if a user has a specific role.

    Args:
        user: The user to check.
        role: The role to check for.

    Returns:
        True if user has role, False otherwise.
    """
    return user.has_role(role)
