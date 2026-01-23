"""
RBAC 模块测试

测试角色与权限管理功能：
- Permission 和 Role 枚举
- User 类和权限检查
- UserStore 线程安全存储
- 全局辅助函数
"""

import pytest
import threading
import time

from pii_airlock.auth.rbac import (
    Permission,
    Role,
    ROLE_PERMISSIONS,
    User,
    UserStore,
    get_user_store,
    reset_user_store,
    check_permission,
    has_role,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def user_store():
    """Create a fresh UserStore for each test."""
    return UserStore()


@pytest.fixture(autouse=True)
def reset_global_store():
    """Reset global user store before and after each test."""
    reset_user_store()
    yield
    reset_user_store()


# ============================================================================
# Permission and Role Tests
# ============================================================================


class TestPermissionEnum:
    """Test Permission enum values."""

    def test_permission_values(self):
        """Test that all permission values are correct."""
        assert Permission.LLM_USE == "llm.use"
        assert Permission.METRICS_VIEW == "metrics.view"
        assert Permission.AUDIT_VIEW == "audit.view"
        assert Permission.TENANT_MANAGE == "tenant.manage"
        assert Permission.KEY_MANAGE == "key.manage"
        assert Permission.QUOTA_VIEW == "quota.view"
        assert Permission.ADMIN_ALL == "admin.all"

    def test_permission_count(self):
        """Test that we have expected number of permissions."""
        assert len(Permission) == 7


class TestRoleEnum:
    """Test Role enum values."""

    def test_role_values(self):
        """Test that all role values are correct."""
        assert Role.ADMIN == "admin"
        assert Role.OPERATOR == "operator"
        assert Role.VIEWER == "viewer"
        assert Role.USER == "user"

    def test_role_count(self):
        """Test that we have expected number of roles."""
        assert len(Role) == 4


class TestRolePermissions:
    """Test default role permissions mapping."""

    def test_admin_has_all_permissions(self):
        """Admin role should have all permissions."""
        admin_perms = ROLE_PERMISSIONS[Role.ADMIN]
        assert Permission.LLM_USE in admin_perms
        assert Permission.METRICS_VIEW in admin_perms
        assert Permission.AUDIT_VIEW in admin_perms
        assert Permission.TENANT_MANAGE in admin_perms
        assert Permission.KEY_MANAGE in admin_perms
        assert Permission.QUOTA_VIEW in admin_perms
        assert Permission.ADMIN_ALL in admin_perms

    def test_operator_permissions(self):
        """Operator role should have limited permissions."""
        operator_perms = ROLE_PERMISSIONS[Role.OPERATOR]
        assert Permission.LLM_USE in operator_perms
        assert Permission.METRICS_VIEW in operator_perms
        assert Permission.QUOTA_VIEW in operator_perms
        # Should not have admin-only permissions
        assert Permission.ADMIN_ALL not in operator_perms
        assert Permission.TENANT_MANAGE not in operator_perms
        assert Permission.KEY_MANAGE not in operator_perms

    def test_viewer_permissions(self):
        """Viewer role should have read-only permissions."""
        viewer_perms = ROLE_PERMISSIONS[Role.VIEWER]
        assert Permission.METRICS_VIEW in viewer_perms
        assert Permission.AUDIT_VIEW in viewer_perms
        assert Permission.QUOTA_VIEW in viewer_perms
        # Should not have write permissions
        assert Permission.LLM_USE not in viewer_perms
        assert Permission.ADMIN_ALL not in viewer_perms

    def test_user_permissions(self):
        """User role should have minimal permissions."""
        user_perms = ROLE_PERMISSIONS[Role.USER]
        assert Permission.LLM_USE in user_perms
        assert len(user_perms) == 1


# ============================================================================
# User Class Tests
# ============================================================================


class TestUserClass:
    """Test User dataclass."""

    def test_user_creation_defaults(self):
        """Test user creation with default values."""
        user = User(user_id="u1", name="Test User", email="test@example.com")

        assert user.user_id == "u1"
        assert user.name == "Test User"
        assert user.email == "test@example.com"
        assert user.roles == [Role.USER]
        assert user.tenant_id is None
        assert user.is_active is True

    def test_user_creation_with_roles(self):
        """Test user creation with custom roles."""
        user = User(
            user_id="u2",
            name="Admin User",
            email="admin@example.com",
            roles=[Role.ADMIN, Role.OPERATOR],
            tenant_id="tenant-1",
            is_active=True,
        )

        assert user.roles == [Role.ADMIN, Role.OPERATOR]
        assert user.tenant_id == "tenant-1"

    def test_user_permissions_property(self):
        """Test that permissions property aggregates from all roles."""
        user = User(
            user_id="u3",
            name="Multi-role User",
            email="multi@example.com",
            roles=[Role.OPERATOR, Role.VIEWER],
        )

        perms = user.permissions
        # Should have permissions from both roles
        assert Permission.LLM_USE in perms  # from OPERATOR
        assert Permission.METRICS_VIEW in perms  # from both
        assert Permission.AUDIT_VIEW in perms  # from VIEWER
        assert Permission.QUOTA_VIEW in perms  # from both

    def test_has_permission_direct(self):
        """Test has_permission for direct permission."""
        user = User(
            user_id="u4",
            name="Operator",
            email="op@example.com",
            roles=[Role.OPERATOR],
        )

        assert user.has_permission(Permission.LLM_USE) is True
        assert user.has_permission(Permission.AUDIT_VIEW) is False

    def test_has_permission_admin_all(self):
        """Test that ADMIN_ALL grants all permissions."""
        admin = User(
            user_id="admin",
            name="Admin",
            email="admin@example.com",
            roles=[Role.ADMIN],
        )

        # Admin should have all permissions via ADMIN_ALL
        assert admin.has_permission(Permission.LLM_USE) is True
        assert admin.has_permission(Permission.TENANT_MANAGE) is True
        assert admin.has_permission(Permission.KEY_MANAGE) is True

    def test_has_role(self):
        """Test has_role method."""
        user = User(
            user_id="u5",
            name="Viewer",
            email="viewer@example.com",
            roles=[Role.VIEWER],
        )

        assert user.has_role(Role.VIEWER) is True
        assert user.has_role(Role.ADMIN) is False
        assert user.has_role(Role.USER) is False

    def test_permissions_empty_roles(self):
        """Test permissions with empty roles list."""
        user = User(
            user_id="u6",
            name="No Role User",
            email="norole@example.com",
            roles=[],
        )

        assert len(user.permissions) == 0
        assert user.has_permission(Permission.LLM_USE) is False


# ============================================================================
# UserStore Tests
# ============================================================================


class TestUserStore:
    """Test UserStore class."""

    def test_create_user(self, user_store):
        """Test creating a user."""
        user = user_store.create_user(
            user_id="u1",
            name="Test User",
            email="test@example.com",
        )

        assert user.user_id == "u1"
        assert user.name == "Test User"
        assert user.email == "test@example.com"
        assert user.is_active is True

    def test_create_user_with_roles(self, user_store):
        """Test creating a user with specific roles."""
        user = user_store.create_user(
            user_id="admin1",
            name="Admin User",
            email="admin@example.com",
            roles=[Role.ADMIN],
            tenant_id="tenant-1",
        )

        assert user.roles == [Role.ADMIN]
        assert user.tenant_id == "tenant-1"

    def test_get_user(self, user_store):
        """Test getting a user by ID."""
        user_store.create_user("u1", "Test", "test@example.com")

        user = user_store.get_user("u1")
        assert user is not None
        assert user.user_id == "u1"

        # Non-existent user
        assert user_store.get_user("nonexistent") is None

    def test_get_user_by_email(self, user_store):
        """Test getting a user by email."""
        user_store.create_user("u1", "Test", "test@example.com")

        user = user_store.get_user_by_email("test@example.com")
        assert user is not None
        assert user.email == "test@example.com"

        # Non-existent email
        assert user_store.get_user_by_email("nonexistent@example.com") is None

    def test_update_user_roles(self, user_store):
        """Test updating user roles."""
        user_store.create_user("u1", "Test", "test@example.com", roles=[Role.USER])

        updated = user_store.update_user_roles("u1", [Role.ADMIN, Role.OPERATOR])

        assert updated is not None
        assert Role.ADMIN in updated.roles
        assert Role.OPERATOR in updated.roles
        assert Role.USER not in updated.roles

    def test_update_user_roles_nonexistent(self, user_store):
        """Test updating roles for non-existent user."""
        result = user_store.update_user_roles("nonexistent", [Role.ADMIN])
        assert result is None

    def test_deactivate_user(self, user_store):
        """Test deactivating a user."""
        user_store.create_user("u1", "Test", "test@example.com")

        result = user_store.deactivate_user("u1")
        assert result is True

        user = user_store.get_user("u1")
        assert user.is_active is False

    def test_deactivate_user_nonexistent(self, user_store):
        """Test deactivating non-existent user."""
        result = user_store.deactivate_user("nonexistent")
        assert result is False

    def test_list_users(self, user_store):
        """Test listing users."""
        user_store.create_user("u1", "User 1", "u1@example.com")
        user_store.create_user("u2", "User 2", "u2@example.com")
        user_store.create_user("u3", "User 3", "u3@example.com")

        users = user_store.list_users()
        assert len(users) == 3

    def test_list_users_by_tenant(self, user_store):
        """Test listing users filtered by tenant."""
        user_store.create_user("u1", "User 1", "u1@example.com", tenant_id="tenant-a")
        user_store.create_user("u2", "User 2", "u2@example.com", tenant_id="tenant-b")
        user_store.create_user("u3", "User 3", "u3@example.com", tenant_id="tenant-a")

        tenant_a_users = user_store.list_users(tenant_id="tenant-a")
        assert len(tenant_a_users) == 2
        assert all(u.tenant_id == "tenant-a" for u in tenant_a_users)

    def test_list_users_by_role(self, user_store):
        """Test listing users filtered by role."""
        user_store.create_user("u1", "User 1", "u1@example.com", roles=[Role.ADMIN])
        user_store.create_user("u2", "User 2", "u2@example.com", roles=[Role.USER])
        user_store.create_user("u3", "User 3", "u3@example.com", roles=[Role.ADMIN, Role.OPERATOR])

        admins = user_store.list_users(role=Role.ADMIN)
        assert len(admins) == 2

    def test_list_users_combined_filters(self, user_store):
        """Test listing users with combined filters."""
        user_store.create_user("u1", "User 1", "u1@example.com", roles=[Role.ADMIN], tenant_id="t1")
        user_store.create_user("u2", "User 2", "u2@example.com", roles=[Role.ADMIN], tenant_id="t2")
        user_store.create_user("u3", "User 3", "u3@example.com", roles=[Role.USER], tenant_id="t1")

        result = user_store.list_users(tenant_id="t1", role=Role.ADMIN)
        assert len(result) == 1
        assert result[0].user_id == "u1"


class TestUserStoreThreadSafety:
    """Test UserStore thread safety."""

    def test_concurrent_user_creation(self, user_store):
        """Test creating users concurrently."""
        errors = []

        def create_user(i):
            try:
                user_store.create_user(
                    f"user_{i}",
                    f"User {i}",
                    f"user{i}@example.com",
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create_user, args=(i,)) for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(user_store.list_users()) == 100

    def test_concurrent_read_write(self, user_store):
        """Test concurrent reads and writes."""
        user_store.create_user("u1", "User 1", "u1@example.com")
        errors = []

        def reader():
            for _ in range(50):
                try:
                    user_store.get_user("u1")
                    user_store.list_users()
                except Exception as e:
                    errors.append(e)

        def writer():
            for i in range(50):
                try:
                    user_store.update_user_roles(
                        "u1",
                        [Role.USER] if i % 2 == 0 else [Role.ADMIN],
                    )
                except Exception as e:
                    errors.append(e)

        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=reader),
            threading.Thread(target=writer),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


# ============================================================================
# Global Function Tests
# ============================================================================


class TestGlobalFunctions:
    """Test global helper functions."""

    def test_get_user_store_singleton(self):
        """Test that get_user_store returns singleton."""
        store1 = get_user_store()
        store2 = get_user_store()
        assert store1 is store2

    def test_get_user_store_creates_default_admin(self):
        """Test that default admin user is created."""
        store = get_user_store()
        admin = store.get_user("admin")

        assert admin is not None
        assert admin.name == "Default Admin"
        assert Role.ADMIN in admin.roles

    def test_reset_user_store(self):
        """Test resetting the global store."""
        store1 = get_user_store()
        store1.create_user("test", "Test", "test@example.com")

        reset_user_store()

        store2 = get_user_store()
        # Should be a new store (no test user)
        assert store2.get_user("test") is None
        # But should have default admin
        assert store2.get_user("admin") is not None

    def test_check_permission_function(self):
        """Test check_permission helper function."""
        user = User(
            user_id="u1",
            name="Test",
            email="test@example.com",
            roles=[Role.OPERATOR],
        )

        assert check_permission(user, Permission.LLM_USE) is True
        assert check_permission(user, Permission.TENANT_MANAGE) is False

    def test_has_role_function(self):
        """Test has_role helper function."""
        user = User(
            user_id="u1",
            name="Test",
            email="test@example.com",
            roles=[Role.VIEWER, Role.USER],
        )

        assert has_role(user, Role.VIEWER) is True
        assert has_role(user, Role.USER) is True
        assert has_role(user, Role.ADMIN) is False


# ============================================================================
# Edge Cases
# ============================================================================


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_user_with_duplicate_roles(self):
        """Test user with duplicate roles."""
        user = User(
            user_id="u1",
            name="Test",
            email="test@example.com",
            roles=[Role.USER, Role.USER, Role.USER],
        )

        # Permissions should still work correctly
        assert Permission.LLM_USE in user.permissions

    def test_empty_email(self, user_store):
        """Test creating user with empty email."""
        user = user_store.create_user("u1", "Test", "")
        assert user.email == ""

    def test_special_characters_in_user_id(self, user_store):
        """Test user ID with special characters."""
        user_id = "user-123_abc@test"
        user = user_store.create_user(user_id, "Test", "test@example.com")

        retrieved = user_store.get_user(user_id)
        assert retrieved is not None
        assert retrieved.user_id == user_id

    def test_unicode_names(self, user_store):
        """Test user with Unicode names."""
        user = user_store.create_user(
            "u1",
            "张三",
            "zhangsan@example.com",
        )

        assert user.name == "张三"
        retrieved = user_store.get_user("u1")
        assert retrieved.name == "张三"

    def test_overwrite_user(self, user_store):
        """Test creating user with existing ID overwrites."""
        user_store.create_user("u1", "Original", "original@example.com")
        user_store.create_user("u1", "Overwritten", "new@example.com")

        user = user_store.get_user("u1")
        assert user.name == "Overwritten"
        assert user.email == "new@example.com"
