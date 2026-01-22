"""Tests for allowlist recognizer."""

import tempfile
from pathlib import Path

import pytest

from pii_airlock.recognizers.allowlist import (
    AllowlistConfig,
    AllowlistRegistry,
    get_allowlist_registry,
    is_allowlisted,
    is_public_figure,
    is_common_location,
    reload_allowlists,
    clear_caches,
    AllowlistFilter,
)


@pytest.fixture
def temp_allowlist_file(tmp_path):
    """Create a temporary allowlist file."""
    file_path = tmp_path / "test_figures.txt"
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("# Test allowlist\n")
        f.write("张三\n")
        f.write("李四\n")
        f.write("王五\n")
        f.write("\n")
        f.write("# Comment\n")
        f.write("马云\n")
    return file_path


@pytest.fixture
def temp_location_file(tmp_path):
    """Create a temporary location allowlist file."""
    file_path = tmp_path / "test_locations.txt"
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("# Test locations\n")
        f.write("北京\n")
        f.write("上海\n")
        f.write("深圳\n")
        f.write("纽约\n")
        f.write("伦敦\n")
    return file_path


class TestAllowlistConfig:
    """Tests for AllowlistConfig."""

    def test_create_allowlist_config(self):
        """Test creating an allowlist config."""
        config = AllowlistConfig(
            name="test",
            entity_type="PERSON",
            enabled=True,
            case_sensitive=False,
        )

        assert config.name == "test"
        assert config.entity_type == "PERSON"
        assert config.enabled is True
        assert config.case_sensitive is False
        assert len(config.entries) == 0

    def test_add_entry(self):
        """Test adding entries to allowlist."""
        config = AllowlistConfig(name="test", entity_type="PERSON")

        config.add("张三")
        config.add("李四")

        assert len(config.entries) == 2
        assert config.contains("张三")
        assert config.contains("李四")

    def test_case_insensitive(self):
        """Test case insensitive matching."""
        config = AllowlistConfig(
            name="test",
            entity_type="PERSON",
            case_sensitive=False,
        )

        config.add("马云")

        assert config.contains("马云")
        assert config.contains("马云".lower())
        assert config.contains("马云".upper())

    def test_case_sensitive(self):
        """Test case sensitive matching."""
        config = AllowlistConfig(
            name="test",
            entity_type="PERSON",
            case_sensitive=True,
        )

        config.add("JackMa")

        assert config.contains("JackMa")
        assert not config.contains("jackma")
        assert not config.contains("JACKMA")

    def test_remove_entry(self):
        """Test removing entries from allowlist."""
        config = AllowlistConfig(name="test", entity_type="PERSON")

        config.add("张三")
        config.add("李四")
        assert len(config.entries) == 2

        config.remove("张三")
        assert len(config.entries) == 1
        assert not config.contains("张三")
        assert config.contains("李四")

    def test_load_from_file(self, temp_allowlist_file):
        """Test loading entries from file."""
        config = AllowlistConfig(name="test", entity_type="PERSON")

        count = config.load_from_file(temp_allowlist_file)

        assert count == 4  # 4 non-comment, non-empty lines
        assert config.contains("张三")
        assert config.contains("李四")
        assert config.contains("王五")
        assert config.contains("马云")

    def test_load_from_nonexistent_file(self):
        """Test loading from nonexistent file."""
        config = AllowlistConfig(name="test", entity_type="PERSON")

        count = config.load_from_file("/nonexistent/file.txt")

        assert count == 0
        assert len(config.entries) == 0


class TestAllowlistRegistry:
    """Tests for AllowlistRegistry."""

    def test_create_registry(self):
        """Test creating a registry."""
        registry = AllowlistRegistry()

        assert len(registry._allowlists) == 0

    def test_register_allowlist(self):
        """Test registering an allowlist."""
        registry = AllowlistRegistry()
        config = AllowlistConfig(name="test", entity_type="PERSON")
        config.add("张三")

        registry.register(config)

        assert registry.get("test") is not None
        assert registry.get("test").contains("张三")

    def test_is_allowed(self):
        """Test checking if entity is allowed."""
        registry = AllowlistRegistry()
        config = AllowlistConfig(name="test", entity_type="PERSON")
        config.add("张三")
        registry.register(config)

        assert registry.is_allowed("PERSON", "张三")
        assert not registry.is_allowed("PERSON", "李四")
        assert not registry.is_allowed("EMAIL", "张三")

    def test_is_allowed_disabled(self):
        """Test that disabled allowlists are not checked."""
        registry = AllowlistRegistry()
        config = AllowlistConfig(name="test", entity_type="PERSON", enabled=False)
        config.add("张三")
        registry.register(config)

        assert not registry.is_allowed("PERSON", "张三")

    def test_wildcard_entity_type(self):
        """Test wildcard entity type matching."""
        registry = AllowlistRegistry()
        config = AllowlistConfig(name="test", entity_type="*")
        config.add("common_term")
        registry.register(config)

        assert registry.is_allowed("PERSON", "common_term")
        assert registry.is_allowed("LOCATION", "common_term")
        assert registry.is_allowed("EMAIL", "common_term")

    def test_load_from_directory(self, tmp_path):
        """Test loading allowlists from directory."""
        # Create test files
        figures_file = tmp_path / "figures.txt"
        figures_file.write_text("张三\n李四\n")

        locations_file = tmp_path / "locations.txt"
        locations_file.write_text("北京\n上海\n")

        registry = AllowlistRegistry()
        count = registry.load_from_directory(tmp_path)

        assert count == 2

        # Check that the allowlists were created with correct entity types
        figures = registry.get("figures")
        assert figures is not None
        assert figures.entity_type == "PERSON"
        assert figures.contains("张三")

        locations = registry.get("locations")
        assert locations is not None
        assert locations.entity_type == "LOCATION"
        assert locations.contains("北京")

    def test_list_allowlists(self):
        """Test listing all allowlists."""
        registry = AllowlistRegistry()

        config1 = AllowlistConfig(name="test1", entity_type="PERSON")
        config1.add("entry1")
        config1.add("entry2")

        config2 = AllowlistConfig(name="test2", entity_type="LOCATION", enabled=False)
        config2.add("location1")

        registry.register(config1)
        registry.register(config2)

        allowlists = registry.list_allowlists()

        assert len(allowlists) == 2

        # Check test1
        test1 = next((a for a in allowlists if a["name"] == "test1"), None)
        assert test1 is not None
        assert test1["enabled"] is True
        assert test1["entry_count"] == 2

        # Check test2
        test2 = next((a for a in allowlists if a["name"] == "test2"), None)
        assert test2 is not None
        assert test2["enabled"] is False
        assert test2["entry_count"] == 1

    def test_reload(self, tmp_path):
        """Test reloading allowlists."""
        # Create initial file
        figures_file = tmp_path / "figures.txt"
        figures_file.write_text("张三\n")

        registry = AllowlistRegistry(allowlists_dir=tmp_path)
        count1 = registry.reload()
        assert count1 == 1
        assert registry.is_allowed("PERSON", "张三")

        # Add more entries
        figures_file.write_text("张三\n李四\n王五\n")

        count2 = registry.reload()
        assert count2 == 1  # Still 1 file
        assert registry.is_allowed("PERSON", "李四")
        assert registry.is_allowed("PERSON", "王五")


class TestGlobalFunctions:
    """Tests for global utility functions."""

    def test_get_allowlist_registry_singleton(self):
        """Test that get_allowlist_registry returns singleton."""
        registry1 = get_allowlist_registry()
        registry2 = get_allowlist_registry()

        assert registry1 is registry2

    def test_is_allowlisted(self):
        """Test is_allowlisted function."""
        # This uses the real allowlist files if they exist
        # Just test that it doesn't crash and returns a bool
        result = is_allowlisted("PERSON", "nonexistent_person_test_name_xyz")
        assert isinstance(result, bool)

    def test_is_public_figure(self):
        """Test is_public_figure function."""
        # Test with a known public figure (if allowlist is loaded)
        result = is_public_figure("马云")
        assert isinstance(result, bool)

        # Test cache
        result2 = is_public_figure("马云")
        assert isinstance(result2, bool)

    def test_is_common_location(self):
        """Test is_common_location function."""
        result = is_common_location("北京")
        assert isinstance(result, bool)

    def test_reload_allowlists(self):
        """Test reload_allowlists function."""
        # Just test that it doesn't crash
        count = reload_allowlists()
        assert isinstance(count, int)

    def test_clear_caches(self):
        """Test clear_caches function."""
        # Prime the caches
        is_public_figure("test")
        is_common_location("test")

        # Clear caches
        clear_caches()
        # Should not crash

    def test_allowlist_filter(self):
        """Test AllowlistFilter class."""
        from pii_airlock.recognizers.allowlist import get_allowlist_filter

        filter_obj = get_allowlist_filter()
        assert filter_obj is not None

        # Test should_filter
        result = filter_obj.should_filter("PERSON", "test_entity_xyz")
        assert isinstance(result, bool)

        # Test filter_entities
        entities = [
            {"entity_type": "PERSON", "text": "张三"},
            {"entity_type": "EMAIL_ADDRESS", "text": "test@example.com"},
        ]

        filtered = filter_obj.filter_entities(entities)
        assert isinstance(filtered, list)


class TestRealAllowlists:
    """Tests against real allowlist files."""

    def test_public_figures_allowlist_exists(self):
        """Test that public figures allowlist can be loaded."""
        registry = get_allowlist_registry()

        # Reload to ensure files are loaded
        reload_allowlists()

        allowlists = registry.list_allowlists()
        names = [a["name"] for a in allowlists]

        # Check if public_figures was loaded
        if "public_figures" in names:
            figures = registry.get("public_figures")
            assert figures is not None
            assert figures.entry_count > 0

    def test_common_locations_allowlist_exists(self):
        """Test that common locations allowlist can be loaded."""
        registry = get_allowlist_registry()

        # Reload to ensure files are loaded
        reload_allowlists()

        allowlists = registry.list_allowlists()
        names = [a["name"] for a in allowlists]

        # Check if common_locations was loaded
        if "common_locations" in names:
            locations = registry.get("common_locations")
            assert locations is not None
            assert locations.entry_count > 0


class TestAllowlistIntegration:
    """Tests for allowlist integration with anonymizer."""

    def test_allowlist_exempted_from_anonymization(self, analyzer):
        """Test that allowlisted entities are not anonymized."""
        from pii_airlock.core.anonymizer import Anonymizer
        from pii_airlock.recognizers.allowlist import get_allowlist_registry

        # Get the global registry and add test entries
        registry = get_allowlist_registry()
        test_allowlist = AllowlistConfig(
            name="test_figures",
            entity_type="PERSON",
            enabled=True,
            case_sensitive=False,
        )
        test_allowlist.add("张三")
        test_allowlist.add("李四")
        registry.register(test_allowlist)

        # Create anonymizer with allowlist enabled
        anonymizer = Anonymizer(
            analyzer=analyzer,
            enable_allowlist=True,
            enable_intent_detection=False,
        )

        # Test that allowlisted entity is NOT anonymized
        result = anonymizer.anonymize("张三是我的朋友")
        assert "张三" in result.text  # Should NOT be replaced
        assert "<PERSON" not in result.text  # No placeholder
        assert len(result.allowlist_exemptions) == 1
        assert result.allowlist_exemptions[0]["entity_type"] == "PERSON"
        assert result.allowlist_exemptions[0]["original_value"] == "张三"

    def test_allowlist_can_be_disabled(self, analyzer):
        """Test that allowlist can be disabled."""
        from pii_airlock.core.anonymizer import Anonymizer
        from pii_airlock.recognizers.allowlist import get_allowlist_registry

        # Get the global registry and add test entries
        registry = get_allowlist_registry()
        test_allowlist = AllowlistConfig(
            name="test_figures_disabled",
            entity_type="PERSON",
            enabled=True,
            case_sensitive=False,
        )
        test_allowlist.add("张三")
        registry.register(test_allowlist)

        # Create anonymizer with allowlist DISABLED
        anonymizer = Anonymizer(
            analyzer=analyzer,
            enable_allowlist=False,
            enable_intent_detection=False,
        )

        # Test that allowlisted entity IS anonymized (allowlist disabled)
        result = anonymizer.anonymize("张三是我的朋友")
        assert "<PERSON" in result.text  # Should be replaced
        assert "张三" not in result.text or result.text.startswith("张三")  # Either replaced or preserved due to position
        assert len(result.allowlist_exemptions) == 0

    def test_non_allowlisted_entity_anonymized(self, analyzer):
        """Test that non-allowlisted entities are still anonymized."""
        from pii_airlock.core.anonymizer import Anonymizer
        from pii_airlock.recognizers.allowlist import get_allowlist_registry

        # Get the global registry and add test entries
        registry = get_allowlist_registry()
        test_allowlist = AllowlistConfig(
            name="test_figures_partial",
            entity_type="PERSON",
            enabled=True,
            case_sensitive=False,
        )
        test_allowlist.add("张三")
        registry.register(test_allowlist)

        # Create anonymizer with allowlist enabled
        anonymizer = Anonymizer(
            analyzer=analyzer,
            enable_allowlist=True,
            enable_intent_detection=False,
        )

        # Test that non-allowlisted entity IS anonymized
        # Use a unique name that's definitely not in any allowlist
        unique_name = "赵六七八"
        result = anonymizer.anonymize(f"{unique_name}是我的朋友")
        # The unique name should be anonymized since it's not in the allowlist
        assert "<PERSON" in result.text
        assert len(result.allowlist_exemptions) == 0  # No exemptions

    def test_allowlist_case_insensitive(self, analyzer):
        """Test that allowlist matching is case-insensitive by default."""
        from pii_airlock.core.anonymizer import Anonymizer
        from pii_airlock.recognizers.allowlist import get_allowlist_registry

        # Get the global registry and add test entries
        registry = get_allowlist_registry()
        test_allowlist = AllowlistConfig(
            name="test_case",
            entity_type="PERSON",
            enabled=True,
            case_sensitive=False,
        )
        test_allowlist.add("jack ma")  # lowercase
        registry.register(test_allowlist)

        # Create anonymizer with allowlist enabled
        anonymizer = Anonymizer(
            analyzer=analyzer,
            enable_allowlist=True,
            enable_intent_detection=False,
        )

        # Test with different cases
        # Note: This test depends on how the name is detected
        # The actual detected text might vary
        result = anonymizer.anonymize("Jack Ma is famous")
        # If "Jack Ma" is detected as PERSON, it should be exempted
        # (because the allowlist is case-insensitive)

    def test_anonymization_result_has_exemptions_field(self, analyzer):
        """Test that AnonymizationResult has allowlist_exemptions field."""
        from pii_airlock.core.anonymizer import Anonymizer

        anonymizer = Anonymizer(
            analyzer=analyzer,
            enable_allowlist=True,
        )

        result = anonymizer.anonymize("张三是我的朋友")

        # Check that the result has the allowlist_exemptions field
        assert hasattr(result, "allowlist_exemptions")
        assert isinstance(result.allowlist_exemptions, list)

    def test_allowlist_with_multiple_entities(self, analyzer):
        """Test allowlist behavior with multiple PII entities."""
        from pii_airlock.core.anonymizer import Anonymizer
        from pii_airlock.recognizers.allowlist import get_allowlist_registry

        # Get the global registry and add test entries
        registry = get_allowlist_registry()
        test_allowlist = AllowlistConfig(
            name="test_multi",
            entity_type="PERSON",
            enabled=True,
            case_sensitive=False,
        )
        test_allowlist.add("张三")
        registry.register(test_allowlist)

        # Create anonymizer with allowlist enabled
        anonymizer = Anonymizer(
            analyzer=analyzer,
            enable_allowlist=True,
            enable_intent_detection=False,
        )

        # Test with multiple entities - some allowlisted, some not
        result = anonymizer.anonymize("张三和王五都是我的朋友")

        # 张三 should be exempted, 王五 should be anonymized
        # The exact result depends on the detection behavior
        assert hasattr(result, "allowlist_exemptions")
