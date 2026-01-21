"""Unit tests for the Mapping module."""

import pytest
from pii_airlock.core.mapping import PIIMapping


class TestPIIMapping:
    """Tests for PIIMapping class."""

    def test_add_and_get_placeholder(self):
        """Test adding and retrieving by placeholder."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        assert mapping.get_original("<PERSON_1>") == "张三"
        assert mapping.get_placeholder("PERSON", "张三") == "<PERSON_1>"

    def test_add_multiple_types(self):
        """Test adding multiple PII types."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")
        mapping.add("PHONE", "13800138000", "<PHONE_1>")
        mapping.add("EMAIL", "test@example.com", "<EMAIL_1>")

        assert len(mapping) == 3
        assert mapping.get_original("<PERSON_1>") == "张三"
        assert mapping.get_original("<PHONE_1>") == "13800138000"
        assert mapping.get_original("<EMAIL_1>") == "test@example.com"

    def test_get_nonexistent(self):
        """Test getting nonexistent mappings."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        assert mapping.get_original("<PERSON_2>") is None
        assert mapping.get_placeholder("PHONE", "13800138000") is None

    def test_contains(self):
        """Test contains operator."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        assert "<PERSON_1>" in mapping
        assert "<PERSON_2>" not in mapping

    def test_session_id(self):
        """Test session ID assignment."""
        mapping = PIIMapping(session_id="test-session-123")
        assert mapping.session_id == "test-session-123"

    def test_to_dict_and_from_dict(self):
        """Test serialization and deserialization."""
        mapping = PIIMapping(session_id="test-session")
        mapping.add("PERSON", "张三", "<PERSON_1>")
        mapping.add("PHONE", "13800138000", "<PHONE_1>")

        # Serialize
        data = mapping.to_dict()
        assert data["session_id"] == "test-session"
        assert "PERSON" in data["mappings"]
        assert "PHONE" in data["mappings"]

        # Deserialize
        restored = PIIMapping.from_dict(data)
        assert restored.session_id == "test-session"
        assert restored.get_original("<PERSON_1>") == "张三"
        assert restored.get_original("<PHONE_1>") == "13800138000"

    def test_to_json_and_from_json(self):
        """Test JSON serialization."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        json_str = mapping.to_json()
        assert "张三" in json_str
        assert "<PERSON_1>" in json_str

        restored = PIIMapping.from_json(json_str)
        assert restored.get_original("<PERSON_1>") == "张三"

    def test_clear(self):
        """Test clearing mappings."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")
        mapping.add("PHONE", "13800138000", "<PHONE_1>")

        assert len(mapping) == 2

        mapping.clear()

        assert len(mapping) == 0
        assert mapping.get_original("<PERSON_1>") is None

    def test_get_all_placeholders(self):
        """Test getting all placeholders."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")
        mapping.add("PHONE", "13800138000", "<PHONE_1>")

        placeholders = mapping.get_all_placeholders()
        assert "<PERSON_1>" in placeholders
        assert "<PHONE_1>" in placeholders
        assert len(placeholders) == 2
