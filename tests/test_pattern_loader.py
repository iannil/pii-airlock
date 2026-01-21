"""Unit tests for pattern loader and custom recognizer factory."""

import pytest
from pathlib import Path
import tempfile
import yaml

from pii_airlock.config.pattern_loader import (
    PatternConfig,
    load_patterns_from_yaml,
    load_patterns_from_yaml_safe,
)
from pii_airlock.recognizers.custom_pattern import (
    create_recognizer_from_config,
    create_recognizers_from_configs,
)


class TestPatternConfig:
    """Tests for PatternConfig dataclass."""

    def test_valid_config(self):
        """Test creating a valid pattern config."""
        config = PatternConfig(
            name="test_pattern",
            entity_type="TEST_ENTITY",
            regex="TEST\\d+",
            score=0.8,
            context=["test", "example"],
        )
        assert config.name == "test_pattern"
        assert config.entity_type == "TEST_ENTITY"
        assert config.regex == "TEST\\d+"
        assert config.score == 0.8
        assert config.context == ["test", "example"]

    def test_default_values(self):
        """Test default values for optional fields."""
        config = PatternConfig(
            name="test",
            entity_type="TEST",
            regex="TEST",
        )
        assert config.score == 0.7
        assert config.context == []

    def test_invalid_empty_name(self):
        """Test that empty name raises ValueError."""
        with pytest.raises(ValueError, match="name cannot be empty"):
            PatternConfig(name="", entity_type="TEST", regex="TEST")

    def test_invalid_empty_entity_type(self):
        """Test that empty entity_type raises ValueError."""
        with pytest.raises(ValueError, match="Entity type cannot be empty"):
            PatternConfig(name="test", entity_type="", regex="TEST")

    def test_invalid_empty_regex(self):
        """Test that empty regex raises ValueError."""
        with pytest.raises(ValueError, match="Regex pattern cannot be empty"):
            PatternConfig(name="test", entity_type="TEST", regex="")

    def test_invalid_score_too_low(self):
        """Test that score below 0 raises ValueError."""
        with pytest.raises(ValueError, match="Score must be between"):
            PatternConfig(name="test", entity_type="TEST", regex="TEST", score=-0.1)

    def test_invalid_score_too_high(self):
        """Test that score above 1 raises ValueError."""
        with pytest.raises(ValueError, match="Score must be between"):
            PatternConfig(name="test", entity_type="TEST", regex="TEST", score=1.1)


class TestLoadPatternsFromYaml:
    """Tests for loading patterns from YAML files."""

    def test_load_valid_yaml(self):
        """Test loading a valid YAML configuration."""
        yaml_content = """
patterns:
  - name: employee_id
    entity_type: EMPLOYEE_ID
    regex: "EMP[A-Z]\\\\d{6}"
    score: 0.85
    context:
      - employee
      - id
  - name: project_code
    entity_type: PROJECT_CODE
    regex: "PROJ-\\\\d{4}"
    score: 0.9
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            path = Path(f.name)

        try:
            patterns = load_patterns_from_yaml(path)
            assert len(patterns) == 2

            assert patterns[0].name == "employee_id"
            assert patterns[0].entity_type == "EMPLOYEE_ID"
            assert patterns[0].score == 0.85
            assert patterns[0].context == ["employee", "id"]

            assert patterns[1].name == "project_code"
            assert patterns[1].entity_type == "PROJECT_CODE"
            assert patterns[1].score == 0.9
        finally:
            path.unlink()

    def test_load_empty_yaml(self):
        """Test loading an empty YAML file returns empty list."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("")
            f.flush()
            path = Path(f.name)

        try:
            patterns = load_patterns_from_yaml(path)
            assert patterns == []
        finally:
            path.unlink()

    def test_load_yaml_no_patterns(self):
        """Test loading YAML with empty patterns list."""
        yaml_content = "patterns: []"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            path = Path(f.name)

        try:
            patterns = load_patterns_from_yaml(path)
            assert patterns == []
        finally:
            path.unlink()

    def test_load_nonexistent_file(self):
        """Test loading from nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_patterns_from_yaml(Path("/nonexistent/file.yaml"))

    def test_load_invalid_yaml_structure(self):
        """Test loading invalid YAML structure raises ValueError."""
        yaml_content = "- just a list"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="expected dict"):
                load_patterns_from_yaml(path)
        finally:
            path.unlink()

    def test_load_missing_required_field(self):
        """Test loading pattern missing required field raises ValueError."""
        yaml_content = """
patterns:
  - name: test
    entity_type: TEST
    # missing regex
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="missing required field: regex"):
                load_patterns_from_yaml(path)
        finally:
            path.unlink()


class TestLoadPatternsFromYamlSafe:
    """Tests for safe loading with error handling."""

    def test_safe_load_success(self):
        """Test safe loading returns patterns on success."""
        yaml_content = """
patterns:
  - name: test
    entity_type: TEST
    regex: "TEST"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            path = Path(f.name)

        try:
            patterns, error = load_patterns_from_yaml_safe(path)
            assert error is None
            assert len(patterns) == 1
        finally:
            path.unlink()

    def test_safe_load_file_not_found(self):
        """Test safe loading returns error for missing file."""
        patterns, error = load_patterns_from_yaml_safe(Path("/nonexistent.yaml"))
        assert patterns == []
        assert error is not None
        assert "not found" in error.lower()

    def test_safe_load_invalid_yaml(self):
        """Test safe loading returns error for invalid YAML."""
        yaml_content = "patterns: {{ invalid }}"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            path = Path(f.name)

        try:
            patterns, error = load_patterns_from_yaml_safe(path)
            assert patterns == []
            assert error is not None
        finally:
            path.unlink()


class TestCreateRecognizerFromConfig:
    """Tests for creating recognizers from config."""

    def test_create_recognizer(self):
        """Test creating a recognizer from config."""
        config = PatternConfig(
            name="employee_id",
            entity_type="EMPLOYEE_ID",
            regex="EMP[A-Z]\\d{6}",
            score=0.85,
            context=["员工", "employee"],
        )

        recognizer = create_recognizer_from_config(config, language="zh")

        assert recognizer.supported_entities == ["EMPLOYEE_ID"]
        assert recognizer.supported_language == "zh"
        assert recognizer.name == "CustomEmployeeIdRecognizer"
        assert len(recognizer.patterns) == 1
        assert recognizer.patterns[0].score == 0.85

    def test_create_recognizer_default_language(self):
        """Test default language is zh."""
        config = PatternConfig(
            name="test",
            entity_type="TEST",
            regex="TEST",
        )

        recognizer = create_recognizer_from_config(config)
        assert recognizer.supported_language == "zh"

    def test_recognizer_can_analyze(self):
        """Test that created recognizer can analyze text."""
        config = PatternConfig(
            name="employee_id",
            entity_type="EMPLOYEE_ID",
            regex="EMPA\\d{6}",
            score=0.85,
        )

        recognizer = create_recognizer_from_config(config)
        results = recognizer.analyze("员工编号 EMPA123456", entities=["EMPLOYEE_ID"])

        assert len(results) == 1
        assert results[0].entity_type == "EMPLOYEE_ID"
        assert results[0].score == 0.85


class TestCreateRecognizersFromConfigs:
    """Tests for batch recognizer creation."""

    def test_create_multiple_recognizers(self):
        """Test creating multiple recognizers from configs."""
        configs = [
            PatternConfig(name="pattern1", entity_type="TYPE1", regex="P1\\d+"),
            PatternConfig(name="pattern2", entity_type="TYPE2", regex="P2\\d+"),
            PatternConfig(name="pattern3", entity_type="TYPE3", regex="P3\\d+"),
        ]

        recognizers = create_recognizers_from_configs(configs)

        assert len(recognizers) == 3
        assert recognizers[0].supported_entities == ["TYPE1"]
        assert recognizers[1].supported_entities == ["TYPE2"]
        assert recognizers[2].supported_entities == ["TYPE3"]

    def test_create_empty_list(self):
        """Test creating from empty list returns empty list."""
        recognizers = create_recognizers_from_configs([])
        assert recognizers == []
