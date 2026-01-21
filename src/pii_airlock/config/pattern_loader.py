"""YAML configuration loader for custom PII patterns.

This module provides functionality to load custom PII recognition patterns
from YAML configuration files, allowing enterprises to define their own
sensitive data patterns without modifying code.

Example YAML configuration:

    patterns:
      - name: employee_id
        entity_type: EMPLOYEE_ID
        regex: "EMP[A-Z]\\d{6}"
        score: 0.85
        context: ["员工", "工号", "employee"]
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class PatternConfig:
    """Configuration for a single PII pattern.

    Attributes:
        name: Unique identifier for the pattern.
        entity_type: The PII entity type (e.g., EMPLOYEE_ID, PROJECT_CODE).
        regex: Regular expression pattern to match the PII.
        score: Confidence score for matches (0.0 to 1.0).
        context: List of context words that increase match confidence.
    """

    name: str
    entity_type: str
    regex: str
    score: float = 0.7
    context: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate configuration values."""
        if not self.name:
            raise ValueError("Pattern name cannot be empty")
        if not self.entity_type:
            raise ValueError("Entity type cannot be empty")
        if not self.regex:
            raise ValueError("Regex pattern cannot be empty")
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"Score must be between 0.0 and 1.0, got {self.score}")


def load_patterns_from_yaml(path: Path | str) -> list[PatternConfig]:
    """Load pattern configurations from a YAML file.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        List of PatternConfig objects.

    Raises:
        FileNotFoundError: If the configuration file doesn't exist.
        ValueError: If the YAML structure is invalid.
        yaml.YAMLError: If the YAML is malformed.

    Example:
        >>> patterns = load_patterns_from_yaml("config/custom_patterns.yaml")
        >>> for p in patterns:
        ...     print(f"{p.name}: {p.entity_type}")
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if data is None:
        return []

    if not isinstance(data, dict):
        raise ValueError(f"Invalid YAML structure: expected dict, got {type(data).__name__}")

    patterns_data = data.get("patterns", [])

    if not isinstance(patterns_data, list):
        raise ValueError(
            f"Invalid patterns structure: expected list, got {type(patterns_data).__name__}"
        )

    patterns = []
    for i, p in enumerate(patterns_data):
        if not isinstance(p, dict):
            raise ValueError(f"Pattern {i} is not a dict: {type(p).__name__}")

        # Check required fields
        if "name" not in p:
            raise ValueError(f"Pattern {i} missing required field: name")
        if "entity_type" not in p:
            raise ValueError(f"Pattern {i} missing required field: entity_type")
        if "regex" not in p:
            raise ValueError(f"Pattern {i} missing required field: regex")

        patterns.append(
            PatternConfig(
                name=p["name"],
                entity_type=p["entity_type"],
                regex=p["regex"],
                score=p.get("score", 0.7),
                context=p.get("context", []),
            )
        )

    return patterns


def load_patterns_from_yaml_safe(path: Path | str) -> tuple[list[PatternConfig], Optional[str]]:
    """Load patterns with error handling, returning any error message.

    This is a convenience wrapper around load_patterns_from_yaml that
    catches exceptions and returns them as error messages instead.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        Tuple of (patterns, error_message). If successful, error_message is None.
        If failed, patterns is an empty list.

    Example:
        >>> patterns, error = load_patterns_from_yaml_safe("config/patterns.yaml")
        >>> if error:
        ...     print(f"Warning: {error}")
        >>> else:
        ...     print(f"Loaded {len(patterns)} patterns")
    """
    try:
        patterns = load_patterns_from_yaml(path)
        return patterns, None
    except FileNotFoundError as e:
        return [], str(e)
    except ValueError as e:
        return [], f"Configuration error: {e}"
    except yaml.YAMLError as e:
        return [], f"YAML parsing error: {e}"
    except Exception as e:
        return [], f"Unexpected error loading patterns: {e}"
