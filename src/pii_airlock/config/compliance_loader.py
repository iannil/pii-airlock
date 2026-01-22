"""Compliance preset loader for regulatory configurations.

This module provides functionality to load and manage compliance presets
for different regulatory frameworks (GDPR, CCPA, PIPL, Financial, etc.).

Compliance presets define:
- Which PII types must be protected
- Appropriate anonymization strategies for each type
- Data retention policies
- Compliance-specific rules and validations
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml


class ComplianceRegion(str, Enum):
    """Supported compliance regions."""

    EU = "EU"
    EEA = "EEA"
    US_CA = "US-CA"
    US = "US"
    CN = "CN"
    GLOBAL = "GLOBAL"


@dataclass
class ComplianceRiskConfig:
    """Risk scoring configuration for a compliance preset.

    Attributes:
        high_risk_types: PII types considered high risk.
        medium_risk_types: PII types considered medium risk.
        risk_factors: Multipliers for different data categories.
    """

    high_risk_types: list[str] = field(default_factory=list)
    medium_risk_types: list[str] = field(default_factory=list)
    risk_factors: dict[str, float] = field(default_factory=dict)


@dataclass
class ComplianceRetentionConfig:
    """Data retention configuration for a compliance preset.

    Attributes:
        mapping_ttl: Time to live for PII mappings in seconds.
        audit_retention_days: Days to retain audit logs.
        log_sensitive_content: Whether to log sensitive content.
        local_storage_reminder: Reminder for local storage requirements.
    """

    mapping_ttl: int = 300
    audit_retention_days: int = 365
    log_sensitive_content: bool = False
    local_storage_reminder: bool = False


@dataclass
class ComplianceAnonymizationConfig:
    """Anonymization configuration for a compliance preset.

    Attributes:
        inject_prompt: Whether to inject anti-hallucination prompts.
        inject_prompt_template: Template for the injected prompt.
    """

    inject_prompt: bool = True
    inject_prompt_template: str = (
        "[SYSTEM NOTICE] This conversation contains anonymized personal data. "
        "Placeholders like <PERSON_1> represent anonymized data. "
        "Do NOT attempt to reverse-engineer original values."
    )


@dataclass
class ComplianceRuleConfig:
    """Compliance rule configuration.

    Attributes:
        enabled: Whether the rule is enabled.
        additional_config: Rule-specific configuration.
    """

    enabled: bool = True
    additional_config: dict = field(default_factory=dict)


@dataclass
class ComplianceRules:
    """All compliance rules for a preset.

    Attributes:
        data_minimization: Data minimization rule configuration.
        consent_management: Consent management configuration.
        subject_rights: Data subject rights configuration.
        pci_dss: PCI-DSS specific rules.
        aml_checks: Anti-money laundering checks.
        kyc_protection: KYC data protection rules.
    """

    data_minimization: ComplianceRuleConfig = field(default_factory=ComplianceRuleConfig)
    consent_management: ComplianceRuleConfig = field(default_factory=ComplianceRuleConfig)
    subject_rights: ComplianceRuleConfig = field(default_factory=ComplianceRuleConfig)
    pci_dss: ComplianceRuleConfig = field(default_factory=ComplianceRuleConfig)
    aml_checks: ComplianceRuleConfig = field(default_factory=ComplianceRuleConfig)
    kyc_protection: ComplianceRuleConfig = field(default_factory=ComplianceRuleConfig)


@dataclass
class CustomPattern:
    """Custom PII pattern for a compliance preset.

    Attributes:
        name: Pattern name.
        entity_type: PII entity type.
        regex: Regular expression pattern.
        score: Confidence score.
        context: Context words for matching.
    """

    name: str
    entity_type: str
    regex: str
    score: float = 0.7
    context: list[str] = field(default_factory=list)


@dataclass
class CompliancePreset:
    """A complete compliance preset configuration.

    Attributes:
        name: Human-readable preset name.
        description: Description of the compliance framework.
        version: Preset version.
        region: Applicable regions.
        language: Supported languages.
        pii_types: PII types covered by this preset.
        strategies: Anonymization strategies per PII type.
        retention: Data retention configuration.
        anonymization: Anonymization configuration.
        compliance_rules: Compliance-specific rules.
        risk_scoring: Risk scoring configuration.
        custom_patterns: Additional PII patterns.
        special_rules: Special handling rules.
    """

    name: str
    description: str
    version: str = "1.0"
    region: list[str] = field(default_factory=list)
    language: list[str] = field(default_factory=list)
    pii_types: list[str] = field(default_factory=list)
    strategies: dict[str, str] = field(default_factory=dict)
    retention: ComplianceRetentionConfig = field(default_factory=ComplianceRetentionConfig)
    anonymization: ComplianceAnonymizationConfig = field(
        default_factory=ComplianceAnonymizationConfig
    )
    compliance_rules: ComplianceRules = field(default_factory=ComplianceRules)
    risk_scoring: ComplianceRiskConfig = field(default_factory=ComplianceRiskConfig)
    custom_patterns: list[CustomPattern] = field(default_factory=list)
    special_rules: dict = field(default_factory=dict)


def _parse_retention_config(data: dict) -> ComplianceRetentionConfig:
    """Parse retention configuration from dict."""
    if not data:
        return ComplianceRetentionConfig()

    return ComplianceRetentionConfig(
        mapping_ttl=data.get("mapping_ttl", 300),
        audit_retention_days=data.get("audit_retention_days", 365),
        log_sensitive_content=data.get("log_sensitive_content", False),
        local_storage_reminder=data.get("local_storage_reminder", False),
    )


def _parse_anonymization_config(data: dict) -> ComplianceAnonymizationConfig:
    """Parse anonymization configuration from dict."""
    if not data:
        return ComplianceAnonymizationConfig()

    return ComplianceAnonymizationConfig(
        inject_prompt=data.get("inject_prompt", True),
        inject_prompt_template=data.get(
            "inject_prompt_template",
            "[SYSTEM NOTICE] This conversation contains anonymized personal data.",
        ),
    )


def _parse_risk_config(data: dict) -> ComplianceRiskConfig:
    """Parse risk scoring configuration from dict."""
    if not data:
        return ComplianceRiskConfig()

    return ComplianceRiskConfig(
        high_risk_types=data.get("high_risk_types", []),
        medium_risk_types=data.get("medium_risk_types", []),
        risk_factors=data.get("risk_factors", {}),
    )


def _parse_rules_config(data: dict) -> ComplianceRules:
    """Parse compliance rules configuration from dict."""
    if not data:
        return ComplianceRules()

    def _parse_rule(rule_data: dict | None) -> ComplianceRuleConfig:
        if not rule_data:
            return ComplianceRuleConfig()
        if isinstance(rule_data, bool):
            return ComplianceRuleConfig(enabled=rule_data)
        return ComplianceRuleConfig(
            enabled=rule_data.get("enabled", True),
            additional_config=rule_data,
        )

    rules = data.get("compliance_rules", {})

    return ComplianceRules(
        data_minimization=_parse_rule(rules.get("data_minimization")),
        consent_management=_parse_rule(rules.get("consent_management")),
        subject_rights=_parse_rule(rules.get("subject_rights")),
        pci_dss=_parse_rule(rules.get("pci_dss")),
        aml_checks=_parse_rule(rules.get("aml_checks")),
        kyc_protection=_parse_rule(rules.get("kyc_protection")),
    )


def _parse_custom_patterns(data: list) -> list[CustomPattern]:
    """Parse custom patterns from list."""
    if not data:
        return []

    patterns = []
    for p in data:
        if isinstance(p, dict):
            patterns.append(
                CustomPattern(
                    name=p.get("name", ""),
                    entity_type=p.get("entity_type", ""),
                    regex=p.get("regex", ""),
                    score=p.get("score", 0.7),
                    context=p.get("context", []),
                )
            )
    return patterns


def load_compliance_preset(path: Path | str) -> CompliancePreset:
    """Load a compliance preset from a YAML file.

    Args:
        path: Path to the YAML compliance preset file.

    Returns:
        CompliancePreset object.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the YAML structure is invalid.
        yaml.YAMLError: If the YAML is malformed.
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Compliance preset file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if data is None:
        raise ValueError(f"Empty compliance preset file: {path}")

    if not isinstance(data, dict):
        raise ValueError(f"Invalid YAML structure: expected dict, got {type(data).__name__}")

    # Extract basic info
    name = data.get("name", path.stem)
    description = data.get("description", "")
    version = data.get("version", "1.0")

    # Extract configuration sections
    strategies = data.get("strategies", {})
    pii_types = data.get("pii_types", [])

    return CompliancePreset(
        name=name,
        description=description,
        version=version,
        region=data.get("region", []),
        language=data.get("language", []),
        pii_types=pii_types,
        strategies=strategies,
        retention=_parse_retention_config(data.get("retention")),
        anonymization=_parse_anonymization_config(data.get("anonymization")),
        compliance_rules=_parse_rules_config(data),
        risk_scoring=_parse_risk_config(data.get("risk_scoring")),
        custom_patterns=_parse_custom_patterns(data.get("custom_patterns", [])),
        special_rules=data.get("special_rules", {}),
    )


def load_compliance_preset_safe(
    path: Path | str,
) -> tuple[Optional[CompliancePreset], Optional[str]]:
    """Load compliance preset with error handling.

    Args:
        path: Path to the YAML compliance preset file.

    Returns:
        Tuple of (preset, error_message). If successful, error_message is None.
    """
    try:
        preset = load_compliance_preset(path)
        return preset, None
    except FileNotFoundError as e:
        return None, str(e)
    except ValueError as e:
        return None, f"Configuration error: {e}"
    except yaml.YAMLError as e:
        return None, f"YAML parsing error: {e}"
    except Exception as e:
        return None, f"Unexpected error loading preset: {e}"


def get_available_presets(
    presets_dir: Optional[Path | str] = None,
) -> dict[str, CompliancePreset]:
    """Load all available compliance presets from a directory.

    Args:
        presets_dir: Directory containing preset YAML files.
                    If None, uses the default config/compliance_presets directory.

    Returns:
        Dictionary mapping preset names to CompliancePreset objects.
    """
    if presets_dir is None:
        # Default to package config directory
        project_root = Path(__file__).parent.parent.parent.parent
        presets_dir = project_root / "config" / "compliance_presets"

    presets_dir = Path(presets_dir)

    if not presets_dir.exists():
        return {}

    presets = {}
    for yaml_file in presets_dir.glob("*.yaml"):
        preset, error = load_compliance_preset_safe(yaml_file)
        if preset:
            # Use lowercase name as key for case-insensitive lookup
            key = yaml_file.stem.lower()
            presets[key] = preset

    return presets


def get_preset_names(presets_dir: Optional[Path | str] = None) -> list[str]:
    """Get list of available preset names.

    Args:
        presets_dir: Directory containing preset YAML files.

    Returns:
        List of preset names in alphabetical order.
    """
    presets = get_available_presets(presets_dir)
    return sorted(presets.keys())


# Global preset cache
_presets_cache: dict[str, CompliancePreset] | None = None


def get_all_presets() -> dict[str, CompliancePreset]:
    """Get all compliance presets with caching.

    Returns:
        Dictionary of preset name to CompliancePreset.
    """
    global _presets_cache

    if _presets_cache is None:
        _presets_cache = get_available_presets()

    return _presets_cache


def clear_preset_cache() -> None:
    """Clear the preset cache. Useful for testing or reloading."""
    global _presets_cache
    _presets_cache = None
