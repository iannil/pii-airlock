"""Tests for compliance preset loader."""

import json
from pathlib import Path

import pytest
import yaml

from pii_airlock.config.compliance_loader import (
    CompliancePreset,
    ComplianceRetentionConfig,
    ComplianceAnonymizationConfig,
    ComplianceRiskConfig,
    ComplianceRules,
    load_compliance_preset,
    load_compliance_preset_safe,
    get_available_presets,
    get_preset_names,
    clear_preset_cache,
)


@pytest.fixture
def temp_preset_file(tmp_path):
    """Create a temporary compliance preset file."""
    preset_data = {
        "name": "Test Compliance",
        "description": "Test compliance preset",
        "version": "1.0",
        "region": ["US", "EU"],
        "language": ["en"],
        "pii_types": ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"],
        "strategies": {
            "default": "placeholder",
            "PERSON": "synthetic",
            "EMAIL_ADDRESS": "mask",
        },
        "retention": {
            "mapping_ttl": 600,
            "audit_retention_days": 365,
        },
        "anonymization": {
            "inject_prompt": True,
        },
        "risk_scoring": {
            "high_risk_types": ["SSN", "PASSPORT"],
            "medium_risk_types": ["EMAIL_ADDRESS", "PHONE_NUMBER"],
        },
    }

    file_path = tmp_path / "test_compliance.yaml"
    with open(file_path, "w") as f:
        yaml.dump(preset_data, f)

    return file_path


def test_load_compliance_preset(temp_preset_file):
    """Test loading a compliance preset from file."""
    preset = load_compliance_preset(temp_preset_file)

    assert preset.name == "Test Compliance"
    assert preset.description == "Test compliance preset"
    assert preset.version == "1.0"
    assert preset.region == ["US", "EU"]
    assert preset.language == ["en"]
    assert "PERSON" in preset.pii_types
    assert "EMAIL_ADDRESS" in preset.pii_types
    assert preset.strategies["PERSON"] == "synthetic"
    assert preset.strategies["EMAIL_ADDRESS"] == "mask"
    assert preset.retention.mapping_ttl == 600
    assert preset.anonymization.inject_prompt is True
    assert "SSN" in preset.risk_scoring.high_risk_types
    assert "EMAIL_ADDRESS" in preset.risk_scoring.medium_risk_types


def test_load_compliance_preset_not_found():
    """Test loading a non-existent preset."""
    with pytest.raises(FileNotFoundError):
        load_compliance_preset("/nonexistent/file.yaml")


def test_load_compliance_preset_safe(temp_preset_file):
    """Test loading a preset with error handling."""
    preset, error = load_compliance_preset_safe(temp_preset_file)

    assert error is None
    assert preset is not None
    assert preset.name == "Test Compliance"


def test_load_compliance_preset_safe_not_found():
    """Test loading a non-existent preset with error handling."""
    preset, error = load_compliance_preset_safe("/nonexistent/file.yaml")

    assert preset is None
    assert error is not None
    assert "not found" in error.lower()


def test_retention_config_defaults():
    """Test retention config defaults."""
    config = ComplianceRetentionConfig()

    assert config.mapping_ttl == 300
    assert config.audit_retention_days == 365
    assert config.log_sensitive_content is False
    assert config.local_storage_reminder is False


def test_anonymization_config_defaults():
    """Test anonymization config defaults."""
    config = ComplianceAnonymizationConfig()

    assert config.inject_prompt is True
    assert "anonymized personal data" in config.inject_prompt_template.lower()


def test_risk_config_defaults():
    """Test risk scoring config defaults."""
    config = ComplianceRiskConfig()

    assert config.high_risk_types == []
    assert config.medium_risk_types == []
    assert config.risk_factors == {}


def test_get_available_presets():
    """Test getting all available presets."""
    clear_preset_cache()
    presets = get_available_presets()

    # Should include the presets we created
    assert len(presets) > 0

    # Check that some expected presets exist
    preset_names = list(presets.keys())
    assert "gdpr" in preset_names
    assert "ccpa" in preset_names
    assert "pipl" in preset_names
    assert "financial" in preset_names


def test_get_preset_names():
    """Test getting preset names."""
    clear_preset_cache()
    names = get_preset_names()

    assert isinstance(names, list)
    assert len(names) > 0
    assert "gdpr" in names
    assert "ccpa" in names


def test_gdpr_preset_exists():
    """Test that GDPR preset can be loaded."""
    clear_preset_cache()
    presets = get_available_presets()

    assert "gdpr" in presets
    gdpr = presets["gdpr"]

    assert "GDPR" in gdpr.name.upper()
    assert "PERSON" in gdpr.pii_types
    assert "EMAIL_ADDRESS" in gdpr.pii_types
    assert "IP_ADDRESS" in gdpr.pii_types
    assert gdpr.retention.mapping_ttl <= 300  # GDPR requires minimal retention
    assert gdpr.anonymization.inject_prompt is True


def test_ccpa_preset_exists():
    """Test that CCPA preset can be loaded."""
    clear_preset_cache()
    presets = get_available_presets()

    assert "ccpa" in presets
    ccpa = presets["ccpa"]

    assert "CCPA" in ccpa.name.upper()
    assert "US-CA" in ccpa.region
    assert "PERSON" in ccpa.pii_types
    assert "EMAIL_ADDRESS" in ccpa.pii_types
    assert "POSTAL_CODE" in ccpa.pii_types  # CCPA specifically mentions zip codes


def test_pipl_preset_exists():
    """Test that PIPL preset can be loaded."""
    clear_preset_cache()
    presets = get_available_presets()

    assert "pipl" in presets
    pipl = presets["pipl"]

    assert "PIPL" in pipl.name.upper()
    assert "CN" in pipl.region
    assert "ZH_PERSON" in pipl.pii_types
    assert "ZH_ID_CARD" in pipl.pii_types
    assert "ZH_PHONE" in pipl.pii_types
    # PIPL has stricter retention
    assert pipl.retention.mapping_ttl <= 180


def test_financial_preset_exists():
    """Test that Financial preset can be loaded."""
    clear_preset_cache()
    presets = get_available_presets()

    assert "financial" in presets
    financial = presets["financial"]

    assert "FINANCIAL" in financial.name.upper() or "金融" in financial.name
    assert "CREDIT_CARD" in financial.pii_types
    assert "BANK_ACCOUNT" in financial.pii_types
    # Financial has very strict retention
    assert financial.retention.mapping_ttl <= 60
    # Financial has longer audit retention
    assert financial.retention.audit_retention_days >= 2000  # ~7 years


def test_custom_patterns_in_preset():
    """Test that custom patterns are loaded from presets."""
    clear_preset_cache()
    presets = get_available_presets()

    # Financial preset should have custom patterns
    financial = presets["financial"]
    assert len(financial.custom_patterns) > 0

    # Check for specific patterns
    pattern_names = [p.name for p in financial.custom_patterns]
    assert "cn_bank_card" in pattern_names or "card_cvv" in pattern_names


def test_preset_strategies():
    """Test that strategies are properly loaded."""
    clear_preset_cache()
    presets = get_available_presets()

    gdpr = presets["gdpr"]
    assert "default" in gdpr.strategies
    assert "PERSON" in gdpr.strategies
    assert "EMAIL_ADDRESS" in gdpr.strategies


def test_compliance_rules():
    """Test that compliance rules are loaded."""
    clear_preset_cache()
    presets = get_available_presets()

    gdpr = presets["gdpr"]
    assert gdpr.compliance_rules is not None
    assert gdpr.compliance_rules.data_minimization is not None


def test_clear_preset_cache():
    """Test clearing the preset cache."""
    # Load presets
    presets1 = get_available_presets()
    assert len(presets1) > 0

    # Clear cache
    clear_preset_cache()

    # Load again should work
    presets2 = get_available_presets()
    assert len(presets2) == len(presets1)


def test_preset_serialization():
    """Test that presets can be serialized to dict."""
    clear_preset_cache()
    presets = get_available_presets()
    gdpr = presets["gdpr"]

    # Convert to dict via dataclass.asdict
    from dataclasses import asdict

    preset_dict = asdict(gdpr)

    assert preset_dict["name"] == gdpr.name
    assert preset_dict["description"] == gdpr.description
    assert preset_dict["version"] == gdpr.version
    assert preset_dict["region"] == gdpr.region
    assert preset_dict["pii_types"] == gdpr.pii_types
