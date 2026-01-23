"""
Compliance API 测试

测试合规预设 API 端点：
- 预设列表查询
- 预设详情查询
- 预设激活/停用
- 预设重新加载
- 辅助函数
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import FastAPI

from pii_airlock.api.compliance_api import (
    router,
    get_active_preset,
    set_active_preset,
    clear_active_preset,
    get_preset_strategies,
    is_preset_active,
    get_active_strategies,
    get_active_strategy_config,
    get_active_custom_patterns,
    get_active_prompt_template,
    _preset_to_detail,
    _apply_preset_strategies,
)
from pii_airlock.config.compliance_loader import CompliancePreset
from pii_airlock.core.strategies import StrategyType


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def app():
    """Create a test FastAPI app with compliance router."""
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_active_preset():
    """Reset active preset before and after each test."""
    clear_active_preset()
    yield
    clear_active_preset()


@pytest.fixture
def mock_gdpr_preset():
    """Create a mock GDPR preset."""
    preset = Mock(spec=CompliancePreset)
    preset.name = "gdpr"
    preset.description = "GDPR Compliance Preset"
    preset.version = "1.0.0"
    preset.region = ["EU"]
    preset.language = ["en", "de", "fr"]
    preset.pii_types = ["PERSON", "EMAIL", "PHONE"]
    preset.strategies = {"PERSON": "placeholder", "EMAIL": "hash", "PHONE": "mask"}
    preset.custom_patterns = []

    # Mock nested objects
    preset.retention = Mock()
    preset.retention.mapping_ttl = 300
    preset.retention.audit_retention_days = 90

    preset.anonymization = Mock()
    preset.anonymization.inject_prompt = True
    preset.anonymization.inject_prompt_template = "Do not reveal PII"

    preset.risk_scoring = Mock()
    preset.risk_scoring.high_risk_types = ["PERSON", "ID_CARD"]
    preset.risk_scoring.medium_risk_types = ["EMAIL", "PHONE"]

    return preset


@pytest.fixture
def mock_ccpa_preset():
    """Create a mock CCPA preset."""
    preset = Mock(spec=CompliancePreset)
    preset.name = "ccpa"
    preset.description = "CCPA Compliance Preset"
    preset.version = "1.0.0"
    preset.region = ["US-CA"]
    preset.language = ["en"]
    preset.pii_types = ["PERSON", "EMAIL"]
    preset.strategies = {"PERSON": "redact", "EMAIL": "hash"}
    preset.custom_patterns = []

    preset.retention = Mock()
    preset.retention.mapping_ttl = 600
    preset.retention.audit_retention_days = 365

    preset.anonymization = Mock()
    preset.anonymization.inject_prompt = False
    preset.anonymization.inject_prompt_template = ""

    preset.risk_scoring = Mock()
    preset.risk_scoring.high_risk_types = ["SSN"]
    preset.risk_scoring.medium_risk_types = ["EMAIL"]

    return preset


# ============================================================================
# API Endpoint Tests
# ============================================================================


class TestListPresets:
    """Test GET /presets endpoint."""

    @patch('pii_airlock.api.compliance_api.get_all_presets')
    def test_list_presets_success(self, mock_get_all, client, mock_gdpr_preset, mock_ccpa_preset):
        """Test listing all presets."""
        mock_get_all.return_value = {
            "gdpr": mock_gdpr_preset,
            "ccpa": mock_ccpa_preset,
        }

        response = client.get("/api/v1/compliance/presets")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        names = [p["name"] for p in data]
        assert "gdpr" in names
        assert "ccpa" in names

    @patch('pii_airlock.api.compliance_api.get_all_presets')
    def test_list_presets_empty(self, mock_get_all, client):
        """Test listing when no presets available."""
        mock_get_all.return_value = {}

        response = client.get("/api/v1/compliance/presets")

        assert response.status_code == 200
        assert response.json() == []


class TestGetPreset:
    """Test GET /presets/{preset_name} endpoint."""

    @patch('pii_airlock.api.compliance_api.get_all_presets')
    def test_get_preset_success(self, mock_get_all, client, mock_gdpr_preset):
        """Test getting a specific preset."""
        mock_get_all.return_value = {"gdpr": mock_gdpr_preset}

        response = client.get("/api/v1/compliance/presets/gdpr")

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "gdpr"
        assert data["description"] == "GDPR Compliance Preset"
        assert "PERSON" in data["pii_types"]

    @patch('pii_airlock.api.compliance_api.get_all_presets')
    def test_get_preset_case_insensitive(self, mock_get_all, client, mock_gdpr_preset):
        """Test that preset name lookup is case-insensitive."""
        mock_get_all.return_value = {"gdpr": mock_gdpr_preset}

        response = client.get("/api/v1/compliance/presets/GDPR")

        assert response.status_code == 200
        assert response.json()["name"] == "gdpr"

    @patch('pii_airlock.api.compliance_api.get_all_presets')
    def test_get_preset_not_found(self, mock_get_all, client):
        """Test getting a non-existent preset."""
        mock_get_all.return_value = {"gdpr": Mock()}

        response = client.get("/api/v1/compliance/presets/nonexistent")

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()


class TestGetComplianceStatus:
    """Test GET /status endpoint."""

    @patch('pii_airlock.api.compliance_api.get_preset_names')
    def test_status_no_active_preset(self, mock_names, client):
        """Test status when no preset is active."""
        mock_names.return_value = ["gdpr", "ccpa", "pipl"]

        response = client.get("/api/v1/compliance/status")

        assert response.status_code == 200
        data = response.json()
        assert data["active_preset"] is None
        assert data["is_configured"] is False
        assert "gdpr" in data["available_presets"]

    @patch('pii_airlock.api.compliance_api.get_preset_names')
    def test_status_with_active_preset(self, mock_names, client, mock_gdpr_preset):
        """Test status when a preset is active."""
        mock_names.return_value = ["gdpr", "ccpa"]
        set_active_preset(mock_gdpr_preset, source="api")

        response = client.get("/api/v1/compliance/status")

        assert response.status_code == 200
        data = response.json()
        assert data["active_preset"] == "gdpr"
        assert data["is_configured"] is True
        assert data["source"] == "api"


class TestActivatePreset:
    """Test POST /activate endpoint."""

    @patch('pii_airlock.api.compliance_api._reset_analyzer_for_preset')
    @patch('pii_airlock.api.compliance_api.get_all_presets')
    def test_activate_preset_success(self, mock_get_all, mock_reset, client, mock_gdpr_preset):
        """Test activating a preset."""
        mock_get_all.return_value = {"gdpr": mock_gdpr_preset}

        response = client.post(
            "/api/v1/compliance/activate",
            json={"preset": "gdpr"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "activated successfully" in data["message"]
        assert data["preset"]["name"] == "gdpr"

        # Verify preset is now active
        assert get_active_preset() is not None
        assert get_active_preset().name == "gdpr"

    @patch('pii_airlock.api.compliance_api.get_all_presets')
    def test_activate_preset_not_found(self, mock_get_all, client):
        """Test activating a non-existent preset."""
        mock_get_all.return_value = {"gdpr": Mock()}

        response = client.post(
            "/api/v1/compliance/activate",
            json={"preset": "nonexistent"}
        )

        assert response.status_code == 404

    @patch('pii_airlock.api.compliance_api._reset_analyzer_for_preset')
    @patch('pii_airlock.api.compliance_api.get_all_presets')
    def test_activate_preset_case_insensitive(self, mock_get_all, mock_reset, client, mock_gdpr_preset):
        """Test that activation is case-insensitive."""
        mock_get_all.return_value = {"gdpr": mock_gdpr_preset}

        response = client.post(
            "/api/v1/compliance/activate",
            json={"preset": "GDPR"}
        )

        assert response.status_code == 200


class TestDeactivatePreset:
    """Test POST /deactivate endpoint."""

    def test_deactivate_preset(self, client, mock_gdpr_preset):
        """Test deactivating the active preset."""
        set_active_preset(mock_gdpr_preset)

        response = client.post("/api/v1/compliance/deactivate")

        assert response.status_code == 200
        assert "deactivated" in response.json()["message"].lower()
        assert get_active_preset() is None

    def test_deactivate_when_none_active(self, client):
        """Test deactivating when no preset is active."""
        response = client.post("/api/v1/compliance/deactivate")

        assert response.status_code == 200
        assert get_active_preset() is None


class TestReloadPresets:
    """Test POST /reload endpoint."""

    @patch('pii_airlock.api.compliance_api.get_all_presets')
    @patch('pii_airlock.api.compliance_api.clear_preset_cache')
    def test_reload_presets(self, mock_clear, mock_get_all, client):
        """Test reloading presets from disk."""
        mock_get_all.return_value = {"gdpr": Mock(), "ccpa": Mock()}

        response = client.post("/api/v1/compliance/reload")

        assert response.status_code == 200
        data = response.json()
        assert "2 presets available" in data["message"]
        mock_clear.assert_called_once()


# ============================================================================
# Helper Function Tests
# ============================================================================


class TestHelperFunctions:
    """Test helper functions."""

    def test_get_active_preset_none(self):
        """Test getting active preset when none is set."""
        clear_active_preset()
        assert get_active_preset() is None

    def test_set_and_get_active_preset(self, mock_gdpr_preset):
        """Test setting and getting active preset."""
        set_active_preset(mock_gdpr_preset, source="test")

        active = get_active_preset()
        assert active is not None
        assert active.name == "gdpr"

    def test_clear_active_preset(self, mock_gdpr_preset):
        """Test clearing active preset."""
        set_active_preset(mock_gdpr_preset)
        clear_active_preset()

        assert get_active_preset() is None

    def test_is_preset_active(self, mock_gdpr_preset):
        """Test is_preset_active function."""
        assert is_preset_active() is False

        set_active_preset(mock_gdpr_preset)
        assert is_preset_active() is True

    @patch('pii_airlock.api.compliance_api.get_all_presets')
    def test_get_preset_strategies(self, mock_get_all, mock_gdpr_preset):
        """Test getting strategies for a preset."""
        mock_get_all.return_value = {"gdpr": mock_gdpr_preset}

        strategies = get_preset_strategies("gdpr")

        assert strategies is not None
        assert "PERSON" in strategies

    @patch('pii_airlock.api.compliance_api.get_all_presets')
    def test_get_preset_strategies_not_found(self, mock_get_all):
        """Test getting strategies for non-existent preset."""
        mock_get_all.return_value = {}

        strategies = get_preset_strategies("nonexistent")

        assert strategies is None

    def test_get_active_strategies_none(self):
        """Test getting strategies when no preset is active."""
        strategies = get_active_strategies()
        assert strategies is None

    def test_get_active_strategies_with_preset(self, mock_gdpr_preset):
        """Test getting strategies from active preset."""
        set_active_preset(mock_gdpr_preset)

        strategies = get_active_strategies()

        assert strategies is not None
        assert "PERSON" in strategies

    def test_get_active_strategy_config(self, mock_gdpr_preset):
        """Test getting strategy config from active preset."""
        set_active_preset(mock_gdpr_preset)

        config = get_active_strategy_config()

        assert config is not None

    def test_get_active_custom_patterns(self, mock_gdpr_preset):
        """Test getting custom patterns from active preset."""
        mock_gdpr_preset.custom_patterns = [{"name": "test"}]
        set_active_preset(mock_gdpr_preset)

        patterns = get_active_custom_patterns()

        assert patterns == [{"name": "test"}]

    def test_get_active_prompt_template(self, mock_gdpr_preset):
        """Test getting prompt template from active preset."""
        set_active_preset(mock_gdpr_preset)

        template = get_active_prompt_template()

        assert template == "Do not reveal PII"


class TestPresetToDetail:
    """Test _preset_to_detail conversion."""

    def test_preset_to_detail(self, mock_gdpr_preset):
        """Test converting preset to detail model."""
        detail = _preset_to_detail(mock_gdpr_preset)

        assert detail.name == "gdpr"
        assert detail.description == "GDPR Compliance Preset"
        assert detail.version == "1.0.0"
        assert "EU" in detail.region
        assert detail.mapping_ttl == 300
        assert detail.audit_retention_days == 90
        assert detail.inject_prompt is True
        assert "PERSON" in detail.high_risk_types


class TestApplyPresetStrategies:
    """Test _apply_preset_strategies function."""

    def test_apply_valid_strategies(self, mock_gdpr_preset):
        """Test applying valid strategies."""
        config = _apply_preset_strategies(mock_gdpr_preset)

        assert config is not None
        # The config should have strategies

    def test_apply_invalid_strategy_skipped(self):
        """Test that invalid strategies are skipped."""
        preset = Mock()
        preset.name = "test"
        preset.strategies = {
            "PERSON": "placeholder",
            "EMAIL": "invalid_strategy",
        }

        config = _apply_preset_strategies(preset)

        # Should not raise, just skip invalid


# ============================================================================
# Edge Cases
# ============================================================================


class TestEdgeCases:
    """Test edge cases."""

    def test_clear_preset_resets_all(self, mock_gdpr_preset):
        """Test that clear_active_preset resets all related state."""
        mock_gdpr_preset.custom_patterns = [{"test": "pattern"}]
        set_active_preset(mock_gdpr_preset)

        clear_active_preset()

        assert get_active_preset() is None
        assert get_active_custom_patterns() == []
        assert get_active_prompt_template() == ""
        assert get_active_strategy_config() is None

    @patch('pii_airlock.api.compliance_api._reset_analyzer_for_preset')
    @patch('pii_airlock.api.compliance_api.get_all_presets')
    def test_activate_replaces_previous(self, mock_get_all, mock_reset, client, mock_gdpr_preset, mock_ccpa_preset):
        """Test that activating a new preset replaces the previous one."""
        mock_get_all.return_value = {
            "gdpr": mock_gdpr_preset,
            "ccpa": mock_ccpa_preset,
        }

        # Activate GDPR
        client.post("/api/v1/compliance/activate", json={"preset": "gdpr"})
        assert get_active_preset().name == "gdpr"

        # Activate CCPA
        client.post("/api/v1/compliance/activate", json={"preset": "ccpa"})
        assert get_active_preset().name == "ccpa"

    def test_invalid_request_body(self, client):
        """Test activation with invalid request body."""
        response = client.post(
            "/api/v1/compliance/activate",
            json={"invalid": "field"}
        )

        assert response.status_code == 422  # Validation error
