"""Compliance preset API endpoints.

Provides endpoints for managing and activating compliance presets
(GDPR, CCPA, PIPL, Financial, etc.).
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from pii_airlock.config.compliance_loader import (
    CompliancePreset,
    get_all_presets,
    get_preset_names,
    clear_preset_cache,
    load_compliance_preset_safe,
)
from pii_airlock.core.strategies import StrategyType, StrategyConfig


logger = logging.getLogger(__name__)


# OPS-007 FIX: Audit logger for config changes
_audit_logger = None


def _get_audit_logger():
    """Lazy import of audit logger."""
    global _audit_logger
    if _audit_logger is None:
        try:
            from pii_airlock.audit import audit_logger
            _audit_logger = audit_logger()
        except ImportError:
            _audit_logger = False
    return _audit_logger if _audit_logger is not False else None


# Global active preset (simple in-memory storage for now)
_active_preset: Optional[CompliancePreset] = None
_preset_source: str = "default"  # "default", "api", "env"

# Global strategy configuration from active preset
_active_strategy_config: Optional[StrategyConfig] = None
_active_custom_patterns: list = []  # Custom patterns from active preset
_active_prompt_template: str = ""  # Custom prompt template from active preset


# Pydantic models
class ComplianceStrategyInfo(BaseModel):
    """Information about a compliance strategy."""

    entity_type: str = Field(..., description="PII entity type")
    strategy: str = Field(..., description="Anonymization strategy")


class CompliancePresetInfo(BaseModel):
    """Basic information about a compliance preset."""

    name: str = Field(..., description="Preset name")
    description: str = Field(..., description="Preset description")
    version: str = Field(..., description="Preset version")
    region: list[str] = Field(default_factory=list, description="Applicable regions")
    language: list[str] = Field(default_factory=list, description="Supported languages")


class CompliancePresetDetail(CompliancePresetInfo):
    """Detailed compliance preset information."""

    pii_types: list[str] = Field(default_factory=list, description="PII types covered")
    strategies: dict[str, str] = Field(default_factory=dict, description="Anonymization strategies per PII type")
    mapping_ttl: int = Field(..., description="Mapping TTL in seconds")
    audit_retention_days: int = Field(..., description="Audit log retention days")
    inject_prompt: bool = Field(..., description="Whether anti-hallucination prompt is enabled")
    high_risk_types: list[str] = Field(default_factory=list, description="High-risk PII types")
    medium_risk_types: list[str] = Field(default_factory=list, description="Medium-risk PII types")


class ComplianceStatusResponse(BaseModel):
    """Current compliance status response."""

    active_preset: Optional[str] = Field(None, description="Active preset name")
    source: str = Field(..., description="How the preset was activated")
    is_configured: bool = Field(..., description="Whether a compliance preset is active")
    available_presets: list[str] = Field(..., description="List of available preset names")


class ComplianceActivateRequest(BaseModel):
    """Request to activate a compliance preset."""

    preset: str = Field(..., description="Preset name (e.g., 'gdpr', 'ccpa', 'pipl', 'financial')")


class ComplianceActivateResponse(BaseModel):
    """Response from activating a compliance preset."""

    message: str = Field(..., description="Success message")
    preset: CompliancePresetDetail = Field(..., description="Activated preset details")


# Router
router = APIRouter(prefix="/api/v1/compliance", tags=["Compliance"])


def get_active_preset() -> Optional[CompliancePreset]:
    """Get the currently active compliance preset."""
    return _active_preset


def set_active_preset(preset: CompliancePreset, source: str = "api") -> None:
    """Set the active compliance preset."""
    global _active_preset, _preset_source, _active_strategy_config, _active_custom_patterns, _active_prompt_template
    _active_preset = preset
    _preset_source = source
    # Also apply the preset strategies
    _active_strategy_config = _apply_preset_strategies(preset)
    _active_custom_patterns = preset.custom_patterns
    _active_prompt_template = preset.anonymization.inject_prompt_template


def clear_active_preset() -> None:
    """Clear the active compliance preset and reset all configurations."""
    global _active_preset, _preset_source, _active_strategy_config, _active_custom_patterns, _active_prompt_template
    _active_preset = None
    _preset_source = "default"
    _active_strategy_config = None
    _active_custom_patterns = []
    _active_prompt_template = ""


def _preset_to_detail(preset: CompliancePreset) -> CompliancePresetDetail:
    """Convert a CompliancePreset to CompliancePresetDetail."""
    return CompliancePresetDetail(
        name=preset.name,
        description=preset.description,
        version=preset.version,
        region=preset.region,
        language=preset.language,
        pii_types=preset.pii_types,
        strategies=preset.strategies,
        mapping_ttl=preset.retention.mapping_ttl,
        audit_retention_days=preset.retention.audit_retention_days,
        inject_prompt=preset.anonymization.inject_prompt,
        high_risk_types=preset.risk_scoring.high_risk_types,
        medium_risk_types=preset.risk_scoring.medium_risk_types,
    )


@router.get("/presets", response_model=list[CompliancePresetInfo])
async def list_presets() -> list[CompliancePresetInfo]:
    """List all available compliance presets.

    Returns a list of available compliance presets with basic information.
    """
    presets = get_all_presets()

    return [
        CompliancePresetInfo(
            name=preset.name,
            description=preset.description,
            version=preset.version,
            region=preset.region,
            language=preset.language,
        )
        for preset in presets.values()
    ]


@router.get("/presets/{preset_name}", response_model=CompliancePresetDetail)
async def get_preset(preset_name: str) -> CompliancePresetDetail:
    """Get detailed information about a specific compliance preset.

    Args:
        preset_name: Name of the preset (e.g., 'gdpr', 'ccpa', 'pipl', 'financial')
    """
    presets = get_all_presets()
    key = preset_name.lower()

    if key not in presets:
        available = ", ".join(presets.keys())
        raise HTTPException(
            status_code=404,
            detail=f"Compliance preset '{preset_name}' not found. Available: {available}",
        )

    return _preset_to_detail(presets[key])


@router.get("/status", response_model=ComplianceStatusResponse)
async def get_compliance_status() -> ComplianceStatusResponse:
    """Get current compliance status.

    Returns information about the currently active compliance preset
    and all available presets.
    """
    active = get_active_preset()
    available = get_preset_names()

    return ComplianceStatusResponse(
        active_preset=active.name if active else None,
        source=_preset_source,
        is_configured=active is not None,
        available_presets=available,
    )


@router.post("/activate", response_model=ComplianceActivateResponse)
async def activate_preset(request: ComplianceActivateRequest) -> ComplianceActivateResponse:
    """Activate a compliance preset.

    Activates the specified compliance preset, which will affect
    how PII is anonymized in subsequent requests.

    This applies:
    - Anonymization strategies per PII type
    - Custom PII patterns for the preset
    - Anti-hallucination prompt template
    - Retention and audit policies

    Args:
        request: Activation request with preset name
    """
    global _active_strategy_config, _active_custom_patterns, _active_prompt_template

    presets = get_all_presets()
    key = request.preset.lower()

    if key not in presets:
        available = ", ".join(presets.keys())
        raise HTTPException(
            status_code=404,
            detail=f"Compliance preset '{request.preset}' not found. Available: {available}",
        )

    preset = presets[key]
    previous_preset = _active_preset.name if _active_preset else None

    # Apply preset strategies to global configuration
    _active_strategy_config = _apply_preset_strategies(preset)
    _active_custom_patterns = preset.custom_patterns
    _active_prompt_template = preset.anonymization.inject_prompt_template

    # Store the active preset
    set_active_preset(preset, source="api")

    # Reset the shared analyzer to reload with new custom patterns
    _reset_analyzer_for_preset(preset)

    logger.info(
        f"Compliance preset '{preset.name}' activated",
        extra={
            "event": "compliance_preset_activated",
            "preset_name": preset.name,
            "preset_version": preset.version,
            "strategies_count": len(preset.strategies),
            "custom_patterns_count": len(preset.custom_patterns),
        },
    )

    # OPS-007 FIX: Audit log config change
    audit = _get_audit_logger()
    if audit:
        try:
            import asyncio
            loop = asyncio.get_running_loop()
            loop.create_task(
                audit.log(
                    event_type="config_changed",
                    metadata={
                        "action": "activate_preset",
                        "preset_name": preset.name,
                        "preset_version": preset.version,
                        "previous_preset": previous_preset,
                        "strategies_count": len(preset.strategies),
                    },
                )
            )
        except RuntimeError:
            pass  # No event loop running

    return ComplianceActivateResponse(
        message=f"Compliance preset '{preset.name}' activated successfully",
        preset=_preset_to_detail(preset),
    )


@router.post("/deactivate")
async def deactivate_preset() -> dict[str, str]:
    """Deactivate the current compliance preset.

    Returns to the default configuration.
    """
    previous_preset = _active_preset.name if _active_preset else None
    clear_active_preset()

    # OPS-007 FIX: Audit log config change
    audit = _get_audit_logger()
    if audit and previous_preset:
        try:
            import asyncio
            loop = asyncio.get_running_loop()
            loop.create_task(
                audit.log(
                    event_type="config_changed",
                    metadata={
                        "action": "deactivate_preset",
                        "previous_preset": previous_preset,
                    },
                )
            )
        except RuntimeError:
            pass

    return {
        "message": "Compliance preset deactivated. Using default configuration.",
    }


@router.post("/reload")
async def reload_presets() -> dict[str, str]:
    """Reload compliance presets from disk.

    Useful after updating preset configuration files.
    """
    clear_preset_cache()
    presets = get_all_presets()

    # OPS-007 FIX: Audit log config reload
    audit = _get_audit_logger()
    if audit:
        try:
            import asyncio
            loop = asyncio.get_running_loop()
            loop.create_task(
                audit.log(
                    event_type="config_reloaded",
                    metadata={
                        "action": "reload_presets",
                        "presets_count": len(presets),
                        "preset_names": list(presets.keys()),
                    },
                )
            )
        except RuntimeError:
            pass

    return {
        "message": f"Compliance presets reloaded. {len(presets)} presets available.",
        "count": str(len(presets)),
    }


def get_preset_strategies(preset_name: str) -> dict[str, str] | None:
    """Get strategies from a compliance preset.

    Args:
        preset_name: Name of the preset

    Returns:
        Dictionary mapping entity types to strategies, or None if preset not found
    """
    presets = get_all_presets()
    key = preset_name.lower()

    if key not in presets:
        return None

    return presets[key].strategies


def is_preset_active() -> bool:
    """Check if a compliance preset is currently active."""
    return _active_preset is not None


def get_active_strategies() -> dict[str, str] | None:
    """Get strategies from the active preset.

    Returns:
        Dictionary mapping entity types to strategies, or None if no preset is active
    """
    preset = get_active_preset()
    if preset is None:
        return None

    return preset.strategies


def get_active_strategy_config() -> Optional[StrategyConfig]:
    """Get the active strategy configuration from the compliance preset.

    Returns:
        StrategyConfig from the active preset, or None if no preset is active
    """
    return _active_strategy_config


def get_active_custom_patterns() -> list:
    """Get custom patterns from the active compliance preset.

    Returns:
        List of CustomPattern objects from the active preset
    """
    return _active_custom_patterns


def get_active_prompt_template() -> str:
    """Get the anti-hallucination prompt template from the active preset.

    Returns:
        Prompt template string, or empty string if no preset is active
    """
    return _active_prompt_template


def _apply_preset_strategies(preset: CompliancePreset) -> StrategyConfig:
    """Convert preset strategies to StrategyConfig.

    Args:
        preset: The compliance preset with strategies.

    Returns:
        StrategyConfig with strategies from the preset.
    """
    strategies: dict[str, StrategyType] = {}
    for entity_type, strategy_name in preset.strategies.items():
        try:
            # Handle both "placeholder" and StrategyType.PLACEHOLDER
            if isinstance(strategy_name, str):
                strategy_type = StrategyType(strategy_name.lower())
            else:
                strategy_type = strategy_name
            strategies[entity_type] = strategy_type
        except (ValueError, AttributeError):
            # Skip invalid strategy names
            logger.warning(
                f"Invalid strategy '{strategy_name}' for entity type '{entity_type}' in preset '{preset.name}'"
            )
            continue

    return StrategyConfig(strategies)


def _reset_analyzer_for_preset(preset: CompliancePreset) -> None:
    """Reset the shared analyzer to apply preset custom patterns.

    Args:
        preset: The compliance preset with custom patterns.
    """
    try:
        from pii_airlock.core.anonymizer import reset_shared_analyzer
        reset_shared_analyzer()
        logger.info(
            f"Shared analyzer reset for preset '{preset.name}'",
            extra={
                "event": "analyzer_reset",
                "preset_name": preset.name,
                "custom_patterns_count": len(preset.custom_patterns),
            },
        )
    except ImportError:
        logger.warning("Could not reset shared analyzer: anonymizer module not found")
    except Exception as e:
        logger.error(f"Error resetting shared analyzer: {e}")
