"""
Intent Detection API

Provides REST API endpoints for intent detection configuration and testing.
"""

import os
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from fastapi import APIRouter, HTTPException

from pii_airlock.core.intent_detector import (
    IntentDetector,
    IntentResult,
    get_intent_detector,
    reset_intent_detector,
)
from pii_airlock.core.anonymizer import Anonymizer


# Request/Response models
class TextAnalysisRequest(BaseModel):
    """Request for text analysis."""

    text: str = Field(..., description="Text to analyze", min_length=1)
    entity_start: Optional[int] = Field(None, description="Start position of entity")
    entity_end: Optional[int] = Field(None, description="End position of entity")
    is_allowlisted: bool = Field(False, description="Whether the entity is in the allowlist")


class TextAnalysisResponse(BaseModel):
    """Response from text analysis."""

    is_question: bool
    confidence: float
    reason: str
    matched_pattern: Optional[str] = None
    recommendation: str = Field(..., description="Whether to preserve or anonymize the entity")


class IntentTestRequest(BaseModel):
    """Request for intent testing."""

    text: str = Field(..., description="Text to test", min_length=1)
    enable_intent_detection: bool = Field(True, description="Enable intent detection")
    enable_allowlist: bool = Field(True, description="Enable allowlist")


class IntentTestResponse(BaseModel):
    """Response from intent testing."""

    original_text: str
    anonymized_text: str
    entities_detected: int
    intent_exemptions: List[Dict[str, Any]]
    allowlist_exemptions: List[Dict[str, Any]]
    recommendation: str


class IntentConfigResponse(BaseModel):
    """Response for intent configuration."""

    enabled: bool
    patterns: List[str]
    context_window: int


# Router
router = APIRouter(prefix="/api/intent", tags=["intent"])


@router.post("/analyze", response_model=TextAnalysisResponse)
async def analyze_text(request: TextAnalysisRequest) -> TextAnalysisResponse:
    """Analyze text to detect if it's in question context.

    Args:
        request: Text analysis request.

    Returns:
        Analysis result with recommendation.
    """
    detector = get_intent_detector()

    if request.entity_start is not None and request.entity_end is not None:
        # Analyze entity context
        result = detector.is_question_context(
            request.text,
            request.entity_start,
            request.entity_end,
        )
    else:
        # Analyze whole text
        result = detector.is_question_text(request.text)

    # Generate recommendation
    if result.is_question:
        recommendation = "preserve"  # Keep the entity for AI context
    elif request.is_allowlisted:
        recommendation = "preserve"  # Allowlisted entity
    else:
        recommendation = "anonymize"  # Protect privacy

    return TextAnalysisResponse(
        is_question=result.is_question,
        confidence=result.confidence,
        reason=result.reason,
        matched_pattern=result.matched_pattern,
        recommendation=recommendation,
    )


@router.post("/test", response_model=IntentTestResponse)
async def test_intent_detection(request: IntentTestRequest) -> IntentTestResponse:
    """Test intent detection with anonymization.

    Args:
        request: Intent test request.

    Returns:
        Test results showing what would be anonymized.
    """
    # Create anonymizer with specified settings
    from pii_airlock.recognizers.registry import create_analyzer_with_chinese_support

    analyzer_engine = create_analyzer_with_chinese_support()
    anonymizer = Anonymizer(
        analyzer=analyzer_engine,
        enable_intent_detection=request.enable_intent_detection,
        enable_allowlist=request.enable_allowlist,
    )

    # Run anonymization
    result = anonymizer.anonymize(request.text)

    # Generate recommendation
    total_exemptions = len(result.intent_exemptions) + len(result.allowlist_exemptions)
    if total_exemptions > 0:
        recommendation = f"Preserved {total_exemptions} entities based on intent/allowlist"
    else:
        recommendation = "All detected entities anonymized"

    return IntentTestResponse(
        original_text=request.text,
        anonymized_text=result.text,
        entities_detected=result.pii_count,
        intent_exemptions=result.intent_exemptions,
        allowlist_exemptions=result.allowlist_exemptions,
        recommendation=recommendation,
    )


@router.get("/config", response_model=IntentConfigResponse)
async def get_intent_config() -> IntentConfigResponse:
    """Get current intent detection configuration.

    Returns:
        Current configuration including patterns and settings.
    """
    from pii_airlock.core.intent_detector import DEFAULT_QUESTION_PATTERNS

    detector = get_intent_detector()

    return IntentConfigResponse(
        enabled=os.getenv("PII_AIRLOCK_INTENT_DETECTION_ENABLED", "true").lower() == "true",
        patterns=DEFAULT_QUESTION_PATTERNS,
        context_window=detector.context_window,
    )


@router.post("/reload")
async def reload_intent_detector() -> Dict[str, str]:
    """Reload the intent detector configuration.

    This resets and reinitializes the intent detector with any
    updated configuration from config/intent_patterns.yaml.

    Returns:
        Status message with configuration details.
    """
    from pii_airlock.core.intent_detector import load_intent_patterns

    # Check if config file exists
    default_config_paths = [
        Path("config/intent_patterns.yaml"),
        Path("/etc/pii_airlock/intent_patterns.yaml"),
    ]
    config_path = None
    for path in default_config_paths:
        if path.exists():
            config_path = path
            break

    # Reset and reload
    reset_intent_detector()
    detector = get_intent_detector(config_path=config_path)

    # Report status
    if config_path:
        # Load and report patterns
        patterns = load_intent_patterns(config_path)
        return {
            "status": "success",
            "message": "Intent detector reloaded from configuration file",
            "config_file": str(config_path),
            "patterns_loaded": len(patterns.get("question_patterns", [])) +
                               len(patterns.get("question_context_patterns", [])) +
                               len(patterns.get("statement_context_patterns", [])),
        }
    else:
        return {
            "status": "success",
            "message": "Intent detector reloaded with default patterns",
            "config_file": "None (using defaults)",
            "patterns_loaded": "0 (built-in defaults)",
        }


@router.get("/patterns")
async def get_intent_patterns() -> Dict[str, List[str]]:
    """Get all intent detection patterns.

    Returns:
        Dictionary of pattern categories and their regex patterns.
    """
    from pii_airlock.core.intent_detector import (
        DEFAULT_QUESTION_PATTERNS,
        QUESTION_CONTEXT_PATTERNS,
        STATEMENT_CONTEXT_PATTERNS,
    )

    return {
        "question_patterns": DEFAULT_QUESTION_PATTERNS,
        "question_context_patterns": QUESTION_CONTEXT_PATTERNS,
        "statement_context_patterns": STATEMENT_CONTEXT_PATTERNS,
    }


class BatchAnalyzeRequest(BaseModel):
    """Request for batch text analysis."""

    texts: List[str] = Field(..., description="List of texts to analyze")


class BatchAnalysisResponse(BaseModel):
    """Response from batch analysis."""

    results: List[TextAnalysisResponse]


@router.post("/analyze/batch", response_model=BatchAnalysisResponse)
async def analyze_batch(request: BatchAnalyzeRequest) -> BatchAnalysisResponse:
    """Analyze multiple texts for question context.

    Args:
        request: Batch analysis request.

    Returns:
        List of analysis results.
    """
    detector = get_intent_detector()
    results = []

    for text in request.texts:
        result = detector.is_question_text(text)

        recommendation = "preserve" if result.is_question else "anonymize"

        results.append(TextAnalysisResponse(
            is_question=result.is_question,
            confidence=result.confidence,
            reason=result.reason,
            matched_pattern=result.matched_pattern,
            recommendation=recommendation,
        ))

    return BatchAnalysisResponse(results=results)
