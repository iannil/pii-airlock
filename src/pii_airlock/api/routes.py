"""
FastAPI routes for PII-AIRLOCK proxy service.

Provides OpenAI-compatible API endpoints and management API.
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, Field

from pii_airlock import __version__
from pii_airlock.api.models import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    HealthResponse,
    ErrorResponse,
    TestAnonymizeRequest,
    TestAnonymizeResponse,
    TestDeanonymizeRequest,
    TestDeanonymizeResponse,
)
from pii_airlock.api.proxy import ProxyService
from pii_airlock.api.middleware import RequestLoggingMiddleware
from pii_airlock.api.auth_middleware import (
    AuthenticationMiddleware,
    get_tenant_id,
    get_tenant,
    get_api_key,
)
from pii_airlock.api.limiter import limiter, get_rate_limit, is_rate_limit_enabled
from pii_airlock.storage.memory_store import MemoryStore
from pii_airlock.core.anonymizer import Anonymizer
from pii_airlock.core.deanonymizer import Deanonymizer
from pii_airlock.core.mapping import PIIMapping
from pii_airlock.core.strategies import StrategyConfig, StrategyType, get_strategy
from pii_airlock.logging.setup import get_logger, setup_logging

# Management API imports
from pii_airlock.auth.tenant import Tenant, get_tenant_config, DEFAULT_TENANT_ID
from pii_airlock.auth.api_key import APIKey, get_api_key_store, KeyStatus
from pii_airlock.cache.llm_cache import get_llm_cache, LLMCache
from pii_airlock.auth.quota import QuotaStore, QuotaType, get_quota_store

# Initialize logging
setup_logging()
logger = get_logger(__name__)


# Global proxy service instance
_proxy_service: Optional[ProxyService] = None
_store: Optional[MemoryStore] = None


def get_proxy_service() -> ProxyService:
    """Get or create the proxy service instance."""
    global _proxy_service, _store

    if _proxy_service is None:
        _store = MemoryStore(
            default_ttl=int(os.getenv("PII_AIRLOCK_MAPPING_TTL", "300"))
        )

        # Check if cache is enabled
        cache_enabled = os.getenv("PII_AIRLOCK_CACHE_ENABLED", "false").lower() == "true"
        cache = get_llm_cache() if cache_enabled else None

        _proxy_service = ProxyService(
            upstream_url=os.getenv("PII_AIRLOCK_UPSTREAM_URL", "https://api.openai.com"),
            api_key=os.getenv("PII_AIRLOCK_API_KEY") or os.getenv("OPENAI_API_KEY"),
            store=_store,
            inject_anti_hallucination=os.getenv(
                "PII_AIRLOCK_INJECT_PROMPT", "true"
            ).lower() == "true",
            timeout=float(os.getenv("PII_AIRLOCK_TIMEOUT", "120")),
            cache=cache,
            enable_cache=cache_enabled,
        )

    return _proxy_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    logger.info("Starting PII-AIRLOCK service", extra={"version": __version__})
    yield
    # Shutdown - cleanup expired mappings and close HTTP client
    logger.info("Shutting down PII-AIRLOCK service")
    if _store:
        _store.shutdown()  # Stop background cleanup thread
        _store.clear()
    # Close the HTTP client if it was created
    await ProxyService.close_http_client()
    # Shutdown cache
    cache = get_llm_cache()
    cache.shutdown()


app = FastAPI(
    title="PII-AIRLOCK",
    description="PII protection middleware for public LLM APIs",
    version=__version__,
    lifespan=lifespan,
)

# Add middleware
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(AuthenticationMiddleware)

# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return HealthResponse(status="ok", version=__version__)


@app.get("/metrics", tags=["Monitoring"])
async def metrics():
    """Prometheus metrics endpoint.

    Returns Prometheus-format metrics for monitoring.
    """
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


@app.get("/v1/models", tags=["OpenAI Compatible"])
async def list_models():
    """List available models (proxy through to upstream)."""
    return {
        "object": "list",
        "data": [
            {
                "id": "gpt-4",
                "object": "model",
                "owned_by": "openai",
            },
            {
                "id": "gpt-4-turbo",
                "object": "model",
                "owned_by": "openai",
            },
            {
                "id": "gpt-3.5-turbo",
                "object": "model",
                "owned_by": "openai",
            },
        ],
    }


@app.post(
    "/v1/chat/completions",
    tags=["OpenAI Compatible"],
)
@limiter.limit(get_rate_limit())
async def chat_completions(
    http_request: Request,
    body: ChatCompletionRequest,
    proxy: ProxyService = Depends(get_proxy_service),
    tenant_id: str = Depends(get_tenant_id),
):
    """Create a chat completion with PII protection.

    This endpoint is fully compatible with OpenAI's /v1/chat/completions API.
    PII in the request is automatically anonymized before sending to the upstream
    LLM, and deanonymized in the response before returning to the client.

    Supported features:
    - Non-streaming completions
    - Streaming completions (SSE)
    - Multiple choices
    - Temperature, top_p, max_tokens parameters
    - Multi-tenant isolation
    - Response caching (if enabled)
    - Quota enforcement (if configured)

    Not yet supported:
    - Function calling
    - Vision inputs
    """
    try:
        if body.stream:
            return StreamingResponse(
                proxy.chat_completion_stream(body, tenant_id=tenant_id),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no",  # Disable nginx buffering
                },
            )
        else:
            response = await proxy.chat_completion(body, tenant_id=tenant_id)
            return response
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions in OpenAI-compatible format."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "message": exc.detail,
                "type": "invalid_request_error",
                "code": exc.status_code,
            }
        },
    )


# ============================================================================
# Test API Endpoints
# ============================================================================

# Lazy-initialized anonymizer for test endpoints
_test_anonymizer: Optional[Anonymizer] = None


def get_test_anonymizer() -> Anonymizer:
    """Get or create the test anonymizer instance."""
    global _test_anonymizer
    if _test_anonymizer is None:
        config_path = os.getenv("PII_AIRLOCK_CONFIG_PATH")
        _test_anonymizer = Anonymizer(
            config_path=Path(config_path) if config_path else None
        )
    return _test_anonymizer


@app.post(
    "/api/test/anonymize",
    response_model=TestAnonymizeResponse,
    tags=["Test"],
)
async def test_anonymize(request: TestAnonymizeRequest):
    """Test anonymization without sending to LLM.

    This endpoint allows testing the PII detection and anonymization
    functionality directly, without forwarding to an upstream LLM.

    Query parameters:
        strategy: Optional anonymization strategy (placeholder, hash, mask, redact)
        entity_strategies: Optional per-entity strategy mapping
    """
    # Build strategy configuration from request
    strategy_config: StrategyConfig | None = None
    strategy_used = "placeholder"

    if request.strategy:
        try:
            strategy_type = StrategyType(request.strategy.lower())
            # Apply this strategy to all entities
            strategy_config = StrategyConfig(
                strategies={
                    "PERSON": strategy_type,
                    "PHONE_NUMBER": strategy_type,
                    "EMAIL_ADDRESS": strategy_type,
                    "CREDIT_CARD": strategy_type,
                    "ID_CARD": strategy_type,
                    "ZH_ID_CARD": strategy_type,
                    "IP_ADDRESS": strategy_type,
                }
            )
            strategy_used = strategy_type.value
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid strategy: {request.strategy}. Must be one of: placeholder, hash, mask, redact",
            )
    elif request.entity_strategies:
        try:
            strategies = {}
            for entity_type, strat_name in request.entity_strategies.items():
                strategies[entity_type] = StrategyType(strat_name.lower())
            strategy_config = StrategyConfig(strategies=strategies)
            strategy_used = "custom"
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid strategy in entity_strategies: {e}",
            )

    # Create anonymizer with the requested strategy or use default
    if strategy_config:
        anonymizer = Anonymizer(strategy_config=strategy_config)
    else:
        anonymizer = get_test_anonymizer()

    result = anonymizer.anonymize(request.text)

    return TestAnonymizeResponse(
        original=request.text,
        anonymized=result.text,
        mapping={
            entry.placeholder: entry.original_value
            for entry in result.mapping._entries
        },
        strategy=strategy_used,
    )


@app.post(
    "/api/test/deanonymize",
    response_model=TestDeanonymizeResponse,
    tags=["Test"],
)
async def test_deanonymize(request: TestDeanonymizeRequest):
    """Test deanonymization without sending to LLM.

    This endpoint allows testing the placeholder replacement functionality
    directly, using a provided mapping.
    """
    deanonymizer = Deanonymizer()

    # Build mapping from request
    mapping = PIIMapping()
    for placeholder, original in request.mapping.items():
        # Extract entity type from placeholder, e.g., "<PERSON_1>" -> "PERSON"
        if placeholder.startswith("<") and placeholder.endswith(">"):
            inner = placeholder[1:-1]  # Remove < and >
            parts = inner.rsplit("_", 1)
            if len(parts) == 2:
                entity_type = parts[0]
                mapping.add(entity_type, original, placeholder)

    result = deanonymizer.deanonymize(request.text, mapping)

    return TestDeanonymizeResponse(
        original=request.text,
        deanonymized=result.text,
    )


# ============================================================================
# Web UI
# ============================================================================

UI_HTML = """<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PII-AIRLOCK 测试界面</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f7fa;
            color: #333;
        }
        h1 {
            color: #1a1a2e;
            border-bottom: 2px solid #4a90d9;
            padding-bottom: 10px;
        }
        .container {
            background: white;
            border-radius: 8px;
            padding: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        label {
            display: block;
            font-weight: 600;
            margin-bottom: 8px;
            color: #444;
        }
        .input-group {
            display: flex;
            gap: 16px;
            margin-bottom: 16px;
        }
        .input-group > div {
            flex: 1;
        }
        select {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            font-family: inherit;
            background: white;
            cursor: pointer;
        }
        select:focus {
            outline: none;
            border-color: #4a90d9;
            box-shadow: 0 0 0 3px rgba(74, 144, 217, 0.1);
        }
        textarea {
            width: 100%;
            height: 120px;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            resize: vertical;
            font-family: inherit;
        }
        textarea:focus {
            outline: none;
            border-color: #4a90d9;
            box-shadow: 0 0 0 3px rgba(74, 144, 217, 0.1);
        }
        .buttons {
            margin-top: 16px;
            display: flex;
            gap: 12px;
        }
        button {
            padding: 10px 24px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-primary {
            background: #4a90d9;
            color: white;
        }
        .btn-primary:hover {
            background: #357abd;
        }
        .btn-secondary {
            background: #e9ecef;
            color: #495057;
        }
        .btn-secondary:hover {
            background: #dee2e6;
        }
        .result {
            background: #f8f9fa;
            padding: 16px;
            border-radius: 6px;
            margin: 12px 0;
            border-left: 4px solid #4a90d9;
            font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
            font-size: 14px;
            word-break: break-all;
            white-space: pre-wrap;
        }
        .strategy-badge {
            display: inline-block;
            padding: 4px 10px;
            background: #4a90d9;
            color: white;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            margin-left: 8px;
        }
        .mapping-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }
        .mapping-table th, .mapping-table td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        .mapping-table th {
            background: #f1f3f4;
            font-weight: 600;
            color: #555;
        }
        .placeholder {
            color: #d63384;
            font-weight: 600;
            font-family: "SF Mono", Monaco, monospace;
        }
        .original {
            color: #198754;
            font-family: "SF Mono", Monaco, monospace;
        }
        .hidden { display: none; }
        .loading {
            opacity: 0.7;
            pointer-events: none;
        }
        .version {
            text-align: center;
            color: #888;
            font-size: 12px;
            margin-top: 20px;
        }
        .error {
            background: #fee;
            border-left-color: #dc3545;
            color: #dc3545;
        }
        .help-text {
            font-size: 12px;
            color: #888;
            margin-top: 4px;
        }
        .strategy-info {
            background: #f0f7ff;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 16px;
            font-size: 13px;
        }
        .strategy-info strong {
            color: #4a90d9;
        }
    </style>
</head>
<body>
    <h1>PII-AIRLOCK 测试界面</h1>

    <div class="container">
        <div class="input-group">
            <div>
                <label for="strategy">脱敏策略</label>
                <select id="strategy">
                    <option value="placeholder">占位符 (placeholder)</option>
                    <option value="hash">哈希 (hash)</option>
                    <option value="mask">掩码 (mask)</option>
                    <option value="redact">完全替换 (redact)</option>
                </select>
                <div class="help-text">选择脱敏策略以查看不同效果</div>
            </div>
        </div>

        <div class="strategy-info" id="strategy-info">
            <strong>占位符策略</strong>: 将敏感信息替换为类型化的占位符（如 &lt;PERSON_1&gt;），适合 LLM 处理
        </div>

        <label for="input">输入文本</label>
        <textarea id="input" placeholder="输入包含敏感信息的文本进行测试...">张三的电话是13800138000，邮箱是test@example.com，身份证号是110101199003077516</textarea>

        <div class="buttons">
            <button class="btn-primary" onclick="anonymize()">脱敏</button>
            <button class="btn-secondary" onclick="clearAll()">清空</button>
        </div>
    </div>

    <div id="results" class="container hidden">
        <label>脱敏结果 <span class="strategy-badge" id="result-strategy"></span></label>
        <div class="result" id="anonymized"></div>

        <label style="margin-top: 20px;">映射关系</label>
        <table class="mapping-table">
            <thead>
                <tr>
                    <th>占位符 / 替换值</th>
                    <th>原始值</th>
                </tr>
            </thead>
            <tbody id="mapping"></tbody>
        </table>
    </div>

    <div id="error" class="container hidden">
        <div class="result error" id="error-message"></div>
    </div>

    <div class="version">
        PII-AIRLOCK v""" + __version__ + """
    </div>

    <script>
        const strategyDescriptions = {
            placeholder: '<strong>占位符策略</strong>: 将敏感信息替换为类型化的占位符（如 &lt;PERSON_1&gt;），适合 LLM 处理，支持回填',
            hash: '<strong>哈希策略</strong>: 使用 SHA256 哈希替换原始值，相同输入产生相同哈希，适合日志分析和数据去重',
            mask: '<strong>掩码策略</strong>: 部分隐藏敏感信息（如 138****8000），保留格式特征，适合显示场景',
            redact: '<strong>完全替换策略</strong>: 将所有敏感信息替换为固定标记 [REDACTED]，提供最高隐私保护'
        };

        function updateStrategyInfo() {
            const strategy = document.getElementById('strategy').value;
            document.getElementById('strategy-info').innerHTML = strategyDescriptions[strategy];
        }

        document.getElementById('strategy').addEventListener('change', updateStrategyInfo);

        async function anonymize() {
            const text = document.getElementById('input').value.trim();
            if (!text) {
                showError('请输入要测试的文本');
                return;
            }

            const strategy = document.getElementById('strategy').value;

            document.body.classList.add('loading');
            hideError();

            try {
                const res = await fetch('/api/test/anonymize', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({text, strategy})
                });

                if (!res.ok) {
                    const err = await res.json();
                    throw new Error(err.detail || '请求失败');
                }

                const data = await res.json();

                document.getElementById('anonymized').textContent = data.anonymized;
                document.getElementById('result-strategy').textContent = data.strategy;

                const mappingBody = document.getElementById('mapping');
                mappingBody.innerHTML = '';

                const entries = Object.entries(data.mapping);
                if (entries.length === 0) {
                    mappingBody.innerHTML = '<tr><td colspan="2" style="color:#888;text-align:center;">未检测到敏感信息</td></tr>';
                } else {
                    entries.forEach(([placeholder, original]) => {
                        const row = document.createElement('tr');
                        row.innerHTML = `<td class="placeholder">${escapeHtml(placeholder)}</td><td class="original">${escapeHtml(original)}</td>`;
                        mappingBody.appendChild(row);
                    });
                }

                document.getElementById('results').classList.remove('hidden');
            } catch (err) {
                showError(err.message);
            } finally {
                document.body.classList.remove('loading');
            }
        }

        function clearAll() {
            document.getElementById('input').value = '';
            document.getElementById('results').classList.add('hidden');
            hideError();
        }

        function showError(message) {
            document.getElementById('error-message').textContent = message;
            document.getElementById('error').classList.remove('hidden');
            document.getElementById('results').classList.add('hidden');
        }

        function hideError() {
            document.getElementById('error').classList.add('hidden');
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
"""


@app.get("/ui", response_class=HTMLResponse, tags=["UI"])
async def ui_page():
    """Serve the test UI page.

    This endpoint returns an interactive web interface for testing
    the PII anonymization functionality without using the proxy.
    """
    return UI_HTML


# ============================================================================
# Management API Endpoints (v1)
# ============================================================================

# Pydantic models for management API
class TenantInfo(BaseModel):
    """Tenant information response."""

    tenant_id: str
    name: str
    status: str
    rate_limit: str
    max_ttl: int
    settings: dict = Field(default_factory=dict)


class APIKeyCreateRequest(BaseModel):
    """Request to create a new API key."""

    name: str = Field(..., description="Name for the API key")
    scopes: list[str] = Field(
        default=["llm:use", "metrics:view"],
        description="Permission scopes",
    )
    expires_in_days: Optional[int] = Field(None, description="Days until expiration")
    rate_limit: Optional[str] = Field(None, description="Rate limit override")


class APIKeyResponse(BaseModel):
    """API key response."""

    key_id: str
    key_prefix: str
    tenant_id: str
    name: str
    status: str
    created_at: str
    last_used: Optional[str] = None
    expires_at: Optional[str] = None
    scopes: list[str]
    rate_limit: Optional[str] = None
    # Full key is only returned on creation
    full_key: Optional[str] = None


class APIKeyCreateResponse(BaseModel):
    """Response for API key creation."""

    api_key: str  # Full API key (only shown once)
    key: APIKeyResponse


class QuotaUsageResponse(BaseModel):
    """Quota usage response."""

    tenant_id: str
    usage: dict[str, dict[str, int]]  # {quota_type: {period: usage}}
    limits: dict[str, dict[str, int]] = Field(default_factory=dict)


class CacheStatsResponse(BaseModel):
    """Cache statistics response."""

    entry_count: int
    total_size_bytes: int
    total_hits: int
    avg_age_seconds: float
    entries: list[dict]


# ============================================================================
# Tenant Management Endpoints
# ============================================================================


@app.get(
    "/api/v1/tenants",
    response_model=list[TenantInfo],
    tags=["Management API"],
)
async def list_tenants(
    request: Request,
) -> list[TenantInfo]:
    """List all tenants.

    Requires authentication. Returns list of all configured tenants.
    """
    config = get_tenant_config()
    tenants = config.list_tenants()

    return [
        TenantInfo(
            tenant_id=t.tenant_id,
            name=t.name,
            status=t.status.value,
            rate_limit=t.rate_limit,
            max_ttl=t.max_ttl,
            settings=t.settings,
        )
        for t in tenants
    ]


@app.get(
    "/api/v1/tenants/{tenant_id}",
    response_model=TenantInfo,
    tags=["Management API"],
)
async def get_tenant_info(
    tenant_id: str,
    request: Request,
) -> TenantInfo:
    """Get information about a specific tenant."""
    config = get_tenant_config()
    tenant = config.get_tenant(tenant_id)

    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    return TenantInfo(
        tenant_id=tenant.tenant_id,
        name=tenant.name,
        status=tenant.status.value,
        rate_limit=tenant.rate_limit,
        max_ttl=tenant.max_ttl,
        settings=tenant.settings,
    )


# ============================================================================
# API Key Management Endpoints
# ============================================================================


@app.post(
    "/api/v1/keys",
    response_model=APIKeyCreateResponse,
    tags=["Management API"],
)
async def create_api_key(
    request: Request,
    body: APIKeyCreateRequest,
    tenant_id: str = Depends(get_tenant_id),
) -> APIKeyCreateResponse:
    """Create a new API key.

    The created key will be associated with the current tenant.
    The full key is only returned once during creation.
    """
    store = get_api_key_store()

    full_key, api_key_obj = store.create_key(
        tenant_id=tenant_id,
        name=body.name,
        scopes=body.scopes,
        expires_in_days=body.expires_in_days,
        rate_limit=body.rate_limit,
    )

    return APIKeyCreateResponse(
        api_key=full_key,
        key=APIKeyResponse(
            key_id=api_key_obj.key_id,
            key_prefix=api_key_obj.key_prefix,
            tenant_id=api_key_obj.tenant_id,
            name=api_key_obj.name,
            status=api_key_obj.status.value,
            created_at=api_key_obj.created_at_datetime.isoformat(),
            last_used=None,
            expires_at=api_key_obj.expires_at_datetime.isoformat()
            if api_key_obj.expires_at
            else None,
            scopes=api_key_obj.scopes,
            rate_limit=api_key_obj.rate_limit,
        ),
    )


@app.get(
    "/api/v1/keys",
    response_model=list[APIKeyResponse],
    tags=["Management API"],
)
async def list_api_keys(
    request: Request,
    tenant_id: str = Depends(get_tenant_id),
) -> list[APIKeyResponse]:
    """List API keys for the current tenant."""
    store = get_api_key_store()
    keys = store.list_keys(tenant_id=tenant_id)

    return [
        APIKeyResponse(
            key_id=k.key_id,
            key_prefix=k.key_prefix,
            tenant_id=k.tenant_id,
            name=k.name,
            status=k.status.value,
            created_at=k.created_at_datetime.isoformat(),
            last_used=k.last_used.isoformat() if k.last_used else None,
            expires_at=k.expires_at_datetime.isoformat() if k.expires_at else None,
            scopes=k.scopes,
            rate_limit=k.rate_limit,
        )
        for k in keys
    ]


@app.delete(
    "/api/v1/keys/{key_id}",
    tags=["Management API"],
)
async def revoke_api_key(
    key_id: str,
    request: Request,
    tenant_id: str = Depends(get_tenant_id),
) -> dict[str, str]:
    """Revoke an API key."""
    store = get_api_key_store()
    success = store.revoke_key(key_id)

    if not success:
        raise HTTPException(status_code=404, detail="API key not found")

    return {"message": "API key revoked", "key_id": key_id}


# ============================================================================
# Quota Management Endpoints
# ============================================================================


@app.get(
    "/api/v1/quota/usage",
    response_model=QuotaUsageResponse,
    tags=["Management API"],
)
async def get_quota_usage(
    request: Request,
    tenant_id: str = Depends(get_tenant_id),
) -> QuotaUsageResponse:
    """Get current quota usage for the tenant."""
    quota_store = get_quota_store()
    usage = quota_store.get_usage_summary(tenant_id)

    # Get limits
    quota_config = quota_store.get_quota_config(tenant_id)
    limits = {}
    if quota_config:
        for limit in quota_config.limits:
            if limit.quota_type.value not in limits:
                limits[limit.quota_type.value] = {}
            limits[limit.quota_type.value][limit.period.value] = limit.limit

    return QuotaUsageResponse(
        tenant_id=tenant_id,
        usage=usage,
        limits=limits,
    )


# ============================================================================
# Cache Management Endpoints
# ============================================================================


@app.get(
    "/api/v1/cache/stats",
    response_model=CacheStatsResponse,
    tags=["Management API"],
)
async def get_cache_stats(
    request: Request,
    tenant_id: str = Depends(get_tenant_id),
) -> CacheStatsResponse:
    """Get cache statistics for the tenant."""
    cache = get_llm_cache()
    stats = cache.get_stats(tenant_id)

    return CacheStatsResponse(**stats)


@app.delete(
    "/api/v1/cache",
    tags=["Management API"],
)
async def clear_cache(
    request: Request,
    tenant_id: str = Depends(get_tenant_id),
) -> dict[str, str]:
    """Clear cache for the tenant."""
    cache = get_llm_cache()
    count = cache.invalidate_tenant(tenant_id)

    return {"message": f"Cache cleared for tenant", "tenant_id": tenant_id, "entries_removed": count}


@app.get(
    "/api/v1/cache/stats/global",
    response_model=CacheStatsResponse,
    tags=["Management API"],
)
async def get_global_cache_stats(
    request: Request,
) -> CacheStatsResponse:
    """Get global cache statistics (all tenants)."""
    cache = get_llm_cache()
    stats = cache.get_stats()

    return CacheStatsResponse(**stats)
