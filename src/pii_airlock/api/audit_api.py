"""
审计日志 API 端点

提供审计日志的查询、导出和统计功能。
"""

import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Query, HTTPException, Depends, Response
from pydantic import BaseModel, Field

from pii_airlock.audit import (
    AuditEvent,
    AuditEventType,
    AuditFilter,
    RiskLevel,
    get_audit_store,
    audit_logger,
)
from pii_airlock.api.auth_middleware import get_tenant_id


# 创建审计 API 路由器
router = APIRouter(prefix="/api/v1/audit", tags=["Audit API"])


# ============================================================================
# Pydantic Models
# ============================================================================


class AuditEventResponse(BaseModel):
    """审计事件响应"""

    event_id: str
    event_type: str
    timestamp: str
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    entity_type: Optional[str] = None
    entity_count: int = 0
    strategy_used: Optional[str] = None
    source_ip: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    status_code: Optional[int] = None
    error_message: Optional[str] = None
    risk_level: str = "none"

    @classmethod
    def from_event(cls, event: AuditEvent) -> "AuditEventResponse":
        """从 AuditEvent 创建响应"""
        return cls(
            event_id=event.event_id,
            event_type=event.event_type.value,
            timestamp=event.timestamp.isoformat(),
            tenant_id=event.tenant_id,
            user_id=event.user_id,
            request_id=event.request_id,
            entity_type=event.entity_type,
            entity_count=event.entity_count,
            strategy_used=event.strategy_used,
            source_ip=event.source_ip,
            endpoint=event.endpoint,
            method=event.method,
            status_code=event.status_code,
            error_message=event.error_message,
            risk_level=event.risk_level.value,
        )


class AuditSummaryResponse(BaseModel):
    """审计摘要响应"""

    period_start: str
    period_end: str
    tenant_id: Optional[str] = None
    total_events: int = 0
    events_by_type: dict[str, int] = Field(default_factory=dict)
    events_by_risk: dict[str, int] = Field(default_factory=dict)
    pii_detected_count: int = 0
    pii_anonymized_count: int = 0
    pii_by_type: dict[str, int] = Field(default_factory=dict)
    pii_by_strategy: dict[str, int] = Field(default_factory=dict)
    api_request_count: int = 0
    api_error_count: int = 0
    auth_failure_count: int = 0
    rate_limit_count: int = 0
    secret_detected_count: int = 0


class ExportQueryParams(BaseModel):
    """导出查询参数"""

    start_date: datetime
    end_date: datetime
    event_types: Optional[list[str]] = None
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    risk_levels: Optional[list[str]] = None
    min_risk_level: Optional[str] = None
    limit: int = Field(1000, ge=1, le=100000)
    offset: int = Field(0, ge=0)
    sort_by: str = Field("timestamp", pattern="^(timestamp|risk_level)$")
    sort_order: str = Field("desc", pattern="^(asc|desc)$")


# ============================================================================
# Query Endpoints
# ============================================================================


@router.get(
    "/events",
    response_model=list[AuditEventResponse],
    summary="查询审计事件",
    description="根据指定条件查询审计日志事件",
)
async def query_audit_events(
    start_date: datetime = Query(..., description="开始日期 (ISO 8601)"),
    end_date: datetime = Query(..., description="结束日期 (ISO 8601)"),
    event_types: Optional[str] = Query(None, description="事件类型，逗号分隔，如: pii_detected,api_request"),
    tenant_id: Optional[str] = Query(None, description="租户 ID"),
    user_id: Optional[str] = Query(None, description="用户 ID"),
    request_id: Optional[str] = Query(None, description="请求 ID"),
    risk_levels: Optional[str] = Query(None, description="风险级别，逗号分隔，如: high,critical"),
    min_risk_level: Optional[str] = Query(None, description="最小风险级别"),
    limit: int = Query(1000, ge=1, le=10000, description="返回数量限制"),
    offset: int = Query(0, ge=0, description="偏移量"),
    sort_by: str = Query("timestamp", pattern="^(timestamp|risk_level)$", description="排序字段"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="排序方向"),
    current_tenant_id: str = Depends(get_tenant_id),
) -> list[AuditEventResponse]:
    """查询审计事件

    支持按时间范围、事件类型、租户、用户、风险级别等条件过滤。
    """
    store = await get_audit_store()

    # 解析逗号分隔的列表
    parsed_event_types = None
    if event_types:
        parsed_event_types = [AuditEventType(t.strip()) for t in event_types.split(",")]

    parsed_risk_levels = None
    if risk_levels:
        parsed_risk_levels = [RiskLevel(r.strip()) for r in risk_levels.split(",")]

    parsed_min_risk = None
    if min_risk_level:
        parsed_min_risk = RiskLevel(min_risk_level)

    # 构建过滤器
    filter = AuditFilter(
        start_date=start_date,
        end_date=end_date,
        event_types=parsed_event_types,
        tenant_id=tenant_id or current_tenant_id,
        user_id=user_id,
        request_id=request_id,
        risk_levels=parsed_risk_levels,
        min_risk_level=parsed_min_risk,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    events = await store.query(filter)

    return [AuditEventResponse.from_event(e) for e in events]


@router.get(
    "/events/count",
    response_model=dict[str, int],
    summary="获取审计事件数量",
)
async def count_audit_events(
    start_date: datetime = Query(..., description="开始日期"),
    end_date: datetime = Query(..., description="结束日期"),
    event_type: Optional[str] = Query(None, description="事件类型"),
    tenant_id: Optional[str] = Query(None, description="租户 ID"),
    current_tenant_id: str = Depends(get_tenant_id),
) -> dict[str, int]:
    """获取审计事件总数"""
    store = await get_audit_store()

    parsed_event_types = [AuditEventType(event_type)] if event_type else None

    # 使用较大的限制获取所有数据
    filter = AuditFilter(
        start_date=start_date,
        end_date=end_date,
        event_types=parsed_event_types,
        tenant_id=tenant_id or current_tenant_id,
        limit=1000000,
    )

    events = await store.query(filter)
    return {"count": len(events)}


# ============================================================================
# Summary Endpoints
# ============================================================================


@router.get(
    "/stats/summary",
    response_model=AuditSummaryResponse,
    summary="获取审计统计摘要",
    description="获取指定时间范围内的审计统计数据",
)
async def get_audit_summary(
    start_date: datetime = Query(..., description="开始日期"),
    end_date: datetime = Query(..., description="结束日期"),
    tenant_id: Optional[str] = Query(None, description="租户 ID"),
    current_tenant_id: str = Depends(get_tenant_id),
) -> AuditSummaryResponse:
    """获取审计统计摘要

    返回 PII 处理统计、API 统计、安全事件统计等。
    """
    store = await get_audit_store()

    summary = await store.get_summary(
        start_date=start_date,
        end_date=end_date,
        tenant_id=tenant_id or current_tenant_id,
    )

    return AuditSummaryResponse(
        period_start=summary.period_start.isoformat(),
        period_end=summary.period_end.isoformat(),
        tenant_id=summary.tenant_id,
        total_events=summary.total_events,
        events_by_type=summary.events_by_type,
        events_by_risk=summary.events_by_risk,
        pii_detected_count=summary.pii_detected_count,
        pii_anonymized_count=summary.pii_anonymized_count,
        pii_by_type=summary.pii_by_type,
        pii_by_strategy=summary.pii_by_strategy,
        api_request_count=summary.api_request_count,
        api_error_count=summary.api_error_count,
        auth_failure_count=summary.auth_failure_count,
        rate_limit_count=summary.rate_limit_count,
        secret_detected_count=summary.secret_detected_count,
    )


@router.get(
    "/stats/by-type",
    response_model=dict[str, int],
    summary="按类型统计审计事件",
)
async def get_stats_by_type(
    start_date: datetime = Query(..., description="开始日期"),
    end_date: datetime = Query(..., description="结束日期"),
    tenant_id: Optional[str] = Query(None, description="租户 ID"),
    current_tenant_id: str = Depends(get_tenant_id),
) -> dict[str, int]:
    """按事件类型统计"""
    store = await get_audit_store()

    summary = await store.get_summary(
        start_date=start_date,
        end_date=end_date,
        tenant_id=tenant_id or current_tenant_id,
    )

    return summary.events_by_type


@router.get(
    "/stats/pii",
    response_model=dict[str, int | dict[str, int]],
    summary="获取 PII 处理统计",
)
async def get_pii_stats(
    start_date: datetime = Query(..., description="开始日期"),
    end_date: datetime = Query(..., description="结束日期"),
    tenant_id: Optional[str] = Query(None, description="租户 ID"),
    current_tenant_id: str = Depends(get_tenant_id),
) -> dict:
    """获取 PII 处理统计"""
    store = await get_audit_store()

    summary = await store.get_summary(
        start_date=start_date,
        end_date=end_date,
        tenant_id=tenant_id or current_tenant_id,
    )

    return {
        "detected_count": summary.pii_detected_count,
        "anonymized_count": summary.pii_anonymized_count,
        "by_type": summary.pii_by_type,
        "by_strategy": summary.pii_by_strategy,
    }


@router.get(
    "/stats/security",
    response_model=dict[str, int],
    summary="获取安全事件统计",
)
async def get_security_stats(
    start_date: datetime = Query(..., description="开始日期"),
    end_date: datetime = Query(..., description="结束日期"),
    tenant_id: Optional[str] = Query(None, description="租户 ID"),
    current_tenant_id: str = Depends(get_tenant_id),
) -> dict[str, int]:
    """获取安全事件统计"""
    store = await get_audit_store()

    summary = await store.get_summary(
        start_date=start_date,
        end_date=end_date,
        tenant_id=tenant_id or current_tenant_id,
    )

    return {
        "auth_failures": summary.auth_failure_count,
        "rate_limit_exceeded": summary.rate_limit_count,
        "secrets_detected": summary.secret_detected_count,
        "api_errors": summary.api_error_count,
    }


# ============================================================================
# Export Endpoints
# ============================================================================


@router.get(
    "/events/export",
    summary="导出审计日志",
    description="导出审计日志为 JSON 或 CSV 格式",
)
async def export_audit_events(
    start_date: datetime = Query(..., description="开始日期"),
    end_date: datetime = Query(..., description="结束日期"),
    format: str = Query("json", pattern="^(json|csv)$", description="导出格式"),
    event_types: Optional[str] = Query(None, description="事件类型，逗号分隔"),
    tenant_id: Optional[str] = Query(None, description="租户 ID"),
    risk_levels: Optional[str] = Query(None, description="风险级别，逗号分隔"),
    pretty: bool = Query(False, description="是否格式化 JSON (仅用于 json 格式)"),
    current_tenant_id: str = Depends(get_tenant_id),
) -> Response:
    """导出审计日志

    支持 JSON 和 CSV 两种格式。导出的文件可以用于合规审计。
    """
    store = await get_audit_store()

    # 解析参数
    parsed_event_types = None
    if event_types:
        parsed_event_types = [AuditEventType(t.strip()) for t in event_types.split(",")]

    parsed_risk_levels = None
    if risk_levels:
        parsed_risk_levels = [RiskLevel(r.strip()) for r in risk_levels.split(",")]

    filter = AuditFilter(
        start_date=start_date,
        end_date=end_date,
        event_types=parsed_event_types,
        tenant_id=tenant_id or current_tenant_id,
        risk_levels=parsed_risk_levels,
        limit=1000000,  # 大限制以导出所有数据
    )

    if format == "json":
        data = await store.export_json(filter, pretty=pretty)
        media_type = "application/json"
        filename = f"audit_{start_date.date()}_{end_date.date()}.json"
    else:  # csv
        data = await store.export_csv(filter)
        media_type = "text/csv"
        filename = f"audit_{start_date.date()}_{end_date.date()}.csv"

    return Response(
        content=data,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


# ============================================================================
# Management Endpoints
# ============================================================================


@router.post(
    "/flush",
    response_model=dict[str, str],
    summary="刷新审计缓冲区",
    description="手动刷新审计日志缓冲区，确保所有日志写入存储",
)
async def flush_audit_logs(
    current_tenant_id: str = Depends(get_tenant_id),
) -> dict[str, str]:
    """刷新审计日志缓冲区"""
    await audit_logger().flush()
    return {"message": "Audit log buffer flushed"}


@router.delete(
    "/logs/old",
    response_model=dict[str, int],
    summary="清理旧审计日志",
    description="删除指定天数之前的旧审计日志",
)
async def cleanup_old_audit_logs(
    retention_days: int = Query(..., ge=1, le=3650, description="保留天数"),
    current_tenant_id: str = Depends(get_tenant_id),
) -> dict[str, int]:
    """清理旧审计日志

    删除超过保留天数的审计日志文件或记录。
    """
    store = await get_audit_store()
    deleted_count = await store.cleanup_old_logs(retention_days)

    return {
        "message": f"Deleted audit logs older than {retention_days} days",
        "deleted_count": deleted_count,
    }


@router.get(
    "/config",
    response_model=dict[str, str | bool | int],
    summary="获取审计配置",
    description="获取当前审计日志配置",
)
async def get_audit_config(
    current_tenant_id: str = Depends(get_tenant_id),
) -> dict:
    """获取审计配置"""
    return {
        "enabled": audit_logger().enabled,
        "store_type": os.getenv("PII_AIRLOCK_AUDIT_STORE", "file"),
        "audit_path": os.getenv("PII_AIRLOCK_AUDIT_PATH", "./logs/audit"),
        "batch_size": int(os.getenv("PII_AIRLOCK_AUDIT_BATCH_SIZE", "100")),
        "flush_interval_ms": int(os.getenv("PII_AIRLOCK_AUDIT_FLUSH_INTERVAL_MS", "1000")),
    }


# ============================================================================
# Convenience Endpoints
# ============================================================================


@router.get(
    "/stats/recent",
    response_model=AuditSummaryResponse,
    summary="获取最近统计",
    description="获取最近 24 小时的审计统计",
)
async def get_recent_stats(
    hours: int = Query(24, ge=1, le=168, description="最近小时数"),
    tenant_id: Optional[str] = Query(None, description="租户 ID"),
    current_tenant_id: str = Depends(get_tenant_id),
) -> AuditSummaryResponse:
    """获取最近统计"""
    store = await get_audit_store()

    end_date = datetime.now()
    start_date = end_date - timedelta(hours=hours)

    summary = await store.get_summary(
        start_date=start_date,
        end_date=end_date,
        tenant_id=tenant_id or current_tenant_id,
    )

    return AuditSummaryResponse(
        period_start=summary.period_start.isoformat(),
        period_end=summary.period_end.isoformat(),
        tenant_id=summary.tenant_id,
        total_events=summary.total_events,
        events_by_type=summary.events_by_type,
        events_by_risk=summary.events_by_risk,
        pii_detected_count=summary.pii_detected_count,
        pii_anonymized_count=summary.pii_anonymized_count,
        pii_by_type=summary.pii_by_type,
        pii_by_strategy=summary.pii_by_strategy,
        api_request_count=summary.api_request_count,
        api_error_count=summary.api_error_count,
        auth_failure_count=summary.auth_failure_count,
        rate_limit_count=summary.rate_limit_count,
        secret_detected_count=summary.secret_detected_count,
    )


@router.get(
    "/events/recent",
    response_model=list[AuditEventResponse],
    summary="获取最近事件",
    description="获取最近的审计事件",
)
async def get_recent_events(
    count: int = Query(100, ge=1, le=1000, description="返回数量"),
    event_type: Optional[str] = Query(None, description="过滤事件类型"),
    tenant_id: Optional[str] = Query(None, description="租户 ID"),
    current_tenant_id: str = Depends(get_tenant_id),
) -> list[AuditEventResponse]:
    """获取最近的审计事件"""
    store = await get_audit_store()

    end_date = datetime.now()
    start_date = end_date - timedelta(hours=24)

    parsed_event_types = [AuditEventType(event_type)] if event_type else None

    filter = AuditFilter(
        start_date=start_date,
        end_date=end_date,
        event_types=parsed_event_types,
        tenant_id=tenant_id or current_tenant_id,
        limit=count,
        sort_by="timestamp",
        sort_order="desc",
    )

    events = await store.query(filter)
    return [AuditEventResponse.from_event(e) for e in events]
