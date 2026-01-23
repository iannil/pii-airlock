"""
审计日志记录器

提供便捷的审计日志记录接口。
支持异步批量写入和自动刷新。
"""

import asyncio
import logging
import os
from collections import defaultdict
from contextvars import ContextVar
from datetime import datetime
from typing import Optional, Any

from pii_airlock.audit.models import (
    AuditEvent,
    AuditEventType,
    RiskLevel,
    create_event,
)
from pii_airlock.audit.store import get_audit_store, AuditStore

# CORE-004 FIX: Add proper logger instead of using print
_logger = logging.getLogger(__name__)

# 请求上下文变量
_audit_context: ContextVar[dict] = ContextVar("audit_context", default={})


def set_audit_context(
    *,
    request_id: str | None = None,
    tenant_id: str | None = None,
    user_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    api_key: str | None = None,
) -> None:
    """设置审计上下文（在请求开始时调用）"""
    context = {}
    if request_id:
        context["request_id"] = request_id
    if tenant_id:
        context["tenant_id"] = tenant_id
    if user_id:
        context["user_id"] = user_id
    if source_ip:
        context["source_ip"] = source_ip
    if user_agent:
        context["user_agent"] = user_agent
    if api_key:
        context["api_key"] = api_key
    _audit_context.set(context)


def get_audit_context() -> dict:
    """获取当前审计上下文"""
    return _audit_context.get({})


def clear_audit_context() -> None:
    """清除审计上下文（在请求结束时调用）"""
    _audit_context.set({})


class AuditLogger:
    """审计日志记录器

    提供便捷的审计日志记录接口，支持批量写入和自动刷新。
    """

    def __init__(
        self,
        store: AuditStore | None = None,
        batch_size: int = 100,
        flush_interval_ms: int = 1000,
        enabled: bool = True,
    ):
        """初始化审计日志记录器

        Args:
            store: 审计存储实例（为 None 时使用全局单例）
            batch_size: 批量写入大小
            flush_interval_ms: 刷新间隔（毫秒）
            enabled: 是否启用审计日志
        """
        self._store = store
        self._batch_size = batch_size
        self._flush_interval_ms = flush_interval_ms
        self._enabled = enabled

        self._pending_events: list[AuditEvent] = []
        self._lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._closed = False

    async def _get_store(self) -> AuditStore:
        """获取存储实例"""
        if self._store:
            return self._store
        return await get_audit_store()

    def _merge_context(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        """合并当前上下文"""
        context = get_audit_context()
        merged = {}

        # 从上下文填充（如果 kwargs 中没有显式指定，或者指定为 None）
        context_keys = [
            "request_id", "tenant_id", "user_id", "source_ip",
            "user_agent", "api_key"
        ]

        for key in context_keys:
            if key in context:
                # 只有当 kwargs 中没有该 key，或者 kwargs 中该 key 为 None 时，才从 context 填充
                if key not in kwargs or kwargs.get(key) is None:
                    merged[key] = context[key]

        # 合并显式传入的参数（覆盖 context 中的值）
        for key, value in kwargs.items():
            if value is not None:  # 只合并非 None 值
                merged[key] = value

        return merged

    async def log(
        self,
        event_type: AuditEventType,
        *,
        tenant_id: str | None = None,
        user_id: str | None = None,
        request_id: str | None = None,
        entity_type: str | None = None,
        entity_count: int = 0,
        strategy_used: str | None = None,
        source_ip: str | None = None,
        user_agent: str | None = None,
        api_key: str | None = None,
        endpoint: str | None = None,
        method: str | None = None,
        status_code: int | None = None,
        error_message: str | None = None,
        risk_level: RiskLevel = RiskLevel.NONE,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """记录审计事件

        Args:
            event_type: 事件类型
            **kwargs: 事件属性（会与当前上下文合并）
        """
        if not self._enabled:
            return

        # 合并上下文
        kwargs = self._merge_context({
            "tenant_id": tenant_id,
            "user_id": user_id,
            "request_id": request_id,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "api_key": api_key,
        })

        event = create_event(
            event_type=event_type,
            entity_type=entity_type,
            entity_count=entity_count,
            strategy_used=strategy_used,
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            error_message=error_message,
            risk_level=risk_level,
            metadata=metadata,
            **kwargs,
        )

        async with self._lock:
            self._pending_events.append(event)
            if len(self._pending_events) >= self._batch_size:
                await self._flush_unlocked()

    async def _flush_unlocked(self) -> None:
        """刷新缓冲区（不加锁版本）"""
        if not self._pending_events:
            return

        events = self._pending_events
        self._pending_events = []

        try:
            store = await self._get_store()
            await store.write_batch(events)
        except Exception as e:
            # 写入失败，重新放入队列（最多保留最近 1000 条）
            self._pending_events.extend(events[-1000:])
            # CORE-004 FIX: Use proper logger instead of print
            _logger.error(
                "Error writing audit logs: %s",
                str(e),
                exc_info=True,
            )

    async def flush(self) -> None:
        """手动刷新缓冲区"""
        if not self._enabled:
            return

        async with self._lock:
            await self._flush_unlocked()

    async def _auto_flush_loop(self):
        """自动刷新循环"""
        while not self._closed:
            await asyncio.sleep(self._flush_interval_ms / 1000)
            if not self._closed:
                await self.flush()

    def start_auto_flush(self):
        """启动自动刷新任务"""
        if self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._auto_flush_loop())

    async def stop_auto_flush(self):
        """停止自动刷新任务"""
        self._closed = True
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        # 最后一次刷新
        await self.flush()

    def enable(self) -> None:
        """启用审计日志"""
        self._enabled = True

    def disable(self) -> None:
        """禁用审计日志"""
        self._enabled = False

    @property
    def enabled(self) -> bool:
        """是否启用"""
        return self._enabled

    # 便捷方法 - PII 操作

    async def log_pii_detected(
        self,
        entity_type: str,
        entity_count: int,
        **kwargs
    ) -> None:
        """记录 PII 检测事件"""
        await self.log(
            AuditEventType.PII_DETECTED,
            entity_type=entity_type,
            entity_count=entity_count,
            **kwargs
        )

    async def log_pii_anonymized(
        self,
        entity_type: str,
        entity_count: int,
        strategy_used: str,
        **kwargs
    ) -> None:
        """记录 PII 脱敏事件"""
        await self.log(
            AuditEventType.PII_ANONYMIZED,
            entity_type=entity_type,
            entity_count=entity_count,
            strategy_used=strategy_used,
            **kwargs
        )

    async def log_pii_deanonymized(
        self,
        placeholder_count: int,
        **kwargs
    ) -> None:
        """记录 PII 回填事件"""
        await self.log(
            AuditEventType.PII_DEANONYMIZED,
            entity_type="PLACEHOLDER",
            entity_count=placeholder_count,
            **kwargs
        )

    # 便捷方法 - API 操作

    async def log_api_request(
        self,
        endpoint: str,
        method: str,
        **kwargs
    ) -> None:
        """记录 API 请求事件"""
        await self.log(
            AuditEventType.API_REQUEST,
            endpoint=endpoint,
            method=method,
            **kwargs
        )

    async def log_api_response(
        self,
        endpoint: str,
        method: str,
        status_code: int,
        **kwargs
    ) -> None:
        """记录 API 响应事件"""
        await self.log(
            AuditEventType.API_RESPONSE,
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            **kwargs
        )

    async def log_api_error(
        self,
        endpoint: str,
        method: str,
        error_message: str,
        **kwargs
    ) -> None:
        """记录 API 错误事件"""
        await self.log(
            AuditEventType.API_ERROR,
            endpoint=endpoint,
            method=method,
            error_message=error_message,
            risk_level=RiskLevel.MEDIUM,
            **kwargs
        )

    # 便捷方法 - 安全事件

    async def log_auth_failure(
        self,
        reason: str | None = None,
        **kwargs
    ) -> None:
        """记录认证失败事件"""
        await self.log(
            AuditEventType.AUTH_FAILURE,
            error_message=reason,
            risk_level=RiskLevel.HIGH,
            metadata={"reason": reason} if reason else None,
            **kwargs
        )

    async def log_rate_limit_exceeded(
        self,
        limit_type: str,
        **kwargs
    ) -> None:
        """记录限流事件"""
        await self.log(
            AuditEventType.RATE_LIMIT_EXCEEDED,
            risk_level=RiskLevel.MEDIUM,
            metadata={"limit_type": limit_type},
            **kwargs
        )

    async def log_secret_detected(
        self,
        secret_type: str,
        count: int = 1,
        **kwargs
    ) -> None:
        """记录秘密检测事件"""
        await self.log(
            AuditEventType.SECRET_DETECTED,
            entity_type=secret_type,
            entity_count=count,
            risk_level=RiskLevel.HIGH,
            **kwargs
        )

    async def log_secret_blocked(
        self,
        secret_type: str,
        count: int = 1,
        **kwargs
    ) -> None:
        """记录秘密阻止事件"""
        await self.log(
            AuditEventType.SECRET_BLOCKED,
            entity_type=secret_type,
            entity_count=count,
            risk_level=RiskLevel.CRITICAL,
            **kwargs
        )


# 全局单例
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """获取全局审计日志记录器"""
    global _audit_logger

    if _audit_logger is None:
        enabled = os.getenv("PII_AIRLOCK_AUDIT_ENABLED", "true").lower() == "true"
        batch_size = int(os.getenv("PII_AIRLOCK_AUDIT_BATCH_SIZE", "100"))
        flush_interval = int(os.getenv("PII_AIRLOCK_AUDIT_FLUSH_INTERVAL_MS", "1000"))

        _audit_logger = AuditLogger(
            enabled=enabled,
            batch_size=batch_size,
            flush_interval_ms=flush_interval,
        )
        _audit_logger.start_auto_flush()

    return _audit_logger


# 创建全局实例的便捷别名
audit_logger = get_audit_logger


# 上下文管理器
class AuditContext:
    """审计上下文管理器

    用法:
        async with AuditContext(request_id="123", tenant_id="tenant1"):
            # 在这个范围内，所有审计日志会自动包含这些上下文
            await audit_logger.log_pii_detected("PERSON", 1)
    """

    def __init__(self, **kwargs):
        self._kwargs = kwargs
        self._old_context: dict | None = None

    async def __aenter__(self):
        self._old_context = get_audit_context()
        set_audit_context(**self._kwargs)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._old_context is not None:
            _audit_context.set(self._old_context)
        else:
            clear_audit_context()
        return False
