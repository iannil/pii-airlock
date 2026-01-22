"""
PII-AIRLOCK 审计日志模块

该模块提供完整的审计日志功能，用于满足 SOX/GDPR/CCPA 等合规要求。

主要组件:
- AuditEvent: 审计事件模型
- AuditStore: 存储抽象接口
- FileAuditStore: 文件存储实现 (开发/小规模)
- DatabaseAuditStore: 数据库存储实现 (生产环境)
- AuditMiddleware: 审计中间件
"""

from pii_airlock.audit.models import (
    AuditEvent,
    AuditEventType,
    AuditFilter,
    RiskLevel,
)
from pii_airlock.audit.store import (
    AuditStore,
    FileAuditStore,
    DatabaseAuditStore,
    get_audit_store,
)
from pii_airlock.audit.logger import audit_logger, AuditLogger

__all__ = [
    # Models
    "AuditEvent",
    "AuditEventType",
    "AuditFilter",
    "RiskLevel",
    # Stores
    "AuditStore",
    "FileAuditStore",
    "DatabaseAuditStore",
    "get_audit_store",
    # Logger
    "audit_logger",
    "AuditLogger",
]
