"""
审计日志模型

定义审计事件的数据结构和相关枚举类型。
"""

import json
import hashlib
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
import uuid


class AuditEventType(str, Enum):
    """审计事件类型"""

    # PII 操作
    PII_DETECTED = "pii_detected"
    PII_ANONYMIZED = "pii_anonymized"
    PII_DEANONYMIZED = "pii_deanonymized"
    PII_MAPPING_CREATED = "pii_mapping_created"
    PII_MAPPING_DELETED = "pii_mapping_deleted"

    # API 操作
    API_REQUEST = "api_request"
    API_RESPONSE = "api_response"
    API_ERROR = "api_error"
    API_STREAM_START = "api_stream_start"
    API_STREAM_END = "api_stream_end"

    # 配置变更
    CONFIG_CHANGED = "config_changed"
    CONFIG_LOADED = "config_loaded"
    CONFIG_RELOADED = "config_reloaded"

    # 安全事件
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SECRET_DETECTED = "secret_detected"
    SECRET_BLOCKED = "secret_blocked"

    # 系统事件
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    HEALTH_CHECK = "health_check"


class RiskLevel(str, Enum):
    """风险级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class AuditEvent:
    """审计事件

    记录系统中所有与 PII 处理相关的操作事件。
    """

    # 核心标识
    event_id: str
    event_type: AuditEventType
    timestamp: datetime

    # 租户和用户信息
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None

    # PII 详情
    entity_type: Optional[str] = None
    entity_count: int = 0
    strategy_used: Optional[str] = None

    # 请求上下文
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    api_key_hash: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None

    # 响应信息
    status_code: Optional[int] = None
    error_message: Optional[str] = None

    # 风险评估
    risk_level: RiskLevel = RiskLevel.NONE

    # 额外元数据 (JSON 序列化)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """初始化后处理"""
        if not self.event_id:
            self.event_id = str(uuid.uuid4())
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp)
        if isinstance(self.event_type, str):
            self.event_type = AuditEventType(self.event_type)
        if isinstance(self.risk_level, str):
            self.risk_level = RiskLevel(self.risk_level)

    def to_dict(self) -> dict[str, Any]:
        """转换为字典"""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["event_type"] = self.event_type.value
        data["risk_level"] = self.risk_level.value
        return data

    def to_json(self, *, indent: bool = False) -> str:
        """转换为 JSON 字符串"""
        if indent:
            return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditEvent":
        """从字典创建实例"""
        if isinstance(data.get("event_type"), str):
            data["event_type"] = AuditEventType(data["event_type"])
        if isinstance(data.get("risk_level"), str):
            data["risk_level"] = RiskLevel(data["risk_level"])
        if isinstance(data.get("timestamp"), str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)

    @classmethod
    def from_json(cls, json_str: str) -> "AuditEvent":
        """从 JSON 字符串创建实例"""
        return cls.from_dict(json.loads(json_str))

    def get_signature(self) -> str:
        """获取事件签名（用于去重）"""
        signature_data = f"{self.event_type}:{self.request_id}:{self.endpoint}:{self.tenant_id}"
        return hashlib.sha256(signature_data.encode()).hexdigest()[:16]


@dataclass
class AuditFilter:
    """审计日志查询过滤器"""

    start_date: datetime
    end_date: datetime

    # 过滤条件
    event_types: Optional[list[AuditEventType]] = None
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    risk_levels: Optional[list[RiskLevel]] = None
    min_risk_level: Optional[RiskLevel] = None

    # 分页
    limit: int = 1000
    offset: int = 0

    # 排序
    sort_by: str = "timestamp"  # timestamp, risk_level
    sort_order: str = "desc"    # asc, desc

    def __post_init__(self):
        """初始化后处理，处理字符串类型的枚举"""
        if self.event_types and isinstance(self.event_types[0], str):
            self.event_types = [AuditEventType(t) for t in self.event_types]
        if self.risk_levels and isinstance(self.risk_levels[0], str):
            self.risk_levels = [RiskLevel(r) for r in self.risk_levels]
        if isinstance(self.min_risk_level, str):
            self.min_risk_level = RiskLevel(self.min_risk_level)

    def match(self, event: AuditEvent) -> bool:
        """检查事件是否匹配过滤器"""
        # 时间范围检查
        if event.timestamp < self.start_date or event.timestamp > self.end_date:
            return False

        # 事件类型检查
        if self.event_types and event.event_type not in self.event_types:
            return False

        # 租户检查
        if self.tenant_id and event.tenant_id != self.tenant_id:
            return False

        # 用户检查
        if self.user_id and event.user_id != self.user_id:
            return False

        # 请求检查
        if self.request_id and event.request_id != self.request_id:
            return False

        # 风险级别检查
        if self.risk_levels and event.risk_level not in self.risk_levels:
            return False

        if self.min_risk_level:
            risk_order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM,
                         RiskLevel.HIGH, RiskLevel.CRITICAL]
            try:
                if risk_order.index(event.risk_level) < risk_order.index(self.min_risk_level):
                    return False
            except ValueError:
                pass

        return True


@dataclass
class AuditSummary:
    """审计统计摘要"""

    period_start: datetime
    period_end: datetime
    tenant_id: Optional[str]

    # 总体统计
    total_events: int = 0
    events_by_type: dict[str, int] = field(default_factory=dict)
    events_by_risk: dict[str, int] = field(default_factory=dict)

    # PII 处理统计
    pii_detected_count: int = 0
    pii_anonymized_count: int = 0
    pii_by_type: dict[str, int] = field(default_factory=dict)
    pii_by_strategy: dict[str, int] = field(default_factory=dict)

    # API 统计
    api_request_count: int = 0
    api_error_count: int = 0
    avg_response_time_ms: Optional[float] = None

    # 安全统计
    auth_failure_count: int = 0
    rate_limit_count: int = 0
    secret_detected_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """转换为字典"""
        return asdict(self)


def hash_api_key(api_key: str | None) -> str | None:
    """对 API Key 进行哈希（用于日志记录）"""
    if not api_key:
        return None
    # 只保留前4位和哈希值，便于调试但不泄露完整密钥
    prefix = api_key[:4] if len(api_key) > 4 else api_key
    hash_value = hashlib.sha256(api_key.encode()).hexdigest()[:16]
    return f"{prefix}...{hash_value}"


def create_event(
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
) -> AuditEvent:
    """创建审计事件的便捷函数"""
    return AuditEvent(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        timestamp=datetime.now(),
        tenant_id=tenant_id,
        user_id=user_id,
        request_id=request_id,
        entity_type=entity_type,
        entity_count=entity_count,
        strategy_used=strategy_used,
        source_ip=source_ip,
        user_agent=user_agent,
        api_key_hash=hash_api_key(api_key),
        endpoint=endpoint,
        method=method,
        status_code=status_code,
        error_message=error_message,
        risk_level=risk_level,
        metadata=metadata or {},
    )
