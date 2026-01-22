# PII-AIRLOCK Phase 6 开发计划

> **版本**: v1.2.0 规划
> **状态**: 规划中
> **创建日期**: 2026-01-22
> **预计周期**: 4-6 周

## 1. 概述

Phase 6 将在现有 MVP 基础上实现 5 大企业级增强功能，使 pii-airlock 从"生产就绪"升级为"企业合规级"产品。

### 1.1 功能列表

| # | 功能 | 商业价值 | 技术复杂度 | 优先级 |
|---|------|---------|-----------|--------|
| 1 | 仿真数据合成 | 高 (改善 LLM 理解) | 中 | P0 |
| 2 | 模糊匹配纠错 | 高 (提升回填准确率) | 中 | P0 |
| 3 | 审计日志系统 | 高 (合规必需) | 中 | P0 |
| 4 | 合规报告生成 | 高 (合规证明) | 低 | P1 |
| 5 | 秘密泄露防护库 | 中 (安全增强) | 低 | P1 |

### 1.2 架构影响评估

```
现有架构影响范围:

仿真数据合成    → core/strategies.py (新增 SyntheticStrategy)
                → core/synthetic/ (新建目录)
模糊匹配纠错    → core/deanonymizer.py (增强 FUZZY_PATTERNS)
审计日志系统    → audit/ (新建模块)
                → storage/audit_store.py (新建)
合规报告生成    → api/reports.py (新建端点)
                → templates/reports/ (模板目录)
秘密泄露防护库  → recognizers/secrets/ (新建目录)
                → config/secrets_patterns.yaml (预置规则)
```

---

## 2. 功能 1: 仿真数据合成 (Synthetic Replacement)

### 2.1 需求描述

将原始敏感信息替换为语义等价的**仿真数据**，而非占位符。这样可以：

1. **保持 LLM 上下文理解**: "张三在北京" → "李四在上海"，保持地理关系
2. **保持数据格式特征**: 邮箱、电话号码的格式特征得以保留
3. **提升自然语言处理能力**: LLM 对真实姓名/地名的处理能力优于占位符

### 2.2 技术设计

#### 2.2.1 新增策略类型

**文件**: `src/pii_airlock/core/strategies.py`

```python
class SyntheticStrategy(AnonymizationStrategy):
    """仿真数据合成策略 - 使用语义等价的假数据替换敏感信息"""

    # 策略配置
    name = "synthetic"
    can_deanonymize = True  # 支持回填
    preserve_type = True
    preserve_format = True  # 保持格式特征

    # 仿真数据生成器注册表
    generators: dict[str, SyntheticGenerator] = {}
```

#### 2.2.2 仿真数据生成器

**文件**: `src/pii_airlock/core/synthetic/generators.py`

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class SyntheticValue:
    """仿真数据值"""
    value: str           # 仿真值
    original: str        # 原始值
    entity_type: str     # 实体类型
    metadata: dict       # 额外元数据 (如性别、地区等)

class SyntheticGenerator(ABC):
    """仿真数据生成器基类"""

    @abstractmethod
    def generate(self, original: str, context: dict | None = None) -> SyntheticValue:
        """根据原始值生成仿真数据"""
        pass

    @abstractmethod
    def validate(self, value: str) -> bool:
        """验证生成的值是否符合格式要求"""
        pass
```

#### 2.2.3 各类型实现方案

| 实体类型 | 实现方案 | 数据源 | 示例 |
|---------|---------|--------|------|
| **PERSON** | 中文姓名生成 | 常见姓氏库 + 随机名字 | 张三 → 李四 |
| **PHONE** | 同运营商/地区号码 | 号段规则库 | 138****8000 → 139****9000 |
| **EMAIL** | 同域名邮箱 | 常见邮箱域名 | test@a.com → user@a.com |
| **LOCATION** | 同级地名替换 | 中国城市/省份库 | 北京 → 上海 |
| **ID_CARD** | 同地区虚拟身份证 | 地区代码 + 校验码算法 | 110... → 310... |
| **CREDIT_CARD** | 同BIN卡号 | BIN规则库 | 4111... → 4242... |

#### 2.2.4 文件结构

```
src/pii_airlock/core/synthetic/
├── __init__.py
├── base.py              # 抽象基类
├── generators.py        # 生成器注册
├── person.py            # 姓名生成器
├── phone.py             # 手机号生成器
├── email.py             # 邮箱生成器
├── location.py          # 地点生成器
├── id_card.py           # 身份证生成器
├── credit_card.py       # 银行卡生成器
└── data/                # 预置数据
    ├── surnames.txt     # 常见姓氏 (500+)
    ├── given_names.txt  # 常见名字
    ├── cities.txt       # 城市列表
    └── phone_prefixes.yaml  # 号段规则
```

### 2.3 接口设计

#### 2.3.1 配置方式

```yaml
# config/synthetic_config.yaml
synthetic:
  # 是否确保仿真数据的属性一致性
  # 例如: 同一个人的姓名性别保持一致
  consistency_enabled: true

  # 地域偏好设置 (null 表示随机)
  region_preference:
    PERSON: null
    LOCATION: "华东"  # 优先替换为华东地区城市

  # 姓名性别推断
  gender_inference: true

  # 随机种子 (用于可重现的脱敏)
  seed: null
```

#### 2.3.2 API 使用

```python
from pii_airlock import Anonymizer
from pii_airlock.core.strategies import StrategyConfig, StrategyType

# 使用仿真策略
anonymizer = Anonymizer(
    strategy_config=StrategyConfig({
        "PERSON": StrategyType.SYNTHETIC,
        "PHONE": StrategyType.SYNTHETIC,
        "EMAIL": StrategyType.SYNTHETIC,
    })
)

result = anonymizer.anonymize("张三的电话是13800138000")
# 结果: "李四的电话是13900139000"
# mapping: {"<PERSON_1>": ("张三", "李四"), "<PHONE_1>": ("13800138000", "13900139000")}
```

### 2.4 实现步骤

| 步骤 | 任务 | 估计工作量 | 依赖 |
|------|------|-----------|------|
| 1.1 | 创建 synthetic 模块结构 | 0.5d | - |
| 1.2 | 实现 SyntheticGenerator 基类 | 0.5d | - |
| 1.3 | 实现 PersonGenerator (姓名) | 1d | 姓氏数据 |
| 1.4 | 实现 PhoneGenerator (手机号) | 1d | 号段规则 |
| 1.5 | 实现 EmailGenerator (邮箱) | 0.5d | - |
| 1.6 | 实现 LocationGenerator (地点) | 1d | 城市数据 |
| 1.7 | 实现 IdCardGenerator (身份证) | 1d | 地区代码库 |
| 1.8 | 实现 CreditCardGenerator (银行卡) | 0.5d | BIN 规则 |
| 1.9 | 集成到 strategies.py | 0.5d | 1.1-1.8 |
| 1.10 | 编写单元测试 | 2d | 1.9 |
| 1.11 | 收集/生成预置数据 | 1d | - |

**总计**: 约 10.5 天

### 2.5 测试策略

```python
# tests/test_synthetic.py
def test_person_synthetic():
    """测试姓名生成: 保持长度、性别、常见度"""
    original = "张三"
    synthetic = generate_synthetic_person(original)
    assert synthetic != original
    assert len(synthetic) == len(original)
    assert is_common_surname(synthetic[0])

def test_phone_synthetic():
    """测试手机号生成: 保持运营商、号段"""
    original = "13800138000"
    synthetic = generate_synthetic_phone(original)
    assert synthetic[:3] == original[:3]  # 保持号段
    assert validate_luhn_checksum(synthetic)

def test_consistency():
    """测试一致性: 同一实体多次替换结果相同"""
    text = "张三给张三打了电话"
    result = anonymizer.anonymize(text)
    # 两个"张三"应替换为同一个仿真名字
    assert result.text.count("李四") == 2
```

### 2.6 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| 仿真数据不够自然 | LLM 理解能力下降 | 使用真实常见姓氏/地名 |
| 生成速度慢 | 延迟增加 | 预加载数据到内存 |
| 跨语言问题 | 英文姓名处理不当 | 分离中英文生成器 |
| 数据泄露 | 仿真数据与真实数据碰撞 | 加盐哈希 + 大数据集 |

---

## 3. 功能 2: 模糊匹配纠错 (Fuzzy Rehydration)

### 3.1 需求描述

LLM 可能会产生"幻觉"，修改占位符格式，导致还原失败。需要智能容错机制。

**问题示例**:
```
原始占位符: <PERSON_1>
LLM 输出变体:
  - <Person_1>      # 大小写变化
  - < PERSON_1 >    # 空格变化
  - [PERSON_1]      # 方括号替代
  - {{PERSON_1}}    # 双大括号
  - PERSON_1        # 缺少尖括号
  - <PERSON_1>.     # 带标点
```

### 3.2 技术设计

#### 3.2.1 增强现有 FUZZY_PATTERNS

**文件**: `src/pii_airlock/core/deanonymizer.py`

```python
# 现有实现
FUZZY_PATTERNS = [
    r"<\s*{entity_type}_{index}\s*>",      # 空格容错
    r"\[\s*{entity_type}_{index}\s*\]",    # 方括号
    r"{{\s*{entity_type}_{index}\s*}}",    # 双大括号
    r"\(\s*{entity_type}_{index}\s*\)",    # 圆括号
    r"{entity_type}_{index}",              # 无括号
    r"{entity_type}_{index}[.,;:!?,。，；]",  # 带标点
]

# 新增增强模式
FUZZY_PATTERNS_ENHANCED = FUZZY_PATTERNS + [
    r"<\s*{entity_type}\s*:\s*{index}\s*>",   # 冒号分隔: <PERSON: 1>
    r"<\s*{entity_type}_{index}\s*\.\s*>",    # 点结尾: <PERSON_1.>
    r"<\s*{entity_type}-{index}\s*>",         # 连字符: <PERSON-1>
    r"{entity_type}_{index}\s+",              # 后跟空格
    r"\{PERSON_{index}\}",                   # 单大括号
    r"<{entity_type}#?{index}>",              # 号号变体
]
```

#### 3.2.2 智能模糊匹配器

**文件**: `src/pii_airlock/core/fuzzy_matcher.py`

```python
from enum import Enum
from dataclasses import dataclass
from typing import Pattern
import re

class FuzzyMatchType(Enum):
    """模糊匹配类型"""
    EXACT = "exact"           # 精确匹配
    CASE_INSENSITIVE = "case" # 大小写不敏感
    WHITESPACE = "whitespace" # 空格变体
    BRACKET_VARIANT = "bracket" # 括号变体
    PUNCTUATION = "punctuation" # 标点符号
    SEPARATOR_VARIANT = "separator" # 分隔符变体
    PARTIAL = "partial"       # 部分匹配 (需确认)

@dataclass
class FuzzyMatch:
    """模糊匹配结果"""
    original: str            # 原始文本
    placeholder: str         # 标准化占位符
    match_type: FuzzyMatchType
    confidence: float        # 匹配置信度
    entity_type: str
    index: int

class FuzzyMatcher:
    """智能模糊匹配器"""

    def __init__(self, confidence_threshold: float = 0.85):
        self.confidence_threshold = confidence_threshold
        self._build_pattern_cache()

    def match(self, text: str, mapping: PIIMapping) -> list[FuzzyMatch]:
        """在文本中查找所有可能的占位符变体"""
        matches = []

        # 1. 尝试精确匹配
        matches.extend(self._exact_match(text, mapping))

        # 2. 尝试大小写变体
        matches.extend(self._case_variant_match(text, mapping))

        # 3. 尝试括号变体
        matches.extend(self._bracket_variant_match(text, mapping))

        # 4. 尝试分隔符变体
        matches.extend(self._separator_variant_match(text, mapping))

        # 5. 尝试标点处理
        matches.extend(self._punctuation_match(text, mapping))

        # 6. 去重和冲突解决
        return self._deduplicate(matches)

    def _exact_match(self, text: str, mapping: PIIMapping) -> list[FuzzyMatch]:
        """精确匹配"""
        matches = []
        for placeholder, value in mapping.items():
            if placeholder in text:
                matches.append(FuzzyMatch(
                    original=text,
                    placeholder=placeholder,
                    match_type=FuzzyMatchType.EXACT,
                    confidence=1.0,
                    entity_type=mapping.get_entity_type(placeholder),
                    index=mapping.get_index(placeholder)
                ))
        return matches
```

#### 3.2.3 置信度评分

```python
def calculate_confidence(match: str, expected: str) -> float:
    """计算匹配置信度"""
    score = 1.0

    # 大小写差异 (影响较小)
    if match.lower() == expected.lower() and match != expected:
        score -= 0.05

    # 空格差异 (影响较小)
    if match.replace(" ", "") == expected.replace(" ", ""):
        score -= 0.03

    # 括号类型变化 (影响中等)
    bracket_pairs = [("<", ">"), ("[", "]"), ("{", "}")]
    if any(match.replace(b[0], "<").replace(b[1], ">") == expected
           for b in bracket_pairs):
        score -= 0.1

    # 分隔符变化
    if re.sub(r"[_:\-#]", "_", match) == expected:
        score -= 0.08

    # 完全不同的格式
    if extract_entity_and_index(match) != extract_entity_and_index(expected):
        score -= 0.5

    return max(0.0, score)
```

### 3.3 接口设计

#### 3.3.1 配置选项

```python
# 环境变量
PII_AIRLOCK_FUZZY_MATCH_ENABLED=true        # 启用模糊匹配
PII_AIRLOCK_FUZZY_CONFIDENCE_THRESHOLD=0.85 # 置信度阈值
PII_AIRLOCK_FUZZY_LOG_MISMATCHES=true       # 记录不匹配情况

# API 请求级别
{
    "fuzzy_matching": {
        "enabled": True,
        "confidence_threshold": 0.85,
        "log_mismatches": True
    }
}
```

#### 3.3.2 响应增强

```python
@dataclass
class DeanonymizationResult:
    """回填结果 (增强版)"""
    text: str
    replaced_count: int
    unresolved: list[str]

    # 新增字段
    fuzzy_matches: list[FuzzyMatch] = field(default_factory=list)
    confidence_scores: dict[str, float] = field(default_factory=dict)
    corrections_made: list[str] = field(default_factory=list)
```

### 3.4 实现步骤

| 步骤 | 任务 | 估计工作量 | 依赖 |
|------|------|-----------|------|
| 2.1 | 实现 FuzzyMatcher 基类 | 1d | - |
| 2.2 | 实现各种匹配模式 | 1.5d | 2.1 |
| 2.3 | 实现置信度评分 | 1d | 2.2 |
| 2.4 | 集成到 Deanonymizer | 0.5d | 2.3 |
| 2.5 | 实现不匹配日志 | 0.5d | 2.4 |
| 2.6 | 编写单元测试 | 1.5d | 2.5 |
| 2.7 | 性能优化 (模式缓存) | 0.5d | 2.2 |

**总计**: 约 6.5 天

### 3.5 测试用例

```python
# tests/test_fuzzy_matcher.py
def test_case_variant():
    """测试大小写变体"""
    result = deanonymizer.deanonymize("请联系 <Person_1>", mapping)
    assert "张三" in result.text

def test_bracket_variant():
    """测试括号变体"""
    result = deanonymizer.deanonymize("请联系 [PERSON_1]", mapping)
    assert "张三" in result.text

def test_separator_variant():
    """测试分隔符变体"""
    result = deanonymizer.deanonymize("请联系 <PERSON-1>", mapping)
    assert "张三" in result.text

def test_punctuation_variant():
    """测试标点符号"""
    result = deanonymizer.deanonymize("请联系 <PERSON_1>。", mapping)
    assert "张三" in result.text

def test_confidence_threshold():
    """测试置信度阈值"""
    # 低置信度匹配不应被替换
    result = deanonymizer.deanonymize("请联系 PERSON1", mapping)
    assert "PERSON1" in result.text  # 不替换

def test_multiple_variants():
    """测试多种变体同时存在"""
    result = deanonymizer.deanonymize(
        "<PERSON_1>和[PERSON_1]以及<Person_1>",
        mapping
    )
    assert result.text.count("张三") == 3
```

---

## 4. 功能 3: 审计日志系统

### 4.1 需求描述

建立完整的审计日志系统，记录所有 PII 相关操作，支持:

1. **操作追踪**: 谁、何时、做了什么
2. **合规审计**: 满足 SOX/GDPR/CCPA 要求
3. **安全分析**: 检测异常行为
4. **日志导出**: 支持 CSV/JSON/Syslog 格式

### 4.2 技术设计

#### 4.2.1 审计事件模型

**文件**: `src/pii_airlock/audit/models.py`

```python
from enum import Enum
from dataclasses import dataclass
from datetime import datetime
from typing import Any
import json

class AuditEventType(Enum):
    """审计事件类型"""
    # PII 操作
    PII_DETECTED = "pii_detected"
    PII_ANONYMIZED = "pii_anonymized"
    PII_DEANONYMIZED = "pii_deanonymized"

    # API 操作
    API_REQUEST = "api_request"
    API_RESPONSE = "api_response"
    API_ERROR = "api_error"

    # 配置变更
    CONFIG_CHANGED = "config_changed"
    CONFIG_LOADED = "config_loaded"

    # 安全事件
    AUTH_FAILURE = "auth_failure"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"

@dataclass
class AuditEvent:
    """审计事件"""
    event_id: str                    # 事件唯一ID
    event_type: AuditEventType       # 事件类型
    timestamp: datetime              # 时间戳
    tenant_id: str | None = None     # 租户ID
    user_id: str | None = None       # 用户ID
    request_id: str | None = None    # 请求ID

    # 事件详情
    entity_type: str | None = None   # PII 类型
    entity_count: int = 0            # PII 数量
    strategy_used: str | None = None # 使用的策略

    # 上下文信息
    source_ip: str | None = None
    user_agent: str | None = None
    api_key: str | None = None       # 脱敏后的 API Key

    # 额外元数据
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "request_id": self.request_id,
            "entity_type": self.entity_type,
            "entity_count": self.entity_count,
            "strategy_used": self.strategy_used,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "api_key_hash": hash_api_key(self.api_key) if self.api_key else None,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """转换为 JSON"""
        return json.dumps(self.to_dict(), ensure_ascii=False)
```

#### 4.2.2 审计日志存储

**文件**: `src/pii_airlock/audit/store.py`

```python
from abc import ABC, abstractmethod
from typing import List
import json
from datetime import datetime, timedelta

class AuditStore(ABC):
    """审计日志存储接口"""

    @abstractmethod
    async def write(self, event: AuditEvent) -> None:
        """写入审计事件"""
        pass

    @abstractmethod
    async def query(self, filter: AuditFilter) -> List[AuditEvent]:
        """查询审计事件"""
        pass

    @abstractmethod
    async def export(self, filter: AuditFilter, format: str) -> str:
        """导出审计日志"""
        pass

class FileAuditStore(AuditStore):
    """文件审计日志存储 (开发/小规模)"""

    def __init__(self, log_dir: str, rotation: str = "daily"):
        self.log_dir = Path(log_dir)
        self.rotation = rotation
        self.log_dir.mkdir(parents=True, exist_ok=True)

    async def write(self, event: AuditEvent) -> None:
        """追加写入日志文件"""
        log_file = self._get_log_file(event.timestamp)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(event.to_json() + "\n")

    async def query(self, filter: AuditFilter) -> List[AuditEvent]:
        """查询日志文件"""
        events = []
        for log_file in self._get_log_files(filter.start_date, filter.end_date):
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    event = AuditEvent.from_dict(json.loads(line))
                    if filter.match(event):
                        events.append(event)
        return events

class DatabaseAuditStore(AuditStore):
    """数据库审计日志存储 (生产环境)"""

    def __init__(self, db_url: str):
        # 使用 SQLite / PostgreSQL
        self.db_url = db_url
        self._init_schema()

    async def write(self, event: AuditEvent) -> None:
        """批量写入数据库"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO audit_logs (...) VALUES (...)
            """, *event.to_dict().values())
```

#### 4.2.3 审计日志 API

**文件**: `src/pii_airlock/api/audit.py`

```python
from fastapi import APIRouter, Depends, Query
from pii_airlock.audit.models import AuditFilter, AuditEvent

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])

@router.get("/events", response_model=List[AuditEvent])
async def query_audit_events(
    start_date: datetime = Query(...),
    end_date: datetime = Query(...),
    event_type: str | None = None,
    tenant_id: str | None = None,
    limit: int = Query(100, le=10000),
    offset: int = Query(0),
    # 权限检查
    current_user = Depends(require_audit_permission)
):
    """查询审计事件"""
    filter = AuditFilter(
        start_date=start_date,
        end_date=end_date,
        event_type=event_type,
        tenant_id=tenant_id
    )
    events = await audit_store.query(filter)
    return events[offset:offset + limit]

@router.get("/events/export")
async def export_audit_events(
    start_date: datetime,
    end_date: datetime,
    format: str = Query("json", regex="^(json|csv|syslog)$"),
    current_user = Depends(require_audit_permission)
):
    """导出审计日志"""
    filter = AuditFilter(start_date=start_date, end_date=end_date)
    data = await audit_store.export(filter, format)

    filename = f"audit_{start_date.date()}_{end_date.date()}.{format}"
    return Response(
        content=data,
        media_type=f"application/{format}",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/stats/summary")
async def get_audit_summary(
    start_date: datetime,
    end_date: datetime,
    current_user = Depends(require_audit_permission)
):
    """获取审计统计摘要"""
    filter = AuditFilter(start_date=start_date, end_date=end_date)
    return await audit_store.get_summary(filter)
```

### 4.3 数据库 Schema

```sql
-- 审计日志表
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    event_id VARCHAR(64) UNIQUE NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    tenant_id VARCHAR(64),
    user_id VARCHAR(64),
    request_id VARCHAR(64),

    -- PII 详情 (加密存储)
    entity_type VARCHAR(50),
    entity_count INTEGER DEFAULT 0,
    strategy_used VARCHAR(50),

    -- 上下文
    source_ip VARCHAR(45),  -- IPv6 兼容
    user_agent TEXT,
    api_key_hash VARCHAR(64),

    -- 元数据 (JSONB)
    metadata JSONB,

    -- 索引
    INDEX idx_timestamp (timestamp),
    INDEX idx_tenant_timestamp (tenant_id, timestamp),
    INDEX idx_event_type (event_type),
    INDEX idx_request_id (request_id)
);

-- 审计摘要表 (预聚合)
CREATE TABLE audit_summary (
    date DATE NOT NULL,
    tenant_id VARCHAR(64),
    event_type VARCHAR(50),
    count BIGINT DEFAULT 0,

    PRIMARY KEY (date, tenant_id, event_type)
);
```

### 4.4 实现步骤

| 步骤 | 任务 | 估计工作量 | 依赖 |
|------|------|-----------|------|
| 3.1 | 实现 AuditEvent 模型 | 0.5d | - |
| 3.2 | 实现 AuditFilter 查询模型 | 0.5d | 3.1 |
| 3.3 | 实现 FileAuditStore | 1d | 3.2 |
| 3.4 | 实现 DatabaseAuditStore | 1.5d | 3.2 |
| 3.5 | 实现 audit API 端点 | 1d | 3.4 |
| 3.6 | 集成到现有代理流程 | 1d | 3.5 |
| 3.7 | 实现日志导出功能 | 1d | 3.3 |
| 3.8 | 实现权限控制 | 0.5d | 3.5 |
| 3.9 | 编写单元测试 | 1.5d | 3.8 |

**总计**: 约 8.5 天

---

## 5. 功能 4: 合规报告生成

### 5.1 需需描述

自动生成符合 GDPR/CCPA 要求的合规性证明报告。

### 5.2 技术设计

#### 5.2.1 报告模板

**文件**: `src/pii_airlock/api/reports/templates/`

```
templates/
├── gdpr_compliance.html.j2     # GDPR 合规报告
├── ccpa_compliance.html.j2     # CCPA 合规报告
├── data_processing.html.j2     # 数据处理活动报告
└── security_assessment.html.j2 # 安全评估报告
```

#### 5.2.2 报告生成器

**文件**: `src/pii_airlock/api/reports/generator.py`

```python
from jinja2 import Environment, FileSystemLoader
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class ComplianceReportConfig:
    """合规报告配置"""
    report_type: str  # gdpr, ccpa, security
    period_start: datetime
    period_end: datetime
    tenant_id: str | None = None
    include_details: bool = True
    language: str = "zh"

class ComplianceReportGenerator:
    """合规报告生成器"""

    def __init__(self, template_dir: str):
        self.jinja_env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=True
        )

    def generate(self, config: ComplianceReportConfig) -> str:
        """生成合规报告"""
        # 1. 收集数据
        data = self._collect_data(config)

        # 2. 选择模板
        template = self.jinja_env.get_template(f"{config.report_type}_compliance.html.j2")

        # 3. 渲染报告
        return template.render(**data)

    def _collect_data(self, config: ComplianceReportConfig) -> dict:
        """收集报告所需数据"""
        audit_store = get_audit_store()

        # 基本信息
        data = {
            "report_id": generate_report_id(),
            "generated_at": datetime.now(),
            "period_start": config.period_start,
            "period_end": config.period_end,
            "tenant_id": config.tenant_id,
        }

        # 统计数据
        stats = audit_store.get_summary(
            AuditFilter(config.period_start, config.period_end, config.tenant_id)
        )
        data["statistics"] = stats

        # PII 处理统计
        data["pii_by_type"] = audit_store.get_pii_statistics(config)
        data["pii_by_strategy"] = audit_store.get_strategy_statistics(config)

        # 合规检查项
        data["compliance_checks"] = self._run_compliance_checks(config)

        return data

    def _run_compliance_checks(self, config: ComplianceReportConfig) -> dict:
        """运行合规检查"""
        return {
            "gdpr": {
                "data_minimization": self._check_data_minimization(config),
                "purpose_limitation": self._check_purpose_limitation(config),
                "storage_limitation": self._check_storage_limitation(config),
                "integrity_confidentiality": self._check_security(config),
            },
            "ccpa": {
                "right_to_know": self._check_right_to_know(config),
                "right_to_delete": self._check_right_to_delete(config),
                "right_to_opt_out": self._check_right_to_opt_out(config),
            }
        }
```

### 5.3 报告内容结构

#### 5.3.1 GDPR 合规报告

```markdown
# GDPR 合规性证明报告

## 1. 报告信息
- 报告ID: REP-2026-001
- 生成时间: 2026-01-22
- 报告周期: 2025-12-01 至 2025-12-31
- 租户: tenant_001

## 2. 数据处理活动摘要
- 总请求数: 125,430
- PII 检测次数: 98,234
- 脱敏成功率: 99.97%
- 回填成功率: 99.92%

## 3. PII 类型分布
| 类型 | 检测次数 | 脱敏策略 |
|------|---------|---------|
| PERSON | 45,123 | placeholder |
| PHONE | 32,456 | synthetic |
| EMAIL | 15,789 | hash |
| ID_CARD | 4,866 | redact |

## 4. GDPR 原则符合性
### 4.1 数据最小化
- ✅ 仅识别和处理必要的 PII 类型
- ✅ 脱敏后数据不包含原始敏感信息

### 4.2 目的限制
- ✅ 数据仅用于 LLM 处理目的
- ✅ 自动过期机制 (TTL: 5分钟)

### 4.3 存储限制
- ✅ 映射数据自动清理
- ✅ 审计日志定期归档

### 4.4 完整性与保密性
- ✅ 传输加密 (HTTPS)
- ✅ 存储加密 (可选)
- ✅ 访问控制 (API Key + RBAC)

## 5. 数据主体权利
### 5.1 访问权
- 提供 `/api/v1/audit` 端点查询个人数据处理记录

### 5.2 删除权
- 映射数据自动过期删除
- 提供 API 手动清除接口

### 5.3 可移植权
- 支持审计日志导出 (JSON/CSV)

## 6. 第三方数据处理
- 上游LLM: OpenAI API
- 传输数据: 已脱敏数据
- 原始数据: 从不发送至第三方

## 7. 安全措施
- 传输加密: TLS 1.3
- 访问日志: 完整记录
- 异常检测: 启用
```

### 5.4 API 端点

```python
@router.post("/api/v1/reports/compliance")
async def generate_compliance_report(
    report_type: str = Query(..., regex="^(gdpr|ccpa|security)$"),
    period_start: datetime = Query(...),
    period_end: datetime = Query(...),
    tenant_id: str | None = None,
    format: str = Query("html", regex="^(html|pdf)$"),
    current_user = Depends(require_report_permission)
):
    """生成合规报告"""
    config = ComplianceReportConfig(
        report_type=report_type,
        period_start=period_start,
        period_end=period_end,
        tenant_id=tenant_id
    )

    generator = ComplianceReportGenerator()
    report_html = generator.generate(config)

    if format == "pdf":
        # 使用 weasyprint 或 playwright 转换
        pdf_bytes = html_to_pdf(report_html)
        return Response(content=pdf_bytes, media_type="application/pdf")

    return HTMLResponse(content=report_html)
```

### 5.5 实现步骤

| 步骤 | 任务 | 估计工作量 | 依赖 |
|------|------|-----------|------|
| 4.1 | 设计报告模板 | 1d | - |
| 4.2 | 实现 ComplianceReportGenerator | 1.5d | 4.1 |
| 4.3 | 实现 GDPR 合规检查 | 1d | 3 (审计日志) |
| 4.4 | 实现 CCPA 合规检查 | 0.5d | 4.3 |
| 4.5 | 实现报告 API 端点 | 0.5d | 4.2 |
| 4.6 | 实现 PDF 导出 | 1d | 4.5 |
| 4.7 | 编写测试 | 0.5d | 4.6 |

**总计**: 约 6 天

---

## 6. 功能 5: 秘密泄露防护库

### 6.1 需求描述

预置常见 API Key、密钥、证书的识别规则，防止开发者误将敏感凭证发送给 LLM。

### 6.2 技术设计

#### 6.2.1 预置规则库

**文件**: `config/secrets_patterns.yaml`

```yaml
# API 密钥规则
patterns:
  # AWS Access Key
  - name: aws_access_key
    entity_type: AWS_ACCESS_KEY
    regex: "(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}"
    score: 0.95
    risk_level: critical
    description: "AWS Access Key ID"

  # AWS Secret Key
  - name: aws_secret_key
    entity_type: AWS_SECRET_KEY
    regex: "[A-Za-z0-9/+=]{40}"
    context: ["aws", "secret", "key"]
    score: 0.9
    risk_level: critical
    description: "AWS Secret Access Key"

  # GitHub Token
  - name: github_token
    entity_type: GITHUB_TOKEN
    regex: "ghp_[a-zA-Z0-9]{36}"
    score: 0.95
    risk_level: high
    description: "GitHub Personal Access Token"

  # GitHub OAuth
  - name: github_oauth
    entity_type: GITHUB_OAUTH
    regex: "gho_[a-zA-Z0-9]{36}"
    score: 0.95
    risk_level: high
    description: "GitHub OAuth Token"

  # Stripe API Key
  - name: stripe_key
    entity_type: STRIPE_KEY
    regex: "sk_live_[0-9a-zA-Z]{24,}"
    score: 0.95
    risk_level: critical
    description: "Stripe Live API Key"

  # OpenAI API Key
  - name: openai_key
    entity_type: OPENAI_KEY
    regex: "sk-[a-zA-Z0-9]{48}"
    score: 0.95
    risk_level: critical
    description: "OpenAI API Key"

  # Slack Token
  - name: slack_token
    entity_type: SLACK_TOKEN
    regex: "xox[baprs]-[a-zA-Z0-9-]{10,}"
    score: 0.9
    risk_level: high
    description: "Slack Bot/User Token"

  # Google API Key
  - name: google_api_key
    entity_type: GOOGLE_API_KEY
    regex: "AIza[A-Za-z0-9_\-]{35}"
    score: 0.9
    risk_level: high
    description: "Google API Key"

  # Google OAuth
  - name: google_oauth
    entity_type: GOOGLE_OAUTH
    regex: "[0-9]+-[a-zA-Z0-9_]{32}\\.apps\\.googleusercontent\\.com"
    score: 0.9
    risk_level: high
    description: "Google OAuth Client ID"

  # JWT Token
  - name: jwt_token
    entity_type: JWT_TOKEN
    regex: "eyJ[A-Za-z0-9_\-]+\\.eyJ[A-Za-z0-9_\-]+\\.[A-Za-z0-9_\-]+"
    score: 0.85
    risk_level: high
    description: "JSON Web Token"

  # Private Key (PEM)
  - name: private_key_pem
    entity_type: PRIVATE_KEY
    regex: "-----BEGIN[A-Z]+ PRIVATE KEY-----"
    score: 0.95
    risk_level: critical
    description: "PEM Private Key"

  # Database Connection String
  - name: db_connection_string
    entity_type: DB_CONNECTION
    regex: "(?:mongodb|mysql|postgres|redis)://[^\s<>]+:[^\s<>]+@"
    score: 0.85
    risk_level: high
    description: "Database Connection String"

  # IP Address (Private)
  - name: private_ip
    entity_type: PRIVATE_IP
    regex: "(?:10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)[0-9.]+"
    score: 0.8
    risk_level: medium
    description: "Private IP Address"

  # SSH Key
  - name: ssh_key
    entity_type: SSH_KEY
    regex: "ssh-(?:rsa|ed25519|dss) [A-Za-z0-9+/=]+"
    score: 0.9
    risk_level: high
    description: "SSH Public Key"

  # Kubernetes Token
  - name: k8s_token
    entity_type: K8S_TOKEN
    regex: "eyJ[A-Za-z0-9_\-]+\\.eyJ[A-Za-z0-9_\-]+\\.[A-Za-z0-9_\-]+"
    context: ["kubernetes", "k8s"]
    score: 0.9
    risk_level: high
    description: "Kubernetes Service Account Token"
```

#### 6.2.2 风险级别与处理策略

```python
class RiskLevel(Enum):
    """风险级别"""
    CRITICAL = "critical"  # 绝对不能发送
    HIGH = "high"          # 强烈建议阻止
    MEDIUM = "medium"      # 需要警告
    LOW = "low"           # 记录即可

class SecretHandlingAction(Enum):
    """秘密处理动作"""
    BLOCK = "block"           # 阻止请求
    REDACT = "redact"         # 完全删除
    REPLACE = "replace"       # 替换为占位符
    WARN = "warn"             # 警告但放行
    LOG = "log"               # 仅记录

# 风险级别默认处理策略
DEFAULT_ACTION_MAP = {
    RiskLevel.CRITICAL: SecretHandlingAction.BLOCK,
    RiskLevel.HIGH: SecretHandlingAction.REDACT,
    RiskLevel.MEDIUM: SecretHandlingAction.WARN,
    RiskLevel.LOW: SecretHandlingAction.LOG,
}
```

#### 6.2.3 秘密扫描器

**文件**: `src/pii_airlock/recognizers/secrets/scanner.py`

```python
class SecretScanner:
    """秘密扫描器"""

    def __init__(self, config_path: str | None = None):
        self.rules = self._load_rules(config_path)
        self.action_map = DEFAULT_ACTION_MAP.copy()

    def scan(self, text: str) -> SecretScanResult:
        """扫描文本中的秘密"""
        findings = []

        for rule in self.rules:
            matches = re.finditer(rule.regex, text)
            for match in matches:
                findings.append(SecretFinding(
                    type=rule.entity_type,
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    risk_level=rule.risk_level,
                    rule_name=rule.name,
                    confidence=rule.score
                ))

        # 按风险级别排序
        findings.sort(key=lambda f: f.risk_level.value, reverse=True)

        return SecretScanResult(findings=findings)

    def get_action(self, finding: SecretFinding) -> SecretHandlingAction:
        """获取处理动作"""
        return self.action_map.get(finding.risk_level, SecretHandlingAction.LOG)

@dataclass
class SecretFinding:
    """秘密发现结果"""
    type: str
    value: str
    start: int
    end: int
    risk_level: RiskLevel
    rule_name: str
    confidence: float

@dataclass
class SecretScanResult:
    """秘密扫描结果"""
    findings: list[SecretFinding]
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0

    def __post_init__(self):
        for f in self.findings:
            if f.risk_level == RiskLevel.CRITICAL:
                self.critical_count += 1
            elif f.risk_level == RiskLevel.HIGH:
                self.high_count += 1
            elif f.risk_level == RiskLevel.MEDIUM:
                self.medium_count += 1

    @property
    def should_block(self) -> bool:
        """是否应该阻止请求"""
        return self.critical_count > 0 or self.high_count > 0
```

### 6.3 API 集成

```python
# 在代理服务中集成
class ProxyService:
    def __init__(self):
        self.secret_scanner = SecretScanner()

    async def chat_completion(self, request: ChatCompletionRequest):
        # 1. 扫描秘密
        content = request.messages[-1].content
        scan_result = self.secret_scanner.scan(content)

        # 2. 记录秘密检测
        if scan_result.findings:
            logger.warning("Secrets detected", extra={
                "count": len(scan_result.findings),
                "critical": scan_result.critical_count,
                "high": scan_result.high_count
            })

        # 3. 根据风险级别处理
        if scan_result.should_block:
            raise SecurityException(
                f"Request blocked: detected {scan_result.critical_count} critical "
                f"and {scan_result.high_count}" + " high-risk secrets"
            )

        # 4. 继续处理...
```

### 6.4 自定义配置

```yaml
# config/secrets_policy.yaml
policy:
  # 全局策略
  default_action: "warn"

  # 按风险级别覆盖
  by_risk_level:
    critical: "block"
    high: "redact"
    medium: "warn"
    low: "log"

  # 按类型覆盖
  by_type:
    AWS_ACCESS_KEY: "block"
    AWS_SECRET_KEY: "block"
    GITHUB_TOKEN: "redact"
    JWT_TOKEN: "warn"

  # 白名单 (例如测试环境)
  whitelist:
    - pattern: "sk-test-[a-zA-Z0-9]+"
      type: "stripe_test_key"
      action: "log"
```

### 6.5 实现步骤

| 步骤 | 任务 | 估计工作量 | 依赖 |
|------|------|-----------|------|
| 5.1 | 收集预置规则 (50+ 规则) | 1d | - |
| 5.2 | 实现 SecretScanner | 1d | 5.1 |
| 5.3 | 实现风险级别处理 | 0.5d | 5.2 |
| 5.4 | 实现策略配置 | 0.5d | 5.3 |
| 5.5 | 集成到代理服务 | 0.5d | 5.4 |
| 5.6 | 实现白名单功能 | 0.5d | 5.4 |
| 5.7 | 编写单元测试 | 1d | 5.5 |

**总计**: 约 5 天

---

## 7. 整体实施计划

### 7.1 依赖关系图

```
功能 3 (审计日志) ← 基础依赖
     ↓
功能 4 (合规报告) ← 依赖审计日志
     ↓
功能 1 (仿真数据) ← 独立
功能 2 (模糊匹配) ← 独立
功能 5 (秘密防护) ← 独立
```

### 7.2 开发阶段划分

| 阶段 | 功能 | 周期 | 优先级 |
|------|------|------|--------|
| **Week 1-2** | 功能 3: 审计日志系统 | 8.5d | P0 (基础依赖) |
| **Week 2-3** | 功能 1: 仿真数据合成 | 10.5d | P0 |
| **Week 3** | 功能 2: 模糊匹配纠错 | 6.5d | P0 |
| **Week 4** | 功能 5: 秘密泄露防护 | 5d | P1 |
| **Week 4-5** | 功能 4: 合规报告生成 | 6d | P1 |
| **Week 5** | 集成测试与文档 | 5d | - |

**总计**: 约 25 工作日 (5 周)

### 7.3 并行开发建议

```
Week 1:
  - 开发者 A: 审计日志系统 (步骤 3.1-3.4)
  - 开发者 B: 收集仿真数据 + 实现 SecretScanner

Week 2:
  - 开发者 A: 审计日志 API (步骤 3.5-3.9)
  - 开发者 B: 仿真数据生成器 (步骤 1.3-1.8)

Week 3:
  - 开发者 A: 模糊匹配纠错 (步骤 2.1-2.7)
  - 开发者 B: 仿真数据集成测试 (步骤 1.9-1.11)

Week 4:
  - 开发者 A: 秘密防护 (步骤 5.1-5.7)
  - 开发者 B: 合规报告 (步骤 4.1-4.4)

Week 5:
  - 全员: 集成测试 + 文档编写
```

---

## 8. 新增文件清单

```
src/pii_airlock/
├── core/
│   ├── synthetic/               # 新建: 仿真数据模块
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── generators.py
│   │   ├── person.py
│   │   ├── phone.py
│   │   ├── email.py
│   │   ├── location.py
│   │   ├── id_card.py
│   │   ├── credit_card.py
│   │   └── data/
│   │       ├── surnames.txt
│   │       ├── given_names.txt
│   │       ├── cities.txt
│   │       └── phone_prefixes.yaml
│   └── fuzzy_matcher.py         # 新建: 模糊匹配器
│
├── audit/                       # 新建: 审计模块
│   ├── __init__.py
│   ├── models.py
│   ├── store.py
│   └── middleware.py            # 审计中间件
│
├── recognizers/
│   └── secrets/                 # 新建: 秘密识别模块
│       ├── __init__.py
│       ├── scanner.py
│       └── rules.py
│
└── api/
    ├── audit.py                 # 新建: 审计 API
    └── reports/                 # 新建: 报告模块
        ├── __init__.py
        ├── generator.py
        └── templates/
            ├── gdpr_compliance.html.j2
            ├── ccpa_compliance.html.j2
            └── security_assessment.html.j2

config/
├── secrets_patterns.yaml        # 新建: 秘密规则库
├── secrets_policy.yaml          # 新建: 秘密处理策略
└── synthetic_config.yaml        # 新建: 仿真数据配置

tests/
├── test_synthetic.py            # 新建
├── test_fuzzy_matcher.py        # 新建
├── test_audit.py                # 新建
├── test_reports.py              # 新建
└── test_secrets.py              # 新建
```

---

## 9. 配置变量汇总

| 变量名 | 说明 | 默认值 | 功能模块 |
|-------|------|--------|---------|
| `PII_AIRLOCK_SYNTHETIC_ENABLED` | 启用仿真数据合成 | false | 1 |
| `PII_AIRLOCK_SYNTHETIC_SEED` | 仿真数据随机种子 | null | 1 |
| `PII_AIRLOCK_SYNTHETIC_REGION` | 地域偏好 | null | 1 |
| `PII_AIRLOCK_FUZZY_MATCH_ENABLED` | 启用模糊匹配 | true | 2 |
| `PII_AIRLOCK_FUZZY_CONFIDENCE` | 置信度阈值 | 0.85 | 2 |
| `PII_AIRLOCK_AUDIT_ENABLED` | 启用审计日志 | true | 3 |
| `PII_AIRLOCK_AUDIT_STORE` | 审计存储类型 | file | 3 |
| `PII_AIRLOCK_AUDIT_PATH` | 审计日志路径 | ./logs/audit | 3 |
| `PII_AIRLOCK_AUDIT_DB_URL` | 审计数据库 URL | null | 3 |
| `PII_AIRLOCK_REPORTS_ENABLED` | 启用合规报告 | true | 4 |
| `PII_AIRLOCK_SECRETS_ENABLED` | 启用秘密扫描 | true | 5 |
| `PII_AIRLOCK_SECRETS_POLICY` | 秘密处理策略 | warn | 5 |

---

## 10. API 端点汇总

| 端点 | 方法 | 说明 | 权限 |
|------|------|------|------|
| `/api/v1/audit/events` | GET | 查询审计事件 | AUDIT_VIEW |
| `/api/v1/audit/events/export` | GET | 导出审计日志 | AUDIT_EXPORT |
| `/api/v1/audit/stats/summary` | GET | 获取审计摘要 | AUDIT_VIEW |
| `/api/v1/reports/compliance` | POST | 生成合规报告 | REPORT_GENERATE |
| `/api/v1/secrets/scan` | POST | 扫描文本中的秘密 | - |
| `/api/v1/secrets/rules` | GET | 获取秘密规则列表 | ADMIN |

---

## 11. 测试策略

### 11.1 单元测试覆盖率目标: 85%+

| 模块 | 测试文件 | 覆盖目标 |
|------|---------|---------|
| synthetic/ | test_synthetic.py | 80% |
| fuzzy_matcher | test_fuzzy_matcher.py | 85% |
| audit/ | test_audit.py | 85% |
| reports/ | test_reports.py | 80% |
| secrets/ | test_secrets.py | 90% |

### 11.2 集成测试

```python
# tests/test_integration_phase6.py
@pytest.mark.asyncio
async def test_synthetic_with_fuzzy_rehydration():
    """测试仿真数据 + 模糊回填"""
    anonymizer = Anonymizer(strategy=StrategyType.SYNTHETIC)
    result = anonymizer.anonymize("张三的电话是13800138000")

    # LLM 返回带格式变化的占位符
    llm_response = "请联系 < Person_1 >"
    restored = deanonymizer.deanonymize(llm_response, result.mapping)

    assert "张三" in restored.text

@pytest.mark.asyncio
async def test_secret_scanning_blocks_request():
    """测试秘密扫描阻止请求"""
    request = ChatCompletionRequest(
        messages=[{"role": "user", "content": "My key is sk-abc123..."}]
    )

    with pytest.raises(SecurityException):
        await proxy.chat_completion(request)

@pytest.mark.asyncio
async def test_audit_trail_complete():
    """测试审计追踪完整性"""
    # 发起请求
    response = await client.chat.completions.create(...)

    # 检查审计日志
    events = await audit_store.query(AuditFilter(
        start_date=datetime.now() - timedelta(minutes=1),
        end_date=datetime.now()
    ))

    assert any(e.event_type == AuditEventType.PII_DETECTED for e in events)
    assert any(e.event_type == AuditEventType.PII_ANONYMIZED for e in events)
    assert any(e.event_type == AuditEventType.API_REQUEST for e in events)
```

### 11.3 性能测试

| 指标 | 目标 | 测试方法 |
|------|------|---------|
| 仿真生成延迟 | <10ms | 基准测试 |
| 模糊匹配延迟 | <5ms | 基准测试 |
| 审计日志写入 | <2ms | 批量写入测试 |
| 秘密扫描延迟 | <20ms | 规则集测试 |

---

## 12. 发布计划

### 12.1 版本规划

| 版本 | 功能 | 发布日期 |
|------|------|---------|
| v1.2.0-alpha1 | 审计日志系统 | Week 2 |
| v1.2.0-alpha2 | 仿真数据 + 模糊匹配 | Week 3 |
| v1.2.0-beta1 | 秘密防护 | Week 4 |
| v1.2.0-rc1 | 合规报告 | Week 5 |
| v1.2.0 | 正式版 | Week 5 末 |

### 12.2 文档更新

- [ ] 更新 README.md 添加新功能说明
- [ ] 创建 Phase 6 功能指南 (docs/guide/phase6-features.md)
- [ ] 更新 API 文档
- [ ] 创建合规白皮书模板
- [ ] 更新 CLAUDE.md 添加新开发命令

---

## 13. 风险管理

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|---------|
| 仿真数据质量问题 | 中 | 高 | 使用真实数据集 + 多轮测试 |
| 模糊匹配误报 | 低 | 中 | 可配置置信度阈值 |
| 审计日志性能影响 | 中 | 中 | 异步写入 + 批量操作 |
| 合规报告准确性 | 低 | 高 | 法务审核 + 模板验证 |
| 秘密规则漏报 | 低 | 高 | 定期更新规则库 |

---

## 14. 后续优化方向

### Phase 7 (可选)
- Redis Cluster 支持
- 分布式限流
- OpenTelemetry 集成
- 多语言 PII 支持

### Phase 8 (长期)
- 机器学习辅助 PII 识别
- 联邦学习支持
- 零信任架构集成

---

*本计划将根据开发进展动态更新*
