# PII 脱敏策略指南

PII-AIRLOCK 支持多种脱敏策略，可根据不同场景选择合适的策略。

## 策略类型

### 1. Placeholder (占位符策略)

**默认策略**，将敏感信息替换为类型化的占位符。

**示例**:
- `张三` → `<PERSON_1>`
- `13800138000` → `<PHONE_1>`
- `test@example.com` → `<EMAIL_1>`

**特点**:
- 支持脱敏/回填完整流程
- 保留实体类型信息
- 适合 LLM 处理，因为 LLM 可以理解占位符的语义

**适用场景**:
- 调用公有 LLM API
- 需要保持文本语义结构
- 需要精确还原原始数据

---

### 2. Hash (哈希策略)

使用 SHA256 哈希替换原始值。

**示例**:
- `张三` → `a1b2c3d4e5f6...` (64 位十六进制)
- `13800138000` → `f7e8d9c0b1a2...`

**特点**:
- 确定性哈希：相同输入始终产生相同输出
- 支持脱敏/回填（通过哈希映射）
- 单向转换，无法从哈希值反推原始值

**适用场景**:
- 日志分析和审计
- 数据去重和关联分析
- 需要长期存储但不需要还原的场景

**注意**: 哈希策略使用实体类型作为盐值，不同实体类型的相同值会产生不同哈希。

---

### 3. Mask (掩码策略)

部分隐藏敏感信息，保留格式特征。

**示例**:
- 手机号: `13800138000` → `138****8000`
- 邮箱: `test@example.com` → `t**t@example.com`
- 身份证: `110101199003077516` → `110101********7516`
- 银行卡: `6222021234567890` → `6222********7890`

**特点**:
- 保留数据格式，易于人工识别
- 不支持回填（无法还原）
- 不同实体类型有特定的掩码规则

**适用场景**:
- 用户界面显示
- 客服系统查看用户信息
- 需要人工验证格式的场景

---

### 4. Redact (完全替换策略)

将所有敏感信息替换为固定标记。

**示例**:
- `张三` → `[REDACTED]`
- `13800138000` → `[REDACTED]`
- `test@example.com` → `[REDACTED]`

**特点**:
- 最高级别的隐私保护
- 不支持回填
- 可自定义替换标记

**适用场景**:
- 高度敏感数据处理
- 仅需判断是否包含 PII 的场景
- 合规性要求严格的日志记录

---

## 策略对比

| 策略 | 支持回填 | 保留类型 | 保留格式 | 隐私级别 | 主要用途 |
|------|----------|----------|----------|----------|----------|
| placeholder | ✅ | ✅ | ❌ | 中 | LLM 处理 |
| hash | ✅ | ❌ | ❌ | 高 | 日志分析 |
| mask | ❌ | ❌ | ✅ | 中 | 显示场景 |
| redact | ❌ | ❌ | ❌ | 最高 | 审计日志 |

---

## 配置方式

### 1. API 请求级别

在调用脱敏 API 时指定策略:

```bash
# 使用 hash 策略
curl -X POST http://localhost:8000/api/test/anonymize \
  -H "Content-Type: application/json" \
  -d '{"text": "张三的电话是13800138000", "strategy": "hash"}'

# 为不同实体类型指定不同策略
curl -X POST http://localhost:8000/api/test/anonymize \
  -H "Content-Type: "application/json" \
  -d '{"text": "张三的电话是13800138000", "entity_strategies": {"PERSON": "mask", "PHONE_NUMBER": "redact"}}'
```

### 2. 环境变量配置

通过环境变量配置默认策略:

```bash
# 为特定实体类型配置策略
export PII_AIRLOCK_STRATEGY_PERSON=mask
export PII_AIRLOCK_STRATEGY_PHONE=redact
export PII_AIRLOCK_STRATEGY_EMAIL=hash
```

### 3. 代码级别配置

```python
from pii_airlock import Anonymizer
from pii_airlock.core.strategies import StrategyConfig, StrategyType

# 创建自定义策略配置
strategy_config = StrategyConfig({
    "PERSON": StrategyType.MASK,
    "PHONE_NUMBER": StrategyType.REDACT,
    "EMAIL_ADDRESS": StrategyType.HASH,
})

# 使用策略配置创建脱敏器
anonymizer = Anonymizer(strategy_config=strategy_config)
result = anonymizer.anonymize("张三的电话是13800138000")
```

### 4. YAML 配置文件

在 `config/custom_patterns.yaml` 中配置:

```yaml
patterns:
  - name: employee_id
    entity_type: EMPLOYEE_ID
    regex: "EMP[A-Z]\\d{6}"
    score: 0.85
    strategy: redact  # 为此自定义模式指定策略
```

---

## Web UI 测试

访问 `http://localhost:8000/ui` 可在 Web 界面中实时切换不同策略查看效果。

1. 在"脱敏策略"下拉框中选择策略
2. 点击"脱敏"按钮查看结果
3. 查看不同策略的脱敏效果对比

---

## 策略选择建议

### 场景一: 调用 LLM API
**推荐策略**: `placeholder`

LLM 需要理解文本的语义结构，占位符策略保留了实体类型信息，使 LLM 能够生成更准确的回复。

### 场景二: 日志记录
**推荐策略**: `hash` 或 `redact`

- `hash`: 适合需要追踪或去重的日志
- `redact`: 适合高度敏感的日志，不需要任何关联

### 场景三: 用户界面显示
**推荐策略**: `mask`

掩码策略保留了数据格式，用户可以验证信息（如核对后四位数字）而不会暴露完整信息。

### 场景四: 数据分析
**推荐策略**: `hash`

哈希策略允许你识别相同的数据点（统计唯一的用户数量），而不会暴露实际值。

---

## 注意事项

1. **回填限制**: 只有 `placeholder` 和 `hash` 策略支持回填。使用 `mask` 或 `redact` 后，原始值将永久丢失。

2. **一致性**: 在同一会话或处理流程中，应使用相同的策略，否则可能导致数据不一致。

3. **性能影响**: 不同策略的性能差异很小，选择时主要考虑业务需求而非性能。

4. **合规性**: 对于涉及 GDPR、个人信息保护法等合规要求的场景，建议咨询法律顾问选择合适的策略。
