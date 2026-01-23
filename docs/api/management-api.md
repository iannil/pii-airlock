# PII-AIRLOCK 管理 API 文档

本文档描述 PII-AIRLOCK 的管理 API 端点，包括合规配置、审计日志、白名单管理和意图检测 API。

## 目录

- [认证](#认证)
- [合规管理 API](#合规管理-api)
- [审计日志 API](#审计日志-api)
- [白名单管理 API](#白名单管理-api)
- [意图检测 API](#意图检测-api)
- [租户管理 API](#租户管理-api)
- [API Key 管理 API](#api-key-管理-api)
- [配额管理 API](#配额管理-api)
- [缓存管理 API](#缓存管理-api)

---

## 认证

管理 API 需要有效的 API Key 进行认证。

### 请求头

```http
Authorization: Bearer <api-key>
X-Tenant-ID: <tenant-id>  # 可选，多租户模式
```

### 认证模式

| 模式 | 环境变量 | 说明 |
|------|---------|------|
| 单租户 | `PII_AIRLOCK_MULTI_TENANT=false` | 使用 `PII_AIRLOCK_API_KEY` |
| 多租户 | `PII_AIRLOCK_MULTI_TENANT=true` | 租户独立的 API Key |

---

## 合规管理 API

基础路径: `/api/v1/compliance`

### 列出所有合规预设

```http
GET /api/v1/compliance/presets
```

**响应示例:**

```json
[
  {
    "name": "gdpr",
    "description": "GDPR 合规配置 - 欧盟通用数据保护条例",
    "version": "1.0.0",
    "region": ["EU", "EEA"],
    "language": ["en", "de", "fr"]
  },
  {
    "name": "pipl",
    "description": "PIPL 合规配置 - 中国个人信息保护法",
    "version": "1.0.0",
    "region": ["CN"],
    "language": ["zh"]
  }
]
```

### 获取预设详情

```http
GET /api/v1/compliance/presets/{preset_name}
```

**路径参数:**

| 参数 | 类型 | 说明 |
|------|------|------|
| `preset_name` | string | 预设名称 (gdpr, ccpa, pipl, financial) |

**响应示例:**

```json
{
  "name": "pipl",
  "description": "PIPL 合规配置",
  "version": "1.0.0",
  "region": ["CN"],
  "language": ["zh"],
  "pii_types": ["PERSON", "PHONE_NUMBER", "ID_CARD", "EMAIL_ADDRESS"],
  "strategies": {
    "PERSON": "placeholder",
    "PHONE_NUMBER": "mask",
    "ID_CARD": "hash",
    "EMAIL_ADDRESS": "placeholder"
  },
  "mapping_ttl": 300,
  "audit_retention_days": 180,
  "inject_prompt": true,
  "high_risk_types": ["ID_CARD", "CREDIT_CARD"],
  "medium_risk_types": ["PHONE_NUMBER", "EMAIL_ADDRESS"]
}
```

### 获取合规状态

```http
GET /api/v1/compliance/status
```

**响应示例:**

```json
{
  "active_preset": "pipl",
  "source": "api",
  "is_configured": true,
  "available_presets": ["gdpr", "ccpa", "pipl", "financial"]
}
```

### 激活合规预设

```http
POST /api/v1/compliance/activate
```

**请求体:**

```json
{
  "preset": "pipl"
}
```

**响应示例:**

```json
{
  "message": "Compliance preset 'pipl' activated successfully",
  "preset": {
    "name": "pipl",
    "description": "PIPL 合规配置",
    ...
  }
}
```

### 停用合规预设

```http
POST /api/v1/compliance/deactivate
```

**响应示例:**

```json
{
  "message": "Compliance preset deactivated. Using default configuration."
}
```

### 重新加载预设

```http
POST /api/v1/compliance/reload
```

**响应示例:**

```json
{
  "message": "Compliance presets reloaded. 4 presets available.",
  "count": "4"
}
```

---

## 审计日志 API

基础路径: `/api/v1/audit`

### 查询审计日志

```http
GET /api/v1/audit/logs
```

**查询参数:**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `event_type` | string | - | 事件类型筛选 |
| `entity_type` | string | - | 实体类型筛选 |
| `start_time` | ISO8601 | 24h ago | 开始时间 |
| `end_time` | ISO8601 | now | 结束时间 |
| `limit` | integer | 100 | 返回数量限制 |
| `offset` | integer | 0 | 分页偏移 |

**事件类型:**

| 类型 | 说明 |
|------|------|
| `pii_detected` | 检测到 PII |
| `pii_anonymized` | PII 已脱敏 |
| `pii_deanonymized` | PII 已回填 |
| `secret_detected` | 检测到密钥 |
| `secret_blocked` | 请求被阻止 |
| `config_changed` | 配置变更 |
| `quota_exceeded` | 配额超限 |

**响应示例:**

```json
{
  "logs": [
    {
      "event_id": "evt_abc123",
      "event_type": "pii_detected",
      "entity_type": "PERSON",
      "timestamp": "2024-01-23T10:00:00Z",
      "tenant_id": "default",
      "metadata": {
        "entity_count": 3,
        "request_id": "req_xyz789"
      }
    }
  ],
  "total": 150,
  "limit": 100,
  "offset": 0
}
```

### 获取审计统计

```http
GET /api/v1/audit/stats
```

**查询参数:**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `period` | string | day | 统计周期 (hour/day/week/month) |

**响应示例:**

```json
{
  "period": "day",
  "start_time": "2024-01-22T00:00:00Z",
  "end_time": "2024-01-23T00:00:00Z",
  "total_events": 1523,
  "by_event_type": {
    "pii_detected": 890,
    "pii_anonymized": 890,
    "pii_deanonymized": 743
  },
  "by_entity_type": {
    "PERSON": 450,
    "PHONE_NUMBER": 280,
    "EMAIL_ADDRESS": 160
  }
}
```

### 导出审计日志

```http
GET /api/v1/audit/export
```

**查询参数:**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `format` | string | json | 导出格式 (json/csv) |
| `start_time` | ISO8601 | - | 开始时间 |
| `end_time` | ISO8601 | - | 结束时间 |

**响应头:**

```http
Content-Type: application/json  # 或 text/csv
Content-Disposition: attachment; filename="audit_logs_20240123.json"
```

---

## 白名单管理 API

基础路径: `/api/v1/allowlist`

### 列出白名单条目

```http
GET /api/v1/allowlist
```

**查询参数:**

| 参数 | 类型 | 说明 |
|------|------|------|
| `category` | string | 类别筛选 (public_figures, locations, organizations) |
| `limit` | integer | 返回数量限制 |

**响应示例:**

```json
{
  "entries": [
    {
      "id": "wl_001",
      "value": "习近平",
      "category": "public_figures",
      "entity_type": "PERSON",
      "created_at": "2024-01-01T00:00:00Z"
    },
    {
      "id": "wl_002",
      "value": "北京",
      "category": "locations",
      "entity_type": "LOCATION",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 150
}
```

### 添加白名单条目

```http
POST /api/v1/allowlist
```

**请求体:**

```json
{
  "value": "阿里巴巴",
  "category": "organizations",
  "entity_type": "ORGANIZATION"
}
```

**响应示例:**

```json
{
  "id": "wl_003",
  "value": "阿里巴巴",
  "category": "organizations",
  "entity_type": "ORGANIZATION",
  "created_at": "2024-01-23T10:00:00Z"
}
```

### 删除白名单条目

```http
DELETE /api/v1/allowlist/{entry_id}
```

**响应示例:**

```json
{
  "message": "Entry deleted",
  "id": "wl_003"
}
```

### 批量导入

```http
POST /api/v1/allowlist/import
```

**请求体:**

```json
{
  "category": "public_figures",
  "entity_type": "PERSON",
  "values": ["人名1", "人名2", "人名3"]
}
```

**响应示例:**

```json
{
  "imported": 3,
  "duplicates": 0,
  "errors": 0
}
```

---

## 意图检测 API

基础路径: `/api/v1/intent`

### 检测文本意图

```http
POST /api/v1/intent/detect
```

**请求体:**

```json
{
  "text": "张三的电话号码是多少？"
}
```

**响应示例:**

```json
{
  "text": "张三的电话号码是多少？",
  "is_question": true,
  "question_type": "seeking_information",
  "pii_references": [
    {
      "text": "张三",
      "entity_type": "PERSON",
      "is_question_target": true
    }
  ],
  "should_anonymize": false,
  "confidence": 0.95
}
```

---

## 租户管理 API

基础路径: `/api/v1/tenants`

### 列出所有租户

```http
GET /api/v1/tenants
```

**响应示例:**

```json
[
  {
    "tenant_id": "team-a",
    "name": "Team A",
    "status": "active",
    "rate_limit": "100/minute",
    "max_ttl": 3600,
    "settings": {}
  }
]
```

### 获取租户详情

```http
GET /api/v1/tenants/{tenant_id}
```

**响应示例:**

```json
{
  "tenant_id": "team-a",
  "name": "Team A",
  "status": "active",
  "rate_limit": "100/minute",
  "max_ttl": 3600,
  "settings": {
    "allowed_models": ["gpt-4", "gpt-3.5-turbo"]
  }
}
```

---

## API Key 管理 API

基础路径: `/api/v1/keys`

### 创建 API Key

```http
POST /api/v1/keys
```

**请求体:**

```json
{
  "name": "Production Key",
  "scopes": ["llm:use", "metrics:view"],
  "expires_in_days": 90,
  "rate_limit": "1000/hour"
}
```

**响应示例:**

```json
{
  "api_key": "pii_abc123...xyz789",
  "key": {
    "key_id": "key_001",
    "key_prefix": "pii_abc",
    "tenant_id": "team-a",
    "name": "Production Key",
    "status": "active",
    "created_at": "2024-01-23T10:00:00Z",
    "expires_at": "2024-04-23T10:00:00Z",
    "scopes": ["llm:use", "metrics:view"],
    "rate_limit": "1000/hour"
  }
}
```

> **注意**: `api_key` 完整值仅在创建时返回一次，请妥善保存。

### 列出 API Keys

```http
GET /api/v1/keys
```

**响应示例:**

```json
[
  {
    "key_id": "key_001",
    "key_prefix": "pii_abc",
    "tenant_id": "team-a",
    "name": "Production Key",
    "status": "active",
    "created_at": "2024-01-23T10:00:00Z",
    "last_used": "2024-01-23T12:00:00Z",
    "expires_at": "2024-04-23T10:00:00Z",
    "scopes": ["llm:use", "metrics:view"],
    "rate_limit": "1000/hour"
  }
]
```

### 撤销 API Key

```http
DELETE /api/v1/keys/{key_id}
```

**响应示例:**

```json
{
  "message": "API key revoked",
  "key_id": "key_001"
}
```

---

## 配额管理 API

基础路径: `/api/v1/quota`

### 获取配额使用情况

```http
GET /api/v1/quota/usage
```

**响应示例:**

```json
{
  "tenant_id": "team-a",
  "usage": {
    "requests": {
      "hourly": 150,
      "daily": 2500
    },
    "tokens": {
      "daily": 500000
    }
  },
  "limits": {
    "requests": {
      "hourly": 1000,
      "daily": 10000
    },
    "tokens": {
      "daily": 5000000
    }
  }
}
```

---

## 缓存管理 API

基础路径: `/api/v1/cache`

### 获取缓存统计

```http
GET /api/v1/cache/stats
```

**响应示例:**

```json
{
  "entry_count": 125,
  "total_size_bytes": 2048576,
  "total_hits": 890,
  "avg_age_seconds": 1800.5,
  "entries": [
    {
      "key": "abc123...",
      "model": "gpt-4",
      "hits": 15,
      "age_seconds": 3600
    }
  ]
}
```

### 清除缓存

```http
DELETE /api/v1/cache
```

**响应示例:**

```json
{
  "message": "Cache cleared for tenant",
  "tenant_id": "team-a",
  "entries_removed": 125
}
```

### 获取全局缓存统计

```http
GET /api/v1/cache/stats/global
```

**响应示例:**

```json
{
  "entry_count": 500,
  "total_size_bytes": 10240000,
  "total_hits": 5000,
  "avg_age_seconds": 900.0,
  "entries": []
}
```

---

## 错误响应

所有 API 使用统一的错误响应格式:

```json
{
  "error": {
    "message": "详细错误信息",
    "type": "error_type",
    "code": 400
  }
}
```

### 常见错误码

| 状态码 | 类型 | 说明 |
|--------|------|------|
| 400 | `invalid_request_error` | 请求参数无效 |
| 401 | `authentication_error` | 认证失败 |
| 403 | `permission_denied` | 权限不足 |
| 404 | `not_found` | 资源不存在 |
| 429 | `rate_limit_error` | 请求频率超限 |
| 500 | `internal_error` | 服务器内部错误 |

---

## 变更日志

| 版本 | 日期 | 变更 |
|------|------|------|
| 1.1.0 | 2024-01-23 | 添加审计日志 API，意图检测 API |
| 1.0.0 | 2024-01-01 | 初始版本 |
