# PII-AIRLOCK 多租户配置指南

本文档详细说明如何配置和管理 PII-AIRLOCK 的多租户功能。

## 目录

- [概述](#概述)
- [启用多租户模式](#启用多租户模式)
- [租户配置](#租户配置)
- [API Key 管理](#api-key-管理)
- [配额管理](#配额管理)
- [数据隔离](#数据隔离)
- [最佳实践](#最佳实践)

---

## 概述

PII-AIRLOCK 支持两种运行模式：

| 模式 | 环境变量 | 适用场景 |
|------|---------|---------|
| **单租户** | `PII_AIRLOCK_MULTI_TENANT=false` | 单一团队或应用使用 |
| **多租户** | `PII_AIRLOCK_MULTI_TENANT=true` | 多个团队共享部署 |

### 多租户特性

- ✅ 独立的 API Key 认证
- ✅ 独立的配额限制
- ✅ 独立的 PII 映射存储
- ✅ 独立的缓存空间
- ✅ 独立的审计日志

---

## 启用多租户模式

### 1. 环境变量配置

```bash
# 启用多租户模式
export PII_AIRLOCK_MULTI_TENANT=true

# 可选：禁止通过 Header 传递租户 ID（更安全）
export PII_AIRLOCK_ALLOW_HEADER_TENANT=false

# 可选：租户配置文件路径
export PII_AIRLOCK_TENANT_CONFIG_PATH=/config/tenants.yaml

# 可选：配额配置文件路径
export PII_AIRLOCK_QUOTA_CONFIG_PATH=/config/quotas.yaml
```

### 2. Docker Compose 配置

```yaml
version: "3.8"
services:
  pii-airlock:
    image: pii-airlock:latest
    environment:
      - PII_AIRLOCK_MULTI_TENANT=true
      - PII_AIRLOCK_ALLOW_HEADER_TENANT=false
      - PII_AIRLOCK_TENANT_CONFIG_PATH=/config/tenants.yaml
      - PII_AIRLOCK_QUOTA_CONFIG_PATH=/config/quotas.yaml
      - PII_AIRLOCK_REDIS_URL=redis://redis:6379/0
    volumes:
      - ./config:/config:ro
```

---

## 租户配置

### 租户配置文件 (`tenants.yaml`)

```yaml
# config/tenants.yaml
tenants:
  # 团队 A - 开发环境
  - tenant_id: "team-a"
    name: "Team A - Development"
    status: "active"  # active | suspended | disabled
    rate_limit: "100/minute"
    max_ttl: 3600  # 映射最大 TTL（秒）
    settings:
      allowed_models:
        - "gpt-4"
        - "gpt-3.5-turbo"
      enable_cache: true
      enable_audit: true
      compliance_preset: "pipl"

  # 团队 B - 生产环境
  - tenant_id: "team-b"
    name: "Team B - Production"
    status: "active"
    rate_limit: "1000/minute"
    max_ttl: 7200
    settings:
      allowed_models:
        - "gpt-4"
        - "gpt-4-turbo"
      enable_cache: true
      enable_audit: true
      compliance_preset: "gdpr"
      custom_patterns:
        - pattern: "EMP[A-Z]\\d{6}"
          entity_type: "EMPLOYEE_ID"
          score: 0.9

  # 测试租户
  - tenant_id: "test"
    name: "Test Environment"
    status: "active"
    rate_limit: "10/minute"
    max_ttl: 300
    settings:
      allowed_models:
        - "gpt-3.5-turbo"
      enable_cache: false
      enable_audit: true
```

### 租户状态说明

| 状态 | 说明 |
|------|------|
| `active` | 正常运行，允许所有操作 |
| `suspended` | 暂停服务，拒绝新请求 |
| `disabled` | 完全禁用，API Key 失效 |

---

## API Key 管理

### 创建租户 API Key

#### 方式 1：通过管理 API

```bash
curl -X POST http://localhost:8000/api/v1/keys \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Team A Production Key",
    "scopes": ["llm:use", "metrics:view"],
    "expires_in_days": 90,
    "rate_limit": "500/hour"
  }'
```

#### 方式 2：通过配置文件

```yaml
# config/api_keys.yaml
api_keys:
  - tenant_id: "team-a"
    name: "Team A Production Key"
    key_hash: "sha256:abc123..."  # 预生成的 Key 哈希
    scopes:
      - "llm:use"
      - "metrics:view"
      - "audit:view"
    rate_limit: "500/hour"
    expires_at: "2024-12-31T23:59:59Z"
```

### API Key 权限范围 (Scopes)

| Scope | 说明 |
|-------|------|
| `llm:use` | 使用 LLM 代理功能 |
| `llm:admin` | 管理 LLM 配置 |
| `metrics:view` | 查看监控指标 |
| `audit:view` | 查看审计日志 |
| `audit:export` | 导出审计日志 |
| `config:view` | 查看配置 |
| `config:manage` | 管理配置 |
| `keys:manage` | 管理 API Key |

### 撤销 API Key

```bash
curl -X DELETE http://localhost:8000/api/v1/keys/{key_id} \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

---

## 配额管理

### 配额配置文件 (`quotas.yaml`)

```yaml
# config/quotas.yaml
quotas:
  # 团队 A 配额
  - tenant_id: "team-a"
    soft_limit_percent: 80  # 80% 时发出警告
    requests:
      hourly: 1000
      daily: 10000
      monthly: 200000
    tokens:
      daily: 5000000
      monthly: 100000000

  # 团队 B 配额（生产环境，更高限制）
  - tenant_id: "team-b"
    soft_limit_percent: 90
    requests:
      hourly: 5000
      daily: 50000
    tokens:
      daily: 20000000

  # 测试租户（低配额）
  - tenant_id: "test"
    requests:
      hourly: 100
      daily: 500
    tokens:
      daily: 100000
```

### 配额类型

| 类型 | 说明 |
|------|------|
| `requests` | API 请求次数 |
| `tokens` | 处理的 Token 数量 |

### 配额周期

| 周期 | 说明 |
|------|------|
| `hourly` | 滚动 1 小时窗口 |
| `daily` | UTC 日历日 |
| `monthly` | UTC 日历月 |

### 查看配额使用情况

```bash
curl http://localhost:8000/api/v1/quota/usage \
  -H "Authorization: Bearer $API_KEY"
```

响应示例：

```json
{
  "tenant_id": "team-a",
  "usage": {
    "requests": {
      "hourly": 450,
      "daily": 3500
    },
    "tokens": {
      "daily": 1500000
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

## 数据隔离

### 映射存储隔离

PII 映射按租户隔离存储：

```
# Redis 键格式
{tenant_id}:mapping:{request_id}

# 示例
team-a:mapping:req_abc123
team-b:mapping:req_xyz789
```

### 缓存隔离

LLM 响应缓存按租户隔离：

```
# 缓存键格式
cache:{tenant_id}:{model}:{content_hash}

# 示例
cache:team-a:gpt-4:sha256_abc123
cache:team-b:gpt-4:sha256_xyz789
```

### 审计日志隔离

每条审计日志包含 `tenant_id` 字段：

```json
{
  "event_id": "evt_001",
  "tenant_id": "team-a",
  "event_type": "pii_detected",
  "timestamp": "2024-01-23T10:00:00Z"
}
```

查询时自动按租户过滤：

```bash
# 只返回当前租户的日志
curl http://localhost:8000/api/v1/audit/logs \
  -H "Authorization: Bearer $TEAM_A_API_KEY"
```

---

## 最佳实践

### 1. 安全配置

```bash
# 生产环境必须禁用 Header 租户传递
export PII_AIRLOCK_ALLOW_HEADER_TENANT=false

# 启用安全端点保护
export PII_AIRLOCK_SECURE_ENDPOINTS=true

# 使用 Redis 进行持久化存储
export PII_AIRLOCK_REDIS_URL=redis://:password@redis:6379/0
```

### 2. API Key 轮换

建议定期轮换 API Key：

1. 创建新的 API Key
2. 更新客户端配置
3. 验证新 Key 工作正常
4. 撤销旧 Key

```bash
# 1. 创建新 Key
NEW_KEY=$(curl -s -X POST http://localhost:8000/api/v1/keys \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Rotated Key", "scopes": ["llm:use"]}' \
  | jq -r '.api_key')

# 2. 验证新 Key
curl http://localhost:8000/health \
  -H "Authorization: Bearer $NEW_KEY"

# 3. 撤销旧 Key
curl -X DELETE http://localhost:8000/api/v1/keys/$OLD_KEY_ID \
  -H "Authorization: Bearer $ADMIN_KEY"
```

### 3. 配额监控

设置 Prometheus 告警规则：

```yaml
# prometheus/rules/pii-airlock.yml
groups:
  - name: pii-airlock-quota
    rules:
      - alert: QuotaSoftLimitApproaching
        expr: |
          pii_airlock_quota_usage / pii_airlock_quota_limit > 0.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Tenant {{ $labels.tenant_id }} approaching quota limit"

      - alert: QuotaExceeded
        expr: |
          increase(pii_airlock_quota_exceeded_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Tenant {{ $labels.tenant_id }} exceeded quota"
```

### 4. 租户隔离验证

定期验证租户隔离：

```python
import httpx

# 使用 Team A 的 Key 尝试访问 Team B 数据
response = httpx.get(
    "http://localhost:8000/api/v1/audit/logs",
    headers={
        "Authorization": f"Bearer {TEAM_A_KEY}",
        "X-Tenant-ID": "team-b"  # 尝试越权
    }
)

# 应该被拒绝或只返回 Team A 数据
assert response.status_code == 403 or \
       all(log["tenant_id"] == "team-a" for log in response.json()["logs"])
```

### 5. 灾难恢复

配置文件备份：

```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="/backup/pii-airlock/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# 备份配置文件
cp /config/tenants.yaml $BACKUP_DIR/
cp /config/quotas.yaml $BACKUP_DIR/
cp /config/api_keys.yaml $BACKUP_DIR/

# 导出审计日志
curl -o $BACKUP_DIR/audit_logs.json \
  "http://localhost:8000/api/v1/audit/export?format=json" \
  -H "Authorization: Bearer $ADMIN_KEY"
```

---

## 故障排除

### 问题：租户无法认证

**症状**：返回 401 Unauthorized

**检查步骤**：

1. 验证 API Key 是否正确
2. 检查 Key 是否过期：`GET /api/v1/keys`
3. 验证租户状态是否为 `active`
4. 检查 Key 是否具有所需权限

### 问题：配额错误

**症状**：返回 429 Quota Exceeded

**检查步骤**：

1. 查看当前使用量：`GET /api/v1/quota/usage`
2. 检查配额配置是否正确
3. 等待配额窗口重置或临时提升配额

### 问题：数据隔离失败

**症状**：看到其他租户的数据

**检查步骤**：

1. 确认 `PII_AIRLOCK_ALLOW_HEADER_TENANT=false`
2. 检查 API Key 是否正确绑定到租户
3. 查看审计日志确认请求的租户 ID

---

## 相关文档

- [管理 API 文档](./management-api.md)
- [故障排查指南](./troubleshooting.md)
- [安全加固指南](./security-hardening.md)
