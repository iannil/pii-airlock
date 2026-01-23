# PII-AIRLOCK 故障排查指南

本文档提供 PII-AIRLOCK 常见问题的诊断和解决方案。

## 目录

- [快速诊断](#快速诊断)
- [启动问题](#启动问题)
- [认证问题](#认证问题)
- [PII 检测问题](#pii-检测问题)
- [流式响应问题](#流式响应问题)
- [性能问题](#性能问题)
- [存储问题](#存储问题)
- [多租户问题](#多租户问题)
- [监控与日志](#监控与日志)

---

## 快速诊断

### 健康检查端点

```bash
# 基础存活检查
curl http://localhost:8000/health

# 详细依赖检查
curl http://localhost:8000/ready
```

**响应示例（健康）：**

```json
{
  "status": "ok",
  "version": "1.1.0",
  "checks": [
    {"name": "spacy", "status": "ok", "latency_ms": 15.2},
    {"name": "redis", "status": "ok", "latency_ms": 2.1},
    {"name": "mapping_store", "status": "ok", "latency_ms": 0.5}
  ]
}
```

**响应示例（异常）：**

```json
{
  "status": "unhealthy",
  "checks": [
    {"name": "redis", "status": "unhealthy", "message": "Connection refused"}
  ]
}
```

### 查看服务日志

```bash
# Docker 环境
docker-compose logs -f pii-airlock

# 筛选错误日志
docker-compose logs pii-airlock | grep '"level":"ERROR"'

# 本地开发
tail -f logs/pii-airlock.log
```

---

## 启动问题

### 问题：服务无法启动

**症状：** 容器启动后立即退出，或显示 "Address already in use"

**诊断步骤：**

```bash
# 检查端口占用
lsof -i :8000

# 检查容器日志
docker-compose logs pii-airlock

# 检查 Python 环境
python -c "import pii_airlock; print(pii_airlock.__version__)"
```

**解决方案：**

| 错误信息 | 原因 | 解决方案 |
|---------|------|---------|
| `Address already in use` | 端口被占用 | 修改 `PII_AIRLOCK_PORT` 或停止占用进程 |
| `ModuleNotFoundError: presidio_analyzer` | 依赖未安装 | `pip install -e ".[dev]"` |
| `OSError: [Errno 12] Cannot allocate memory` | 内存不足 | 增加容器内存限制或使用更小的 spaCy 模型 |

### 问题：spaCy 模型加载失败

**症状：** 日志显示 "Can't find model 'zh_core_web_trf'"

**解决方案：**

```bash
# 下载中文模型
python -m spacy download zh_core_web_trf

# 或使用更小的模型（内存受限环境）
python -m spacy download zh_core_web_sm
```

### 问题：环境变量未生效

**症状：** 配置修改后行为未改变

**诊断步骤：**

```bash
# 检查容器内环境变量
docker-compose exec pii-airlock env | grep PII_AIRLOCK

# 检查 .env 文件是否被加载
docker-compose config
```

**解决方案：**

1. 确保 `.env` 文件在项目根目录
2. 重启服务使配置生效：`docker-compose restart pii-airlock`
3. 检查 docker-compose.yml 中的 `env_file` 配置

---

## 认证问题

### 问题：返回 401 Unauthorized

**症状：** API 调用返回 `{"error": {"message": "Invalid API key", "code": 401}}`

**诊断步骤：**

```bash
# 测试 API Key
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:8000/api/v1/tenants

# 检查 Key 状态
curl -H "Authorization: Bearer ADMIN_KEY" \
     http://localhost:8000/api/v1/keys
```

**常见原因与解决方案：**

| 原因 | 检查方法 | 解决方案 |
|------|---------|---------|
| API Key 过期 | 查看 `expires_at` 字段 | 创建新的 API Key |
| API Key 已撤销 | 查看 `status` 字段 | 使用有效的 Key |
| 租户已禁用 | 查看租户状态 | 激活租户或联系管理员 |
| Key 格式错误 | 检查 Authorization 头 | 使用 `Bearer <key>` 格式 |

### 问题：返回 403 Forbidden

**症状：** API 调用返回权限不足错误

**诊断步骤：**

```bash
# 查看 Key 的权限范围
curl -H "Authorization: Bearer YOUR_KEY" \
     http://localhost:8000/api/v1/keys
```

**解决方案：**

1. 确认 API Key 具有所需的 scope（如 `llm:use`, `audit:view`）
2. 创建具有适当权限的新 Key：

```bash
curl -X POST http://localhost:8000/api/v1/keys \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Full Access Key",
    "scopes": ["llm:use", "metrics:view", "audit:view", "config:manage"]
  }'
```

---

## PII 检测问题

### 问题：PII 未被检测到

**症状：** 包含敏感信息的文本未被脱敏

**诊断步骤：**

```bash
# 使用测试端点验证
curl -X POST http://localhost:8000/api/test/anonymize \
  -H "Content-Type: application/json" \
  -d '{"text": "张三的电话是13800138000"}'
```

**常见原因与解决方案：**

| 原因 | 解决方案 |
|------|---------|
| 非标准格式 | 添加自定义识别规则 |
| 白名单误排除 | 检查白名单配置 |
| 置信度阈值过高 | 降低 `PII_AIRLOCK_CONFIDENCE_THRESHOLD` |
| 语言检测错误 | 明确设置 `language` 参数 |

### 问题：过度脱敏（误报）

**症状：** 普通文本被误识别为 PII

**解决方案：**

1. **添加到白名单：**

```bash
curl -X POST http://localhost:8000/api/v1/allowlist \
  -H "Authorization: Bearer API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "value": "产品名称",
    "category": "products",
    "entity_type": "PERSON"
  }'
```

2. **提高置信度阈值：**

```bash
export PII_AIRLOCK_CONFIDENCE_THRESHOLD=0.7
```

3. **检查并调整合规预设：**

```bash
# 查看当前预设
curl http://localhost:8000/api/v1/compliance/status \
  -H "Authorization: Bearer API_KEY"

# 切换到更宽松的预设
curl -X POST http://localhost:8000/api/v1/compliance/activate \
  -H "Authorization: Bearer API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"preset": "gdpr"}'
```

### 问题：回填失败

**症状：** 响应中包含占位符（如 `<PERSON_1>`）而非原始值

**诊断步骤：**

1. 检查映射是否存在：

```bash
# 查看审计日志中的映射信息
curl "http://localhost:8000/api/v1/audit/logs?event_type=pii_deanonymized" \
  -H "Authorization: Bearer API_KEY"
```

**常见原因与解决方案：**

| 原因 | 解决方案 |
|------|---------|
| 映射 TTL 过期 | 增加 `PII_AIRLOCK_MAPPING_TTL` |
| LLM 修改了占位符格式 | 启用模糊匹配 `PII_AIRLOCK_FUZZY_MATCHING=true` |
| 多次请求使用不同 session | 确保使用相同的 request_id |

---

## 流式响应问题

### 问题：流式响应中断

**症状：** SSE 连接突然断开，响应不完整

**诊断步骤：**

```bash
# 测试流式连接
curl -N -X POST http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello"}],
    "stream": true
  }'
```

**常见原因与解决方案：**

| 原因 | 解决方案 |
|------|---------|
| 代理超时 | 增加 `PII_AIRLOCK_TIMEOUT` |
| Nginx 缓冲 | 添加 `X-Accel-Buffering: no` 头 |
| 网络不稳定 | 实现客户端重试逻辑 |

### 问题：流式响应占位符未回填

**症状：** 流式输出中仍然显示占位符

**解决方案：**

1. 确保映射 TTL 足够长：

```bash
export PII_AIRLOCK_MAPPING_TTL=3600  # 1小时
```

2. 检查流式缓冲配置是否正确

---

## 性能问题

### 问题：响应延迟高

**症状：** API 响应时间超过预期

**诊断步骤：**

```bash
# 查看 Prometheus 指标
curl http://localhost:8000/metrics | grep -E "request_duration|pii_"

# 检查上游延迟
curl http://localhost:8000/metrics | grep upstream_latency
```

**优化建议：**

| 瓶颈位置 | 指标 | 优化方案 |
|---------|------|---------|
| PII 检测 | `pii_detection_duration_seconds` | 使用更小的 spaCy 模型 |
| 上游 LLM | `upstream_latency_seconds` | 启用响应缓存 |
| 映射存储 | `mapping_store_latency_seconds` | 使用 Redis 替代内存存储 |

**启用缓存：**

```bash
export PII_AIRLOCK_CACHE_ENABLED=true
export PII_AIRLOCK_CACHE_TTL=3600
```

### 问题：内存使用过高

**症状：** 容器 OOM 或内存持续增长

**诊断步骤：**

```bash
# 检查容器内存使用
docker stats pii-airlock

# 检查映射存储大小
curl http://localhost:8000/metrics | grep mapping_store_size
```

**解决方案：**

1. 减少映射 TTL：`PII_AIRLOCK_MAPPING_TTL=60`
2. 设置缓存大小限制：`PII_AIRLOCK_CACHE_MAX_SIZE=1000`
3. 使用 Redis 外部存储
4. 使用更小的 spaCy 模型（`zh_core_web_sm`）

---

## 存储问题

### 问题：Redis 连接失败

**症状：** 日志显示 "Redis connection refused" 或 `/ready` 返回 Redis unhealthy

**诊断步骤：**

```bash
# 测试 Redis 连接
redis-cli -h localhost -p 6379 ping

# 检查 Redis 容器状态
docker-compose ps redis
```

**解决方案：**

| 错误 | 解决方案 |
|------|---------|
| Connection refused | 确保 Redis 容器正在运行 |
| Authentication failed | 检查 `REDIS_PASSWORD` 配置 |
| Timeout | 检查网络连接和防火墙规则 |

**Redis 连接配置：**

```bash
# 带认证的连接
export PII_AIRLOCK_REDIS_URL=redis://:password@redis:6379/0

# 带 TLS 的连接
export PII_AIRLOCK_REDIS_URL=rediss://:password@redis:6379/0
```

### 问题：映射数据丢失

**症状：** 重启后无法回填之前的请求

**原因与解决方案：**

1. **内存存储（默认）：** 重启会丢失所有数据，使用 Redis 持久化
2. **Redis 未配置持久化：** 启用 AOF：

```yaml
# docker-compose.yml
redis:
  command: redis-server --appendonly yes
  volumes:
    - redis_data:/data
```

---

## 多租户问题

### 问题：租户数据泄露

**症状：** 能看到其他租户的数据

**诊断步骤：**

```bash
# 验证请求的租户 ID
curl http://localhost:8000/api/v1/audit/logs \
  -H "Authorization: Bearer TENANT_A_KEY" | jq '.logs[].tenant_id'
```

**解决方案：**

1. 禁用 Header 租户覆盖：

```bash
export PII_AIRLOCK_ALLOW_HEADER_TENANT=false
```

2. 确保 API Key 正确绑定到租户

### 问题：配额错误

**症状：** 返回 429 Quota Exceeded

**诊断步骤：**

```bash
# 查看当前配额使用
curl http://localhost:8000/api/v1/quota/usage \
  -H "Authorization: Bearer API_KEY"
```

**解决方案：**

1. 等待配额窗口重置（小时/天/月）
2. 联系管理员提升配额限制
3. 检查是否有异常流量消耗配额

---

## 监控与日志

### 启用详细日志

```bash
# 开发环境
export PII_AIRLOCK_LOG_LEVEL=DEBUG
export PII_AIRLOCK_LOG_FORMAT=text

# 生产环境
export PII_AIRLOCK_LOG_LEVEL=INFO
export PII_AIRLOCK_LOG_FORMAT=json
```

### 常用日志过滤

```bash
# 查看 PII 检测事件
docker-compose logs pii-airlock | jq 'select(.event == "pii_detected")'

# 查看错误
docker-compose logs pii-airlock | jq 'select(.level == "ERROR")'

# 查看特定请求
docker-compose logs pii-airlock | jq 'select(.request_id == "xxx")'
```

### Prometheus 告警规则

```yaml
# prometheus/rules/pii-airlock.yml
groups:
  - name: pii-airlock
    rules:
      - alert: HighErrorRate
        expr: |
          sum(rate(pii_airlock_errors_total[5m])) /
          sum(rate(pii_airlock_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Error rate exceeds 5%"

      - alert: HighLatency
        expr: |
          histogram_quantile(0.95,
            rate(pii_airlock_request_duration_seconds_bucket[5m])
          ) > 2
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "P95 latency exceeds 2 seconds"

      - alert: RedisDown
        expr: pii_airlock_redis_up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Redis connection lost"
```

---

## 获取支持

如果以上方案无法解决问题：

1. **收集诊断信息：**

```bash
# 生成诊断报告
curl http://localhost:8000/ready > ready.json
curl http://localhost:8000/metrics > metrics.txt
docker-compose logs pii-airlock > logs.txt
```

2. **检查 GitHub Issues：** https://github.com/your-org/pii-airlock/issues

3. **提交 Issue 时包含：**
   - PII-AIRLOCK 版本
   - 环境信息（Docker/K8s/本地）
   - 完整错误日志
   - 复现步骤

---

## 相关文档

- [管理 API 文档](../api/management-api.md)
- [多租户配置指南](./multi-tenant.md)
- [安全加固指南](./security-hardening.md)
