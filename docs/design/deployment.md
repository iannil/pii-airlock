# PII-AIRLOCK 部署指南

> 文档版本：v1.0
> 创建日期：2026-01-22
> 状态：已实现

## 1. 部署方式

### 1.1 Docker Compose（推荐）

适用于生产环境和快速部署。

```bash
# 克隆仓库
git clone https://github.com/your-org/pii-airlock.git
cd pii-airlock

# 配置环境变量
cp .env.example .env
# 编辑 .env 文件，设置 OPENAI_API_KEY

# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f pii-airlock

# 停止服务
docker-compose down
```

### 1.2 Docker 单容器部署

适用于已有 Redis 实例的场景。

```bash
# 构建镜像
docker build -t pii-airlock:latest .

# 运行容器
docker run -d \
  -p 8000:8000 \
  -e OPENAI_API_KEY=sk-xxx \
  -e PII_AIRLOCK_UPSTREAM_URL=https://api.openai.com \
  --name pii-airlock \
  pii-airlock:latest
```

### 1.3 本地开发部署

```bash
# 安装依赖
pip install -e ".[dev]"

# 下载中文 NLP 模型
python -m spacy download zh_core_web_sm

# 设置环境变量
export OPENAI_API_KEY=sk-xxx

# 启动服务
python -m pii_airlock.main
```

## 2. 环境变量配置

| 变量 | 必需 | 默认值 | 说明 |
|------|------|--------|------|
| `OPENAI_API_KEY` | ✅ | - | OpenAI API Key |
| `PII_AIRLOCK_UPSTREAM_URL` | - | https://api.openai.com | 上游 LLM API 地址 |
| `PII_AIRLOCK_PORT` | - | 8000 | 服务监听端口 |
| `PII_AIRLOCK_TIMEOUT` | - | 120 | 请求超时时间（秒） |
| `PII_AIRLOCK_MAPPING_TTL` | - | 300 | PII 映射过期时间（秒） |
| `PII_AIRLOCK_INJECT_PROMPT` | - | true | 是否注入防幻觉提示 |
| `PII_AIRLOCK_CONFIG_PATH` | - | - | 自定义 PII 规则配置文件路径 |
| `PII_AIRLOCK_LOG_LEVEL` | - | INFO | 日志级别 |
| `PII_AIRLOCK_LOG_FORMAT` | - | json | 日志格式（json/text） |
| `PII_AIRLOCK_RATE_LIMIT` | - | 60/minute | API 限流配置 |
| `PII_AIRLOCK_RATE_LIMIT_ENABLED` | - | true | 是否启用限流 |
| `REDIS_URL` | - | - | Redis 连接 URL（不使用则用内存存储） |

## 3. 健康检查

```bash
# 检查服务健康状态
curl http://localhost:8000/health

# 返回示例
{
  "status": "ok",
  "version": "1.0.0"
}
```

## 4. 监控

### 4.1 Prometheus 指标

服务在 `/metrics` 端点暴露 Prometheus 格式的指标：

```bash
curl http://localhost:8000/metrics
```

**可用指标**：

| 指标名 | 类型 | 说明 |
|--------|------|------|
| `pii_airlock_request_duration_seconds` | Histogram | 请求处理延迟 |
| `pii_airlock_requests_total` | Counter | 总请求数 |
| `pii_airlock_pii_detected_total` | Counter | PII 检测总数 |
| `pii_airlock_upstream_duration_seconds` | Histogram | 上游 API 延迟 |
| `pii_airlock_upstream_errors_total` | Counter | 上游 API 错误数 |
| `pii_airlock_active_requests` | Gauge | 当前活跃请求数 |

### 4.2 Prometheus 配置示例

```yaml
scrape_configs:
  - job_name: 'pii-airlock'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
```

## 5. 日志

### 5.1 日志格式

**JSON 格式（默认）**：

```json
{
  "service": "pii-airlock",
  "request_id": "abc123",
  "level": "INFO",
  "timestamp": "2026-01-22T10:00:00Z",
  "message": "Request completed",
  "method": "POST",
  "path": "/v1/chat/completions",
  "status_code": 200,
  "duration_ms": 1234
}
```

**文本格式**：

```
2026-01-22 10:00:00 [INFO] pii-airlock abc123 - Request completed
```

### 5.2 日志级别

- `DEBUG`: 详细调试信息
- `INFO`: 常规操作日志（默认）
- `WARNING`: 警告信息
- `ERROR`: 错误信息

## 6. 自定义 PII 规则

创建 YAML 配置文件定义企业特定的 PII 模式：

```yaml
# config/custom_patterns.yaml
patterns:
  - name: employee_id
    entity_type: EMPLOYEE_ID
    regex: "EMP[A-Z]\\d{6}"
    score: 0.85
    context: ["员工", "工号", "employee"]

  - name: project_code
    entity_type: PROJECT_CODE
    regex: "PROJ-\\d{4}"
    score: 0.9
    context: ["项目", "编码"]
```

然后设置环境变量：

```bash
export PII_AIRLOCK_CONFIG_PATH=./config/custom_patterns.yaml
```

## 7. 性能优化

### 7.1 资源建议

| 场景 | CPU | 内存 | 并发 |
|------|-----|------|------|
| 开发测试 | 1 核 | 1GB | 10 |
| 小规模生产 | 2 核 | 2GB | 50 |
| 大规模生产 | 4 核+ | 4GB+ | 100+ |

### 7.2 优化建议

1. **连接池**：已内置 HTTP 连接池，无需额外配置
2. **单例模式**：Presidio Analyzer 使用单例，避免重复加载模型
3. **内存存储**：开发环境使用内存存储，生产环境建议使用 Redis
4. **TTL 设置**：根据业务需求调整 `PII_AIRLOCK_MAPPING_TTL`

## 8. 故障排查

### 8.1 常见问题

**问题：spaCy 模型未找到**

```
OSError: [E050] Can't find model 'zh_core_web_sm'
```

**解决**：
```bash
python -m spacy download zh_core_web_sm
```

**问题：限流导致请求被拒绝**

**解决**：调整限流配置或禁用限流
```bash
export PII_AIRLOCK_RATE_LIMIT=120/minute
# 或
export PII_AIRLOCK_RATE_LIMIT_ENABLED=false
```

**问题：上游 API 超时**

**解决**：增加超时时间
```bash
export PII_AIRLOCK_TIMEOUT=300
```

### 8.2 调试模式

启用调试日志：

```bash
export PII_AIRLOCK_LOG_LEVEL=DEBUG
export PII_AIRLOCK_LOG_FORMAT=text
```

## 9. 安全建议

1. **API Key 保护**：使用环境变量或密钥管理服务存储 API Key
2. **网络隔离**：部署在内网或 VPC 内，限制外部访问
3. **HTTPS**：生产环境使用反向代理（Nginx）启用 HTTPS
4. **访问控制**：配置防火墙规则，限制访问来源
5. **日志脱敏**：确保日志不包含原始 PII 数据

## 10. Nginx 反向代理配置示例

```nginx
server {
    listen 443 ssl http2;
    server_name pii-airlock.example.com;

    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE 流式响应需要
        proxy_buffering off;
        proxy_cache off;
    }
}
```
