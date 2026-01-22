<div align="center">

# PII-AIRLOCK

### 让公有 LLM 变得私有 — LLM API 敏感信息保护中间件

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.2.0-blue.svg)](https://github.com/pii-airlock/pii-airlock/releases)
[![Tests](https://img.shields.io/badge/tests-170%20passed-brightgreen.svg)](https://github.com/pii-airlock/pii-airlock/actions)
[![Coverage](https://img.shields.io/badge/coverage-82%25-green.svg)](https://github.com/pii-airlock/pii-airlock/actions)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

[English](README.md) | [文档](docs/) | [更新日志](docs/progress/changelog.md)

---

PII-AIRLOCK 是一个开源中间件/反向代理，用于在使用公有 LLM API 时保护敏感个人信息。将其部署在您的应用程序和 LLM 提供商（OpenAI、Claude 等）之间，实时自动检测、匿名化和还原 PII。

</div>

---

## 项目简介

```
┌─────────────────┐     ┌─────────────────────────────────────────┐     ┌─────────────────┐
│                 │     │           PII-AIRLOCK (v1.2)            │     │                 │
│  您的应用        │────▶│  ┌─────────┐    ┌─────────────────┐     │────▶│   OpenAI API    │
│  (Dify/Flowise) │     │  │ 匿名化   │────│  映射存储 + 缓存  │     │     │   Claude API    │
│                 │◀────│  └─────────┘    └─────────────────┘     │◀────│   Azure OpenAI  │
└─────────────────┘     └─────────────────────────────────────────┘     └─────────────────┘
                              ▲
                         多租户 │ API 密钥 │ 配额
```

## 核心特性

### 基础能力

| 特性 | 描述 |
| ----- | ------ |
| 零代码集成 | 只需修改 `base_url` — 完全兼容 OpenAI API 格式 |
| 智能匿名化 | 使用语义占位符（`<PERSON_1>`）让 LLM 自然理解 |
| 流式支持 | 处理 SSE 流式响应，智能缓冲被拆分的占位符 |
| 模糊恢复 | 即使 LLM 修改了占位符格式也能恢复 PII |
| 自定义规则 | 通过 YAML 配置定义自己的 PII 模式 |

### 企业特性 (v1.2)

| 特性 | 描述 |
| ----- | ------ |
| 多租户 | 租户隔离，独立配置和限流 |
| 响应缓存 | LLM 响应缓存，降低 API 成本和延迟 |
| 配额管理 | 请求/token 配额，支持小时/日/月限制 |
| API 密钥管理 | 安全的 API 密钥创建和生命周期管理 |
| RBAC | 基于角色的访问控制（管理员/操作员/访客/用户） |
| 生产就绪 | 结构化日志、Prometheus 指标、限流 |

### 脱敏策略

| 策略 | 描述 | 示例 | 适用场景 |
| ----- | ------ | ----- | --------- |
| placeholder | 类型化占位符 | `张三` → `<PERSON_1>` | LLM 处理（默认） |
| hash | SHA256 哈希 | `张三` → `a1b2c3d4...` | 日志分析、数据去重 |
| mask | 部分掩码 | `13800138000` → `1388000` | UI 展示、客服 |
| redact | 完全替换 | `test@example.com` → `[REDACTED]` | 最大隐私保护 |

## 支持的 PII 类型

| 类型 | 占位符 | 示例 |
| ----- | -------- | ----- |
| 姓名 | `<PERSON_N>` | 张三 → `<PERSON_1>` |
| 手机号 | `<PHONE_N>` | 13800138000 → `<PHONE_1>` |
| 邮箱 | `<EMAIL_N>` | test@example.com → `<EMAIL_1>` |
| 身份证 | `<ID_CARD_N>` | 110101199003077758 → `<ID_CARD_1>` |
| 银行卡 | `<CREDIT_CARD_N>` | 6222021234567890 → `<CREDIT_CARD_1>` |
| IP 地址 | `<IP_N>` | 192.168.1.1 → `<IP_1>` |
| 自定义 | 可配置 | PROJ-2024-AB → `<PROJECT_CODE_1>` |

## 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/pii-airlock/pii-airlock.git
cd pii-airlock

# 创建虚拟环境
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 安装依赖
pip install -e .

# 下载中文 NLP 模型（可选，用于中文 PII 检测）
python -m spacy download zh_core_web_sm
```

### 启动服务

```bash
# 设置您的 OpenAI API 密钥
export OPENAI_API_KEY=sk-your-api-key

# 启动代理服务器
python -m pii_airlock.main

# 服务运行在 http://localhost:8000
# API 文档: http://localhost:8000/docs
# Web UI: http://localhost:8000/ui
```

### 使用 OpenAI Python 客户端

```python
from openai import OpenAI

# 只需将 base_url 指向 PII-AIRLOCK
client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="sk-your-api-key"
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "user", "content": "给 John (john@example.com) 写一封关于会议的邮件"}
    ]
)

print(response.choices[0].message.content)
# PII 在发送到 OpenAI 之前自动匿名化，
# 在响应中自动还原
```

### Docker 部署

```bash
# 使用 docker-compose（推荐）
docker-compose up -d

# 或手动构建和运行
docker build -t pii-airlock .
docker run -p 8000:8000 -e OPENAI_API_KEY=sk-xxx pii-airlock
```

## 配置说明

### 环境变量

| 变量 | 说明 | 默认值 |
| ----- | ------ | -------- |
| 基础配置 |
| `OPENAI_API_KEY` | OpenAI API 密钥 | - |
| `PII_AIRLOCK_UPSTREAM_URL` | 上游 LLM API 地址 | `https://api.openai.com` |
| `PII_AIRLOCK_PORT` | 服务端口 | `8000` |
| `PII_AIRLOCK_MAPPING_TTL` | 映射过期时间（秒） | `300` |
| `PII_AIRLOCK_INJECT_PROMPT` | 注入防幻觉提示 | `true` |
| 多租户 (v1.2) |
| `PII_AIRLOCK_MULTI_TENANT_ENABLED` | 启用多租户模式 | `false` |
| `PII_AIRLOCK_TENANT_CONFIG_PATH` | tenants.yaml 路径 | - |
| 缓存 (v1.2) |
| `PII_AIRLOCK_CACHE_ENABLED` | 启用响应缓存 | `false` |
| `PII_AIRLOCK_CACHE_TTL` | 缓存 TTL（秒） | `3600` |
| `PII_AIRLOCK_CACHE_MAX_SIZE` | 最大缓存条目数 | `10000` |
| 配额 (v1.2) |
| `PII_AIRLOCK_QUOTA_CONFIG_PATH` | quotas.yaml 路径 | - |
| 日志 |
| `PII_AIRLOCK_LOG_LEVEL` | 日志级别 | `INFO` |
| `PII_AIRLOCK_LOG_FORMAT` | 日志格式 (json/text) | `json` |
| 限流 |
| `PII_AIRLOCK_RATE_LIMIT` | 限流配置 | `60/minute` |
| `PII_AIRLOCK_RATE_LIMIT_ENABLED` | 启用限流 | `true` |

### 自定义 PII 规则

创建 `config/custom_patterns.yaml`：

```yaml
patterns:
  - name: employee_id
    entity_type: EMPLOYEE_ID
    regex: "EMP[A-Z]\\d{6}"
    score: 0.85
    context:
      - 员工
      - 工号
      - 职员

  - name: project_code
    entity_type: PROJECT_CODE
    regex: "PROJ-\\d{4}-[A-Z]{2}"
    score: 0.9
    context:
      - 项目
      - 代码
```

设置配置路径：

```bash
export PII_AIRLOCK_CONFIG_PATH=./config/custom_patterns.yaml
```

## API 端点

### OpenAI 兼容 API

| 端点 | 方法 | 说明 |
| ----- | ------ | ----- |
| `/v1/chat/completions` | POST | 带 PII 保护的对话补全 |
| `/v1/models` | GET | 列出可用模型 |

### 管理 API (v1.2)

| 端点 | 方法 | 说明 |
| ----- | ------ | ----- |
| 租户管理 |
| `/api/v1/tenants` | GET | 列出所有租户 |
| `/api/v1/tenants/{id}` | GET | 获取租户信息 |
| API 密钥管理 |
| `/api/v1/keys` | POST/GET | 创建/列出 API 密钥 |
| `/api/v1/keys/{id}` | DELETE | 撤销 API 密钥 |
| 配额管理 |
| `/api/v1/quota/usage` | GET | 获取配额使用情况 |
| 缓存管理 |
| `/api/v1/cache/stats` | GET | 获取缓存统计 |
| `/api/v1/cache` | DELETE | 清空缓存 |
| `/api/v1/cache/stats/global` | GET | 全局缓存统计 |

### 监控与测试

| 端点 | 说明 |
| ----- | ------ |
| `/health` | 健康检查 |
| `/metrics` | Prometheus 指标 |
| `/ui` | Web 测试界面 |
| `/api/test/anonymize` | 测试匿名化 |
| `/api/test/deanonymize` | 测试还原 |

## 编程方式使用

```python
from pii_airlock import Anonymizer, Deanonymizer
from pii_airlock.core.strategies import StrategyConfig, StrategyType

# 基础匿名化
anonymizer = Anonymizer()
result = anonymizer.anonymize("联系 John，邮箱 john@example.com")
print(result.text)  # 联系 <PERSON_1>，邮箱 <EMAIL_1>
print(result.mapping.get_original("<PERSON_1>"))  # John

# 还原
deanonymizer = Deanonymizer()
restored = deanonymizer.deanonymize(result.text, result.mapping)
print(restored.text)  # 联系 John，邮箱 john@example.com

# 使用自定义策略
strategy_config = StrategyConfig({
    "PERSON": StrategyType.MASK,
    "PHONE_NUMBER": StrategyType.REDACT,
})
anonymizer = Anonymizer(strategy_config=strategy_config)
result = anonymizer.anonymize("张三的电话是13800138000")
print(result.text)  # 张*的电话是[REDACTED]
```

## 工作原理

```
1. 拦截    → 捕获传入请求
2. 匿名化  → 使用 NLP 检测 PII，替换为占位符
3. 检查缓存→ 如有缓存则返回缓存响应 (v1.2)
4. 检查配额→ 验证配额限制 (v1.2)
5. 映射    → 存储占位符到原始值的映射
6. 转发    → 将净化后的提示发送给上游 LLM
7. 缓存    → 存储响应供未来请求使用 (v1.2)
8. 去匿名化→ 将响应中的占位符替换为原始值
9. 返回    → 将还原后的响应返回给客户端
```

### 处理 LLM 幻觉

LLM 可能会修改占位符（如 `<PERSON_1>` → `<Person 1>`）。PII-AIRLOCK 通过以下方式处理：

1. 系统提示注入：指示 LLM 精确保留占位符
2. 模糊匹配：使用灵活的正则表达式匹配修改后的占位符

## 开发指南

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行测试
pytest

# 运行测试（带覆盖率）
pytest --cov=pii_airlock --cov-report=term-missing

# 代码检查
ruff check src/ tests/

# 类型检查
mypy src/
```

## 项目结构

```
pii-airlock/
├── src/pii_airlock/
│   ├── core/               # 核心匿名化引擎
│   │   ├── anonymizer.py   # 主要匿名化逻辑
│   │   ├── deanonymizer.py # 带模糊匹配的还原
│   │   ├── mapping.py      # PII 映射管理
│   │   ├── strategies.py   # 匿名化策略
│   │   └── stream_buffer.py# SSE 流式缓冲
│   ├── api/                # FastAPI 路由和代理
│   │   ├── routes.py       # API 端点
│   │   ├── proxy.py        # 代理服务逻辑
│   │   ├── models.py       # Pydantic 模型
│   │   ├── middleware.py   # 请求日志中间件
│   │   ├── auth_middleware.py # 认证中间件 (v1.2)
│   │   └── limiter.py      # 限流
│   ├── auth/               # 认证与授权 (v1.2)
│   │   ├── tenant.py       # 多租户支持
│   │   ├── api_key.py      # API 密钥管理
│   │   ├── rbac.py         # 基于角色的访问控制
│   │   └── quota.py        # 配额管理
│   ├── cache/              # 响应缓存 (v1.2)
│   │   └── llm_cache.py    # LLM 响应缓存
│   ├── recognizers/        # PII 识别器
│   │   ├── zh_phone.py     # 中文手机号识别
│   │   ├── zh_id_card.py   # 中文身份证识别
│   │   ├── zh_person.py    # 中文姓名识别
│   │   └── registry.py     # 识别器注册
│   ├── storage/            # 存储后端
│   │   ├── memory_store.py # 内存存储
│   │   └── redis_store.py  # Redis 存储
│   ├── logging/            # 结构化日志
│   ├── metrics/            # Prometheus 指标
│   └── config/             # 配置加载
├── tests/                  # 测试套件 (170+ 测试)
├── config/                 # 配置示例
│   ├── custom_patterns.example.yaml
│   ├── tenants.example.yaml
│   └── quotas.example.yaml
├── docs/                   # 文档
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

## 路线图

### 即将推出 (v1.3)

- [ ] 增强审计日志
- [ ] OpenTelemetry 集成
- [ ] Kubernetes 部署指南
- [ ] 配额告警 Webhook 通知

### 未来 (v2.0)

- [ ] Go 代理层以提升性能
- [ ] Redis Cluster 分布式缓存
- [ ] 支持更多 LLM 提供商
- [ ] 更多语言支持（日语、韩语等）

## 贡献指南

我们欢迎贡献！详情请参阅[贡献指南](CONTRIBUTING.md)。

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 使用场景

- 企业合规：在使用 GPT-4/Claude 的同时满足 GDPR、CCPA、个人信息保护法要求
- 低代码平台：作为 Dify、Flowise、LangFlow 的网关
- 医疗/金融：安全地使用云 LLM 处理敏感数据
- 开发测试：在不暴露真实 PII 的情况下测试 LLM 应用
- 多团队：共享基础设施，配置和配额隔离

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 致谢

- [Microsoft Presidio](https://github.com/microsoft/presidio) - PII 检测引擎
- [spaCy](https://spacy.io/) - NLP 框架
- [FastAPI](https://fastapi.tiangolo.com/) - Web 框架
- [OpenAI](https://openai.com/) - LLM API

---

<div align="center">

由 PII-AIRLOCK 团队用 ❤️ 制作

[⭐ 在 GitHub 上关注我们](https://github.com/pii-airlock/pii-airlock) — 您的支持是我们前进的动力！

</div>
