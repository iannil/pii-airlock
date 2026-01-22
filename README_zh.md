<div align="center">

# PII-AIRLOCK

### 让公有 LLM 变私有 — 面向 LLM API 的 PII 保护中间件

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/pii-airlock/pii-airlock/releases)
[![Tests](https://img.shields.io/badge/tests-600%20passed-brightgreen.svg)](https://github.com/pii-airlock/pii-airlock/actions)
[![Coverage](https://img.shields.io/badge/coverage-73%25-green.svg)](https://github.com/pii-airlock/pii-airlock/actions)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

[English](README.md) | [文档](docs/) | [更新日志](docs/progress/changelog.md)

---

PII-AIRLOCK 是一个开源中间件/反向代理，用于在使用公有 LLM API 时保护敏感个人信息。将其部署在您的应用程序和 LLM 提供商（OpenAI、Claude 等）之间，可自动实时检测、脱敏和还原 PII。

</div>

---

## 概述

```
┌─────────────────┐     ┌─────────────────────────────────────────┐     ┌─────────────────┐
│                 │     │           PII-AIRLOCK (v2.0)            │     │                 │
│  您的应用       │────▶│  ┌─────────┐    ┌─────────────────┐     │────▶│   OpenAI API    │
│  (Dify/Flowise) │     │  │  脱敏   │────│   映射存储      │     │     │   Claude API    │
│                 │◀────│  └─────────┘    │   + 缓存        │     │◀────│   Azure OpenAI  │
└─────────────────┘     └─────────────────────────────────────────┘     └─────────────────┘
                              ▲
                   多租户 │ 合规 │ 审计 │ 管理界面
```

## 核心特性

### 基础能力

| 特性 | 说明 |
| ------- | ----------- |
| 零代码接入 | 只需修改 `base_url` - 完全兼容 OpenAI API 格式 |
| 智能脱敏 | 语义化占位符（`<PERSON_1>`），LLM 可自然理解 |
| 流式支持 | 处理 SSE 流式响应，智能缓冲区处理分割的占位符 |
| 模糊恢复 | 即使 LLM 修改了占位符格式也能恢复 PII |
| 自定义规则 | 通过 YAML 配置定义企业专属 PII 模式 |
| 意图检测 | 智能上下文感知检测，在询问语境中跳过脱敏 |
| 密钥扫描 | 在发送到 LLM 之前检测 API 密钥、令牌等秘密信息 |

### 企业级特性

| 特性 | 说明 |
| ------- | ----------- |
| 多租户 | 租户隔离，独立配置和限流 |
| 响应缓存 | LLM 响应缓存，降低 API 成本和延迟 |
| 配额管理 | 支持按小时/天/月的请求/令牌配额限制 |
| API 密钥管理 | 安全的 API 密钥创建和生命周期管理 |
| RBAC | 基于角色的访问控制（Admin/Operator/Viewer/User） |
| 合规预设 | 预配置的 GDPR、CCPA、PIPL、金融合规规则 |
| 白名单 | 公众人物、地名等安全实体白名单 |
| 审计日志 | 完整的审计追踪，支持查询和导出 |
| Web 管理控制台 | 全功能管理界面 |
| 生产就绪 | 结构化日志、Prometheus 指标、API 限流 |

### 脱敏策略

| 策略 | 说明 | 示例 | 适用场景 |
| -------- | ----------- | ------- | -------- |
| placeholder | 类型化占位符 | `张三` → `<PERSON_1>` | LLM 处理（默认） |
| hash | SHA256 哈希 | `张三` → `a1b2c3d4...` | 日志分析、去重 |
| mask | 部分掩码 | `13800138000` → `138****8000` | 界面显示 |
| redact | 完全替换 | `test@example.com` → `[REDACTED]` | 最高隐私 |
| synthetic | 仿真数据替换 | `张三` → `李明` | 测试、演示 |

## 支持的 PII 类型

| 类型 | 占位符 | 示例 |
| ---- | ----------- | ------- |
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

# 下载中文 NLP 模型（中文 PII 检测必需）
python -m spacy download zh_core_web_trf
```

### 启动服务

```bash
# 设置 OpenAI API 密钥
export OPENAI_API_KEY=sk-your-api-key

# 启动代理服务
python -m pii_airlock.main

# 服务运行在 http://localhost:8000
# API 文档: http://localhost:8000/docs
# Web UI: http://localhost:8000/ui
# 调试控制台: http://localhost:8000/debug
# 管理控制台: http://localhost:8000/admin
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
        {"role": "user", "content": "给张三（john@example.com）写一封关于会议的邮件。"}
    ]
)

print(response.choices[0].message.content)
# PII 会在发送到 OpenAI 之前自动脱敏，
# 并在响应中自动还原
```

### 流式支持

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="sk-your-api-key"
)

# 流式响应同样支持
stream = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "user", "content": "介绍一下张三（电话：13800138000）"}
    ],
    stream=True
)

for chunk in stream:
    if chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)
# 即使占位符被分割到多个 chunk，也能正确处理
```

### Docker 部署

```bash
# 使用 docker-compose（推荐）
docker-compose up -d

# 或手动构建运行
docker build -t pii-airlock .
docker run -p 8000:8000 -e OPENAI_API_KEY=sk-xxx pii-airlock
```

## Web 界面

### 测试界面 (`/ui`)
简单的 Web 界面，用于测试 PII 检测和脱敏，无需调用 LLM。

### 调试控制台 (`/debug`)
可视化调试界面，具备：
- 原始文本与脱敏文本并排对比
- PII 高亮显示，不同类型颜色区分
- 交互式工具提示显示详细信息
- 导出映射数据为 JSON

### 管理控制台 (`/admin`)
全功能管理界面，包括：
- **仪表盘**：系统统计、最近活动、实时状态
- **合规配置**：激活/切换合规预设（GDPR/CCPA/PIPL/金融）
- **白名单管理**：添加/删除白名单条目、批量导入
- **审计日志**：查询、过滤、导出审计记录

## 配置

### 环境变量

| 变量 | 说明 | 默认值 |
| -------- | ----------- | ------- |
| **基础配置** |
| `OPENAI_API_KEY` | OpenAI API 密钥 | - |
| `PII_AIRLOCK_UPSTREAM_URL` | 上游 LLM API 地址 | `https://api.openai.com` |
| `PII_AIRLOCK_PORT` | 服务端口 | `8000` |
| `PII_AIRLOCK_MAPPING_TTL` | 映射过期时间（秒） | `300` |
| `PII_AIRLOCK_INJECT_PROMPT` | 注入防幻觉提示 | `true` |
| **多租户** |
| `PII_AIRLOCK_MULTI_TENANT_ENABLED` | 启用多租户模式 | `false` |
| `PII_AIRLOCK_TENANT_CONFIG_PATH` | tenants.yaml 路径 | - |
| **缓存** |
| `PII_AIRLOCK_CACHE_ENABLED` | 启用响应缓存 | `false` |
| `PII_AIRLOCK_CACHE_TTL` | 缓存 TTL（秒） | `3600` |
| `PII_AIRLOCK_CACHE_MAX_SIZE` | 最大缓存条目数 | `10000` |
| **安全** |
| `PII_AIRLOCK_SECRET_SCAN_ENABLED` | 启用密钥扫描 | `true` |
| **日志** |
| `PII_AIRLOCK_LOG_LEVEL` | 日志级别 | `INFO` |
| `PII_AIRLOCK_LOG_FORMAT` | 日志格式 (json/text) | `json` |
| **限流** |
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
      - employee

  - name: project_code
    entity_type: PROJECT_CODE
    regex: "PROJ-\\d{4}-[A-Z]{2}"
    score: 0.9
    context:
      - 项目
      - 编号
```

设置配置路径：

```bash
export PII_AIRLOCK_CONFIG_PATH=./config/custom_patterns.yaml
```

### 合规预设

预配置的合规预设位于 `config/compliance_presets/`：

- **GDPR** (`gdpr.yaml`)：欧洲数据保护规则
- **CCPA** (`ccpa.yaml`)：加州消费者隐私法案
- **PIPL** (`pipl.yaml`)：中国个人信息保护法
- **Financial** (`financial.yaml`)：金融行业合规规则

## API 端点

### OpenAI 兼容 API

| 端点 | 方法 | 说明 |
| -------- | ------ | ----------- |
| `/v1/chat/completions` | POST | 带 PII 保护的聊天补全 |
| `/v1/models` | GET | 列出可用模型 |

### 管理 API

| 端点 | 方法 | 说明 |
| -------- | ------ | ----------- |
| **合规** |
| `/api/v1/compliance/presets` | GET | 列出可用预设 |
| `/api/v1/compliance/active` | GET/POST | 获取/设置活跃预设 |
| **白名单** |
| `/api/v1/allowlist` | GET | 列出所有白名单 |
| `/api/v1/allowlist/{name}/entries` | GET/POST/DELETE | 管理白名单条目 |
| **审计** |
| `/api/v1/audit/events` | GET | 查询审计事件 |
| `/api/v1/audit/export` | GET | 导出审计日志 |
| **意图检测** |
| `/api/v1/intent/patterns` | GET/POST | 管理意图模式 |

### 监控与测试

| 端点 | 说明 |
| -------- | ----------- |
| `/health` | 健康检查 |
| `/metrics` | Prometheus 指标 |
| `/ui` | Web 测试界面 |
| `/debug` | 可视化调试控制台 |
| `/admin` | 管理控制台 |
| `/api/test/anonymize` | 测试脱敏 |
| `/api/test/deanonymize` | 测试还原 |

## 编程接口

```python
from pii_airlock import Anonymizer, Deanonymizer
from pii_airlock.core.strategies import StrategyConfig, StrategyType

# 基础脱敏
anonymizer = Anonymizer()
result = anonymizer.anonymize("联系张三，邮箱 john@example.com")
print(result.text)  # 联系 <PERSON_1>，邮箱 <EMAIL_1>
print(result.mapping.get_original("<PERSON_1>"))  # 张三

# 还原
deanonymizer = Deanonymizer()
restored = deanonymizer.deanonymize(result.text, result.mapping)
print(restored.text)  # 联系张三，邮箱 john@example.com

# 使用自定义策略
strategy_config = StrategyConfig({
    "PERSON": StrategyType.MASK,
    "PHONE_NUMBER": StrategyType.REDACT,
})
anonymizer = Anonymizer(strategy_config=strategy_config)
result = anonymizer.anonymize("张三的电话是13800138000")
print(result.text)  # 张*的电话是[REDACTED]

# 禁用意图检测实现严格脱敏
anonymizer = Anonymizer(enable_intent_detection=False)
result = anonymizer.anonymize("谁是张三？")  # 张三会被脱敏
```

## 工作原理

```
1. 拦截    → 捕获入站请求
2. 密钥扫描 → 检查 API 密钥/令牌（发现则阻止）
3. 脱敏    → 使用 NLP 检测 PII，替换为占位符
4. 检查缓存 → 如有缓存响应则返回
5. 检查配额 → 验证配额限制
6. 映射    → 存储占位符到原始值的映射
7. 转发    → 将脱敏后的提示发送给上游 LLM
8. 缓存    → 存储响应供后续请求使用
9. 还原    → 替换响应中的占位符
10. 审计   → 记录事务日志
11. 返回   → 将还原后的响应返回给客户端
```

### 处理 LLM 幻觉

LLM 可能会修改占位符（例如 `<PERSON_1>` → `<Person 1>`）。PII-AIRLOCK 通过以下方式处理：

1. **系统提示注入**：指示 LLM 原样保留占位符
2. **模糊匹配**：使用灵活的正则模式匹配修改后的占位符

## 开发

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
│   ├── core/                   # 核心脱敏引擎
│   │   ├── anonymizer.py       # 主要脱敏逻辑
│   │   ├── deanonymizer.py     # 带模糊匹配的还原
│   │   ├── mapping.py          # PII 映射管理
│   │   ├── strategies.py       # 脱敏策略（5种）
│   │   ├── stream_buffer.py    # SSE 流式缓冲
│   │   ├── intent_detector.py  # 上下文感知意图检测
│   │   ├── synthetic/          # 仿真数据生成
│   │   ├── fuzzy/              # 模糊匹配引擎
│   │   └── secret_scanner/     # 密钥检测
│   ├── api/                    # FastAPI 路由和代理
│   │   ├── routes.py           # API 端点（含 Web UI）
│   │   ├── proxy.py            # 代理服务逻辑
│   │   ├── compliance_api.py   # 合规管理 API
│   │   ├── allowlist_api.py    # 白名单管理 API
│   │   ├── audit_api.py        # 审计日志 API
│   │   └── intent_api.py       # 意图检测 API
│   ├── auth/                   # 认证与授权
│   │   ├── tenant.py           # 多租户支持
│   │   ├── api_key.py          # API 密钥管理
│   │   ├── rbac.py             # 基于角色的访问控制
│   │   └── quota.py            # 配额管理
│   ├── audit/                  # 审计日志
│   │   ├── models.py           # 审计事件模型
│   │   ├── store.py            # 审计存储
│   │   └── logger.py           # 审计日志器
│   ├── cache/                  # 响应缓存
│   │   └── llm_cache.py        # LLM 响应缓存
│   ├── config/                 # 配置加载
│   │   ├── pattern_loader.py   # 自定义规则加载器
│   │   └── compliance_loader.py# 合规预设加载器
│   ├── recognizers/            # PII 识别器
│   │   ├── zh_phone.py         # 中国手机号识别
│   │   ├── zh_id_card.py       # 中国身份证识别
│   │   ├── zh_person.py        # 中文姓名识别
│   │   ├── allowlist.py        # 白名单识别器
│   │   ├── entropy_detector.py # 高熵值检测器
│   │   └── registry.py         # 识别器注册表
│   ├── static/                 # 静态文件
│   │   ├── debug.html          # 调试控制台
│   │   └── admin.html          # 管理控制台
│   ├── storage/                # 存储后端
│   ├── logging/                # 结构化日志
│   └── metrics/                # Prometheus 指标
├── config/                     # 配置文件
│   ├── compliance_presets/     # GDPR, CCPA, PIPL, 金融
│   └── allowlists/             # 白名单文件
├── tests/                      # 测试套件（600+ 测试）
├── docs/                       # 文档
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

## 应用场景

- **企业合规**：使用 GPT-4/Claude 同时满足 GDPR、CCPA、PIPL 要求
- **低代码平台**：为 Dify、Flowise、LangFlow 添加网关
- **医疗/金融**：使用云端 LLM 安全处理敏感数据
- **开发测试**：无需暴露真实 PII 测试 LLM 应用
- **多团队协作**：共享基础设施，隔离配置和配额

## 贡献

我们欢迎贡献！请查看我们的 [贡献指南](CONTRIBUTING.md) 了解详情。

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 致谢

- [Microsoft Presidio](https://github.com/microsoft/presidio) - PII 检测引擎
- [spaCy](https://spacy.io/) - NLP 框架
- [FastAPI](https://fastapi.tiangolo.com/) - Web 框架
- [OpenAI](https://openai.com/) - LLM API

---

<div align="center">

由 PII-AIRLOCK 团队用心打造

[在 GitHub 上给我们 Star](https://github.com/pii-airlock/pii-airlock) — 这对我们很重要！

</div>
