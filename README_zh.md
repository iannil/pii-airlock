# PII-AIRLOCK

> 让公有大模型私有化 - LLM API 的 PII 保护中间件

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](https://github.com/iannil/pii-airlock/releases)
[![Tests](https://img.shields.io/badge/tests-286%20passed-brightgreen.svg)](https://github.com/iannil/pii-airlock/actions)
[![Coverage](https://img.shields.io/badge/coverage-81%25-green.svg)](https://github.com/iannil/pii-airlock/actions)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

[English](README.md) | [文档](docs/) | [更新日志](docs/progress/changelog.md)

---

## 概述

PII-AIRLOCK 是一个开源的中间件/反向代理，用于在调用公有 LLM API 时保护敏感个人信息。将它部署在您的应用程序和 LLM 提供商（OpenAI、Claude 等）之间，可自动实时检测、脱敏和恢复 PII。

```
┌─────────────────┐     ┌─────────────────────────────────────┐     ┌─────────────────┐
│                 │     │           PII-AIRLOCK               │     │                 │
│  企业应用        │────▶│  ┌─────────┐    ┌─────────────────┐ │────▶│   OpenAI API    │
│ (Dify/LangChain)│     │  │ 脱敏引擎 │────│    映射存储      │ │     │   Claude API    │
│                 │◀────│  └─────────┘    └─────────────────┘ │◀────│                 │
└─────────────────┘     └─────────────────────────────────────┘     └─────────────────┘
```

## 核心特性

| 特性 | 描述 |
| ------ | ------ |
| **零代码接入** | 只需修改 `base_url`，完全兼容 OpenAI API 格式 |
| **类型保留脱敏** | 使用语义化占位符（`<PERSON_1>`、`<PHONE_2>`），LLM 能理解上下文 |
| **流式响应支持** | 通过滑动窗口缓冲处理 SSE 流式响应 |
| **模糊匹配恢复** | 即使 LLM 修改了占位符格式，也能正确恢复 |
| **自定义规则** | 通过 YAML 配置文件定义企业专属的 PII 识别规则 |
| **多种脱敏策略** | 支持占位符、哈希、掩码、完全替换四种脱敏策略 |
| **生产就绪** | 结构化日志、Prometheus 监控、API 限流、连接池优化 |
| **Web 测试界面** | 内置可视化界面验证脱敏效果 |

## 支持的 PII 类型

| 类型 | 占位符 | 示例 |
| ------ | -------- | ------ |
| 姓名 | `<PERSON_N>` | 张三 → `<PERSON_1>` |
| 手机号 | `<PHONE_N>` | 13800138000 → `<PHONE_1>` |
| 邮箱 | `<EMAIL_N>` | test@example.com → `<EMAIL_1>` |
| 身份证 | `<ID_CARD_N>` | 110101199003077758 → `<ID_CARD_1>` |
| 银行卡 | `<CREDIT_CARD_N>` | 6222021234567890 → `<CREDIT_CARD_1>` |
| IP 地址 | `<IP_N>` | 192.168.1.1 → `<IP_1>` |
| 自定义 | 可配置 | PROJ-2024-AB → `<PROJECT_CODE_1>` |

## 脱敏策略

| 策略 | 描述 | 示例 | 适用场景 |
| ------ | ------ | ------ | ---------- |
| **placeholder** | 占位符替换 | `张三` → `<PERSON_1>` | LLM 处理（默认） |
| **hash** | SHA256 哈希 | `张三` → `a1b2c3d4...` | 日志分析、数据去重 |
| **mask** | 部分掩码 | `13800138000` → `138****8000` | UI 显示、客服场景 |
| **redact** | 完全替换 | `test@example.com` → `[REDACTED]` | 最高隐私、审计日志 |

详细的策略文档请参阅 [docs/guide/strategies.md](docs/guide/strategies.md)。

## 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/iannil/pii-airlock.git
cd pii-airlock

# 创建虚拟环境
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 安装依赖
pip install -e .

# 下载中文 NLP 模型（可选，用于中文支持）
python -m spacy download zh_core_web_sm
```

### 启动服务

```bash
# 设置 OpenAI API Key
export OPENAI_API_KEY=sk-your-api-key

# 启动代理服务
python -m pii_airlock.main

# 服务运行在 http://localhost:8000
```

### 使用 OpenAI 客户端

```python
from openai import OpenAI

# 只需修改 base_url 指向 PII-AIRLOCK
client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="sk-your-api-key"
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "user", "content": "请帮我给张三（电话：13800138000）写一封催款邮件"}
    ]
)

print(response.choices[0].message.content)
# PII 自动脱敏后发送给 OpenAI，响应自动恢复原始值
```

### Docker 部署

```bash
# 使用 docker-compose（推荐）
docker-compose up -d

# 或手动构建运行
docker build -t pii-airlock .
docker run -p 8000:8000 -e OPENAI_API_KEY=sk-xxx pii-airlock
```

## 配置说明

### 环境变量

| 变量 | 说明 | 默认值 |
| ------ | ------ | -------- |
| `PII_AIRLOCK_UPSTREAM_URL` | 上游 LLM API 地址 | `https://api.openai.com` |
| `OPENAI_API_KEY` | OpenAI API Key | - |
| `PII_AIRLOCK_PORT` | 服务端口 | `8000` |
| `PII_AIRLOCK_MAPPING_TTL` | 映射过期时间（秒） | `300` |
| `PII_AIRLOCK_INJECT_PROMPT` | 注入防幻觉提示 | `true` |
| `PII_AIRLOCK_CONFIG_PATH` | 自定义规则配置路径 | - |
| `PII_AIRLOCK_LOG_LEVEL` | 日志级别 (DEBUG/INFO/WARNING/ERROR) | `INFO` |
| `PII_AIRLOCK_LOG_FORMAT` | 日志格式 (json/text) | `json` |
| `PII_AIRLOCK_RATE_LIMIT` | API 限流配置 | `60/minute` |
| `PII_AIRLOCK_RATE_LIMIT_ENABLED` | 是否启用限流 | `true` |

### 自定义 PII 规则

创建 YAML 配置文件：

```yaml
# config/custom_patterns.yaml
patterns:
  # 员工编号
  - name: employee_id
    entity_type: EMPLOYEE_ID
    regex: "EMP[A-Z]\\d{6}"
    score: 0.85
    context:
      - 员工
      - 工号
      - employee

  # 项目编码
  - name: project_code
    entity_type: PROJECT_CODE
    regex: "PROJ-\\d{4}-[A-Z]{2}"
    score: 0.9
    context:
      - 项目
      - project
```

设置环境变量：

```bash
export PII_AIRLOCK_CONFIG_PATH=./config/custom_patterns.yaml
```

## API 端点

| 端点 | 方法 | 说明 |
| ------ | ------ | ------ |
| `/v1/chat/completions` | POST | OpenAI 兼容的聊天补全接口 |
| `/v1/models` | GET | 列出可用模型 |
| `/health` | GET | 健康检查 |
| `/metrics` | GET | Prometheus 监控指标 |
| `/ui` | GET | Web 测试界面 |
| `/api/test/anonymize` | POST | 测试脱敏功能 |
| `/api/test/deanonymize` | POST | 测试回填功能 |

### 测试脱敏 API

```bash
curl -X POST http://localhost:8000/api/test/anonymize \
  -H "Content-Type: application/json" \
  -d '{"text": "张三的电话是13800138000", "strategy": "mask"}'
```

响应示例：
```json
{
  "original": "张三的电话是13800138000",
  "anonymized": "张*的电话是138****8000",
  "mapping": {},
  "strategy": "mask"
}
```

## 编程接口

```python
from pii_airlock import Anonymizer, Deanonymizer
from pii_airlock.core.strategies import StrategyConfig, StrategyType

# 基础脱敏
anonymizer = Anonymizer()
result = anonymizer.anonymize("张三的邮箱是test@example.com")
print(result.text)  # <PERSON_1>的邮箱是<EMAIL_1>
print(result.mapping.get_original("<PERSON_1>"))  # 张三

# 回填
deanonymizer = Deanonymizer()
restored = deanonymizer.deanonymize(result.text, result.mapping)
print(restored.text)  # 张三的邮箱是test@example.com

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

1. **拦截 (Intercept)**：捕获客户端发出的 Prompt
2. **脱敏 (Anonymize)**：NLP 引擎识别敏感实体，替换为语义化占位符
3. **映射 (Map)**：在存储中保存占位符与原始值的映射关系，设置 TTL
4. **转发 (Forward)**：将清洗后的 Prompt 发送给上游 LLM
5. **回填 (Deanonymize)**：将响应中的占位符替换为原始值
6. **返回 (Return)**：将恢复后的结果返回客户端

### 处理 LLM 幻觉

LLM 可能会修改占位符格式（如 `<PERSON_1>` → `<Person 1>`）。PII-AIRLOCK 通过以下方式处理：

1. **System Prompt 注入**：指示 LLM 保持占位符原样不变
2. **模糊匹配**：使用灵活的正则模式匹配被修改的占位符

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
│   ├── core/               # 核心脱敏引擎
│   │   ├── anonymizer.py   # 主脱敏逻辑
│   │   ├── deanonymizer.py # 带模糊匹配的回填
│   │   ├── mapping.py      # PII 映射管理
│   │   ├── strategies.py   # 脱敏策略
│   │   └── stream_buffer.py# SSE 流式缓冲
│   ├── api/                # FastAPI 路由和代理
│   │   ├── routes.py       # API 端点
│   │   ├── proxy.py        # 代理服务逻辑
│   │   ├── models.py       # Pydantic 模型
│   │   ├── middleware.py   # 请求日志中间件
│   │   └── limiter.py      # 限流
│   ├── recognizers/        # PII 识别器
│   │   ├── zh_phone.py     # 中国手机号识别器
│   │   ├── zh_id_card.py   # 中国身份证识别器
│   │   ├── zh_person.py    # 中文姓名识别器
│   │   └── registry.py     # 识别器注册中心
│   ├── storage/            # 存储后端
│   │   ├── memory_store.py # 内存存储
│   │   └── redis_store.py  # Redis 存储
│   ├── logging/            # 结构化日志
│   ├── metrics/            # Prometheus 指标
│   └── config/             # 配置加载
├── tests/                  # 测试套件（286 个测试）
├── config/                 # 配置示例
├── docs/                   # 文档
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

## 路线图

- [ ] 多租户支持
- [ ] 审计日志
- [ ] OpenTelemetry 集成
- [ ] 分布式限流
- [ ] Kubernetes 部署指南
- [ ] 更多语言支持（日语、韩语等）

## 贡献指南

欢迎贡献代码！请参阅我们的 [贡献指南](CONTRIBUTING.md) 了解详情。

1. Fork 本仓库
2. 创建您的特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交您的更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 开启 Pull Request

## 应用场景

- **企业合规**：在满足数据保护法规（GDPR、CCPA、个人信息保护法）的前提下使用 GPT-4/Claude
- **低代码平台**：作为 Dify、FastGPT、LangFlow 的前置网关
- **医疗/金融**：安全地使用云端 LLM 处理敏感数据
- **开发测试**：在不暴露真实 PII 的情况下测试 LLM 应用

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 致谢

- [Microsoft Presidio](https://github.com/microsoft/presidio) - PII 检测引擎
- [spaCy](https://spacy.io/) - NLP 框架
- [FastAPI](https://fastapi.tiangolo.com/) - Web 框架
- [OpenAI](https://openai.com/) - LLM API

## Star 历史

[![Star History Chart](https://api.star-history.com/svg?repos=iannil/pii-airlock&type=Date)](https://star-history.com/#iannil/pii-airlock&Date)

---

**由 PII-AIRLOCK 团队用 ❤️ 制作**
