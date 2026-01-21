# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 在本仓库中工作时提供指导。

## 项目概述

PII-AIRLOCK（敏感信息气闸）是一个中间件/反向代理，用于在调用公有 LLM API 时保护敏感个人信息。它部署在企业系统与公有 LLM（OpenAI、Claude）之间，实时进行 PII 检测、脱敏和回填。

**状态**：Phase 5 生产优化已完成。支持结构化日志、Prometheus 监控、API 限流、连接池优化、自定义 PII 规则、Web UI 测试界面、完整的 OpenAI API 兼容接口。

## 技术栈

- **语言**：Python 3.10+
- **Web 框架**：FastAPI + Uvicorn
- **PII 识别**：Microsoft Presidio + spaCy (zh_core_web_trf)
- **存储**：Redis / Memory Store
- **部署**：Docker/docker-compose

## 开发命令

```bash
# 安装依赖
pip install -e ".[dev]"

# 下载中文 NLP 模型
python -m spacy download zh_core_web_trf

# 运行代理服务
python -m pii_airlock.main
# 或
uvicorn pii_airlock.api.routes:app --reload

# 运行测试
pytest

# 运行测试（带覆盖率）
pytest --cov=pii_airlock --cov-report=term-missing

# 代码检查
ruff check src/ tests/

# Docker 部署
docker-compose up -d
```

## 项目结构

```
pii-airlock/
├── pyproject.toml              # 项目配置
├── Dockerfile                  # Docker 镜像
├── docker-compose.yml          # 容器编排
├── config/                     # 配置文件
│   └── custom_patterns.example.yaml  # 自定义规则示例
├── src/pii_airlock/
│   ├── main.py                 # 服务入口
│   ├── config/                 # 配置加载
│   │   └── pattern_loader.py   # YAML 配置加载器
│   ├── core/                   # 核心引擎
│   │   ├── anonymizer.py       # 脱敏引擎
│   │   ├── deanonymizer.py     # 回填引擎
│   │   ├── mapping.py          # PII映射管理
│   │   ├── counter.py          # 占位符计数器
│   │   └── stream_buffer.py    # 流式缓冲处理器
│   ├── api/                    # API 层
│   │   ├── routes.py           # FastAPI 路由 (含 Web UI)
│   │   ├── proxy.py            # 代理逻辑
│   │   ├── models.py           # Pydantic 模型
│   │   ├── middleware.py       # 请求日志中间件
│   │   └── limiter.py          # API 限流配置
│   ├── logging/                # 日志模块
│   │   └── setup.py            # 日志配置
│   ├── metrics/                # 监控模块
│   │   └── collectors.py       # Prometheus 指标
│   ├── storage/                # 存储层
│   │   ├── redis_store.py      # Redis 存储
│   │   └── memory_store.py     # 内存存储
│   └── recognizers/            # 识别器
│       ├── registry.py         # 识别器注册
│       ├── custom_pattern.py   # 自定义模式识别器
│       ├── zh_phone.py         # 手机号识别
│       ├── zh_id_card.py       # 身份证识别
│       └── zh_person.py        # 姓名识别
└── tests/                      # 测试用例 (151 个测试)
```

## 使用方式

### 1. 启动服务

```bash
# 设置环境变量
export OPENAI_API_KEY=sk-xxx

# 启动服务
python -m pii_airlock.main
```

### 2. 客户端接入

```python
from openai import OpenAI

# 只需修改 base_url，其他代码无需改动
client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="sk-xxx"  # 你的 OpenAI API Key
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "user", "content": "张三的电话是13800138000，请帮我写一封邮件"}
    ]
)

print(response.choices[0].message.content)
# PII 自动脱敏后发送给 OpenAI，响应自动回填
```

### 3. 流式响应

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="sk-xxx"
)

# 流式响应同样支持 PII 自动脱敏/回填
stream = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "user", "content": "请介绍张三（电话：13800138000）"}
    ],
    stream=True  # 启用流式响应
)

for chunk in stream:
    if chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)
# 即使占位符被分割到多个 chunk，也能正确处理
```

## 核心 API

```python
from pii_airlock import Anonymizer, Deanonymizer

# 脱敏
anonymizer = Anonymizer()
result = anonymizer.anonymize("张三的电话是13800138000")
print(result.text)  # <PERSON_1>的电话是<PHONE_1>

# 回填
deanonymizer = Deanonymizer()
restored = deanonymizer.deanonymize(result.text, result.mapping)
print(restored.text)  # 张三的电话是13800138000
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `PII_AIRLOCK_UPSTREAM_URL` | 上游 LLM API 地址 | `https://api.openai.com` |
| `OPENAI_API_KEY` | OpenAI API Key | - |
| `PII_AIRLOCK_PORT` | 服务端口 | `8000` |
| `PII_AIRLOCK_MAPPING_TTL` | 映射过期时间(秒) | `300` |
| `PII_AIRLOCK_INJECT_PROMPT` | 注入防幻觉提示 | `true` |
| `PII_AIRLOCK_CONFIG_PATH` | 自定义配置文件路径 | - |
| `PII_AIRLOCK_LOG_LEVEL` | 日志级别 (DEBUG/INFO/WARNING/ERROR) | `INFO` |
| `PII_AIRLOCK_LOG_FORMAT` | 日志格式 (json/text) | `json` |
| `PII_AIRLOCK_RATE_LIMIT` | API 限流配置 | `60/minute` |
| `PII_AIRLOCK_RATE_LIMIT_ENABLED` | 是否启用限流 | `true` |

## 监控端点

- `/metrics` - Prometheus 指标端点
- `/health` - 健康检查端点

## Web UI 测试界面

访问 `http://localhost:8000/ui` 可使用 Web 测试界面：
- 输入文本测试脱敏效果
- 查看占位符与原始值的映射关系
- 无需调用 LLM 即可验证 PII 识别

## 自定义 PII 规则

通过 YAML 配置文件添加企业特定的 PII 识别规则：

```bash
# 设置配置文件路径
export PII_AIRLOCK_CONFIG_PATH=./config/custom_patterns.yaml
```

配置文件格式示例（参见 `config/custom_patterns.example.yaml`）：

```yaml
patterns:
  - name: employee_id
    entity_type: EMPLOYEE_ID
    regex: "EMP[A-Z]\\d{6}"
    score: 0.85
    context: ["员工", "工号", "employee"]
```

## 支持的 PII 类型

| 类型 | 占位符 | 示例 |
|------|--------|------|
| 姓名 | `<PERSON_N>` | 张三 → `<PERSON_1>` |
| 手机号 | `<PHONE_N>` | 13800138000 → `<PHONE_1>` |
| 邮箱 | `<EMAIL_N>` | test@example.com → `<EMAIL_1>` |
| 身份证 | `<ID_CARD_N>` | 110101199003077758 → `<ID_CARD_1>` |
| 银行卡 | `<CREDIT_CARD_N>` | 6222... → `<CREDIT_CARD_1>` |

## 文档结构

```
docs/
├── design/              # 设计文档
│   ├── architecture.md  # 技术架构
│   └── roadmap.md       # 开发路线图
├── progress/            # 进展追踪
│   ├── changelog.md     # 变更日志
│   └── status-report.md # 状态报告
└── archive/             # 归档文档
```
