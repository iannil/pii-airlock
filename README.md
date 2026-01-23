<div align="center">

# PII-AIRLOCK

### Make Public LLMs Private — PII Protection Middleware for LLM APIs

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](https://github.com/pii-airlock/pii-airlock/releases)
[![Tests](https://img.shields.io/badge/tests-600%20passed-brightgreen.svg)](https://github.com/pii-airlock/pii-airlock/actions)
[![Coverage](https://img.shields.io/badge/coverage-73%25-green.svg)](https://github.com/pii-airlock/pii-airlock/actions)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

[中文文档](README_zh.md) | [Documentation](docs/) | [Changelog](docs/progress/changelog.md)

---

PII-AIRLOCK is an open-source middleware/reverse proxy that protects sensitive personal information when using public LLM APIs. Deploy it between your applications and LLM providers (OpenAI, Claude, etc.) to automatically detect, anonymize, and restore PII in real-time.

</div>

---

## Overview

```
┌─────────────────┐     ┌─────────────────────────────────────────┐     ┌─────────────────┐
│                 │     │           PII-AIRLOCK (v1.1)            │     │                 │
│  Your App       │────▶│  ┌─────────┐    ┌─────────────────┐     │────▶│   OpenAI API    │
│  (Dify/Flowise) │     │  │Anonymize│────│  Mapping Store  │     │     │   Claude API    │
│                 │◀────│  └─────────┘    │   + Cache       │     │◀────│   Azure OpenAI  │
└─────────────────┘     └─────────────────────────────────────────┘     └─────────────────┘
                              ▲
                   Multi-Tenant │ Compliance │ Audit │ Admin UI
```

## Key Features

### Core Capabilities

| Feature | Description |
| ------- | ----------- |
| Zero-Code Integration | Just change `base_url` - fully compatible with OpenAI API format |
| Smart Anonymization | Semantic placeholders (`<PERSON_1>`) that LLMs understand naturally |
| Streaming Support | Handles SSE streaming with intelligent buffer for split placeholders |
| Fuzzy Recovery | Recovers PII even when LLMs modify placeholder format |
| Custom Patterns | Define your own PII patterns via YAML configuration |
| Intent Detection | Smart context-aware detection to skip anonymization in question contexts |
| Secret Scanning | Detect API keys, tokens, and other secrets before sending to LLM |

### Enterprise Features

| Feature | Description |
| ------- | ----------- |
| Multi-Tenancy | Tenant isolation with dedicated configurations and rate limits |
| Response Caching | LLM response caching to reduce API costs and latency |
| Quota Management | Request/token quotas with hourly/daily/monthly limits |
| API Key Management | Secure API key creation and lifecycle management |
| RBAC | Role-based access control (Admin/Operator/Viewer/User) |
| Compliance Presets | Pre-configured rules for GDPR, CCPA, PIPL, Financial compliance |
| Allowlists | Whitelist public figures, locations, and other safe entities |
| Audit Logging | Complete audit trail with query and export capabilities |
| Web Admin Console | Full-featured management interface |
| Production Ready | Structured logging, Prometheus metrics, rate limiting |

### Anonymization Strategies

| Strategy | Description | Example | Use Case |
| -------- | ----------- | ------- | -------- |
| placeholder | Type-based placeholders | `张三` → `<PERSON_1>` | LLM processing (default) |
| hash | SHA256 hash | `张三` → `a1b2c3d4...` | Log analysis, deduplication |
| mask | Partial masking | `13800138000` → `138****8000` | UI display |
| redact | Complete replacement | `test@example.com` → `[REDACTED]` | Maximum privacy |
| synthetic | Fake data replacement | `张三` → `李明` | Testing, demos |

## Supported PII Types

| Type | Placeholder | Example |
| ---- | ----------- | ------- |
| Person Name | `<PERSON_N>` | John Doe → `<PERSON_1>` |
| Phone Number | `<PHONE_N>` | 13800138000 → `<PHONE_1>` |
| Email | `<EMAIL_N>` | test@example.com → `<EMAIL_1>` |
| ID Card | `<ID_CARD_N>` | 110101199003077758 → `<ID_CARD_1>` |
| Credit Card | `<CREDIT_CARD_N>` | 6222021234567890 → `<CREDIT_CARD_1>` |
| IP Address | `<IP_N>` | 192.168.1.1 → `<IP_1>` |
| Custom | Configurable | PROJ-2024-AB → `<PROJECT_CODE_1>` |

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/pii-airlock/pii-airlock.git
cd pii-airlock

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -e .

# Download Chinese NLP model (required for Chinese PII detection)
python -m spacy download zh_core_web_trf
```

### Start the Server

```bash
# Set your OpenAI API key
export OPENAI_API_KEY=sk-your-api-key

# Start the proxy server
python -m pii_airlock.main

# Server runs at http://localhost:8000
# API Docs: http://localhost:8000/docs
# Web UI: http://localhost:8000/ui
# Debug Console: http://localhost:8000/debug
# Admin Console: http://localhost:8000/admin
```

### Use with OpenAI Python Client

```python
from openai import OpenAI

# Simply change base_url to point to PII-AIRLOCK
client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="sk-your-api-key"
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "user", "content": "Write an email to John (john@example.com) about the meeting."}
    ]
)

print(response.choices[0].message.content)
# PII is automatically anonymized before sending to OpenAI,
# and restored in the response
```

### Streaming Support

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="sk-your-api-key"
)

# Streaming responses are also supported
stream = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "user", "content": "Tell me about John (phone: 13800138000)"}
    ],
    stream=True
)

for chunk in stream:
    if chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)
# Placeholders split across chunks are handled correctly
```

### Docker Deployment

```bash
# Using docker-compose (recommended)
docker-compose up -d

# Or build and run manually
docker build -t pii-airlock .
docker run -p 8000:8000 -e OPENAI_API_KEY=sk-xxx pii-airlock
```

## Web Interfaces

### Test Interface (`/ui`)
Simple web interface for testing PII detection and anonymization without calling LLM.

### Debug Console (`/debug`)
Visual debugging interface with:
- Side-by-side comparison of original and anonymized text
- PII highlighting with color-coded entity types
- Interactive tooltips with detailed information
- Export mapping data as JSON

### Admin Console (`/admin`)
Full management interface with:
- **Dashboard**: System statistics, recent activity, real-time status
- **Compliance**: Activate/switch compliance presets (GDPR/CCPA/PIPL/Financial)
- **Allowlists**: Add/remove whitelist entries, bulk import
- **Audit Logs**: Query, filter, and export audit records

## Configuration

### Environment Variables

| Variable | Description | Default |
| -------- | ----------- | ------- |
| **Basic** |
| `OPENAI_API_KEY` | OpenAI API Key | - |
| `PII_AIRLOCK_UPSTREAM_URL` | Upstream LLM API URL | `https://api.openai.com` |
| `PII_AIRLOCK_PORT` | Server port | `8000` |
| `PII_AIRLOCK_MAPPING_TTL` | Mapping expiration (seconds) | `300` |
| `PII_AIRLOCK_INJECT_PROMPT` | Inject anti-hallucination prompt | `true` |
| **Multi-Tenant** |
| `PII_AIRLOCK_MULTI_TENANT_ENABLED` | Enable multi-tenant mode | `false` |
| `PII_AIRLOCK_TENANT_CONFIG_PATH` | Path to tenants.yaml | - |
| **Caching** |
| `PII_AIRLOCK_CACHE_ENABLED` | Enable response caching | `false` |
| `PII_AIRLOCK_CACHE_TTL` | Cache TTL (seconds) | `3600` |
| `PII_AIRLOCK_CACHE_MAX_SIZE` | Max cache entries | `10000` |
| **Security** |
| `PII_AIRLOCK_SECRET_SCAN_ENABLED` | Enable secret scanning | `true` |
| **Logging** |
| `PII_AIRLOCK_LOG_LEVEL` | Log level | `INFO` |
| `PII_AIRLOCK_LOG_FORMAT` | Log format (json/text) | `json` |
| **Rate Limiting** |
| `PII_AIRLOCK_RATE_LIMIT` | Rate limit | `60/minute` |
| `PII_AIRLOCK_RATE_LIMIT_ENABLED` | Enable rate limiting | `true` |

### Custom PII Patterns

Create `config/custom_patterns.yaml`:

```yaml
patterns:
  - name: employee_id
    entity_type: EMPLOYEE_ID
    regex: "EMP[A-Z]\\d{6}"
    score: 0.85
    context:
      - employee
      - staff
      - worker

  - name: project_code
    entity_type: PROJECT_CODE
    regex: "PROJ-\\d{4}-[A-Z]{2}"
    score: 0.9
    context:
      - project
      - code
```

Set the config path:

```bash
export PII_AIRLOCK_CONFIG_PATH=./config/custom_patterns.yaml
```

### Compliance Presets

Pre-configured compliance presets are available in `config/compliance_presets/`:

- **GDPR** (`gdpr.yaml`): European data protection rules
- **CCPA** (`ccpa.yaml`): California Consumer Privacy Act
- **PIPL** (`pipl.yaml`): China Personal Information Protection Law
- **Financial** (`financial.yaml`): Financial industry regulations

## API Endpoints

### OpenAI-Compatible API

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/v1/chat/completions` | POST | Chat completions with PII protection |
| `/v1/models` | GET | List available models |

### Management API

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| **Compliance** |
| `/api/v1/compliance/presets` | GET | List available presets |
| `/api/v1/compliance/active` | GET/POST | Get/set active preset |
| **Allowlists** |
| `/api/v1/allowlist` | GET | List all allowlists |
| `/api/v1/allowlist/{name}/entries` | GET/POST/DELETE | Manage allowlist entries |
| **Audit** |
| `/api/v1/audit/events` | GET | Query audit events |
| `/api/v1/audit/export` | GET | Export audit logs |
| **Intent Detection** |
| `/api/v1/intent/patterns` | GET/POST | Manage intent patterns |

### Monitoring & Testing

| Endpoint | Description |
| -------- | ----------- |
| `/health` | Health check |
| `/metrics` | Prometheus metrics |
| `/ui` | Web testing interface |
| `/debug` | Visual debug console |
| `/admin` | Admin console |
| `/api/test/anonymize` | Test anonymization |
| `/api/test/deanonymize` | Test deanonymization |

## Programmatic Usage

```python
from pii_airlock import Anonymizer, Deanonymizer
from pii_airlock.core.strategies import StrategyConfig, StrategyType

# Basic anonymization
anonymizer = Anonymizer()
result = anonymizer.anonymize("Contact John at john@example.com")
print(result.text)  # Contact <PERSON_1> at <EMAIL_1>
print(result.mapping.get_original("<PERSON_1>"))  # John

# Deanonymization
deanonymizer = Deanonymizer()
restored = deanonymizer.deanonymize(result.text, result.mapping)
print(restored.text)  # Contact John at john@example.com

# With custom strategy
strategy_config = StrategyConfig({
    "PERSON": StrategyType.MASK,
    "PHONE_NUMBER": StrategyType.REDACT,
})
anonymizer = Anonymizer(strategy_config=strategy_config)
result = anonymizer.anonymize("张三的电话是13800138000")
print(result.text)  # 张*的电话是[REDACTED]

# Disable intent detection for strict anonymization
anonymizer = Anonymizer(enable_intent_detection=False)
result = anonymizer.anonymize("Who is John?")  # John will be anonymized
```

## How It Works

```
1. Intercept   → Capture incoming request
2. Secret Scan → Check for API keys/tokens (block if found)
3. Anonymize   → Detect PII using NLP, replace with placeholders
4. Check Cache → Return cached response if available
5. Check Quota → Verify quota limits
6. Map         → Store placeholder-to-original mappings
7. Forward     → Send sanitized prompt to upstream LLM
8. Cache       → Store response for future requests
9. Deanonymize → Replace placeholders in response
10. Audit      → Log the transaction
11. Return     → Return restored response to client
```

### Handling LLM Hallucinations

LLMs may modify placeholders (e.g., `<PERSON_1>` → `<Person 1>`). PII-AIRLOCK handles this with:

1. **System Prompt Injection**: Instructs LLM to preserve placeholders exactly
2. **Fuzzy Matching**: Uses flexible regex patterns to match modified placeholders

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=pii_airlock --cov-report=term-missing

# Code linting
ruff check src/ tests/

# Type checking
mypy src/
```

## Project Structure

```
pii-airlock/
├── src/pii_airlock/
│   ├── core/                   # Core anonymization engine
│   │   ├── anonymizer.py       # Main anonymization logic
│   │   ├── deanonymizer.py     # Deanonymization with fuzzy matching
│   │   ├── mapping.py          # PII mapping management
│   │   ├── strategies.py       # Anonymization strategies (5 types)
│   │   ├── stream_buffer.py    # Streaming buffer for SSE
│   │   ├── intent_detector.py  # Context-aware intent detection
│   │   ├── synthetic/          # Synthetic data generation
│   │   ├── fuzzy/              # Fuzzy matching engine
│   │   └── secret_scanner/     # Secret detection
│   ├── api/                    # FastAPI routes & proxy
│   │   ├── routes.py           # API endpoints (with Web UI)
│   │   ├── proxy.py            # Proxy service logic
│   │   ├── compliance_api.py   # Compliance management API
│   │   ├── allowlist_api.py    # Allowlist management API
│   │   ├── audit_api.py        # Audit log API
│   │   └── intent_api.py       # Intent detection API
│   ├── auth/                   # Authentication & Authorization
│   │   ├── tenant.py           # Multi-tenant support
│   │   ├── api_key.py          # API key management
│   │   ├── rbac.py             # Role-based access control
│   │   └── quota.py            # Quota management
│   ├── audit/                  # Audit logging
│   │   ├── models.py           # Audit event models
│   │   ├── store.py            # Audit storage
│   │   └── logger.py           # Audit logger
│   ├── cache/                  # Response caching
│   │   └── llm_cache.py        # LLM response cache
│   ├── config/                 # Configuration loading
│   │   ├── pattern_loader.py   # Custom pattern loader
│   │   └── compliance_loader.py# Compliance preset loader
│   ├── recognizers/            # PII recognizers
│   │   ├── zh_phone.py         # Chinese phone recognizer
│   │   ├── zh_id_card.py       # Chinese ID card recognizer
│   │   ├── zh_person.py        # Chinese name recognizer
│   │   ├── allowlist.py        # Allowlist recognizer
│   │   ├── entropy_detector.py # High entropy detector
│   │   └── registry.py         # Recognizer registry
│   ├── static/                 # Static files
│   │   ├── debug.html          # Debug console
│   │   └── admin.html          # Admin console
│   ├── storage/                # Storage backends
│   ├── logging/                # Structured logging
│   └── metrics/                # Prometheus metrics
├── config/                     # Configuration files
│   ├── compliance_presets/     # GDPR, CCPA, PIPL, Financial
│   └── allowlists/             # Allowlist files
├── tests/                      # Test suite (600+ tests)
├── docs/                       # Documentation
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

## Use Cases

- **Enterprise Compliance**: Use GPT-4/Claude while meeting GDPR, CCPA, PIPL requirements
- **Low-Code Platforms**: Add as a gateway for Dify, Flowise, LangFlow
- **Healthcare/Finance**: Process sensitive data with cloud LLMs safely
- **Development**: Test LLM applications without exposing real PII
- **Multi-Team**: Shared infrastructure with isolated configurations and quotas

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Microsoft Presidio](https://github.com/microsoft/presidio) - PII detection engine
- [spaCy](https://spacy.io/) - NLP framework
- [FastAPI](https://fastapi.tiangolo.com/) - Web framework
- [OpenAI](https://openai.com/) - LLM API

---

<div align="center">

Made with love by the PII-AIRLOCK team

[Star us on GitHub](https://github.com/pii-airlock/pii-airlock) — it helps!

</div>
