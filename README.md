# PII-AIRLOCK

**Make Public LLMs Private**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-151%20passed-brightgreen.svg)]()
[![Coverage](https://img.shields.io/badge/coverage-78%25-green.svg)]()

[中文文档](README_zh.md)

PII-AIRLOCK is an open-source middleware/reverse proxy that protects sensitive personal information when using public LLM APIs. Deploy it between your applications and LLM providers (OpenAI, Claude, etc.) to automatically detect, anonymize, and restore PII in real-time.

```
┌─────────────────┐     ┌─────────────────────────────────────┐     ┌─────────────────┐
│                 │     │           PII-AIRLOCK               │     │                 │
│  Your App       │────▶│  ┌─────────┐    ┌─────────────────┐ │────▶│   OpenAI API    │
│ (Dify/LangChain)│     │  │Anonymize│────│  Mapping Store  │ │     │   Claude API    │
│                 │◀────│  └─────────┘    └─────────────────┘ │◀────│                 │
└─────────────────┘     └─────────────────────────────────────┘     └─────────────────┘
```

## Features

- **Zero-Code Integration**: Just change `base_url` - fully compatible with OpenAI API format
- **Type-Preserving Anonymization**: Uses semantic placeholders (`<PERSON_1>`, `<PHONE_2>`) that LLMs understand
- **Streaming Support**: Handles SSE streaming responses with sliding window buffering
- **Fuzzy Matching**: Recovers PII even when LLMs modify placeholder format
- **Custom Rules**: Define your own PII patterns via YAML configuration
- **Production Ready**: Structured logging, Prometheus metrics, rate limiting, connection pooling
- **Web UI**: Built-in testing interface for verifying anonymization

## Supported PII Types

| Type | Placeholder | Example |
| ------ | ------------- | --------- |
| Person Name | `<PERSON_N>` | John Doe → `<PERSON_1>` |
| Phone Number | `<PHONE_N>` | 13800138000 → `<PHONE_1>` |
| Email | `<EMAIL_N>` | <test@example.com> → `<EMAIL_1>` |
| ID Card | `<ID_CARD_N>` | 110101199003077758 → `<ID_CARD_1>` |
| Credit Card | `<CREDIT_CARD_N>` | 6222021234567890 → `<CREDIT_CARD_1>` |
| IP Address | `<IP_N>` | 192.168.1.1 → `<IP_1>` |
| Custom | Configurable | PROJ-2024-AB → `<PROJECT_CODE_1>` |

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/iannil/pii-airlock.git
cd pii-airlock

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Download Chinese NLP model (optional, for Chinese support)
python -m spacy download zh_core_web_trf
```

### Start the Server

```bash
# Set your OpenAI API key
export OPENAI_API_KEY=sk-your-api-key

# Start the proxy server
python -m pii_airlock.main

# Server runs at http://localhost:8000
```

### Use with OpenAI Client

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
stream = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "user", "content": "Introduce John Doe (phone: 13800138000)"}
    ],
    stream=True
)

for chunk in stream:
    if chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)
# Placeholders are correctly restored even when split across chunks
```

## Docker Deployment

```bash
# Using docker-compose (recommended)
docker-compose up -d

# Or build and run manually
docker build -t pii-airlock .
docker run -p 8000:8000 -e OPENAI_API_KEY=sk-xxx pii-airlock
```

## Configuration

### Environment Variables

| Variable | Description | Default |
| ---------- | ------------- | --------- |
| `PII_AIRLOCK_UPSTREAM_URL` | Upstream LLM API URL | `https://api.openai.com` |
| `OPENAI_API_KEY` | OpenAI API Key | - |
| `PII_AIRLOCK_PORT` | Server port | `8000` |
| `PII_AIRLOCK_MAPPING_TTL` | Mapping expiration (seconds) | `300` |
| `PII_AIRLOCK_INJECT_PROMPT` | Inject anti-hallucination prompt | `true` |
| `PII_AIRLOCK_CONFIG_PATH` | Custom patterns config path | - |
| `PII_AIRLOCK_LOG_LEVEL` | Log level (DEBUG/INFO/WARNING/ERROR) | `INFO` |
| `PII_AIRLOCK_LOG_FORMAT` | Log format (json/text) | `json` |
| `PII_AIRLOCK_RATE_LIMIT` | Rate limit configuration | `60/minute` |
| `PII_AIRLOCK_RATE_LIMIT_ENABLED` | Enable rate limiting | `true` |

### Custom PII Patterns

Create a YAML configuration file:

```yaml
# custom_patterns.yaml
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

Then set the environment variable:

```bash
export PII_AIRLOCK_CONFIG_PATH=./custom_patterns.yaml
```

## API Endpoints

| Endpoint | Description |
| ---------- | ------------- |
| `POST /v1/chat/completions` | OpenAI-compatible chat completions |
| `GET /v1/models` | List available models |
| `GET /health` | Health check |
| `GET /metrics` | Prometheus metrics |
| `GET /ui` | Web testing interface |
| `POST /api/test/anonymize` | Test anonymization |
| `POST /api/test/deanonymize` | Test deanonymization |

## Programmatic Usage

```python
from pii_airlock import Anonymizer, Deanonymizer

# Anonymize
anonymizer = Anonymizer()
result = anonymizer.anonymize("Contact John at john@example.com")
print(result.text)  # Contact <PERSON_1> at <EMAIL_1>
print(result.mapping.get_original("<PERSON_1>"))  # John

# Deanonymize
deanonymizer = Deanonymizer()
restored = deanonymizer.deanonymize(result.text, result.mapping)
print(restored.text)  # Contact John at john@example.com
```

## How It Works

1. **Intercept**: Capture the incoming prompt
2. **Anonymize**: Detect PII using NLP and replace with semantic placeholders
3. **Map**: Store placeholder-to-original mappings with TTL
4. **Forward**: Send sanitized prompt to upstream LLM
5. **Deanonymize**: Replace placeholders in response with original values
6. **Return**: Return restored response to client

### Handling LLM Hallucinations

LLMs may modify placeholders (e.g., `<PERSON_1>` → `<Person 1>`). PII-AIRLOCK handles this with:

1. **System Prompt Injection**: Instructs LLM to preserve placeholders exactly
2. **Fuzzy Matching**: Uses flexible patterns to match modified placeholders

## Development

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=pii_airlock --cov-report=term-missing

# Code linting
ruff check src/ tests/
```

## Project Structure

```
pii-airlock/
├── src/pii_airlock/
│   ├── core/           # Anonymization engine
│   │   ├── anonymizer.py
│   │   ├── deanonymizer.py
│   │   ├── mapping.py
│   │   └── stream_buffer.py
│   ├── api/            # FastAPI routes & proxy
│   │   ├── routes.py
│   │   ├── proxy.py
│   │   └── limiter.py
│   ├── recognizers/    # PII recognizers
│   ├── storage/        # Redis/Memory store
│   ├── logging/        # Structured logging
│   └── metrics/        # Prometheus metrics
├── tests/              # Test suite (151 tests)
├── config/             # Configuration examples
├── Dockerfile
└── docker-compose.yml
```

## Use Cases

- **Enterprise Compliance**: Use GPT-4/Claude while meeting data protection regulations
- **Low-Code Platforms**: Add as a gateway for Dify, FastGPT, LangFlow
- **Healthcare/Finance**: Process sensitive data with cloud LLMs safely
- **Development**: Test LLM applications without exposing real PII

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Microsoft Presidio](https://github.com/microsoft/presidio) - PII detection engine
- [spaCy](https://spacy.io/) - NLP framework
- [FastAPI](https://fastapi.tiangolo.com/) - Web framework
