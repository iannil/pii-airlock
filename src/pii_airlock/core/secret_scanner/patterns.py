"""
预定义的秘密模式

包含常见 API Keys、Tokens、证书等敏感信息的检测模式。

参考:
- GitHub Secret Scanning
- GitLab Secret Detection
- truffleHog
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Pattern


class SecretType(str, Enum):
    """秘密类型"""
    # API Keys
    OPENAI_API_KEY = "openai_api_key"
    ANTHROPIC_API_KEY = "anthropic_api_key"
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    GCP_API_KEY = "gcp_api_key"
    AZURE_KEY = "azure_key"
    GOOGLE_OAUTH = "google_oauth"

    # Tokens
    GITHUB_TOKEN = "github_token"
    GITLAB_TOKEN = "gitlab_token"
    BITBUCKET_TOKEN = "bitbucket_token"
    SLACK_TOKEN = "slack_token"
    DISCORD_TOKEN = "discord_token"
    TELEGRAM_BOT_TOKEN = "telegram_bot_token"

    # Database
    DATABASE_URL = "database_url"
    MONGODB_URI = "mongodb_uri"
    REDIS_URL = "redis_url"

    # Payment
    STRIPE_API_KEY = "stripe_api_key"
    PAYPAL_CLIENT_ID = "paypal_client_id"

    # Cloud Services
    TWILIO_ACCOUNT_SID = "twilio_account_sid"
    SENDGRID_API_KEY = "sendgrid_api_key"
    MAILGUN_API_KEY = "mailgun_api_key"

    # Certificates/Keys
    PRIVATE_KEY = "private_key"
    SSH_PRIVATE_KEY = "ssh_private_key"
    PGP_PRIVATE_KEY = "pgp_private_key"
    SSL_CERTIFICATE = "ssl_certificate"

    # OAuth
    OAUTH_ACCESS_TOKEN = "oauth_access_token"
    OAUTH_REFRESH_TOKEN = "oauth_refresh_token"
    OAUTH_CLIENT_SECRET = "oauth_client_secret"

    # JWT
    JWT_TOKEN = "jwt_token"

    # Generic
    GENERIC_API_KEY = "generic_api_key"
    GENERIC_SECRET = "generic_secret"
    PASSWORD = "password"


@dataclass
class SecretPattern:
    """秘密模式定义"""
    name: str
    type: SecretType
    pattern: Pattern
    description: str
    risk_level: str  # critical, high, medium, low
    examples: list[str]

    def match(self, text: str) -> list[re.Match]:
        """在文本中查找所有匹配"""
        return list(self.pattern.finditer(text))


# 预定义的秘密模式
PREDEFINED_PATTERNS: list[SecretPattern] = [
    # OpenAI API Key (sk-...) - supports various key lengths
    SecretPattern(
        name="OpenAI API Key",
        type=SecretType.OPENAI_API_KEY,
        pattern=re.compile(
            r'(sk-[a-zA-Z0-9]{10,48})',
            re.IGNORECASE,
        ),
        description="OpenAI API 密钥",
        risk_level="critical",
        examples=["sk-abcdefghijklmnopqrstuvwxyz1234567890AB"],
    ),

    # Anthropic API Key
    SecretPattern(
        name="Anthropic API Key",
        type=SecretType.ANTHROPIC_API_KEY,
        pattern=re.compile(
            r'(sk-ant-[a-zA-Z0-9_-]{95})',
            re.IGNORECASE,
        ),
        description="Anthropic/Claude API 密钥",
        risk_level="critical",
        examples=["sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456"],
    ),

    # AWS Access Key ID
    SecretPattern(
        name="AWS Access Key ID",
        type=SecretType.AWS_ACCESS_KEY,
        pattern=re.compile(
            r'(AKIA[0-9A-Z]{16})',
        ),
        description="AWS 访问密钥 ID",
        risk_level="critical",
        examples=["AKIAIOSFODNN7EXAMPLE"],
    ),

    # AWS Secret Access Key
    SecretPattern(
        name="AWS Secret Access Key",
        type=SecretType.AWS_SECRET_KEY,
        pattern=re.compile(
            r'aws_secret_access_key\s*[:=]\s*["\']?([a-zA-Z0-9+/]{40})["\']?\s*$',
            re.IGNORECASE | re.MULTILINE,
        ),
        description="AWS 秘密访问密钥",
        risk_level="critical",
        examples=["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
    ),

    # GitHub Personal Access Token
    SecretPattern(
        name="GitHub Token",
        type=SecretType.GITHUB_TOKEN,
        pattern=re.compile(
            r'(ghp_[a-zA-Z0-9]{36})',
            re.IGNORECASE,
        ),
        description="GitHub 个人访问令牌",
        risk_level="critical",
        examples=["ghp_1234567890abcdefghijklmnopqrstuv"],
    ),

    # GitHub OAuth Token
    SecretPattern(
        name="GitHub OAuth Token",
        type=SecretType.GITHUB_TOKEN,
        pattern=re.compile(
            r'(gho_[a-zA-Z0-9]{36})',
            re.IGNORECASE,
        ),
        description="GitHub OAuth 令牌",
        risk_level="critical",
        examples=["gho_1234567890abcdefghijklmnopqrstuv"],
    ),

    # GitLab Personal Access Token
    SecretPattern(
        name="GitLab Token",
        type=SecretType.GITLAB_TOKEN,
        pattern=re.compile(
            r'(glpat-[a-zA-Z0-9_-]{20})',
            re.IGNORECASE,
        ),
        description="GitLab 个人访问令牌",
        risk_level="critical",
        examples=["glpat-abcdefghijklmnopqrstuvwxyz12345"],
    ),

    # Slack Token
    SecretPattern(
        name="Slack Token",
        type=SecretType.SLACK_TOKEN,
        pattern=re.compile(
            r'(xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24})',
            re.IGNORECASE,
        ),
        description="Slack API 令牌",
        risk_level="high",
        examples=["xoxb-123456789012-123456789012-123456789012-abcdefghijklmnop"],
    ),

    # Discord Bot Token
    SecretPattern(
        name="Discord Bot Token",
        type=SecretType.DISCORD_TOKEN,
        pattern=re.compile(
            r'(M[NiD][a-zA-Z0-9]{23}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_-]{27})',
            re.IGNORECASE,
        ),
        description="Discord 机器人令牌",
        risk_level="high",
        examples=["<DISCORD_TOKEN_FORMAT: MXX...XXX.XXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXX>"],
    ),

    # Stripe API Key
    SecretPattern(
        name="Stripe API Key",
        type=SecretType.STRIPE_API_KEY,
        pattern=re.compile(
            r'(sk_live_[0-9a-zA-Z]{24,})',
            re.IGNORECASE,
        ),
        description="Stripe API 密钥",
        risk_level="critical",
        examples=["sk_live_<32_OR_MORE_ALPHANUMERIC_CHARS>"],
    ),

    # Telegram Bot Token
    SecretPattern(
        name="Telegram Bot Token",
        type=SecretType.TELEGRAM_BOT_TOKEN,
        pattern=re.compile(
            r'(\d{6,10}:[A-Za-z0-9_-]{35})',
        ),
        description="Telegram 机器人令牌",
        risk_level="high",
        examples=["123456789:ABCdefGHIjklMNOpqrsTUVwxyz-1234567890"],
    ),

    # Google API Key
    SecretPattern(
        name="Google Cloud API Key",
        type=SecretType.GCP_API_KEY,
        pattern=re.compile(
            r'(["\'])(AIza[A-Za-z0-9_-]{35})\1',
        ),
        description="Google Cloud API 密钥",
        risk_level="critical",
        examples=["AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"],
    ),

    # Google OAuth Access Token
    SecretPattern(
        name="Google OAuth Token",
        type=SecretType.GOOGLE_OAUTH,
        pattern=re.compile(
            r'(ya29\.[a-zA-Z0-9_-]{100,})',
        ),
        description="Google OAuth 访问令牌",
        risk_level="high",
        examples=["ya29.a0AfH6SMBx..."],
    ),

    # JWT Token
    SecretPattern(
        name="JWT Token",
        type=SecretType.JWT_TOKEN,
        pattern=re.compile(
            r'(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)',
        ),
        description="JSON Web Token",
        risk_level="high",
        examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"],
    ),

    # Database URL (PostgreSQL, MySQL, etc.)
    SecretPattern(
        name="Database URL",
        type=SecretType.DATABASE_URL,
        pattern=re.compile(
            r'(?i)(?:postgresql?|mysql|mariadb|sqlite|mongodb)://[^\s\'"<>]+(?:password[=][^\s\'"<>]+)?',
        ),
        description="数据库连接字符串",
        risk_level="critical",
        examples=["postgresql://user:password@localhost:5432/dbname"],
    ),

    # MongoDB URI
    SecretPattern(
        name="MongoDB URI",
        type=SecretType.MONGODB_URI,
        pattern=re.compile(
            r'mongodb(?:\+srv)://[^\s\'"<>]+',
        ),
        description="MongoDB 连接字符串",
        risk_level="critical",
        examples=["mongodb+srv://user:password@cluster.mongodb.net/dbname"],
    ),

    # Redis URL
    SecretPattern(
        name="Redis URL",
        type=SecretType.REDIS_URL,
        pattern=re.compile(
            r'redis://[^\s\'"<>]+',
        ),
        description="Redis 连接字符串",
        risk_level="high",
        examples=["redis://:password@localhost:6379/0"],
    ),

    # Private Key (RSA/EC)
    SecretPattern(
        name="Private Key",
        type=SecretType.PRIVATE_KEY,
        pattern=re.compile(
            r'-----BEGIN ([A-Z]+ )?PRIVATE KEY-----',
            re.IGNORECASE,
        ),
        description="私钥文件头",
        risk_level="critical",
        examples=["-----BEGIN RSA PRIVATE KEY-----"],
    ),

    # SSH Private Key
    SecretPattern(
        name="SSH Private Key",
        type=SecretType.SSH_PRIVATE_KEY,
        pattern=re.compile(
            r'-----BEGIN OPENSSH PRIVATE KEY-----',
        ),
        description="SSH 私钥文件头",
        risk_level="critical",
        examples=["-----BEGIN OPENSSH PRIVATE KEY-----"],
    ),

    # PGP Private Key
    SecretPattern(
        name="PGP Private Key",
        type=SecretType.PGP_PRIVATE_KEY,
        pattern=re.compile(
            r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        ),
        description="PGP 私钥文件头",
        risk_level="critical",
        examples=["-----BEGIN PGP PRIVATE KEY BLOCK-----"],
    ),

    # OAuth Client Secret
    SecretPattern(
        name="OAuth Client Secret",
        type=SecretType.OAUTH_CLIENT_SECRET,
        pattern=re.compile(
            r'client_secret\s*[:=]\s*["\']?([a-zA-Z0-9_-]{32,})["\']?\s*$',
            re.IGNORECASE | re.MULTILINE,
        ),
        description="OAuth 客户端密钥",
        risk_level="high",
        examples=["abcdefghijklmnopqrstuvwxyz123456"],
    ),

    # Generic API Key pattern
    SecretPattern(
        name="Generic API Key",
        type=SecretType.GENERIC_API_KEY,
        pattern=re.compile(
            r'(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
            re.IGNORECASE,
        ),
        description="通用 API 密钥模式",
        risk_level="medium",
        examples=["api_key=abc123def456ghi789jkl012mno345pqr6"],
    ),

    # Password in connection string
    SecretPattern(
        name="Password in Connection String",
        type=SecretType.PASSWORD,
        pattern=re.compile(
            r'(?i)password\s*=\s*[^\s\'"<>]+',
        ),
        description="连接字符串中的密码",
        risk_level="high",
        examples=["password=SecretPassword123"],
    ),

    # Twilio Account SID
    SecretPattern(
        name="Twilio Account SID",
        type=SecretType.TWILIO_ACCOUNT_SID,
        pattern=re.compile(
            r'(AC[a-zA-Z0-9]{32})',
        ),
        description="Twilio 账户 SID",
        risk_level="high",
        examples=["AC<32_ALPHANUMERIC_CHARACTERS_HERE>"],
    ),

    # SendGrid API Key
    SecretPattern(
        name="SendGrid API Key",
        type=SecretType.SENDGRID_API_KEY,
        pattern=re.compile(
            r'(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})',
        ),
        description="SendGrid API 密钥",
        risk_level="high",
        examples=["SG.xyz123abc456def789ghi012jkl345mno6789pq0rst1uv2wx3yz4"],
    ),

    # Mailgun API Key
    SecretPattern(
        name="Mailgun API Key",
        type=SecretType.MAILGUN_API_KEY,
        pattern=re.compile(
            r'(?<=key-)[a-zA-Z0-9]{32}',
        ),
        description="Mailgun API 密钥",
        risk_level="high",
        examples=["key-1234567890abcdefghijklmnopqrstuv"],
    ),
]


def get_predefined_patterns(
    types: list[SecretType] | None = None,
    min_risk_level: str | None = None,
) -> list[SecretPattern]:
    """获取预定义的秘密模式

    Args:
        types: 过滤指定的秘密类型，None 表示获取所有
        min_risk_level: 最低风险级别 (critical > high > medium > low)

    Returns:
        符合条件的秘密模式列表
    """
    patterns = PREDEFINED_PATTERNS

    # 按类型过滤
    if types:
        patterns = [p for p in patterns if p.type in types]

    # 按风险级别过滤
    if min_risk_level:
        risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        min_level = risk_order.get(min_risk_level, 0)
        patterns = [p for p in patterns if risk_order.get(p.risk_level, 0) >= min_level]

    return patterns


def get_pattern_by_type(secret_type: SecretType) -> SecretPattern | None:
    """根据类型获取秘密模式"""
    for pattern in PREDEFINED_PATTERNS:
        if pattern.type == secret_type:
            return pattern
    return None
