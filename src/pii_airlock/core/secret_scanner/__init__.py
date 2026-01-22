"""
秘密扫描模块

提供敏感秘密检测功能，防止 API Keys、Tokens 等敏感信息泄露给 LLM。

主要组件:
- SecretPattern: 秘密模式定义
- SecretScanner: 秘密扫描器
- SecretMatch: 秘密匹配结果
- SecretInterceptor: 秘密拦截器
"""

from pii_airlock.core.secret_scanner.patterns import (
    SecretPattern,
    SecretType,
    get_predefined_patterns,
    get_pattern_by_type,
)
from pii_airlock.core.secret_scanner.scanner import (
    SecretMatch,
    SecretScanResult,
    SecretScanner,
    get_secret_scanner,
    quick_scan,
)
from pii_airlock.core.secret_scanner.interceptor import (
    InterceptResult,
    SecretInterceptor,
    get_secret_interceptor,
)

__all__ = [
    "SecretPattern",
    "SecretType",
    "SecretMatch",
    "SecretScanResult",
    "SecretScanner",
    "InterceptResult",
    "SecretInterceptor",
    "get_predefined_patterns",
    "get_pattern_by_type",
    "get_secret_scanner",
    "get_secret_interceptor",
    "quick_scan",
]
