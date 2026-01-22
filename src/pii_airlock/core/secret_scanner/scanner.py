"""
秘密扫描器

扫描文本中的敏感秘密信息。
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pii_airlock.core.secret_scanner.patterns import (
    SecretPattern,
    SecretType,
    get_predefined_patterns,
)


class RiskLevel(str, Enum):
    """风险级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SecretMatch:
    """秘密匹配结果"""
    secret_type: SecretType
    pattern_name: str
    matched_text: str
    start: int
    end: int
    risk_level: str
    line_number: int | None = None
    line_content: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        preview = self.matched_text[:20] + "..." if len(self.matched_text) > 20 else self.matched_text
        return f"SecretMatch({self.pattern_name}: {preview})"

    def redacted(self) -> str:
        """返回脱敏显示的匹配文本"""
        if len(self.matched_text) <= 8:
            return "*" * len(self.matched_text)
        return self.matched_text[:4] + "****" + self.matched_text[-4:]


@dataclass
class SecretScanResult:
    """秘密扫描结果"""
    matches: list[SecretMatch]
    text_length: int
    scan_time_ms: float
    has_critical: bool = False
    has_high: bool = False

    @property
    def total_count(self) -> int:
        """匹配总数"""
        return len(self.matches)

    @property
    def critical_count(self) -> int:
        """严重级别匹配数"""
        return sum(1 for m in self.matches if m.risk_level == "critical")

    @property
    def high_count(self) -> int:
        """高风险匹配数"""
        return sum(1 for m in self.matches if m.risk_level == "high")

    @property
    def should_block(self) -> bool:
        """是否应该阻止此请求"""
        # 有严重或高风险秘密时阻止
        return self.has_critical or self.has_high

    def get_by_type(self, secret_type: SecretType) -> list[SecretMatch]:
        """获取指定类型的所有匹配"""
        return [m for m in self.matches if m.secret_type == secret_type]

    def get_by_risk_level(self, risk_level: str) -> list[SecretMatch]:
        """获取指定风险级别的所有匹配"""
        return [m for m in self.matches if m.risk_level == risk_level]

    def summary(self) -> str:
        """获取扫描摘要"""
        parts = []
        parts.append(f"发现 {self.total_count} 个潜在秘密")

        if self.critical_count > 0:
            parts.append(f"({self.critical_count} 个严重)")
        if self.high_count > 0:
            parts.append(f"({self.high_count} 个高风险)")

        return " ".join(parts)


class SecretScanner:
    """秘密扫描器

    扫描文本中的敏感秘密信息，如 API Keys、Tokens 等。

    Example:
        >>> scanner = SecretScanner()
        >>> result = scanner.scan("我的 API key 是 sk-abc123...")
        >>> if result.should_block:
        ...     print("发现敏感信息！")
    """

    def __init__(
        self,
        *,
        patterns: list[SecretPattern] | None = None,
        enable_predefined: bool = True,
        block_on_risk: list[str] | None = None,
        max_match_length: int = 1000,
    ):
        """初始化秘密扫描器

        Args:
            patterns: 自定义秘密模式列表
            enable_predefined: 是否启用预定义模式
            block_on_risk: 触发阻止的风险级别列表
            max_match_length: 单个匹配的最大长度
        """
        self._patterns: list[SecretPattern] = []

        # 添加预定义模式
        if enable_predefined:
            self._patterns.extend(get_predefined_patterns())

        # 添加自定义模式
        if patterns:
            self._patterns.extend(patterns)

        # 阻止风险级别
        self._block_on_risk = set(block_on_risk or ["critical", "high"])
        self._max_match_length = max_match_length

    def scan(self, text: str, **metadata) -> SecretScanResult:
        """扫描文本中的秘密

        Args:
            text: 要扫描的文本
            **metadata: 额外的元数据（如来源文件、行号等）

        Returns:
            SecretScanResult 扫描结果
        """
        import time
        start_time = time.time()

        matches = []
        lines = text.split('\n')

        for pattern in self._patterns:
            for match in pattern.pattern.finditer(text):
                # 限制匹配长度
                matched_text = match.group(0)
                if len(matched_text) > self._max_match_length:
                    continue

                # 计算行号
                line_number = None
                line_content = None
                if "line_number" not in metadata:
                    pos = 0
                    for i, line in enumerate(lines):
                        pos += len(line) + 1  # +1 for newline
                        if pos > match.start():
                            line_number = i + 1
                            line_content = line.strip()
                            break

                secret_match = SecretMatch(
                    secret_type=pattern.type,
                    pattern_name=pattern.name,
                    matched_text=matched_text,
                    start=match.start(),
                    end=match.end(),
                    risk_level=pattern.risk_level,
                    line_number=line_number,
                    line_content=line_content,
                    metadata={
                        "description": pattern.description,
                        **metadata,
                    },
                )

                matches.append(secret_match)

        # 去重（相同位置和类型的只保留一个）
        seen = set()
        unique_matches = []
        for m in matches:
            key = (m.start, m.end, m.secret_type)
            if key not in seen:
                seen.add(key)
                unique_matches.append(m)

        # 按位置排序
        unique_matches.sort(key=lambda m: m.start)

        scan_time = (time.time() - start_time) * 1000

        return SecretScanResult(
            matches=unique_matches,
            text_length=len(text),
            scan_time_ms=scan_time,
            has_critical=any(m.risk_level == "critical" for m in unique_matches),
            has_high=any(m.risk_level == "high" for m in unique_matches),
        )

    def scan_json(self, json_data: dict | list, **metadata) -> SecretScanResult:
        """扫描 JSON 数据中的秘密

        Args:
            json_data: JSON 数据
            **metadata: 额外的元数据

        Returns:
            SecretScanResult 扫描结果
        """
        import json

        text = json.dumps(json_data, separators=(',', ':'))
        metadata["source_type"] = "json"
        return self.scan(text, **metadata)

    def add_pattern(self, pattern: SecretPattern) -> None:
        """添加自定义模式

        Args:
            pattern: 要添加的秘密模式
        """
        self._patterns.append(pattern)

    def remove_pattern_by_type(self, secret_type: SecretType) -> int:
        """移除指定类型的模式

        Args:
            secret_type: 要移除的秘密类型

        Returns:
            移除的模式数量
        """
        original_count = len(self._patterns)
        self._patterns = [p for p in self._patterns if p.type != secret_type]
        return original_count - len(self._patterns)

    def get_patterns(self) -> list[SecretPattern]:
        """获取所有模式"""
        return self._patterns.copy()

    def get_pattern_count(self) -> int:
        """获取模式数量"""
        return len(self._patterns)


# 全局单例
_secret_scanner: SecretScanner | None = None


def get_secret_scanner(**kwargs) -> SecretScanner:
    """获取全局秘密扫描器实例

    Args:
        **kwargs: 传递给 SecretScanner 的参数

    Returns:
        SecretScanner 实例
    """
    global _secret_scanner

    if _secret_scanner is None:
        _secret_scanner = SecretScanner(**kwargs)

    return _secret_scanner


def quick_scan(text: str) -> list[SecretMatch]:
    """快速扫描，返回匹配列表

    Args:
        text: 要扫描的文本

    Returns:
        匹配的秘密列表
    """
    scanner = get_secret_scanner()
    result = scanner.scan(text)
    return result.matches
