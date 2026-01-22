"""
秘密拦截中间件

在 API 请求中检测并阻止包含敏感秘密的请求。
"""

import time
from dataclasses import dataclass
from typing import Any

from pii_airlock.core.secret_scanner.scanner import (
    SecretMatch,
    SecretScanResult,
    SecretScanner,
)


@dataclass
class InterceptResult:
    """拦截结果"""
    should_block: bool
    scan_result: SecretScanResult
    reason: str | None = None
    blocked_matches: list[SecretMatch] | None = None

    @property
    def safe_to_proceed(self) -> bool:
        """是否安全继续"""
        return not self.should_block


class SecretInterceptor:
    """秘密拦截器

    在请求发送给 LLM 之前扫描并拦截包含敏感秘密的内容。

    Example:
        >>> interceptor = SecretInterceptor()
        >>> result = interceptor.check("请帮我分析 sk-abc123...")
        >>> if result.should_block:
        ...     print("请求被阻止：检测到敏感信息")
    """

    def __init__(
        self,
        scanner: SecretScanner | None = None,
        block_on_risk: list[str] | None = None,
        enable_logging: bool = True,
    ):
        """初始化秘密拦截器

        Args:
            scanner: 秘密扫描器实例
            block_on_risk: 触发阻止的风险级别
            enable_logging: 是否记录拦截日志
        """
        self._scanner = scanner or SecretScanner()
        self._block_on_risk = set(block_on_risk or ["critical", "high"])
        self._enable_logging = enable_logging

        # 拦截统计
        self._stats = {
            "total_scans": 0,
            "total_blocks": 0,
            "total_matches": 0,
        }

    def check(
        self,
        content: str,
        context: dict[str, Any] | None = None,
    ) -> InterceptResult:
        """检查内容是否包含敏感秘密

        Args:
            content: 要检查的内容
            context: 上下文信息（如请求ID、用户ID等）

        Returns:
            InterceptResult 拦截结果
        """
        self._stats["total_scans"] += 1

        # 扫描内容
        scan_result = self._scanner.scan(
            content,
            **(context or {}),
        )

        self._stats["total_matches"] += scan_result.total_count

        # 判断是否需要阻止
        blocked_matches = []
        should_block = False
        reason = None

        for match in scan_result.matches:
            if match.risk_level in self._block_on_risk:
                should_block = True
                blocked_matches.append(match)

        if should_block:
            self._stats["total_blocks"] += 1
            reason = self._format_block_reason(blocked_matches)

            if self._enable_logging:
                self._log_block(blocked_matches, context)

        return InterceptResult(
            should_block=should_block,
            scan_result=scan_result,
            reason=reason,
            blocked_matches=blocked_matches if should_block else None,
        )

    def check_dict(
        self,
        data: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> InterceptResult:
        """检查字典数据中的秘密

        Args:
            data: 要检查的字典数据
            context: 上下文信息

        Returns:
            InterceptResult 拦截结果
        """
        import json
        content = json.dumps(data, separators=(',', ':'))
        return self.check(content, context)

    def check_messages(
        self,
        messages: list[dict[str, str]],
        context: dict[str, Any] | None = None,
    ) -> InterceptResult:
        """检查聊天消息列表中的秘密

        Args:
            messages: 聊天消息列表
            context: 上下文信息

        Returns:
            InterceptResult 拦截结果
        """
        import json
        content = json.dumps(messages, separators=(',', ':'))
        context = context or {}
        context["source_type"] = "chat_messages"
        return self.check(content, context)

    def sanitize(self, content: str, scan_result: SecretScanResult | None = None) -> str:
        """清理内容中的秘密（替换为脱敏文本）

        Args:
            content: 原始内容
            scan_result: 扫描结果（如果为 None 则重新扫描）

        Returns:
            清理后的内容
        """
        if scan_result is None:
            scan_result = self._scanner.scan(content)

        if not scan_result.matches:
            return content

        # 按位置倒序替换，避免位置偏移
        result = content
        for match in sorted(scan_result.matches, key=lambda m: -m.start):
            result = (
                result[:match.start] +
                f"[REDACTED:{match.pattern_name}]" +
                result[match.end:]
            )

        return result

    def _format_block_reason(self, matches: list[SecretMatch]) -> str:
        """格式化阻止原因"""
        type_counts = {}
        for match in matches:
            match_type = match.secret_type.value
            type_counts[match_type] = type_counts.get(match_type, 0) + 1

        parts = []
        for secret_type, count in type_counts.items():
            parts.append(f"{count} 个 {secret_type}")

        return "检测到敏感信息：" + "、".join(parts)

    def _log_block(
        self,
        matches: list[SecretMatch],
        context: dict[str, Any] | None,
    ) -> None:
        """记录拦截日志"""
        import logging
        logger = logging.getLogger(__name__)

        log_parts = [f"秘密拦截: 检测到 {len(matches)} 个敏感信息"]

        for match in matches:
            log_parts.append(
                f"  - {match.pattern_name} ({match.risk_level}) "
                f"在位置 {match.start}-{match.end}"
            )

        if context:
            log_parts.append(f"上下文: {context}")

        logger.warning("\n".join(log_parts))

    def get_stats(self) -> dict[str, int]:
        """获取拦截统计信息"""
        return self._stats.copy()

    def reset_stats(self) -> None:
        """重置统计信息"""
        self._stats = {
            "total_scans": 0,
            "total_blocks": 0,
            "total_matches": 0,
        }


# 全局单例
_secret_interceptor: SecretInterceptor | None = None


def get_secret_interceptor(**kwargs) -> SecretInterceptor:
    """获取全局秘密拦截器实例

    Args:
        **kwargs: 传递给 SecretInterceptor 的参数

    Returns:
        SecretInterceptor 实例
    """
    global _secret_interceptor

    if _secret_interceptor is None:
        _secret_interceptor = SecretInterceptor(**kwargs)

    return _secret_interceptor
