"""
模糊匹配器

处理 LLM 产生的占位符格式变化，提供智能容错还原功能。

支持的占位符变体：
- 大小写变化: <Person_1>, <person_1>
- 空格变化: < PERSON_1 >, <PERSON_ 1>
- 括号类型: [PERSON_1], {PERSON_1}, (PERSON_1)
- 分隔符: <PERSON-1>, <PERSON:1>
- 标点符号: <PERSON_1>., <PERSON_1>,
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Pattern

from pii_airlock.core.mapping import PIIMapping


class FuzzyMatchType(str, Enum):
    """模糊匹配类型"""
    EXACT = "exact"           # 精确匹配
    CASE_VARIANT = "case"     # 大小写变体
    WHITESPACE = "whitespace" # 空格变体
    BRACKET_VARIANT = "bracket" # 括号变体
    SEPARATOR_VARIANT = "separator" # 分隔符变体
    PUNCTUATION = "punctuation"   # 标点符号
    COMBINED = "combined"     # 组合变体
    NONE = "none"            # 无匹配


@dataclass
class FuzzyMatch:
    """模糊匹配结果"""
    original: str           # 原始文本中的占位符
    normalized: str         # 标准化后的占位符
    match_type: FuzzyMatchType
    confidence: float        # 匹配置信度 (0.0 - 1.0)
    entity_type: str
    index: int


class FuzzyMatcher:
    """智能模糊匹配器

    识别和标准化各种格式的占位符变体。
    """

    # 标准占位符格式
    STANDARD_PATTERN = re.compile(r"<([A-Z_]+)_(\d+)>")

    # 扩展的模糊模式（按优先级排序）
    FUZZY_PATTERNS = [
        # 1. 混合大小写变体 (如 <Person_1>) - 最高优先级
        # 不匹配标准格式 <PERSON_1> 因为它会被 STANDARD_PATTERN 先匹配
        (re.compile(r"<([a-z][a-z_]+)_(\d+)>", re.IGNORECASE),
         FuzzyMatchType.CASE_VARIANT, 0.95),

        # 2. 全小写变体 (如 <person_1>)
        (re.compile(r"<([a-z_]+)_(\d+)>"),
         FuzzyMatchType.CASE_VARIANT, 0.95),

        # 3. 空格变体 - 高优先级 (underscore with optional spaces)
        (re.compile(r"<\s*([A-Za-z_]+)\s*_\s*(\d+)\s*>", re.IGNORECASE),
         FuzzyMatchType.WHITESPACE, 0.90),

        # CORE-001 FIX: 4. 空格替代下划线变体 (如 <PERSON 1>, <person 1>)
        (re.compile(r"<([A-Za-z_]+)\s+(\d+)>", re.IGNORECASE),
         FuzzyMatchType.WHITESPACE, 0.90),

        # 5. 方括号变体
        (re.compile(r"\[\s*([A-Za-z_]+)\s*[_\s]\s*(\d+)\s*\]", re.IGNORECASE),
         FuzzyMatchType.BRACKET_VARIANT, 0.85),

        # 6. 大括号变体
        (re.compile(r"\{\s*([A-Za-z_]+)\s*[_\s]\s*(\d+)\s*\}", re.IGNORECASE),
         FuzzyMatchType.BRACKET_VARIANT, 0.85),

        # 7. 圆括号变体
        (re.compile(r"\(\s*([A-Za-z_]+)\s*[_\s]\s*(\d+)\s*\)", re.IGNORECASE),
         FuzzyMatchType.BRACKET_VARIANT, 0.85),

        # 8. 连字符分隔符
        (re.compile(r"<([A-Za-z_]+)-(\d+)>", re.IGNORECASE),
         FuzzyMatchType.SEPARATOR_VARIANT, 0.90),

        # 9. 冒号分隔符
        (re.compile(r"<([A-Za-z_]+):(\d+)>", re.IGNORECASE),
         FuzzyMatchType.SEPARATOR_VARIANT, 0.90),
    ]

    # 标点符号模式（在占位符之后）
    TRAILING_PUNCTUATION = r"[.,;:!?,。，、；]"

    def __init__(self, confidence_threshold: float = 0.75):
        """初始化模糊匹配器

        Args:
            confidence_threshold: 最低置信度阈值，低于此值的匹配将被忽略
        """
        self.confidence_threshold = confidence_threshold

    def normalize_placeholder(self, placeholder: str) -> Optional[str]:
        """将占位符标准化为 <TYPE_N> 格式

        Args:
            placeholder: 原始占位符字符串

        Returns:
            标准化的占位符，或 None 如果无法解析
        """
        # 尝试标准格式
        match = self.STANDARD_PATTERN.match(placeholder)
        if match:
            return f"<{match.group(1)}_{match.group(2)}>"

        # 尝试模糊匹配
        for pattern, match_type, _ in self.FUZZY_PATTERNS:
            match = pattern.match(placeholder)
            if match:
                entity_type = match.group(1).upper().replace("-", "_")
                index = match.group(2)

                # 验证格式
                if self._is_valid_entity_type(entity_type):
                    return f"<{entity_type}_{index}>"

        return None

    def _is_valid_entity_type(self, entity_type: str) -> bool:
        """验证实体类型是否有效"""
        # 检查是否只包含大写字母和下划线
        return bool(re.match(r"^[A-Z_]+$", entity_type))

    def match(self, text: str, mapping: PIIMapping) -> list[FuzzyMatch]:
        """在文本中查找所有模糊占位符

        Args:
            text: 要扫描的文本
            mapping: PII 映射，用于验证匹配是否有效

        Returns:
            查找到的模糊匹配列表（按位置排序）
        """
        matches = []
        seen_offsets = set()

        # 1. 首先进行标准匹配
        for match in self.STANDARD_PATTERN.finditer(text):
            entity_type = match.group(1)
            index = match.group(2)
            placeholder = f"<{entity_type}_{index}>"

            if mapping.get_original(placeholder):
                matches.append(FuzzyMatch(
                    original=match.group(0),
                    normalized=placeholder,
                    match_type=FuzzyMatchType.EXACT,
                    confidence=1.0,
                    entity_type=entity_type,
                    index=int(index),
                ))
                seen_offsets.add(match.start())

        # 2. 然后进行模糊匹配（排除已匹配的位置）
        for pattern, match_type, base_confidence in self.FUZZY_PATTERNS:
            for match in pattern.finditer(text):
                # 跳过已匹配的位置
                if any(start <= match.start() < end
                       for start, end in seen_offsets):
                    continue

                entity_type = match.group(1).upper().replace("-", "_")
                index = match.group(2)
                normalized = f"<{entity_type}_{index}>"

                # 验证映射中是否存在
                if mapping.get_original(normalized):
                    # 计算置信度
                    confidence = self._calculate_confidence(
                        match.group(0), normalized, base_confidence, match_type
                    )

                    if confidence >= self.confidence_threshold:
                        matches.append(FuzzyMatch(
                            original=match.group(0),
                            normalized=normalized,
                            match_type=match_type,
                            confidence=confidence,
                            entity_type=entity_type,
                            index=int(index),
                        ))
                        seen_offsets.add((match.start(), match.end()))

        return matches

    def _calculate_confidence(
        self,
        original: str,
        normalized: str,
        base_confidence: float,
        match_type: FuzzyMatchType = None,
    ) -> float:
        """计算匹配置信度

        基于以下因素降低置信度：
        - 偏离标准格式的程度
        - 大小写混合（对于 CASE_VARIANT 类型不惩罚）
        - 额外的空格或标点

        Args:
            original: 原始匹配的字符串
            normalized: 标准化的占位符
            base_confidence: 该模式的基础置信度
            match_type: 匹配类型，用于判断是否应用特定惩罚

        Returns:
            最终置信度 (0.0 - 1.0)
        """
        confidence = base_confidence

        # 大小写混合惩罚 - 不适用于 CASE_VARIANT 类型
        if match_type != FuzzyMatchType.CASE_VARIANT:
            if original != original.upper() and original != original.lower():
                confidence -= 0.05

        # 空格惩罚
        if " " in original and "< " not in original:
            confidence -= 0.05

        # 额外字符惩罚
        extra_chars = len(original) - len(normalized)
        if extra_chars > 0:
            confidence -= min(0.1, extra_chars * 0.02)

        # 非标准括号惩罚
        if original.startswith("[") or original.startswith("{"):
            confidence -= 0.05

        return max(0.0, min(1.0, confidence))

    def find_and_replace(
        self,
        text: str,
        mapping: PIIMapping
    ) -> tuple[str, int, list[FuzzyMatch]]:
        """查找并替换所有占位符

        Args:
            text: 要处理的文本
            mapping: PII 映射

        Returns:
            (替换后的文本, 替换数量, 匹配列表)
        """
        matches = self.match(text, mapping)
        result_text = text

        # 按位置从后向前替换，避免位置偏移
        for match in sorted(matches, key=lambda m: m.original, reverse=True):
            original = mapping.get_original(match.normalized)
            if original:
                result_text = result_text.replace(match.original, original, 1)

        return result_text, len(matches), matches


class SmartRehydrator:
    """智能还原器

    结合精确匹配和模糊匹配的还原引擎。
    """

    def __init__(
        self,
        enable_fuzzy: bool = True,
        confidence_threshold: float = 0.75,
        log_mismatches: bool = False,
    ):
        """初始化智能还原器

        Args:
            enable_fuzzy: 是否启用模糊匹配
            confidence_threshold: 模糊匹配的最低置信度阈值
            log_mismatches: 是否记录不匹配的占位符
        """
        self.enable_fuzzy = enable_fuzzy
        self.matcher = FuzzyMatcher(confidence_threshold=confidence_threshold)
        self.log_mismatches = log_mismatches

        # 用于记录不匹配的占位符
        self.unmatched_placeholders: list[str] = []

    def rehydrate(
        self,
        text: str,
        mapping: PIIMapping
    ) -> tuple[str, int, int]:
        """还原文本中的所有占位符

        Args:
            text: 包含占位符的文本
            mapping: PII 映射

        Returns:
            (还原后的文本, 精确匹配数, 模糊匹配数)
        """
        self.unmatched_placeholders.clear()

        # 精确匹配
        exact_count = 0
        result_text = text

        def replace_exact(match: re.Match) -> str:
            nonlocal exact_count
            placeholder = f"<{match.group(1)}_{match.group(2)}>"
            original = mapping.get_original(placeholder)

            if original:
                exact_count += 1
                return original
            else:
                self.unmatched_placeholders.append(placeholder)
                return match.group(0)

        result_text = self.matcher.STANDARD_PATTERN.sub(replace_exact, result_text)

        # 模糊匹配
        fuzzy_count = 0
        if self.enable_fuzzy:
            result_text, fuzzy_count, _ = self.matcher.find_and_replace(result_text, mapping)

        return result_text, exact_count, fuzzy_count


def get_fuzzy_matcher(confidence_threshold: float = 0.75) -> FuzzyMatcher:
    """获取全局模糊匹配器实例"""
    return FuzzyMatcher(confidence_threshold=confidence_threshold)
