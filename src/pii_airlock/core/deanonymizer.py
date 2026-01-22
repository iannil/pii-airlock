"""
PII Deanonymization (Re-hydration) Engine

This module provides functionality to restore original PII values
from anonymized text using stored mappings.

Example:
    >>> from pii_airlock.core.deanonymizer import Deanonymizer
    >>> from pii_airlock.core.mapping import PIIMapping
    >>> mapping = PIIMapping()
    >>> mapping.add("PERSON", "张三", "<PERSON_1>")
    >>> deanonymizer = Deanonymizer()
    >>> result = deanonymizer.deanonymize("<PERSON_1>您好", mapping)
    >>> print(result.text)
    张三您好
"""

import re
from dataclasses import dataclass, field
from typing import Optional

from pii_airlock.core.mapping import PIIMapping

# 导入模糊匹配模块（可选，如果可用）
try:
    from pii_airlock.core.fuzzy import SmartRehydrator, FuzzyMatcher
    FUZZY_AVAILABLE = True
except ImportError:
    FUZZY_AVAILABLE = False


@dataclass
class DeanonymizationResult:
    """Result of deanonymization operation.

    Attributes:
        text: The restored text with original PII values.
        replaced_count: Number of placeholders that were replaced.
        unresolved: List of placeholders that couldn't be resolved.
    """

    text: str
    replaced_count: int = 0
    unresolved: list[str] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """Check if all placeholders were resolved."""
        return len(self.unresolved) == 0


class Deanonymizer:
    """Deanonymization engine for restoring PII values.

    This class handles the reverse operation of anonymization,
    replacing placeholders with their original values.

    It supports:
    - Exact placeholder matching
    - Fuzzy matching for LLM-modified placeholders (using enhanced fuzzy matcher)

    Example:
        >>> deanonymizer = Deanonymizer()
        >>> mapping = PIIMapping()
        >>> mapping.add("PERSON", "张三", "<PERSON_1>")
        >>> result = deanonymizer.deanonymize("致<PERSON_1>：您好", mapping)
        >>> print(result.text)
        致张三：您好
    """

    # Standard placeholder pattern: <TYPE_N>
    PLACEHOLDER_PATTERN = re.compile(r"<([A-Z_]+)_(\d+)>")

    # Fuzzy patterns for LLM hallucinations (legacy, for backward compatibility)
    FUZZY_PATTERNS = [
        # <Person 1>, <PERSON 1> (space instead of underscore)
        re.compile(r"<([A-Za-z_]+)\s+(\d+)>", re.IGNORECASE),
        # [PERSON_1], [Person_1] (square brackets)
        re.compile(r"\[([A-Za-z_]+)[_\s](\d+)\]", re.IGNORECASE),
        # {{PERSON_1}} (double curly braces)
        re.compile(r"\{\{([A-Za-z_]+)[_\s](\d+)\}\}", re.IGNORECASE),
        # (PERSON_1) (parentheses)
        re.compile(r"\(([A-Z_]+)[_\s](\d+)\)", re.IGNORECASE),
        # <PERSON-1> (hyphen instead of underscore)
        re.compile(r"<([A-Za-z_]+)-(\d+)>", re.IGNORECASE),
    ]

    def __init__(
        self,
        enable_fuzzy_matching: bool = True,
        use_enhanced_fuzzy: bool = False,
        confidence_threshold: float = 0.75,
    ) -> None:
        """Initialize the deanonymizer.

        Args:
            enable_fuzzy_matching: Whether to attempt fuzzy matching
                for LLM-modified placeholders.
            use_enhanced_fuzzy: Whether to use the enhanced fuzzy matcher
                (with confidence scoring). Recommended for production.
            confidence_threshold: Minimum confidence threshold for enhanced
                fuzzy matching (0.0 - 1.0).
        """
        self.enable_fuzzy_matching = enable_fuzzy_matching
        self.use_enhanced_fuzzy = use_enhanced_fuzzy

        # 初始化增强模糊匹配器
        self._smart_rehydrator: Optional[SmartRehydrator] = None
        if FUZZY_AVAILABLE and use_enhanced_fuzzy:
            self._smart_rehydrator = SmartRehydrator(
                enable_fuzzy=True,
                confidence_threshold=confidence_threshold,
            )

    def deanonymize(
        self,
        text: str,
        mapping: PIIMapping,
    ) -> DeanonymizationResult:
        """Restore original PII values in anonymized text.

        Args:
            text: Anonymized text containing placeholders or synthetic values.
            mapping: The PIIMapping used during anonymization.

        Returns:
            DeanonymizationResult with restored text and statistics.

        Example:
            >>> mapping = PIIMapping()
            >>> mapping.add("PERSON", "张三", "<PERSON_1>")
            >>> result = deanonymizer.deanonymize("致<PERSON_1>：您好", mapping)
            >>> print(result.text)
            致张三：您好

            >>> # Synthetic data example
            >>> mapping.add_synthetic("PERSON", "张三", "李四")
            >>> result = deanonymizer.deanonymize("致李四：您好", mapping)
            >>> print(result.text)
            致张三：您好
        """
        if not text:
            return DeanonymizationResult(text=text)

        # 使用增强模糊匹配器（如果启用且可用）
        if self.use_enhanced_fuzzy and self._smart_rehydrator:
            result_text, exact_count, fuzzy_count = self._smart_rehydrator.rehydrate(text, mapping)

            return DeanonymizationResult(
                text=result_text,
                replaced_count=exact_count + fuzzy_count,
                unresolved=[],
            )

        # 使用传统方法（向后兼容）
        result_text = text
        replaced_count = 0
        unresolved: list[str] = []

        # First pass: synthetic value replacement (before placeholder replacement)
        # Synthetic values are longer strings that could contain placeholder-like patterns
        if mapping.has_synthetic_mappings():
            result_text = self._replace_synthetic(result_text, mapping)
            replaced_count += self._count_synthetic_replacements(text, result_text, mapping)

        # Second pass: exact placeholder matching
        def replace_exact(match: re.Match) -> str:
            nonlocal replaced_count
            entity_type = match.group(1)
            index = match.group(2)
            placeholder = f"<{entity_type}_{index}>"

            original = mapping.get_original(placeholder)
            if original:
                replaced_count += 1
                return original
            else:
                unresolved.append(placeholder)
                return placeholder

        result_text = self.PLACEHOLDER_PATTERN.sub(replace_exact, result_text)

        # Third pass: fuzzy matching (if enabled)
        if self.enable_fuzzy_matching:
            result_text, fuzzy_count = self._fuzzy_replace(result_text, mapping)
            replaced_count += fuzzy_count

        return DeanonymizationResult(
            text=result_text,
            replaced_count=replaced_count,
            unresolved=unresolved,
        )

    def _replace_synthetic(self, text: str, mapping: PIIMapping) -> str:
        """Replace synthetic values with original values.

        Args:
            text: Text potentially containing synthetic values.
            mapping: The PIIMapping with synthetic mappings.

        Returns:
            Text with synthetic values replaced by originals.
        """
        result = text
        # Sort by length descending to avoid partial replacements
        # (e.g., replace "李四" before "李")
        synthetic_values = sorted(
            mapping._synthetic_mappings.keys(),
            key=len,
            reverse=True,
        )

        for synthetic in synthetic_values:
            original = mapping.get_original_from_synthetic(synthetic)
            if original:
                result = result.replace(synthetic, original)

        return result

    def _count_synthetic_replacements(
        self,
        original_text: str,
        result_text: str,
        mapping: PIIMapping,
    ) -> int:
        """Count how many synthetic replacements were made.

        Args:
            original_text: Text before replacement.
            result_text: Text after replacement.
            mapping: The PIIMapping with synthetic mappings.

        Returns:
            Count of synthetic replacements made.
        """
        count = 0
        for synthetic in mapping._synthetic_mappings.keys():
            count += original_text.count(synthetic)
        return count

    def _fuzzy_replace(
        self,
        text: str,
        mapping: PIIMapping,
    ) -> tuple[str, int]:
        """Attempt fuzzy matching for LLM-modified placeholders.

        Args:
            text: Text with potential fuzzy placeholders.
            mapping: The PIIMapping to consult.

        Returns:
            Tuple of (modified text, count of fuzzy replacements).
        """
        resolved_count = 0

        for pattern in self.FUZZY_PATTERNS:

            def make_replacer(p: re.Pattern) -> callable:
                def replace_fuzzy(match: re.Match) -> str:
                    nonlocal resolved_count
                    entity_type = match.group(1).upper().replace("-", "_")
                    index = match.group(2)

                    # Normalize to standard format
                    normalized = f"<{entity_type}_{index}>"
                    original = mapping.get_original(normalized)

                    if original:
                        resolved_count += 1
                        return original
                    return match.group(0)

                return replace_fuzzy

            text = pattern.sub(make_replacer(pattern), text)

        return text, resolved_count

    def extract_placeholders(self, text: str) -> list[tuple[str, str]]:
        """Extract all placeholders from text.

        Args:
            text: Text to scan for placeholders.

        Returns:
            List of (entity_type, index) tuples for each placeholder found.
        """
        return self.PLACEHOLDER_PATTERN.findall(text)

    def has_placeholders(self, text: str) -> bool:
        """Check if text contains any placeholders.

        Args:
            text: Text to check.

        Returns:
            True if placeholders are found, False otherwise.
        """
        return bool(self.PLACEHOLDER_PATTERN.search(text))
