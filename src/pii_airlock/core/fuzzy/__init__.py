"""
模糊匹配模块

提供智能的占位符模糊匹配功能，用于处理 LLM 产生的占位符格式变化。
"""

from pii_airlock.core.fuzzy.matcher import (
    FuzzyMatcher,
    FuzzyMatch,
    FuzzyMatchType,
    SmartRehydrator,
    get_fuzzy_matcher,
)

__all__ = [
    "FuzzyMatcher",
    "FuzzyMatch",
    "FuzzyMatchType",
    "SmartRehydrator",
    "get_fuzzy_matcher",
]
