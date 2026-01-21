"""
Chinese Mobile Phone Number Recognizer

Recognizes Chinese mainland mobile phone numbers with carrier-aware patterns.
"""

from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer


class ChinesePhoneRecognizer(PatternRecognizer):
    """Recognizer for Chinese mobile phone numbers.

    Supports:
    - 11-digit mobile numbers (13x, 14x, 15x, 16x, 17x, 18x, 19x)
    - Optional +86 or 86 prefix
    - Common formatting with spaces/dashes

    Example:
        >>> recognizer = ChinesePhoneRecognizer()
        >>> # Used through Presidio AnalyzerEngine
    """

    PATTERNS = [
        # Basic 11-digit mobile: 1[3-9]XXXXXXXXX
        # Note: Not using \b for word boundaries as they don't work well in Chinese
        Pattern(
            name="zh_mobile_basic",
            regex=r"(?<!\d)1[3-9]\d{9}(?!\d)",
            score=0.7,
        ),
        # With country code: +86 or 86
        Pattern(
            name="zh_mobile_with_country_code",
            regex=r"(?:\+?86[-\s]?)1[3-9]\d{9}(?!\d)",
            score=0.85,
        ),
        # Formatted with spaces/dashes: 138-0000-0000 or 138 0000 0000
        Pattern(
            name="zh_mobile_formatted",
            regex=r"(?<!\d)1[3-9]\d[-\s]?\d{4}[-\s]?\d{4}(?!\d)",
            score=0.65,
        ),
    ]

    CONTEXT = [
        "电话",
        "手机",
        "手机号",
        "手机号码",
        "电话号码",
        "联系电话",
        "联系方式",
        "phone",
        "mobile",
        "tel",
        "telephone",
        "号码",
        "打电话",
        "call",
        "拨打",
    ]

    def __init__(
        self,
        supported_language: str = "zh",
        context: Optional[list[str]] = None,
    ) -> None:
        """Initialize the recognizer.

        Args:
            supported_language: Language code (default: zh).
            context: Additional context words.
        """
        context_words = list(self.CONTEXT) + (context or [])

        super().__init__(
            supported_entity="PHONE_NUMBER",
            patterns=self.PATTERNS,
            context=context_words,
            supported_language=supported_language,
        )
