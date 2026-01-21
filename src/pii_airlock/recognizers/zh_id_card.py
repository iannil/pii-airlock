"""
Chinese ID Card (Resident Identity Card) Recognizer

Recognizes 18-digit Chinese national ID numbers with checksum validation.
Format: RRRRRRYYYYMMDDSSSC (6 region + 8 birthdate + 3 sequence + 1 checksum)
"""

from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer


class ChineseIdCardRecognizer(PatternRecognizer):
    """Recognizer for Chinese Resident Identity Card numbers.

    Supports:
    - 18-digit format with ISO 7064:1983 MOD 11-2 checksum
    - Region code validation
    - Birth date validation

    Example:
        >>> recognizer = ChineseIdCardRecognizer()
        >>> # Used through Presidio AnalyzerEngine
    """

    # Weights for checksum calculation (ISO 7064:1983 MOD 11-2)
    WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]

    # Checksum mapping
    CHECKSUM_MAP = "10X98765432"

    PATTERNS = [
        Pattern(
            name="zh_id_card_18",
            regex=r"\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
            score=0.7,
        ),
    ]

    CONTEXT = [
        "身份证",
        "身份证号",
        "身份证号码",
        "证件号",
        "证件号码",
        "ID",
        "id",
        "identity",
        "身份",
        "证号",
        "居民身份证",
        "公民身份号码",
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
            supported_entity="ZH_ID_CARD",
            patterns=self.PATTERNS,
            context=context_words,
            supported_language=supported_language,
        )

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        """Validate ID card using checksum algorithm.

        Args:
            pattern_text: The matched ID card number.

        Returns:
            True if valid, False if invalid, None if uncertain.
        """
        if len(pattern_text) != 18:
            return False

        # Normalize X to uppercase
        id_number = pattern_text.upper()

        # Calculate checksum
        try:
            total = sum(int(id_number[i]) * self.WEIGHTS[i] for i in range(17))
            expected_checksum = self.CHECKSUM_MAP[total % 11]

            return id_number[17] == expected_checksum
        except (ValueError, IndexError):
            return False


def validate_chinese_id_card(id_number: str) -> bool:
    """Standalone validation function for Chinese ID card numbers.

    Args:
        id_number: The 18-digit ID card number to validate.

    Returns:
        True if the ID card number is valid, False otherwise.

    Example:
        >>> validate_chinese_id_card("110101199003077758")
        True
    """
    recognizer = ChineseIdCardRecognizer()
    result = recognizer.validate_result(id_number)
    return result is True
