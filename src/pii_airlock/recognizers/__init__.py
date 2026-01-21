"""Custom PII recognizers for Chinese language support."""

from pii_airlock.recognizers.zh_phone import ChinesePhoneRecognizer
from pii_airlock.recognizers.zh_id_card import ChineseIdCardRecognizer
from pii_airlock.recognizers.zh_person import ChinesePersonRecognizer
from pii_airlock.recognizers.registry import create_analyzer_with_chinese_support

__all__ = [
    "ChinesePhoneRecognizer",
    "ChineseIdCardRecognizer",
    "ChinesePersonRecognizer",
    "create_analyzer_with_chinese_support",
]
