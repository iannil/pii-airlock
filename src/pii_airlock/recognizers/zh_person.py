"""
Chinese Person Name Recognizer

Leverages spaCy's Chinese NER model for person name detection.
"""

import os
from typing import Optional

from presidio_analyzer import EntityRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts


class ChinesePersonRecognizerConfig:
    """Configuration for Chinese person name recognizer.

    Scoring parameters can be overridden via environment variables:
    - PII_AIRLOCK_PERSON_BASE_SCORE: Base confidence score (default: 0.85)
    - PII_AIRLOCK_PERSON_SURNAME_BOOST: Score boost for common surnames (default: 0.1)
    - PII_AIRLOCK_PERSON_FULL_NAME_BOOST: Score boost for typical name length (default: 0.05)
    - PII_AIRLOCK_PERSON_MAX_SCORE: Maximum confidence score (default: 0.95)
    """

    BASE_SCORE: float = float(os.getenv("PII_AIRLOCK_PERSON_BASE_SCORE", "0.85"))
    SURNAME_BOOST: float = float(os.getenv("PII_AIRLOCK_PERSON_SURNAME_BOOST", "0.1"))
    FULL_NAME_BOOST: float = float(os.getenv("PII_AIRLOCK_PERSON_FULL_NAME_BOOST", "0.05"))
    MAX_SCORE: float = float(os.getenv("PII_AIRLOCK_PERSON_MAX_SCORE", "0.95"))

    # Typical Chinese name length range
    MIN_NAME_LENGTH: int = int(os.getenv("PII_AIRLOCK_PERSON_MIN_NAME_LENGTH", "2"))
    MAX_NAME_LENGTH: int = int(os.getenv("PII_AIRLOCK_PERSON_MAX_NAME_LENGTH", "4"))


class ChinesePersonRecognizer(EntityRecognizer):
    """Recognizer for Chinese person names using spaCy NER.

    This recognizer wraps spaCy's Chinese NER model to detect
    person names in Chinese text.

    Note:
        Requires `zh_core_web_trf` or `zh_core_web_sm` spaCy model.
        Install via: python -m spacy download zh_core_web_trf
    """

    ENTITIES = ["PERSON"]

    # Common Chinese surnames (top 100) for context enhancement
    COMMON_SURNAMES = [
        "王", "李", "张", "刘", "陈", "杨", "黄", "赵", "周", "吴",
        "徐", "孙", "马", "胡", "朱", "郭", "何", "林", "高", "罗",
        "郑", "梁", "谢", "宋", "唐", "许", "韩", "冯", "邓", "曹",
        "彭", "曾", "萧", "田", "董", "潘", "袁", "蔡", "蒋", "余",
        "于", "杜", "叶", "程", "魏", "苏", "吕", "丁", "任", "沈",
        "姚", "卢", "傅", "钟", "姜", "崔", "谭", "廖", "范", "汪",
        "陆", "金", "石", "戴", "贾", "韦", "夏", "邱", "方", "侯",
        "邹", "熊", "孟", "秦", "白", "江", "阎", "薛", "尹", "段",
        "雷", "黎", "史", "龙", "贺", "陶", "顾", "毛", "郝", "龚",
        "邵", "万", "钱", "严", "覃", "武", "戚", "莫", "孔", "向",
    ]

    def __init__(
        self,
        supported_language: str = "zh",
        supported_entities: Optional[list[str]] = None,
    ) -> None:
        """Initialize the recognizer.

        Args:
            supported_language: Language code.
            supported_entities: Entity types to detect.
        """
        super().__init__(
            supported_entities=supported_entities or self.ENTITIES,
            supported_language=supported_language,
            name="ChinesePersonRecognizer",
        )

    def load(self) -> None:
        """Load any required resources."""
        pass  # spaCy model is loaded by NLP engine

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: Optional[NlpArtifacts] = None,
    ) -> list[RecognizerResult]:
        """Analyze text for person names.

        Args:
            text: Input text to analyze.
            entities: Entity types to look for.
            nlp_artifacts: Pre-processed NLP data from spaCy.

        Returns:
            List of RecognizerResult for detected persons.
        """
        results = []

        if not nlp_artifacts or not nlp_artifacts.entities:
            return results

        for entity in nlp_artifacts.entities:
            if entity.label_ in ("PERSON", "PER"):
                # Calculate confidence based on context
                score = ChinesePersonRecognizerConfig.BASE_SCORE

                # Get entity text
                entity_text = text[entity.start_char : entity.end_char]

                # Boost score if starts with common surname
                if entity_text and entity_text[0] in self.COMMON_SURNAMES:
                    score = min(
                        ChinesePersonRecognizerConfig.MAX_SCORE,
                        score + ChinesePersonRecognizerConfig.SURNAME_BOOST,
                    )

                # Adjust for name length (2-4 chars is typical for Chinese names)
                name_len = len(entity_text)
                min_len = ChinesePersonRecognizerConfig.MIN_NAME_LENGTH
                max_len = ChinesePersonRecognizerConfig.MAX_NAME_LENGTH
                if min_len <= name_len <= max_len:
                    score = min(
                        ChinesePersonRecognizerConfig.MAX_SCORE,
                        score + ChinesePersonRecognizerConfig.FULL_NAME_BOOST,
                    )

                results.append(
                    RecognizerResult(
                        entity_type="PERSON",
                        start=entity.start_char,
                        end=entity.end_char,
                        score=score,
                    )
                )

        return results
