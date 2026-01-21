"""Pytest fixtures and configuration."""

import os
import pytest


# Use smaller model for faster testing
SPACY_MODEL = os.getenv("SPACY_MODEL", "zh_core_web_sm")


@pytest.fixture(scope="session")
def analyzer():
    """Create analyzer with Chinese support for testing."""
    from pii_airlock.recognizers.registry import create_analyzer_with_chinese_support
    return create_analyzer_with_chinese_support(spacy_model=SPACY_MODEL)


@pytest.fixture
def sample_texts():
    """Sample texts for testing."""
    return {
        "simple_person": "张三是我的朋友",
        "simple_phone": "我的电话是13800138000",
        "simple_email": "请发送到test@example.com",
        "mixed_pii": "张三(13800138000)的邮箱是zhangsan@example.com",
        "no_pii": "今天天气很好",
        "empty": "",
        "english_in_chinese": "请联系John的邮箱john@company.com",
    }


@pytest.fixture
def valid_id_cards():
    """Valid Chinese ID card numbers for testing."""
    # Note: These are test numbers with valid checksums
    return [
        "110101199003077715",  # Beijing, 1990-03-07
        "11010119900307109X",  # Beijing, with X checksum
    ]


@pytest.fixture
def invalid_id_cards():
    """Invalid Chinese ID card numbers for testing."""
    return [
        "110101199003077710",  # Invalid checksum
        "12345678901234567X",  # Invalid format
        "11010119900307",      # Too short
    ]
