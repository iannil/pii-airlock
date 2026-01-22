"""Text processing utility functions."""

import re
import unicodedata
from typing import Optional


def normalize_text(text: str) -> str:
    """Normalize text by handling whitespace and Unicode normalization.

    This function:
    - Converts all whitespace characters (including non-breaking spaces) to regular spaces
    - Collapses multiple consecutive spaces into single spaces
    - Performs Unicode NFKC normalization
    - Strips leading/trailing whitespace

    Args:
        text: Input text to normalize.

    Returns:
        Normalized text string.

    Examples:
        >>> normalize_text("张三  电话是\\t13800138000")
        '张三 电话是 13800138000'
        >>> normalize_text("Hello\\u00a0World  ")
        'Hello World'
    """
    if not text:
        return ""

    # Unicode NFKC normalization (decomposes and recomposes compatibly)
    text = unicodedata.normalize("NFKC", text)

    # Convert all whitespace characters to regular space
    # This includes \\t, \\n, \\r, non-breaking spaces, etc.
    text = re.sub(r"\s+", " ", text)

    # Strip leading/trailing whitespace
    text = text.strip()

    return text


def truncate_text(text: str, max_length: int, suffix: str = "...") -> str:
    """Truncate text to a maximum length, adding suffix if truncated.

    Args:
        text: Input text to truncate.
        max_length: Maximum length of the output text including suffix.
        suffix: Suffix to add if text is truncated (default: "...").

    Returns:
        Truncated text with suffix if needed, or original text if short enough.

    Raises:
        ValueError: If max_length is less than suffix length.

    Examples:
        >>> truncate_text("This is a long text", 10)
        'This is...'
        >>> truncate_text("Short", 20)
        'Short'
    """
    if not text:
        return ""

    if max_length < len(suffix):
        raise ValueError(f"max_length ({max_length}) must be >= suffix length ({len(suffix)})")

    if len(text) <= max_length:
        return text

    # Truncate and add suffix
    return text[: max_length - len(suffix)] + suffix


def count_words(text: str) -> int:
    """Count the number of words in text.

    Handles both Chinese (character-based) and English (space-based) text.

    Args:
        text: Input text to count words in.

    Returns:
        Number of words/characters.

    Examples:
        >>> count_words("Hello world")
        2
        >>> count_words("你好世界")
        4
    """
    if not text:
        return 0

    # Count Chinese characters and non-words separately
    chinese_chars = len(re.findall(r"[\u4e00-\u9fff]", text))
    # Remove Chinese characters and count remaining words
    remaining = re.sub(r"[\u4e00-\u9fff]", " ", text)
    english_words = len([w for w in remaining.split() if w])

    return chinese_chars + english_words


def split_text_preserve_pii(text: str, max_chunk_size: int) -> list[str]:
    """Split text into chunks while attempting to preserve PII placeholder boundaries.

    This function tries to avoid splitting in the middle of PII placeholders
    like <PERSON_1>, <PHONE_2>, etc.

    Args:
        text: Input text to split.
        max_chunk_size: Maximum size of each chunk.

    Returns:
        List of text chunks.

    Examples:
        >>> split_text_preserve_pii("Hello <PERSON_1> world", 15)
        ['Hello <PERSON_1>', ' world']
    """
    if not text or len(text) <= max_chunk_size:
        return [text] if text else []

    chunks = []
    current_chunk = ""
    placeholder_pattern = re.compile(r"<[A-Z_]+_\d+>")

    i = 0
    while i < len(text):
        remaining_space = max_chunk_size - len(current_chunk)

        if remaining_space <= 0:
            chunks.append(current_chunk)
            current_chunk = ""
            continue

        # Check if we're at a placeholder
        match = placeholder_pattern.match(text, i)
        if match:
            placeholder = match.group(0)
            if len(current_chunk) + len(placeholder) <= max_chunk_size:
                current_chunk += placeholder
                i += len(placeholder)
            else:
                # Start new chunk with placeholder
                if current_chunk:
                    chunks.append(current_chunk)
                    current_chunk = placeholder
                    i += len(placeholder)
                else:
                    # Placeholder is too large, force add it
                    current_chunk = placeholder
                    i += len(placeholder)
        else:
            # Add one character
            current_chunk += text[i]
            i += 1

    if current_chunk:
        chunks.append(current_chunk)

    return chunks


def clean_whitespace(text: str, preserve_newlines: bool = False) -> str:
    """Clean whitespace in text.

    Args:
        text: Input text to clean.
        preserve_newlines: If True, preserve newline characters.

    Returns:
        Text with cleaned whitespace.

    Examples:
        >>> clean_whitespace("  Hello   world  ")
        'Hello world'
        >>> clean_whitespace("Hello\\n\\nworld", preserve_newlines=True)
        'Hello\\n\\nworld'
    """
    if not text:
        return ""

    if preserve_newlines:
        # Preserve newlines but clean other whitespace
        lines = text.split("\n")
        cleaned_lines = [normalize_text(line) for line in lines]
        return "\n".join(cleaned_lines)

    return normalize_text(text)


def contains_chinese(text: str) -> bool:
    """Check if text contains Chinese characters.

    Args:
        text: Input text to check.

    Returns:
        True if text contains Chinese characters, False otherwise.

    Examples:
        >>> contains_chinese("Hello world")
        False
        >>> contains_chinese("Hello 世界")
        True
    """
    if not text:
        return False
    return bool(re.search(r"[\u4e00-\u9fff]", text))


def extract_pii_placeholders(text: str) -> list[str]:
    """Extract all PII placeholders from text.

    Args:
        text: Input text to extract placeholders from.

    Returns:
        List of placeholder strings found in text.

    Examples:
        >>> extract_pii_placeholders("Hello <PERSON_1>, call <PHONE_1>")
        ['<PERSON_1>', '<PHONE_1>']
    """
    if not text:
        return []
    return re.findall(r"<([A-Z_]+_\d+)>", text)


def sanitize_for_logging(text: str, max_length: int = 100) -> str:
    """Sanitize text for safe logging (truncate and remove sensitive patterns).

    Args:
        text: Input text to sanitize.
        max_length: Maximum length after sanitization.

    Returns:
        Sanitized text safe for logging.

    Examples:
        >>> sanitize_for_logging("Very long text here...", 10)
        'Very long...'
    """
    if not text:
        return ""

    # Truncate first
    result = truncate_text(text, max_length, suffix="...")

    # Replace any remaining potential PII patterns with generic indicators
    result = re.sub(r"\b\d{11}\b", "[PHONE]", result)  # Chinese phone
    result = re.sub(r"\b\d{15,18}\b", "[ID_CARD]", result)  # ID card
    result = re.sub(r"\b[\w.-]+@[\w.-]+\.\w+\b", "[EMAIL]", result)  # Email

    return result
