"""Validation utility functions."""

import re
from typing import Optional


# Regex patterns for validation
_CHINESE_PHONE_PATTERN = re.compile(r"^1[3-9]\d{9}$")
_EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    re.IGNORECASE,
)
_CHINESE_ID_CARD_PATTERN = re.compile(r"^[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]$")
_CREDIT_CARD_PATTERN = re.compile(r"^\d{13,19}$")
_IPV4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV6_PATTERN = re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")


def validate_email(email: str) -> bool:
    """Validate an email address.

    Uses a comprehensive regex pattern that matches most valid email formats.

    Args:
        email: Email address to validate.

    Returns:
        True if the email is valid, False otherwise.

    Examples:
        >>> validate_email("user@example.com")
        True
        >>> validate_email("invalid.email")
        False
        >>> validate_email("test+tag@domain.co.uk")
        True
    """
    if not email or not isinstance(email, str):
        return False
    return bool(_EMAIL_PATTERN.match(email.strip()))


def validate_phone(phone: str) -> bool:
    """Validate a Chinese mainland mobile phone number.

    Chinese mobile numbers start with 1, followed by 3-9, then 9 more digits.

    Args:
        phone: Phone number to validate.

    Returns:
        True if the phone is a valid Chinese mobile number, False otherwise.

    Examples:
        >>> validate_phone("13800138000")
        True
        >>> validate_phone("12345678901")
        False
        >>> validate_phone("1380013800")
        False
    """
    if not phone or not isinstance(phone, str):
        return False
    phone = phone.strip()
    # Remove common separators
    phone = re.sub(r"[\s\-]", "", phone)
    return bool(_CHINESE_PHONE_PATTERN.match(phone))


def validate_phone_international(phone: str) -> bool:
    """Validate an international phone number (E.164 format).

    E.164 format: +[country code][subscriber number]
    Minimum length: 8 digits (after country code)
    Maximum length: 15 digits (after country code)

    Args:
        phone: Phone number to validate.

    Returns:
        True if the phone matches E.164 format, False otherwise.

    Examples:
        >>> validate_phone_international("+8613800138000")
        True
        >>> validate_phone_international("+14155552671")
        True
        >>> validate_phone_international("13800138000")
        False
    """
    if not phone or not isinstance(phone, str):
        return False
    phone = phone.strip()
    # E.164 format: + followed by up to 15 digits
    e164_pattern = re.compile(r"^\+\d{1,3}\d{6,14}$")
    return bool(e164_pattern.match(phone))


def validate_chinese_id_card(id_card: str) -> bool:
    """Validate a Chinese ID card number (18-digit).

    Args:
        id_card: ID card number to validate.

    Returns:
        True if the ID card is valid, False otherwise.

    Note:
        This validates format but does not verify the checksum.

    Examples:
        >>> validate_chinese_id_card("110101199003077758")
        True
        >>> validate_chinese_id_card("123456789012345678")
        False
    """
    if not id_card or not isinstance(id_card, str):
        return False
    id_card = id_card.strip()
    return bool(_CHINESE_ID_CARD_PATTERN.match(id_card))


def validate_chinese_id_card_with_checksum(id_card: str) -> bool:
    """Validate Chinese ID card number with checksum verification.

    Args:
        id_card: ID card number to validate.

    Returns:
        True if the ID card is valid including checksum, False otherwise.

    Examples:
        >>> validate_chinese_id_card_with_checksum("110101199003077758")
        True
    """
    if not validate_chinese_id_card(id_card):
        return False

    # Verify checksum
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    checksum_chars = "10X98765432"
    id_card = id_card.strip().upper()

    total = sum(int(id_card[i]) * weights[i] for i in range(17))
    checksum = checksum_chars[total % 11]

    return id_card[-1] == checksum


def validate_credit_card(card_number: str) -> bool:
    """Validate a credit card number using Luhn algorithm.

    Args:
        card_number: Credit card number to validate.

    Returns:
        True if the card number is valid, False otherwise.

    Examples:
        >>> validate_credit_card("4111111111111111")
        True
        >>> validate_credit_card("1234567890123456")
        False
    """
    if not card_number or not isinstance(card_number, str):
        return False
    card_number = card_number.strip()
    # Remove spaces and dashes
    card_number = re.sub(r"[\s\-]", "", card_number)

    # Check basic format
    if not _CREDIT_CARD_PATTERN.match(card_number):
        return False

    # Luhn algorithm
    total = 0
    for i, digit in enumerate(reversed(card_number)):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


def validate_ip_address(ip: str) -> bool:
    """Validate an IPv4 or IPv6 address.

    Args:
        ip: IP address to validate.

    Returns:
        True if the IP is valid, False otherwise.

    Examples:
        >>> validate_ip_address("192.168.1.1")
        True
        >>> validate_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        True
        >>> validate_ip_address("256.256.256.256")
        False
    """
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()

    if _IPV4_PATTERN.match(ip):
        # Validate each octet is 0-255
        octets = ip.split(".")
        return all(0 <= int(octet) <= 255 for octet in octets)

    if _IPV6_PATTERN.match(ip):
        return True

    return False


def is_chinese_text(text: str, threshold: float = 0.3) -> bool:
    """Check if text is primarily Chinese.

    Args:
        text: Text to check.
        threshold: Minimum ratio of Chinese characters to consider text as Chinese.

    Returns:
        True if the text is primarily Chinese, False otherwise.

    Examples:
        >>> is_chinese_text("你好世界")
        True
        >>> is_chinese_text("Hello world")
        False
        >>> is_chinese_text("Hello 世界", threshold=0.2)
        True
    """
    if not text:
        return False

    chinese_chars = len(re.findall(r"[\u4e00-\u9fff]", text))
    total_chars = len(re.findall(r"\S", text))

    if total_chars == 0:
        return False

    return (chinese_chars / total_chars) >= threshold


def validate_url(url: str) -> bool:
    """Validate a URL.

    Args:
        url: URL to validate.

    Returns:
        True if the URL is valid, False otherwise.

    Examples:
        >>> validate_url("https://example.com")
        True
        >>> validate_url("ftp://files.example.com/path")
        True
        >>> validate_url("not a url")
        False
    """
    if not url or not isinstance(url, str):
        return False

    url_pattern = re.compile(
        r"^(https?|ftp|file)://"  # protocol
        r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"  # domain
        r"(:\d+)?"  # optional port
        r"(/.*)?$",  # optional path
        re.IGNORECASE,
    )
    return bool(url_pattern.match(url.strip()))


def validate_ssn(ssn: str) -> bool:
    """Validate a US Social Security Number.

    Args:
        ssn: SSN to validate (format: XXX-XX-XXXX or XXXXXXXXX).

    Returns:
        True if the SSN is valid, False otherwise.

    Examples:
        >>> validate_ssn("123-45-6789")
        True
        >>> validate_ssn("123456789")
        True
        >>> validate_ssn("000-00-0000")
        False
    """
    if not ssn or not isinstance(ssn, str):
        return False
    ssn = ssn.strip()

    # Remove dashes
    ssn = ssn.replace("-", "")

    # Check format
    if not re.match(r"^\d{9}$", ssn):
        return False

    # Check for invalid SSNs (000, 666, 900-999 in area number)
    area = ssn[:3]
    group = ssn[3:5]
    serial = ssn[5:]

    if area == "000" or area == "666" or int(area) >= 900:
        return False
    if group == "00":
        return False
    if serial == "0000":
        return False

    return True


def validate_postal_code(code: str, country: str = "CN") -> bool:
    """Validate a postal code based on country.

    Args:
        code: Postal code to validate.
        country: ISO country code (default: CN for China).

    Returns:
        True if the postal code is valid for the country, False otherwise.

    Examples:
        >>> validate_postal_code("100000")  # China
        True
        >>> validate_postal_code("100084")  # China
        True
        >>> validate_postal_code("90210", country="US")  # US ZIP code
        True
    """
    if not code or not isinstance(code, str):
        return False
    code = code.strip()

    patterns = {
        "CN": re.compile(r"^\d{6}$"),  # China: 6 digits
        "US": re.compile(r"^\d{5}(-\d{4})?$"),  # US: 5 digits or ZIP+4
        "UK": re.compile(r"^[A-Z]{1,2}\d[A-Z\d]? \d[A-Z]{2}$", re.IGNORECASE),
        "JP": re.compile(r"^\d{3}-\d{4}$"),  # Japan: XXX-XXXX
        "DE": re.compile(r"^\d{5}$"),  # Germany: 5 digits
        "FR": re.compile(r"^\d{5}$"),  # France: 5 digits
        "CA": re.compile(r"^[A-Z]\d[A-Z] \d[A-Z]\d$", re.IGNORECASE),
    }

    pattern = patterns.get(country.upper())
    if not pattern:
        # If no pattern for country, do basic validation
        return len(code) >= 3 and len(code) <= 10

    return bool(pattern.match(code))


def sanitize_input(text: str, max_length: int = 10000) -> tuple[bool, Optional[str]]:
    """Validate and sanitize user input.

    Args:
        text: Input text to validate.
        max_length: Maximum allowed length.

    Returns:
        Tuple of (is_valid, sanitized_text or error_message).

    Examples:
        >>> sanitize_input("Hello world", 100)
        (True, 'Hello world')
        >>> sanitize_input("", 100)
        (False, 'Input cannot be empty')
        >>> sanitize_input("a" * 10001, 10000)
        (False, 'Input exceeds maximum length')
    """
    if not text or not text.strip():
        return False, "Input cannot be empty"

    if len(text) > max_length:
        return False, f"Input exceeds maximum length of {max_length}"

    # Check for potentially malicious patterns
    dangerous_patterns = [
        r"<script[^>]*>",  # Script tags
        r"javascript:",  # JavaScript protocol
        r"on\w+\s*=",  # Event handlers
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return False, "Input contains potentially malicious content"

    return True, text.strip()
