"""High entropy detector for unknown secrets.

This module provides functionality to detect high-entropy strings that may
represent API keys, tokens, or other secrets not covered by predefined patterns.

Uses Shannon entropy calculation to identify strings with high randomness
characteristic of secrets and cryptographic material.
"""

import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class EntropyLevel(str, Enum):
    """Entropy risk levels."""

    LOW = "low"        # < 3.5 bits/char - likely natural language
    MEDIUM = "medium"  # 3.5 - 4.5 bits/char - suspicious
    HIGH = "high"      # > 4.5 bits/char - very likely a secret
    CRITICAL = "critical"  # > 5.0 bits/char - almost certainly a secret


@dataclass
class EntropyResult:
    """Result of entropy analysis.

    Attributes:
        text: The analyzed text.
        entropy_bits: Shannon entropy in bits per character.
        level: Risk level classification.
        is_suspicious: Whether the string appears to be a secret.
        reason: Human-readable explanation.
    """

    text: str
    entropy_bits: float
    level: EntropyLevel
    is_suspicious: bool
    reason: str


# Patterns that commonly produce false positives (low entropy but look random)
FALSE_POSITIVE_PATTERNS = [
    # UUIDs (handled separately)
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
    # Simple hex colors
    r'^#[0-9a-fA-F]{6}$',
    r'^#[0-9a-fA-F]{3}$',
    # Common ID formats
    r'^[A-Z]{2,3}-\d{3,5}$',  # Airport codes, license plates
    # Dates
    r'^\d{4}-\d{2}-\d{2}$',
    r'^\d{2}/\d{2}/\d{4}$',
    # Times
    r'^\d{2}:\d{2}:\d{2}$',
    # Simple numbers
    r'^\d{4,}$',
]

# Patterns that indicate a string is likely a secret (not just high entropy)
SECRET_INDICATORS = [
    r'key', r'token', r'secret', r'password', r'passwd', r'pwd',
    r'api', r'auth', r'session', r'credential', r'private',
    r'access', r'refresh', r'Bearer', r'Basic',
]

# Base64-like patterns (high entropy, common in tokens)
BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
HEX_PATTERN = re.compile(r'^[0-9a-fA-F]{16,}$')


class EntropyDetector:
    """Detector for high-entropy strings that may be secrets."""

    def __init__(
        self,
        high_threshold: float = 4.5,
        medium_threshold: float = 3.5,
        critical_threshold: float = 5.0,
        min_length: int = 16,
    ):
        """Initialize the entropy detector.

        Args:
            high_threshold: Entropy threshold for HIGH risk level.
            medium_threshold: Entropy threshold for MEDIUM risk level.
            critical_threshold: Entropy threshold for CRITICAL risk level.
            min_length: Minimum string length to analyze.
        """
        self.high_threshold = high_threshold
        self.medium_threshold = medium_threshold
        self.critical_threshold = critical_threshold
        self.min_length = min_length

    def calculate_shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string.

        Shannon entropy measures the randomness/unpredictability of a string.
        Higher values indicate more random (more likely to be a secret).

        Args:
            text: The text to analyze.

        Returns:
            Entropy value in bits per character.
        """
        if not text:
            return 0.0

        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate entropy
        text_len = len(text)
        entropy = 0.0

        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def classify_entropy(self, entropy: float) -> EntropyLevel:
        """Classify an entropy value into a risk level.

        Args:
            entropy: Entropy value in bits per character.

        Returns:
            EntropyLevel classification.
        """
        if entropy >= self.critical_threshold:
            return EntropyLevel.CRITICAL
        if entropy >= self.high_threshold:
            return EntropyLevel.HIGH
        if entropy >= self.medium_threshold:
            return EntropyLevel.MEDIUM
        return EntropyLevel.LOW

    def is_false_positive(self, text: str) -> bool:
        """Check if a high-entropy string is a known false positive.

        Args:
            text: The text to check.

        Returns:
            True if this is a known false positive pattern.
        """
        for pattern in FALSE_POSITIVE_PATTERNS:
            if re.match(pattern, text):
                return True
        return False

    def has_secret_indicators(self, context: str = "") -> bool:
        """Check if context contains indicators of a secret.

        Args:
            context: Surrounding context text.

        Returns:
            True if context suggests this is a secret.
        """
        if not context:
            return False

        context_lower = context.lower()
        return any(indicator in context_lower for indicator in SECRET_INDICATORS)

    def looks_like_token(self, text: str) -> bool:
        """Check if text looks like an API token or key.

        Args:
            text: The text to check.

        Returns:
            True if text has characteristics of a token.
        """
        # Base64-like tokens
        if BASE64_PATTERN.match(text):
            return True

        # Long hex strings
        if HEX_PATTERN.match(text) and len(text) >= 32:
            return True

        # Mixed alphanumeric with special chars
        if len(text) >= 20:
            has_lower = any(c.islower() for c in text)
            has_upper = any(c.isupper() for c in text)
            has_digit = any(c.isdigit() for c in text)
            has_special = any(c in '_-.' for c in text)

            if has_lower and has_upper and has_digit:
                return True

        return False

    def analyze(
        self,
        text: str,
        context: str = "",
    ) -> Optional[EntropyResult]:
        """Analyze a text string for high entropy.

        Args:
            text: The text to analyze.
            context: Optional surrounding context.

        Returns:
            EntropyResult if analysis was performed, None if text is too short.
        """
        if len(text) < self.min_length:
            return None

        # Check for false positives first
        if self.is_false_positive(text):
            return EntropyResult(
                text=text,
                entropy_bits=0.0,
                level=EntropyLevel.LOW,
                is_suspicious=False,
                reason="Matches known false positive pattern",
            )

        # Calculate entropy
        entropy = self.calculate_shannon_entropy(text)
        level = self.classify_entropy(entropy)

        # Determine if suspicious
        is_suspicious = level in (EntropyLevel.HIGH, EntropyLevel.CRITICAL)

        # Adjust based on context
        if context and self.has_secret_indicators(context):
            # If context suggests secret, be more lenient
            if level == EntropyLevel.MEDIUM:
                is_suspicious = True

        # Check for token-like characteristics
        looks_like_token = self.looks_like_token(text)
        if looks_like_token and level == EntropyLevel.MEDIUM:
            is_suspicious = True

        # Build reason
        reasons = []
        if level == EntropyLevel.CRITICAL:
            reasons.append("Critical entropy - likely cryptographic material")
        elif level == EntropyLevel.HIGH:
            reasons.append("High entropy - possible secret")
        elif level == EntropyLevel.MEDIUM:
            reasons.append("Medium entropy - suspicious")
        else:
            reasons.append("Low entropy - likely benign")

        if looks_like_token:
            reasons.append("Token-like format detected")
        if context and self.has_secret_indicators(context):
            reasons.append("Context contains secret indicators")

        return EntropyResult(
            text=text,
            entropy_bits=round(entropy, 3),
            level=level,
            is_suspicious=is_suspicious,
            reason="; ".join(reasons),
        )

    def scan_text(
        self,
        text: str,
    ) -> list[EntropyResult]:
        """Scan text for high-entropy strings.

        Args:
            text: The text to scan.

        Returns:
            List of EntropyResult for suspicious strings found.
        """
        results = []

        # Look for potential secrets - strings that are:
        # - Long enough
        # - Contain alphanumeric mix
        # - Not natural language words

        # Split on whitespace and common delimiters
        candidates = re.findall(r'\S+', text)

        for candidate in candidates:
            # Skip if too short
            if len(candidate) < self.min_length:
                continue

            # Skip if all digits
            if candidate.isdigit():
                continue

            # Skip if all same case letters (likely natural language)
            if candidate.isalpha() and (candidate.islower() or candidate.isupper()):
                continue

            result = self.analyze(candidate)
            if result and result.is_suspicious:
                results.append(result)

        return results


class SecretScanner:
    """Scanner that combines entropy detection with pattern matching.

    This class provides a more comprehensive secret detection by combining
    high entropy detection with known secret patterns.
    """

    def __init__(
        self,
        entropy_detector: Optional[EntropyDetector] = None,
    ):
        """Initialize the secret scanner.

        Args:
            entropy_detector: Entropy detector to use. If None, creates default.
        """
        self.entropy_detector = entropy_detector or EntropyDetector()

    def is_high_entropy_secret(
        self,
        text: str,
        context: str = "",
    ) -> bool:
        """Check if text is likely a secret based on entropy.

        Args:
            text: The text to check.
            context: Optional surrounding context.

        Returns:
            True if text appears to be a secret.
        """
        result = self.entropy_detector.analyze(text, context)
        return result.is_suspicious if result else False

    def scan_and_report(
        self,
        text: str,
    ) -> dict:
        """Scan text and return a detailed report.

        Args:
            text: The text to scan.

        Returns:
            Dictionary with scan results including:
            - found: Number of suspicious strings found
            - items: List of entropy results
            - risk_level: Overall risk level
        """
        results = self.entropy_detector.scan_text(text)

        if not results:
            return {
                "found": 0,
                "items": [],
                "risk_level": "none",
            }

        # Determine overall risk
        has_critical = any(r.level == EntropyLevel.CRITICAL for r in results)
        has_high = any(r.level == EntropyLevel.HIGH for r in results)

        if has_critical:
            overall_risk = "critical"
        elif has_high:
            overall_risk = "high"
        else:
            overall_risk = "medium"

        return {
            "found": len(results),
            "items": [
                {
                    "text": r.text,
                    "entropy": r.entropy_bits,
                    "level": r.level.value,
                    "reason": r.reason,
                }
                for r in results
            ],
            "risk_level": overall_risk,
        }


# Global detector instance
_detector: Optional[EntropyDetector] = None


def get_entropy_detector() -> EntropyDetector:
    """Get the global entropy detector instance."""
    global _detector
    if _detector is None:
        _detector = EntropyDetector()
    return _detector


def is_secret(text: str, context: str = "") -> bool:
    """Check if text is likely a secret.

    Convenience function using the global detector.

    Args:
        text: The text to check.
        context: Optional surrounding context.

    Returns:
        True if text appears to be a secret.
    """
    scanner = SecretScanner()
    return scanner.is_high_entropy_secret(text, context)


def scan_for_secrets(text: str) -> dict:
    """Scan text for potential secrets.

    Convenience function using the global scanner.

    Args:
        text: The text to scan.

    Returns:
        Dictionary with scan results.
    """
    scanner = SecretScanner()
    return scanner.scan_and_report(text)


# Presidio recognizer integration
def create_entropy_recognizer() -> "PatternRecognizer":  # type: ignore
    """Create a Presidio recognizer for entropy-based detection.

    This can be registered with Presidio's recognizer registry.
    """
    try:
        from presidio_analyzer import PatternRecognizer, RecognizerResult
        from presidio_analyzer.context_aware_enhancement import ContextAwareEnhancement

        detector = get_entropy_detector()

        class EntropyBasedRecognizer(PatternRecognizer):
            """Presidio recognizer that uses entropy detection."""

            def __init__(self):
                super().__init__(
                    supported_entity="HIGH_ENTROPY_SECRET",
                    name="EntropyBasedRecognizer",
                )

            def analyze(self, text: str, entities=None, nlp_engine=None):
                """Analyze text for high-entropy secrets."""
                results = []

                # Scan for high entropy strings
                entropy_results = detector.scan_text(text)

                for er in entropy_results:
                    # Find the position in text
                    start = text.find(er.text)
                    if start >= 0:
                        # Calculate score based on entropy level
                        if er.level == EntropyLevel.CRITICAL:
                            score = 0.99
                        elif er.level == EntropyLevel.HIGH:
                            score = 0.85
                        else:
                            score = 0.7

                        results.append(
                            RecognizerResult(
                                entity_type="HIGH_ENTROPY_SECRET",
                                start=start,
                                end=start + len(er.text),
                                score=score,
                            )
                        )

                return results

        return EntropyBasedRecognizer()

    except ImportError:
        # Presidio not available, return None
        return None
