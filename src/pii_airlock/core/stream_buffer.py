"""
Streaming Buffer for PII Deanonymization

This module provides a sliding window buffer that handles placeholder
detection and replacement across SSE chunk boundaries.

The core challenge: LLM streaming responses may split placeholders across chunks:
    Chunk 1: "Please contact <PER"
    Chunk 2: "SON_1> for help"

Without buffering, Chunk 1 would be sent to the client with an incomplete
placeholder that can't be fixed retroactively.

Example:
    >>> from pii_airlock.core.stream_buffer import StreamBuffer
    >>> buffer = StreamBuffer(mapping, deanonymizer)
    >>> output1 = buffer.process_chunk("Hello <PER")  # Returns "Hello "
    >>> output2 = buffer.process_chunk("SON_1>!")     # Returns "张三!"
    >>> final = buffer.flush()                         # Returns any remainder
"""

import re
from typing import Optional

from pii_airlock.core.mapping import PIIMapping
from pii_airlock.core.deanonymizer import Deanonymizer


class StreamBuffer:
    """Sliding window buffer for streaming PII deanonymization.

    This class buffers incoming text chunks and only emits text when
    it's safe to do so (i.e., no incomplete placeholders at the end).

    Attributes:
        mapping: The PIIMapping for placeholder lookup.
        deanonymizer: The Deanonymizer for text restoration.
        buffer: Current buffered text awaiting processing.

    Example:
        >>> mapping = PIIMapping()
        >>> mapping.add("PERSON", "张三", "<PERSON_1>")
        >>> deanonymizer = Deanonymizer()
        >>> buffer = StreamBuffer(mapping, deanonymizer)
        >>>
        >>> # Simulate chunked input
        >>> out1 = buffer.process_chunk("Hello <PERS")
        >>> out2 = buffer.process_chunk("ON_1>, how are you?")
        >>> final = buffer.flush()
        >>>
        >>> print(out1 + out2 + final)
        Hello 张三, how are you?
    """

    # Maximum length of a placeholder (e.g., <CREDIT_CARD_999>)
    MAX_PLACEHOLDER_LENGTH = 25

    # Pattern for complete placeholders
    COMPLETE_PLACEHOLDER = re.compile(r"<[A-Z_]+_\d+>")

    # Pattern for potential placeholder start (incomplete)
    POTENTIAL_START = re.compile(r"<[A-Z_]*\d*$")

    def __init__(
        self,
        mapping: PIIMapping,
        deanonymizer: Optional[Deanonymizer] = None,
    ) -> None:
        """Initialize the stream buffer.

        Args:
            mapping: PIIMapping containing placeholder-to-original mappings.
            deanonymizer: Optional Deanonymizer instance. If not provided,
                         a new one will be created.
        """
        self.mapping = mapping
        self.deanonymizer = deanonymizer or Deanonymizer()
        self.buffer = ""

    def process_chunk(self, chunk: str) -> str:
        """Process an incoming chunk and return safe-to-emit text.

        This method appends the chunk to the internal buffer, then
        determines what portion of the buffer is safe to emit (i.e.,
        contains no incomplete placeholders at the end).

        Args:
            chunk: The incoming text chunk from the stream.

        Returns:
            Text that is safe to emit to the client. May be empty if
            the entire buffer needs to remain buffered.

        Example:
            >>> buffer.process_chunk("Contact <PER")  # Returns "Contact "
            >>> buffer.process_chunk("SON_1>")        # Returns "张三"
        """
        if not chunk:
            return ""

        self.buffer += chunk
        safe_text, remainder = self._extract_safe_portion()
        self.buffer = remainder
        return safe_text

    def flush(self) -> str:
        """Flush any remaining buffered content.

        This should be called when the stream ends to emit any
        remaining buffered text. The buffer will be cleared.

        Returns:
            Any remaining text in the buffer after deanonymization.
        """
        if not self.buffer:
            return ""

        result = self.deanonymizer.deanonymize(self.buffer, self.mapping)
        self.buffer = ""
        return result.text

    def _extract_safe_portion(self) -> tuple[str, str]:
        """Extract the safe-to-emit portion of the buffer.

        Scans the buffer from the end to find any potential incomplete
        placeholder patterns. Text before this point is safe to emit;
        text after needs to remain buffered.

        Returns:
            A tuple of (safe_text, remainder) where:
            - safe_text: Text that has been deanonymized and is safe to emit
            - remainder: Text that should remain in the buffer
        """
        if not self.buffer:
            return "", ""

        # Find the last '<' character
        last_open = self.buffer.rfind("<")

        if last_open == -1:
            # No '<' in buffer, everything is safe
            result = self.deanonymizer.deanonymize(self.buffer, self.mapping)
            return result.text, ""

        # Check if there's a complete placeholder starting at last_open
        potential = self.buffer[last_open:]

        # If it's a complete placeholder, the whole buffer is safe
        if self.COMPLETE_PLACEHOLDER.match(potential):
            # But we need to check if there's another '<' after this placeholder
            match = self.COMPLETE_PLACEHOLDER.match(potential)
            if match:
                end_of_placeholder = last_open + match.end()
                if end_of_placeholder < len(self.buffer):
                    # There's more text after the placeholder
                    # Recursively check the remainder
                    after_placeholder = self.buffer[end_of_placeholder:]
                    next_open = after_placeholder.rfind("<")
                    if next_open != -1:
                        # There's another '<' after this placeholder
                        # Check if it's complete
                        remaining = after_placeholder[next_open:]
                        if not self.COMPLETE_PLACEHOLDER.match(remaining):
                            # Incomplete placeholder, split there
                            safe = self.buffer[: end_of_placeholder + next_open]
                            remainder = self.buffer[end_of_placeholder + next_open :]
                            result = self.deanonymizer.deanonymize(safe, self.mapping)
                            return result.text, remainder

            # All placeholders are complete
            result = self.deanonymizer.deanonymize(self.buffer, self.mapping)
            return result.text, ""

        # Check if this looks like a potential placeholder start
        if self.POTENTIAL_START.search(potential):
            # It's an incomplete placeholder, split here
            safe = self.buffer[:last_open]
            remainder = self.buffer[last_open:]

            # Safety check: if remainder is too long, it's probably not a placeholder
            if len(remainder) > self.MAX_PLACEHOLDER_LENGTH:
                # Force emit everything, it's not a real placeholder
                result = self.deanonymizer.deanonymize(self.buffer, self.mapping)
                return result.text, ""

            if safe:
                result = self.deanonymizer.deanonymize(safe, self.mapping)
                return result.text, remainder
            else:
                return "", remainder

        # The '<' is followed by something that doesn't look like a placeholder
        # (e.g., "<html>" or "< ")
        # Check if it could still become a placeholder
        if len(potential) < self.MAX_PLACEHOLDER_LENGTH:
            # Still could become a placeholder, buffer it
            safe = self.buffer[:last_open]
            remainder = self.buffer[last_open:]
            if safe:
                result = self.deanonymizer.deanonymize(safe, self.mapping)
                return result.text, remainder
            else:
                return "", remainder
        else:
            # Too long to be a placeholder, emit everything
            result = self.deanonymizer.deanonymize(self.buffer, self.mapping)
            return result.text, ""

    def clear(self) -> None:
        """Clear the buffer without emitting anything."""
        self.buffer = ""

    @property
    def has_pending(self) -> bool:
        """Check if there's any pending content in the buffer."""
        return len(self.buffer) > 0

    @property
    def pending_length(self) -> int:
        """Get the length of pending buffered content."""
        return len(self.buffer)
