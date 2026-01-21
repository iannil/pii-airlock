"""Unit tests for StreamBuffer."""

import pytest
from pii_airlock.core.stream_buffer import StreamBuffer
from pii_airlock.core.mapping import PIIMapping
from pii_airlock.core.deanonymizer import Deanonymizer


@pytest.fixture
def mapping():
    """Create a mapping with test data."""
    m = PIIMapping()
    m.add("PERSON", "张三", "<PERSON_1>")
    m.add("PERSON", "李四", "<PERSON_2>")
    m.add("PHONE", "13800138000", "<PHONE_1>")
    m.add("EMAIL", "test@example.com", "<EMAIL_1>")
    return m


@pytest.fixture
def deanonymizer():
    """Create a deanonymizer instance."""
    return Deanonymizer()


@pytest.fixture
def buffer(mapping, deanonymizer):
    """Create a stream buffer with test mapping."""
    return StreamBuffer(mapping, deanonymizer)


class TestStreamBufferBasic:
    """Basic functionality tests."""

    def test_empty_chunk(self, buffer):
        """Test processing empty chunk."""
        result = buffer.process_chunk("")
        assert result == ""
        assert not buffer.has_pending

    def test_no_placeholder(self, buffer):
        """Test text without any placeholders passes through."""
        result = buffer.process_chunk("Hello world!")
        assert result == "Hello world!"
        assert not buffer.has_pending

    def test_complete_placeholder(self, buffer):
        """Test complete placeholder is replaced."""
        result = buffer.process_chunk("Hello <PERSON_1>!")
        assert result == "Hello 张三!"
        assert not buffer.has_pending

    def test_multiple_complete_placeholders(self, buffer):
        """Test multiple complete placeholders are replaced."""
        result = buffer.process_chunk("<PERSON_1>和<PERSON_2>是朋友")
        assert result == "张三和李四是朋友"
        assert not buffer.has_pending

    def test_flush_empty(self, buffer):
        """Test flush on empty buffer."""
        result = buffer.flush()
        assert result == ""


class TestStreamBufferSplitPlaceholder:
    """Tests for split placeholder handling."""

    def test_split_at_start(self, buffer):
        """Test placeholder split at the very start."""
        out1 = buffer.process_chunk("<PER")
        assert out1 == ""
        assert buffer.has_pending
        assert buffer.pending_length == 4

        out2 = buffer.process_chunk("SON_1>世界")
        assert out2 == "张三世界"
        assert not buffer.has_pending

    def test_split_in_middle(self, buffer):
        """Test placeholder split in the middle of text."""
        out1 = buffer.process_chunk("联系<PERS")
        assert out1 == "联系"
        assert buffer.has_pending

        out2 = buffer.process_chunk("ON_1>获取帮助")
        assert out2 == "张三获取帮助"
        assert not buffer.has_pending

    def test_split_after_complete(self, buffer):
        """Test split placeholder after a complete one."""
        out1 = buffer.process_chunk("<PERSON_1>的电话是<PHO")
        assert "张三" in out1
        assert buffer.has_pending

        out2 = buffer.process_chunk("NE_1>")
        assert "13800138000" in out2
        assert not buffer.has_pending

    def test_multiple_splits(self, buffer):
        """Test multiple chunk splits."""
        chunks = ["请联系<", "PERS", "ON_", "1>", "获取帮助"]
        outputs = []
        for chunk in chunks:
            outputs.append(buffer.process_chunk(chunk))
        final = buffer.flush()

        combined = "".join(outputs) + final
        assert combined == "请联系张三获取帮助"

    def test_flush_with_pending(self, buffer):
        """Test flush with incomplete placeholder."""
        out1 = buffer.process_chunk("Hello <PERS")
        assert out1 == "Hello "  # Safe portion already emitted
        result = buffer.flush()
        # Flush returns the remainder (incomplete placeholder)
        assert "<PERS" in result
        assert not buffer.has_pending
        # Combined output contains everything
        combined = out1 + result
        assert "Hello" in combined


class TestStreamBufferEdgeCases:
    """Edge case tests."""

    def test_less_than_not_placeholder(self, buffer):
        """Test < that's not a placeholder."""
        out1 = buffer.process_chunk("a < b > c")
        # "a " is safe, "< b > c" is buffered (could be start of placeholder)
        assert out1 == "a "
        # Flush returns the buffered content
        out2 = buffer.flush()
        assert "< b > c" in out2
        # Combined output has everything
        combined = out1 + out2
        assert "a < b > c" == combined

    def test_angle_brackets_in_text(self, buffer):
        """Test angle brackets that aren't placeholders."""
        out1 = buffer.process_chunk("Use <html>")
        out2 = buffer.flush()
        combined = out1 + out2
        assert "<html>" in combined or "html" in combined

    def test_very_long_non_placeholder(self, buffer):
        """Test very long content after < that exceeds max length."""
        # This is longer than MAX_PLACEHOLDER_LENGTH
        long_text = "Hello <" + "X" * 30 + "> world"
        result = buffer.process_chunk(long_text)
        final = buffer.flush()
        combined = result + final
        assert "Hello" in combined
        assert "world" in combined

    def test_single_character_chunks(self, buffer):
        """Test processing single character at a time."""
        text = "Hi <PERSON_1>!"
        outputs = []
        for char in text:
            outputs.append(buffer.process_chunk(char))
        final = buffer.flush()

        combined = "".join(outputs) + final
        assert combined == "Hi 张三!"

    def test_clear_buffer(self, buffer):
        """Test clearing the buffer."""
        buffer.process_chunk("Hello <PERS")
        assert buffer.has_pending
        buffer.clear()
        assert not buffer.has_pending
        assert buffer.pending_length == 0


class TestStreamBufferProperties:
    """Tests for buffer properties."""

    def test_has_pending_after_incomplete(self, buffer):
        """Test has_pending after incomplete placeholder."""
        buffer.process_chunk("<PERS")
        assert buffer.has_pending is True

    def test_pending_length(self, buffer):
        """Test pending_length calculation."""
        buffer.process_chunk("Hello <PERS")
        assert buffer.pending_length == 5  # "<PERS"

    def test_properties_after_flush(self, buffer):
        """Test properties after flush."""
        buffer.process_chunk("<PERSON_1>")
        buffer.flush()
        assert buffer.has_pending is False
        assert buffer.pending_length == 0


class TestStreamBufferRealWorld:
    """Real-world scenario tests."""

    def test_typical_llm_response(self, buffer):
        """Test typical LLM streaming response pattern."""
        # Simulate realistic chunk sizes from LLM
        chunks = [
            "您好，",
            "<PERSON_1>",
            "！\n\n您的电话号码",
            "<PHONE_1>",
            "已经登记成功。",
        ]

        outputs = []
        for chunk in chunks:
            outputs.append(buffer.process_chunk(chunk))
        final = buffer.flush()

        combined = "".join(outputs) + final
        assert "张三" in combined
        assert "13800138000" in combined
        assert "您好" in combined
        assert "登记成功" in combined

    def test_placeholder_at_chunk_boundary(self, buffer):
        """Test placeholder exactly at chunk boundary."""
        out1 = buffer.process_chunk("Name: ")
        out2 = buffer.process_chunk("<PERSON_1>")
        out3 = buffer.process_chunk(" Email: ")
        out4 = buffer.process_chunk("<EMAIL_1>")
        final = buffer.flush()

        combined = out1 + out2 + out3 + out4 + final
        assert "张三" in combined
        assert "test@example.com" in combined

    def test_chinese_text_with_placeholders(self, buffer):
        """Test Chinese text mixed with placeholders."""
        chunks = [
            "尊敬的",
            "<PERSON_1>",
            "先生/女士：\n\n感谢您的来信。我们已收到您的电话",
            "<PHONE_1>",
            "。",
        ]

        outputs = []
        for chunk in chunks:
            outputs.append(buffer.process_chunk(chunk))
        final = buffer.flush()

        combined = "".join(outputs) + final
        assert "张三" in combined
        assert "13800138000" in combined
        assert "感谢您的来信" in combined
