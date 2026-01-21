"""Unit tests for streaming functionality."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from contextlib import asynccontextmanager
from httpx import Response

from pii_airlock.api.proxy import ProxyService
from pii_airlock.api.models import ChatCompletionRequest, Message
from pii_airlock.core.mapping import PIIMapping
from pii_airlock.storage.memory_store import MemoryStore


def make_sse_line(content: str = None, finish_reason: str = None, done: bool = False) -> str:
    """Create an SSE line for testing."""
    if done:
        return "data: [DONE]"

    delta = {}
    if content is not None:
        delta["content"] = content

    chunk = {
        "id": "chatcmpl-test123",
        "object": "chat.completion.chunk",
        "created": 1234567890,
        "model": "gpt-4",
        "choices": [
            {
                "index": 0,
                "delta": delta,
                "finish_reason": finish_reason,
            }
        ],
    }
    return f"data: {json.dumps(chunk)}"


class AsyncIteratorMock:
    """Mock async iterator for SSE lines."""

    def __init__(self, lines: list[str]):
        self.lines = lines
        self.index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.index >= len(self.lines):
            raise StopAsyncIteration
        line = self.lines[self.index]
        self.index += 1
        return line


class MockStreamResponse:
    """Mock streaming response."""

    def __init__(self, lines: list[str]):
        self.lines = lines

    def raise_for_status(self):
        pass

    def aiter_lines(self):
        return AsyncIteratorMock(self.lines)


@asynccontextmanager
async def mock_stream_context(response):
    """Async context manager for mock stream."""
    yield response


@asynccontextmanager
async def mock_client_context(mock_client):
    """Async context manager for mock client."""
    yield mock_client


@pytest.fixture
def proxy():
    """Create a proxy service for testing."""
    return ProxyService(
        upstream_url="https://api.example.com",
        api_key="test-key",
        inject_anti_hallucination=False,  # Simplify tests
    )


@pytest.fixture
def simple_request():
    """Create a simple streaming request."""
    return ChatCompletionRequest(
        model="gpt-4",
        messages=[Message(role="user", content="Hello")],
        stream=True,
    )


@pytest.fixture
def pii_request():
    """Create a request with PII."""
    return ChatCompletionRequest(
        model="gpt-4",
        messages=[Message(role="user", content="张三的电话是13800138000")],
        stream=True,
    )


class TestStreamingBasic:
    """Basic streaming tests."""

    @pytest.mark.asyncio
    async def test_stream_simple_response(self, proxy, simple_request):
        """Test streaming a simple response without PII."""
        sse_lines = [
            make_sse_line(content="Hello"),
            make_sse_line(content=" world"),
            make_sse_line(content="!"),
            make_sse_line(finish_reason="stop"),
            make_sse_line(done=True),
        ]

        mock_response = MockStreamResponse(sse_lines)

        # Create a mock client with stream method
        mock_client = MagicMock()
        mock_client.stream.return_value = mock_stream_context(mock_response)

        with patch.object(ProxyService, "get_http_client", new_callable=AsyncMock) as mock_get_client:
            mock_get_client.return_value = mock_client

            chunks = []
            async for chunk in proxy.chat_completion_stream(simple_request):
                chunks.append(chunk)

        # Verify we got SSE-formatted output
        assert len(chunks) > 0
        assert chunks[-1] == "data: [DONE]\n\n"

        # Extract content from all chunks
        content_parts = []
        for chunk in chunks[:-1]:  # Skip [DONE]
            if chunk.startswith("data: "):
                data = json.loads(chunk[6:].strip())
                delta_content = data["choices"][0]["delta"].get("content")
                if delta_content:
                    content_parts.append(delta_content)

        combined = "".join(content_parts)
        assert "Hello" in combined
        assert "world" in combined

    @pytest.mark.asyncio
    async def test_stream_empty_deltas(self, proxy, simple_request):
        """Test handling of chunks with empty deltas."""
        sse_lines = [
            make_sse_line(content="Hi"),
            "data: {\"id\":\"test\",\"object\":\"chat.completion.chunk\",\"created\":123,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":null}]}",
            make_sse_line(content="!"),
            make_sse_line(finish_reason="stop"),
            make_sse_line(done=True),
        ]

        mock_response = MockStreamResponse(sse_lines)

        mock_client = MagicMock()
        mock_client.stream.return_value = mock_stream_context(mock_response)

        with patch.object(ProxyService, "get_http_client", new_callable=AsyncMock) as mock_get_client:
            mock_get_client.return_value = mock_client

            chunks = []
            async for chunk in proxy.chat_completion_stream(simple_request):
                chunks.append(chunk)

        # Should still work with empty deltas
        assert len(chunks) > 0
        assert chunks[-1] == "data: [DONE]\n\n"


class TestStreamingPIIDeanonymization:
    """Tests for PII deanonymization in streaming."""

    @pytest.mark.asyncio
    async def test_stream_complete_placeholder(self, proxy, pii_request):
        """Test deanonymization of complete placeholder in stream."""
        # LLM returns anonymized content
        sse_lines = [
            make_sse_line(content="您好，"),
            make_sse_line(content="<PERSON_1>"),
            make_sse_line(content="！"),
            make_sse_line(finish_reason="stop"),
            make_sse_line(done=True),
        ]

        mock_response = MockStreamResponse(sse_lines)

        mock_client = MagicMock()
        mock_client.stream.return_value = mock_stream_context(mock_response)

        with patch.object(ProxyService, "get_http_client", new_callable=AsyncMock) as mock_get_client:
            mock_get_client.return_value = mock_client

            chunks = []
            async for chunk in proxy.chat_completion_stream(pii_request):
                chunks.append(chunk)

        # Extract all content
        content_parts = []
        for chunk in chunks:
            if chunk.startswith("data: ") and chunk.strip() != "data: [DONE]":
                try:
                    data = json.loads(chunk[6:].strip())
                    delta_content = data["choices"][0]["delta"].get("content")
                    if delta_content:
                        content_parts.append(delta_content)
                except json.JSONDecodeError:
                    pass

        combined = "".join(content_parts)
        # Placeholder should be replaced with original
        assert "张三" in combined
        assert "<PERSON_1>" not in combined

    @pytest.mark.asyncio
    async def test_stream_split_placeholder(self, proxy, pii_request):
        """Test deanonymization when placeholder is split across chunks."""
        # Simulate placeholder split: "<PER" + "SON_1>"
        sse_lines = [
            make_sse_line(content="联系"),
            make_sse_line(content="<PER"),
            make_sse_line(content="SON_1>"),
            make_sse_line(content="吧"),
            make_sse_line(finish_reason="stop"),
            make_sse_line(done=True),
        ]

        mock_response = MockStreamResponse(sse_lines)

        mock_client = MagicMock()
        mock_client.stream.return_value = mock_stream_context(mock_response)

        with patch.object(ProxyService, "get_http_client", new_callable=AsyncMock) as mock_get_client:
            mock_get_client.return_value = mock_client

            chunks = []
            async for chunk in proxy.chat_completion_stream(pii_request):
                chunks.append(chunk)

        # Extract all content
        content_parts = []
        for chunk in chunks:
            if chunk.startswith("data: ") and chunk.strip() != "data: [DONE]":
                try:
                    data = json.loads(chunk[6:].strip())
                    delta_content = data["choices"][0]["delta"].get("content")
                    if delta_content:
                        content_parts.append(delta_content)
                except json.JSONDecodeError:
                    pass

        combined = "".join(content_parts)
        # Even with split, should be properly deanonymized
        assert "张三" in combined
        assert "<PER" not in combined
        assert "SON_1>" not in combined


class TestStreamingSSEFormat:
    """Tests for SSE format correctness."""

    @pytest.mark.asyncio
    async def test_sse_chunk_format(self, proxy, simple_request):
        """Test that output chunks are properly SSE formatted."""
        sse_lines = [
            make_sse_line(content="Test"),
            make_sse_line(finish_reason="stop"),
            make_sse_line(done=True),
        ]

        mock_response = MockStreamResponse(sse_lines)

        mock_client = MagicMock()
        mock_client.stream.return_value = mock_stream_context(mock_response)

        with patch.object(ProxyService, "get_http_client", new_callable=AsyncMock) as mock_get_client:
            mock_get_client.return_value = mock_client

            chunks = []
            async for chunk in proxy.chat_completion_stream(simple_request):
                chunks.append(chunk)

        # All chunks should be SSE formatted
        for chunk in chunks:
            assert chunk.startswith("data: ")
            assert chunk.endswith("\n\n")

    @pytest.mark.asyncio
    async def test_sse_chunk_structure(self, proxy, simple_request):
        """Test that SSE chunks have correct JSON structure."""
        sse_lines = [
            make_sse_line(content="Hello"),
            make_sse_line(finish_reason="stop"),
            make_sse_line(done=True),
        ]

        mock_response = MockStreamResponse(sse_lines)

        mock_client = MagicMock()
        mock_client.stream.return_value = mock_stream_context(mock_response)

        with patch.object(ProxyService, "get_http_client", new_callable=AsyncMock) as mock_get_client:
            mock_get_client.return_value = mock_client

            chunks = []
            async for chunk in proxy.chat_completion_stream(simple_request):
                chunks.append(chunk)

        # Check structure of non-DONE chunks
        for chunk in chunks[:-1]:  # Skip [DONE]
            data = json.loads(chunk[6:].strip())
            assert "id" in data
            assert "object" in data
            assert data["object"] == "chat.completion.chunk"
            assert "created" in data
            assert "model" in data
            assert "choices" in data
            assert len(data["choices"]) > 0
            assert "delta" in data["choices"][0]


class TestStreamingCleanup:
    """Tests for resource cleanup after streaming."""

    @pytest.mark.asyncio
    async def test_mapping_cleanup_on_success(self, proxy, simple_request):
        """Test that mapping is cleaned up after successful stream."""
        sse_lines = [
            make_sse_line(content="Done"),
            make_sse_line(finish_reason="stop"),
            make_sse_line(done=True),
        ]

        mock_response = MockStreamResponse(sse_lines)

        mock_client = MagicMock()
        mock_client.stream.return_value = mock_stream_context(mock_response)

        with patch.object(ProxyService, "get_http_client", new_callable=AsyncMock) as mock_get_client:
            mock_get_client.return_value = mock_client

            # Consume the stream
            async for _ in proxy.chat_completion_stream(simple_request):
                pass

        # Store should be empty after cleanup
        assert len(proxy.store._store) == 0

    @pytest.mark.asyncio
    async def test_mapping_cleanup_on_error(self, proxy, simple_request):
        """Test that mapping is cleaned up even on error."""

        class ErrorResponse:
            def raise_for_status(self):
                raise Exception("Connection error")

        mock_response = ErrorResponse()

        mock_client = MagicMock()
        mock_client.stream.return_value = mock_stream_context(mock_response)

        with patch.object(ProxyService, "get_http_client", new_callable=AsyncMock) as mock_get_client:
            mock_get_client.return_value = mock_client

            with pytest.raises(Exception, match="Connection error"):
                async for _ in proxy.chat_completion_stream(simple_request):
                    pass

        # Store should still be empty after cleanup
        assert len(proxy.store._store) == 0
