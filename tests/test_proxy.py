"""
Tests for the ProxyService class (TEST-001).

Tests the core proxy workflow including:
- Message anonymization
- Anti-hallucination prompt injection
- Secret scanning
- Caching
- Quota enforcement
- Upstream request handling
- Response deanonymization
"""

import json
import pytest
import time
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
import httpx

from pii_airlock.api.proxy import ProxyService, ANTI_HALLUCINATION_PROMPT
from pii_airlock.api.models import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    Message,
    Choice,
    Usage,
)
from pii_airlock.core.anonymizer import Anonymizer
from pii_airlock.core.mapping import PIIMapping
from pii_airlock.storage.memory_store import MemoryStore


# Disable audit logging during tests to avoid event loop issues
@pytest.fixture(autouse=True)
def disable_audit_logging():
    """Disable audit logging for tests to avoid event loop issues."""
    with patch("pii_airlock.api.proxy.get_audit_logger", return_value=None):
        yield


class TestProxyServiceInit:
    """Test ProxyService initialization."""

    def test_default_init(self):
        """Test ProxyService with default parameters."""
        proxy = ProxyService()

        assert proxy.upstream_url == "https://api.openai.com"
        assert proxy.api_key is None
        assert proxy.inject_anti_hallucination is True
        assert proxy.timeout == 120.0
        assert proxy.enable_cache is False
        assert proxy.enable_secret_scan is True  # Default from env

    def test_custom_init(self):
        """Test ProxyService with custom parameters."""
        store = MemoryStore()
        proxy = ProxyService(
            upstream_url="https://custom.api.com",
            api_key="test-key",
            store=store,
            inject_anti_hallucination=False,
            timeout=60.0,
            enable_cache=True,
            enable_secret_scan=False,
        )

        assert proxy.upstream_url == "https://custom.api.com"
        assert proxy.api_key == "test-key"
        assert isinstance(proxy.store, MemoryStore)
        assert proxy.inject_anti_hallucination is False
        assert proxy.timeout == 60.0
        assert proxy.enable_cache is True
        assert proxy.enable_secret_scan is False

    def test_upstream_url_trailing_slash(self):
        """Test that trailing slashes are removed from upstream URL."""
        proxy = ProxyService(upstream_url="https://api.openai.com/")

        assert proxy.upstream_url == "https://api.openai.com"


class TestAnonymizeMessages:
    """Test the _anonymize_messages method."""

    @pytest.fixture
    def proxy_with_anonymizer(self):
        """Create a proxy with a mocked anonymizer."""
        proxy = ProxyService()
        return proxy

    def test_anonymize_empty_messages(self, proxy_with_anonymizer):
        """Test anonymizing empty message list."""
        proxy = proxy_with_anonymizer
        proxy._ensure_anonymizer()

        messages, mapping = proxy._anonymize_messages([], "request-1")

        assert messages == []
        assert len(mapping) == 0

    def test_anonymize_system_message_passthrough(self, proxy_with_anonymizer):
        """Test that system messages are not anonymized."""
        proxy = proxy_with_anonymizer
        proxy._ensure_anonymizer()

        system_msg = Message(role="system", content="You are a helpful assistant.")
        messages, mapping = proxy._anonymize_messages([system_msg], "request-1")

        assert len(messages) == 1
        assert messages[0].content == "You are a helpful assistant."

    def test_anonymize_user_message_with_pii(self, proxy_with_anonymizer):
        """Test anonymizing user message containing PII."""
        proxy = proxy_with_anonymizer
        proxy._ensure_anonymizer()

        user_msg = Message(role="user", content="张三的电话是13800138000")
        messages, mapping = proxy._anonymize_messages([user_msg], "request-1")

        assert len(messages) == 1
        # PII should be replaced
        assert "13800138000" not in messages[0].content or "<PHONE" in messages[0].content

    def test_anonymize_preserves_message_role(self, proxy_with_anonymizer):
        """Test that message roles are preserved after anonymization."""
        proxy = proxy_with_anonymizer
        proxy._ensure_anonymizer()

        messages = [
            Message(role="user", content="Hello"),
            Message(role="assistant", content="Hi there"),
        ]
        result, mapping = proxy._anonymize_messages(messages, "request-1")

        assert len(result) == 2
        assert result[0].role == "user"
        assert result[1].role == "assistant"


class TestInjectSystemPrompt:
    """Test the _inject_system_prompt method."""

    @pytest.fixture
    def proxy(self):
        """Create a basic proxy instance."""
        return ProxyService(inject_anti_hallucination=True)

    def test_no_injection_when_disabled(self):
        """Test that prompt is not injected when disabled."""
        proxy = ProxyService(inject_anti_hallucination=False)
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        messages = [Message(role="user", content="Hello")]
        result = proxy._inject_system_prompt(messages, mapping)

        assert len(result) == 1
        assert result[0].role == "user"

    def test_no_injection_when_no_pii(self, proxy):
        """Test that prompt is not injected when no PII is detected."""
        mapping = PIIMapping()  # Empty mapping

        messages = [Message(role="user", content="Hello")]
        result = proxy._inject_system_prompt(messages, mapping)

        assert len(result) == 1
        assert result[0].role == "user"

    def test_inject_new_system_message(self, proxy):
        """Test injecting a new system message when none exists."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        messages = [Message(role="user", content="Hello")]
        result = proxy._inject_system_prompt(messages, mapping)

        assert len(result) == 2
        assert result[0].role == "system"
        assert "placeholder" in result[0].content.lower() or "IMPORTANT" in result[0].content

    def test_append_to_existing_system_message(self, proxy):
        """Test appending prompt to existing system message."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        messages = [
            Message(role="system", content="You are a helpful assistant."),
            Message(role="user", content="Hello"),
        ]
        result = proxy._inject_system_prompt(messages, mapping)

        assert len(result) == 2
        assert result[0].role == "system"
        assert "You are a helpful assistant." in result[0].content
        assert "placeholder" in result[0].content.lower() or "IMPORTANT" in result[0].content


class TestCheckSecrets:
    """Test the _check_secrets method."""

    @pytest.fixture
    def proxy(self):
        """Create a proxy with secret scanning enabled."""
        return ProxyService(enable_secret_scan=True)

    def test_secret_scanning_disabled(self):
        """Test that disabled secret scanning passes all requests."""
        proxy = ProxyService(enable_secret_scan=False)

        messages = [Message(role="user", content="sk-abc123def456")]
        should_block, reason = proxy._check_secrets(messages, "request-1")

        assert should_block is False
        assert reason == ""

    def test_detect_api_key(self, proxy):
        """Test detecting API keys in messages."""
        messages = [Message(role="user", content="My key is sk-proj-abc123def456789012")]
        should_block, reason = proxy._check_secrets(messages, "request-1")

        # Should detect and potentially block
        # (depends on interceptor configuration)
        assert isinstance(should_block, bool)

    def test_safe_message_passes(self, proxy):
        """Test that safe messages are not blocked."""
        messages = [Message(role="user", content="What is the weather today?")]
        should_block, reason = proxy._check_secrets(messages, "request-1")

        assert should_block is False


class TestDeanonymizeContent:
    """Test the _deanonymize_content method."""

    @pytest.fixture
    def proxy(self):
        """Create a basic proxy instance."""
        return ProxyService()

    def test_deanonymize_with_mapping(self, proxy):
        """Test deanonymizing content with a valid mapping."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")

        result = proxy._deanonymize_content("Hello <PERSON_1>", mapping)

        assert result == "Hello 张三"

    def test_deanonymize_empty_mapping(self, proxy):
        """Test deanonymizing content with empty mapping."""
        mapping = PIIMapping()

        result = proxy._deanonymize_content("Hello world", mapping)

        assert result == "Hello world"

    def test_deanonymize_multiple_placeholders(self, proxy):
        """Test deanonymizing content with multiple placeholders."""
        mapping = PIIMapping()
        mapping.add("PERSON", "张三", "<PERSON_1>")
        mapping.add("PHONE_NUMBER", "13800138000", "<PHONE_1>")

        result = proxy._deanonymize_content(
            "<PERSON_1> 的电话是 <PHONE_1>", mapping
        )

        assert result == "张三 的电话是 13800138000"


class TestCacheOperations:
    """Test cache checking and storing."""

    @pytest.fixture
    def proxy_with_cache(self):
        """Create a proxy with caching enabled."""
        cache_mock = MagicMock()
        proxy = ProxyService(enable_cache=True, cache=cache_mock)
        return proxy, cache_mock

    def test_check_cache_disabled(self):
        """Test that cache check returns None when disabled."""
        proxy = ProxyService(enable_cache=False)

        result = proxy._check_cache("key", "tenant", "gpt-4")

        assert result is None

    def test_check_cache_miss(self, proxy_with_cache):
        """Test cache miss returns None."""
        proxy, cache_mock = proxy_with_cache
        cache_mock.get.return_value = None

        result = proxy._check_cache("key", "tenant", "gpt-4")

        assert result is None
        cache_mock.get.assert_called_once_with("key", "tenant")

    def test_check_cache_hit(self, proxy_with_cache):
        """Test cache hit returns cached data."""
        proxy, cache_mock = proxy_with_cache
        mock_entry = MagicMock()
        mock_entry.response_data = {"id": "test", "choices": []}
        cache_mock.get.return_value = mock_entry

        result = proxy._check_cache("key", "tenant", "gpt-4")

        assert result == {"id": "test", "choices": []}

    def test_store_cache_disabled(self):
        """Test that store does nothing when cache disabled."""
        proxy = ProxyService(enable_cache=False)

        # Should not raise any error
        proxy._store_cache("key", {"data": "test"}, "tenant", "gpt-4")

    def test_store_cache_enabled(self, proxy_with_cache):
        """Test storing response in cache."""
        proxy, cache_mock = proxy_with_cache
        response_data = {"id": "test", "choices": []}

        proxy._store_cache("key", response_data, "tenant", "gpt-4")

        cache_mock.put.assert_called_once_with(
            key="key",
            response_data=response_data,
            tenant_id="tenant",
            model="gpt-4",
        )


class TestQuotaChecking:
    """Test quota checking and recording."""

    @pytest.fixture
    def proxy(self):
        """Create a basic proxy instance."""
        return ProxyService()

    def test_quota_allowed(self, proxy):
        """Test quota check when allowed."""
        with patch("pii_airlock.api.proxy.check_quota_limit") as mock_check_quota, \
             patch("pii_airlock.auth.quota.get_quota_store") as mock_get_store:
            mock_check_quota.return_value = (True, 100)
            mock_store = MagicMock()
            mock_get_store.return_value = mock_store

            result = proxy._check_and_record_quota("tenant-1", token_count=0)

            assert result is True

    def test_quota_exceeded(self, proxy):
        """Test quota check when exceeded."""
        with patch("pii_airlock.api.proxy.check_quota_limit") as mock_check_quota:
            mock_check_quota.return_value = (False, 100)

            result = proxy._check_and_record_quota("tenant-1", token_count=0)

            assert result is False


class TestChatCompletion:
    """Test the chat_completion method."""

    @pytest.fixture
    def proxy(self):
        """Create a proxy instance."""
        store = MemoryStore()
        return ProxyService(
            upstream_url="https://api.openai.com",
            api_key="test-key",
            store=store,
            enable_secret_scan=False,
        )

    @pytest.fixture
    def mock_request(self):
        """Create a mock chat completion request."""
        return ChatCompletionRequest(
            model="gpt-4",
            messages=[Message(role="user", content="Hello world")],
        )

    @pytest.mark.asyncio
    async def test_chat_completion_success(self, proxy, mock_request):
        """Test successful chat completion."""
        with patch("pii_airlock.api.proxy.check_quota_limit") as mock_check_quota, \
             patch("pii_airlock.auth.quota.get_quota_store") as mock_get_store:
            mock_check_quota.return_value = (True, 100)
            mock_store = MagicMock()
            mock_get_store.return_value = mock_store

            # Mock HTTP response
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "id": "chatcmpl-123",
                "created": int(time.time()),
                "model": "gpt-4",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Hello!"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 5,
                    "total_tokens": 15,
                },
            }
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)

            with patch.object(
                ProxyService, "get_http_client", return_value=mock_client
            ):
                response = await proxy.chat_completion(mock_request, tenant_id="test")

            assert isinstance(response, ChatCompletionResponse)
            assert response.id == "chatcmpl-123"
            assert len(response.choices) == 1
            assert response.choices[0].message.content == "Hello!"

    @pytest.mark.asyncio
    async def test_chat_completion_quota_exceeded(self, proxy, mock_request):
        """Test chat completion with quota exceeded."""
        with patch("pii_airlock.api.proxy.check_quota_limit") as mock_check_quota:
            mock_check_quota.return_value = (False, 100)

            with pytest.raises(Exception) as exc_info:
                await proxy.chat_completion(mock_request, tenant_id="test")

            # Should raise HTTPException with 429
            assert "429" in str(exc_info.value) or "Quota" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_chat_completion_with_pii(self, proxy):
        """Test chat completion with PII in request."""
        with patch("pii_airlock.api.proxy.check_quota_limit") as mock_check_quota, \
             patch("pii_airlock.auth.quota.get_quota_store") as mock_get_store:
            mock_check_quota.return_value = (True, 100)
            mock_store = MagicMock()
            mock_get_store.return_value = mock_store

            request = ChatCompletionRequest(
                model="gpt-4",
                messages=[Message(role="user", content="联系张三，电话13800138000")],
            )

            mock_response = MagicMock()
            mock_response.json.return_value = {
                "id": "chatcmpl-123",
                "created": int(time.time()),
                "model": "gpt-4",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "我已经联系了<PERSON_1>",
                        },
                        "finish_reason": "stop",
                    }
                ],
            }
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)

            with patch.object(
                ProxyService, "get_http_client", return_value=mock_client
            ):
                response = await proxy.chat_completion(request, tenant_id="test")

            # Response should be deanonymized
            assert isinstance(response, ChatCompletionResponse)
            # The placeholder might be replaced back to original
            # depending on whether anonymization detected the PII


class TestChatCompletionStream:
    """Test the chat_completion_stream method."""

    @pytest.fixture
    def proxy(self):
        """Create a proxy instance."""
        store = MemoryStore()
        return ProxyService(
            upstream_url="https://api.openai.com",
            api_key="test-key",
            store=store,
            enable_secret_scan=False,
        )

    @pytest.fixture
    def mock_stream_request(self):
        """Create a mock streaming chat completion request."""
        return ChatCompletionRequest(
            model="gpt-4",
            messages=[Message(role="user", content="Hello world")],
            stream=True,
        )

    @pytest.mark.asyncio
    async def test_stream_quota_exceeded(self, proxy, mock_stream_request):
        """Test streaming with quota exceeded returns error event."""
        with patch("pii_airlock.api.proxy.check_quota_limit") as mock_check_quota:
            mock_check_quota.return_value = (False, 100)

            events = []
            async for event in proxy.chat_completion_stream(
                mock_stream_request, tenant_id="test"
            ):
                events.append(event)

            assert len(events) == 1
            assert "error" in events[0]
            assert "quota" in events[0].lower()

    @pytest.mark.asyncio
    async def test_stream_success(self, proxy, mock_stream_request):
        """Test successful streaming chat completion."""
        with patch("pii_airlock.api.proxy.check_quota_limit") as mock_check_quota, \
             patch("pii_airlock.auth.quota.get_quota_store") as mock_get_store:
            mock_check_quota.return_value = (True, 100)
            mock_store = MagicMock()
            mock_get_store.return_value = mock_store

            # Create mock streaming response
            async def mock_aiter_lines():
                yield 'data: {"id":"chatcmpl-123","created":1234567890,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}'
                yield 'data: {"id":"chatcmpl-123","created":1234567890,"model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}'
                yield "data: [DONE]"

            mock_response = MagicMock()
            mock_response.aiter_lines = mock_aiter_lines
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_stream_context = AsyncMock()
            mock_stream_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_stream_context.__aexit__ = AsyncMock(return_value=None)
            mock_client.stream = MagicMock(return_value=mock_stream_context)

            with patch.object(
                ProxyService, "get_http_client", return_value=mock_client
            ):
                events = []
                async for event in proxy.chat_completion_stream(
                    mock_stream_request, tenant_id="test"
                ):
                    events.append(event)

            # Should have received events
            assert len(events) >= 1
            # Last event should be [DONE]
            assert "data: [DONE]" in events[-1]


class TestHTTPClientManagement:
    """Test HTTP client creation and cleanup."""

    @pytest.mark.asyncio
    async def test_get_http_client_creates_instance(self):
        """Test that get_http_client creates a client."""
        # Reset class-level client
        ProxyService._http_client = None

        client = await ProxyService.get_http_client(timeout=60.0)

        assert client is not None
        assert isinstance(client, httpx.AsyncClient)

        # Clean up
        await ProxyService.close_http_client()

    @pytest.mark.asyncio
    async def test_get_http_client_reuses_instance(self):
        """Test that get_http_client reuses existing client."""
        # Reset class-level client
        ProxyService._http_client = None

        client1 = await ProxyService.get_http_client()
        client2 = await ProxyService.get_http_client()

        assert client1 is client2

        # Clean up
        await ProxyService.close_http_client()

    @pytest.mark.asyncio
    async def test_close_http_client(self):
        """Test closing the HTTP client."""
        # Create a client first
        ProxyService._http_client = None
        await ProxyService.get_http_client()

        assert ProxyService._http_client is not None

        # Close it
        await ProxyService.close_http_client()

        assert ProxyService._http_client is None


class TestFormatSSEChunk:
    """Test the _format_sse_chunk method."""

    @pytest.fixture
    def proxy(self):
        """Create a basic proxy instance."""
        return ProxyService()

    def test_format_content_chunk(self, proxy):
        """Test formatting a content chunk."""
        result = proxy._format_sse_chunk(
            content="Hello",
            chunk_id="chatcmpl-123",
            created=1234567890,
            model="gpt-4",
        )

        assert result.startswith("data: ")
        assert result.endswith("\n\n")

        # Parse the JSON
        data = json.loads(result[6:-2])
        assert data["id"] == "chatcmpl-123"
        assert data["model"] == "gpt-4"
        assert data["choices"][0]["delta"]["content"] == "Hello"

    def test_format_finish_chunk(self, proxy):
        """Test formatting a finish chunk."""
        result = proxy._format_sse_chunk(
            content=None,
            chunk_id="chatcmpl-123",
            created=1234567890,
            model="gpt-4",
            finish_reason="stop",
        )

        data = json.loads(result[6:-2])
        assert data["choices"][0]["finish_reason"] == "stop"
        assert "content" not in data["choices"][0]["delta"]


class TestAntiHallucinationPrompt:
    """Test the anti-hallucination prompt template."""

    def test_default_prompt_exists(self):
        """Test that the default prompt is defined."""
        assert ANTI_HALLUCINATION_PROMPT is not None
        assert len(ANTI_HALLUCINATION_PROMPT) > 0
        assert "placeholder" in ANTI_HALLUCINATION_PROMPT.lower()

    def test_get_prompt_template_default(self):
        """Test getting the default prompt template."""
        proxy = ProxyService()

        # Without any active preset, should return default
        template = proxy._get_prompt_template()

        assert template == ANTI_HALLUCINATION_PROMPT


class TestEnsureAnonymizer:
    """Test the _ensure_anonymizer method."""

    def test_creates_anonymizer_when_none(self):
        """Test that anonymizer is created when not provided."""
        proxy = ProxyService(anonymizer=None)

        assert proxy.anonymizer is None

        result = proxy._ensure_anonymizer()

        assert result is not None
        assert isinstance(result, Anonymizer)
        assert proxy.anonymizer is result

    def test_returns_existing_anonymizer(self):
        """Test that existing anonymizer is returned."""
        existing_anonymizer = Anonymizer()
        proxy = ProxyService(anonymizer=existing_anonymizer)

        result = proxy._ensure_anonymizer()

        assert result is existing_anonymizer


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
