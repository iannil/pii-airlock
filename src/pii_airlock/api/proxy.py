"""
Proxy logic for forwarding requests to upstream LLM APIs.

Handles the core workflow:
1. Intercept request
2. Anonymize PII in messages
3. Check cache (if enabled)
4. Forward to upstream (if cache miss)
5. Deanonymize PII in response
6. Return to client

Supports:
- Multi-tenant isolation
- LLM response caching
- Quota enforcement
"""

import json
import time
import uuid
import httpx
from typing import Optional, AsyncIterator, ClassVar

from pii_airlock.core.anonymizer import Anonymizer, AnonymizationResult
from pii_airlock.core.deanonymizer import Deanonymizer
from pii_airlock.core.mapping import PIIMapping
from pii_airlock.core.stream_buffer import StreamBuffer
from pii_airlock.storage.memory_store import MemoryStore
from pii_airlock.api.models import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatCompletionChunk,
    StreamChoice,
    Message,
    Choice,
    Usage,
)
from pii_airlock.logging.setup import get_logger
from pii_airlock.metrics.collectors import (
    PII_DETECTED,
    UPSTREAM_LATENCY,
    UPSTREAM_ERRORS,
    QUOTA_EXCEEDED,
)
from pii_airlock.cache.llm_cache import LLMCache, get_cache_key
from pii_airlock.auth.quota import QuotaType, check_quota as check_quota_limit

logger = get_logger(__name__)


# System prompt to prevent LLM from modifying placeholders
ANTI_HALLUCINATION_PROMPT = """IMPORTANT: This text contains placeholders in the format <TYPE_N> (e.g., <PERSON_1>, <PHONE_2>).
You MUST preserve these placeholders exactly as they appear. Do not modify, translate, or explain them.
Return them exactly in your response when referring to the same entities."""


class ProxyService:
    """Core proxy service for PII protection.

    This service orchestrates the anonymization workflow:
    - Intercepts incoming requests
    - Anonymizes PII in message content
    - Checks quota limits
    - Checks cache for cached responses
    - Forwards requests to upstream LLM (if cache miss)
    - Stores response in cache (if cache miss)
    - Deanonymizes PII in responses
    - Returns clean responses to clients

    Supports multi-tenant isolation, response caching, and quota enforcement.

    Example:
        >>> proxy = ProxyService(
        ...     upstream_url="https://api.openai.com",
        ...     api_key="sk-xxx"
        ... )
        >>> response = await proxy.chat_completion(request)
    """

    # Class-level HTTP client for connection pooling
    _http_client: ClassVar[Optional[httpx.AsyncClient]] = None

    @classmethod
    async def get_http_client(cls, timeout: float = 120.0) -> httpx.AsyncClient:
        """Get or create the shared HTTP client.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            Shared httpx.AsyncClient instance.
        """
        if cls._http_client is None:
            cls._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(timeout),
                limits=httpx.Limits(
                    max_keepalive_connections=20,
                    max_connections=100,
                ),
            )
        return cls._http_client

    @classmethod
    async def close_http_client(cls) -> None:
        """Close the shared HTTP client."""
        if cls._http_client is not None:
            await cls._http_client.aclose()
            cls._http_client = None

    def __init__(
        self,
        upstream_url: str = "https://api.openai.com",
        api_key: Optional[str] = None,
        store: Optional[MemoryStore] = None,
        anonymizer: Optional[Anonymizer] = None,
        inject_anti_hallucination: bool = True,
        timeout: float = 120.0,
        cache: Optional[LLMCache] = None,
        enable_cache: bool = False,
    ) -> None:
        """Initialize the proxy service.

        Args:
            upstream_url: Base URL of the upstream LLM API.
            api_key: API key for upstream authentication.
            store: Storage backend for mappings (default: MemoryStore).
            anonymizer: Anonymizer instance (default: creates new one).
            inject_anti_hallucination: Whether to inject anti-hallucination prompt.
            timeout: Request timeout in seconds.
            cache: Optional LLM cache instance.
            enable_cache: Whether response caching is enabled.
        """
        self.upstream_url = upstream_url.rstrip("/")
        self.api_key = api_key
        self.store = store or MemoryStore()
        self.anonymizer = anonymizer
        self.deanonymizer = Deanonymizer()
        self.inject_anti_hallucination = inject_anti_hallucination
        self.timeout = timeout
        self.cache = cache
        self.enable_cache = enable_cache

        # Lazy initialization of anonymizer (requires spaCy model)
        self._anonymizer_initialized = False

    def _ensure_anonymizer(self) -> Anonymizer:
        """Ensure anonymizer is initialized (lazy loading)."""
        if self.anonymizer is None:
            self.anonymizer = Anonymizer()
        return self.anonymizer

    def _anonymize_messages(
        self,
        messages: list[Message],
        request_id: str,
    ) -> tuple[list[Message], PIIMapping]:
        """Anonymize PII in all messages.

        Args:
            messages: List of conversation messages.
            request_id: Unique request identifier.

        Returns:
            Tuple of (anonymized messages, combined mapping).
        """
        anonymizer = self._ensure_anonymizer()
        combined_mapping = PIIMapping(session_id=request_id)
        anonymized_messages = []

        # Track PII counts by type for metrics
        pii_counts: dict[str, int] = {}

        for msg in messages:
            # Skip system messages (don't anonymize instructions)
            if msg.role == "system":
                anonymized_messages.append(msg)
                continue

            result = anonymizer.anonymize(msg.content, session_id=request_id)

            # Merge mappings and track PII counts
            for entry in result.mapping._entries:
                if not combined_mapping.get_placeholder(
                    entry.entity_type, entry.original_value
                ):
                    combined_mapping.add(
                        entry.entity_type,
                        entry.original_value,
                        entry.placeholder,
                    )
                    # Track PII counts
                    pii_counts[entry.entity_type] = pii_counts.get(entry.entity_type, 0) + 1

            anonymized_messages.append(
                Message(
                    role=msg.role,
                    content=result.text,
                    name=msg.name,
                )
            )

        # Record PII detection metrics
        for entity_type, count in pii_counts.items():
            PII_DETECTED.labels(entity_type=entity_type).inc(count)

        # Log anonymization result
        if pii_counts:
            logger.info(
                "PII anonymization completed",
                extra={
                    "event": "pii_anonymized",
                    "pii_counts": pii_counts,
                    "total_entities": sum(pii_counts.values()),
                    "message_count": len(messages),
                },
            )
        else:
            logger.debug(
                "No PII detected in messages",
                extra={
                    "event": "no_pii_detected",
                    "message_count": len(messages),
                },
            )

        return anonymized_messages, combined_mapping

    def _inject_system_prompt(
        self,
        messages: list[Message],
        mapping: PIIMapping,
    ) -> list[Message]:
        """Inject anti-hallucination system prompt if needed.

        Args:
            messages: List of messages.
            mapping: The PII mapping (to check if any PII was found).

        Returns:
            Messages with optional system prompt prepended.
        """
        if not self.inject_anti_hallucination:
            return messages

        if len(mapping) == 0:
            return messages

        # Check if there's already a system message
        if messages and messages[0].role == "system":
            # Append to existing system message
            updated_system = Message(
                role="system",
                content=f"{messages[0].content}\n\n{ANTI_HALLUCINATION_PROMPT}",
                name=messages[0].name,
            )
            return [updated_system] + messages[1:]
        else:
            # Prepend new system message
            system_msg = Message(role="system", content=ANTI_HALLUCINATION_PROMPT)
            return [system_msg] + messages

    def _deanonymize_content(self, content: str, mapping: PIIMapping) -> str:
        """Deanonymize content using mapping.

        Args:
            content: Text potentially containing placeholders.
            mapping: The PII mapping.

        Returns:
            Text with placeholders replaced by original values.
        """
        result = self.deanonymizer.deanonymize(content, mapping)
        return result.text

    def _check_cache(
        self,
        cache_key: str,
        tenant_id: str,
        model: str,
    ) -> Optional[dict]:
        """Check cache for a cached response.

        Args:
            cache_key: Cache key to look up.
            tenant_id: Tenant identifier.
            model: Model name.

        Returns:
            Cached response dict if found, None otherwise.
        """
        if not self.enable_cache or not self.cache:
            return None

        entry = self.cache.get(cache_key, tenant_id)
        if entry:
            logger.info(
                "Cache hit for request",
                extra={
                    "event": "cache_hit",
                    "tenant_id": tenant_id,
                    "model": model,
                    "cache_key": cache_key[:16] + "...",
                },
            )
            return entry.response_data
        return None

    def _store_cache(
        self,
        cache_key: str,
        response_data: dict,
        tenant_id: str,
        model: str,
    ) -> None:
        """Store response in cache.

        Args:
            cache_key: Cache key to store under.
            response_data: Response JSON to cache.
            tenant_id: Tenant identifier.
            model: Model name.
        """
        if not self.enable_cache or not self.cache:
            return

        self.cache.put(
            key=cache_key,
            response_data=response_data,
            tenant_id=tenant_id,
            model=model,
        )
        logger.debug(
            "Response cached",
            extra={
                "event": "cache_stored",
                "tenant_id": tenant_id,
                "model": model,
                "cache_key": cache_key[:16] + "...",
            },
        )

    def _check_and_record_quota(
        self,
        tenant_id: str,
        token_count: int = 0,
    ) -> bool:
        """Check quota and record usage.

        Args:
            tenant_id: Tenant identifier.
            token_count: Number of tokens to record.

        Returns:
            True if within quota, False otherwise.

        Raises:
            QuotaExceededError: If quota limit is exceeded.
        """
        # Check request quota
        allowed, limit = check_quota_limit(tenant_id, QuotaType.REQUESTS, 1)
        if not allowed:
            QUOTA_EXCEEDED.labels(tenant_id=tenant_id, quota_type="requests").inc()
            logger.warning(
                "Request quota exceeded",
                extra={
                    "event": "quota_exceeded",
                    "tenant_id": tenant_id,
                    "quota_type": "requests",
                },
            )
            return False

        # Check token quota if tokens provided
        if token_count > 0:
            allowed, limit = check_quota_limit(tenant_id, QuotaType.TOKENS, token_count)
            if not allowed:
                QUOTA_EXCEEDED.labels(tenant_id=tenant_id, quota_type="tokens").inc()
                logger.warning(
                    "Token quota exceeded",
                    extra={
                        "event": "quota_exceeded",
                        "tenant_id": tenant_id,
                        "quota_type": "tokens",
                    },
                )
                return False

        # Record usage (we'll update with actual token count later)
        from pii_airlock.auth.quota import get_quota_store
        quota_store = get_quota_store()
        quota_store.record_usage(tenant_id, QuotaType.REQUESTS, 1)

        return True

    async def chat_completion(
        self,
        request: ChatCompletionRequest,
        tenant_id: str = "default",
    ) -> ChatCompletionResponse:
        """Process a chat completion request.

        Args:
            request: The incoming chat completion request.
            tenant_id: Tenant identifier for multi-tenant isolation.

        Returns:
            Chat completion response with deanonymized content.

        Raises:
            QuotaExceededError: If quota limit is exceeded.
        """
        request_id = str(uuid.uuid4())

        logger.info(
            "Processing chat completion request",
            extra={
                "event": "chat_completion_started",
                "tenant_id": tenant_id,
                "model": request.model,
                "message_count": len(request.messages),
            },
        )

        # Step 0: Check quota
        if not self._check_and_record_quota(tenant_id):
            from fastapi import HTTPException
            raise HTTPException(status_code=429, detail="Quota exceeded")

        # Step 1: Anonymize messages
        anonymized_messages, mapping = self._anonymize_messages(
            request.messages, request_id
        )

        # Step 2: Inject anti-hallucination prompt
        final_messages = self._inject_system_prompt(anonymized_messages, mapping)

        # Step 3: Generate cache key from anonymized messages
        anonymized_messages_dict = [m.model_dump() for m in anonymized_messages]
        cache_key = get_cache_key(
            tenant_id=tenant_id,
            model=request.model,
            anonymized_messages=anonymized_messages_dict,
            temperature=request.temperature,
            top_p=request.top_p,
            max_tokens=request.max_tokens,
            presence_penalty=request.presence_penalty,
            frequency_penalty=request.frequency_penalty,
        )

        # Step 4: Check cache
        cached_response = self._check_cache(cache_key, tenant_id, request.model)
        if cached_response:
            # Deanonymize cached response
            choices = []
            for choice_data in cached_response.get("choices", []):
                message_data = choice_data.get("message", {})
                original_content = message_data.get("content", "")
                deanonymized_content = self._deanonymize_content(original_content, mapping)

                choices.append(
                    Choice(
                        index=choice_data.get("index", 0),
                        message=Message(
                            role=message_data.get("role", "assistant"),
                            content=deanonymized_content,
                        ),
                        finish_reason=choice_data.get("finish_reason"),
                    )
                )

            usage_data = cached_response.get("usage")
            usage = None
            if usage_data:
                usage = Usage(
                    prompt_tokens=usage_data.get("prompt_tokens", 0),
                    completion_tokens=usage_data.get("completion_tokens", 0),
                    total_tokens=usage_data.get("total_tokens", 0),
                )

            logger.info(
                "Returning cached response",
                extra={
                    "event": "chat_completion_from_cache",
                    "tenant_id": tenant_id,
                    "model": request.model,
                    "pii_entities": len(mapping),
                },
            )

            return ChatCompletionResponse(
                id=cached_response.get("id", f"chatcmpl-{request_id}"),
                created=cached_response.get("created", int(time.time())),
                model=cached_response.get("model", request.model),
                choices=choices,
                usage=usage,
            )

        # Step 5: Store mapping for potential streaming use
        self.store.save(request_id, mapping, tenant_id=tenant_id)

        # Step 6: Forward to upstream
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": request.model,
            "messages": [m.model_dump() for m in final_messages],
            "temperature": request.temperature,
            "top_p": request.top_p,
            "n": request.n,
            "stream": False,  # Non-streaming for now
            "max_tokens": request.max_tokens,
            "presence_penalty": request.presence_penalty,
            "frequency_penalty": request.frequency_penalty,
        }

        # Remove None values
        payload = {k: v for k, v in payload.items() if v is not None}

        # Use shared HTTP client for connection pooling
        client = await self.get_http_client(self.timeout)
        upstream_start = time.time()

        try:
            logger.debug(
                "Forwarding request to upstream",
                extra={
                    "event": "upstream_request",
                    "tenant_id": tenant_id,
                    "upstream_url": self.upstream_url,
                    "model": request.model,
                },
            )

            response = await client.post(
                f"{self.upstream_url}/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

            # Record upstream latency
            upstream_duration = time.time() - upstream_start
            UPSTREAM_LATENCY.labels(model=request.model).observe(upstream_duration)

            logger.debug(
                "Upstream response received",
                extra={
                    "event": "upstream_response",
                    "tenant_id": tenant_id,
                    "model": request.model,
                    "duration_ms": round(upstream_duration * 1000, 2),
                },
            )

        except httpx.HTTPStatusError as e:
            UPSTREAM_ERRORS.labels(error_type="http_error").inc()
            logger.error(
                "Upstream HTTP error",
                extra={
                    "event": "upstream_error",
                    "tenant_id": tenant_id,
                    "error_type": "http_error",
                    "status_code": e.response.status_code,
                    "model": request.model,
                },
            )
            raise
        except httpx.RequestError as e:
            UPSTREAM_ERRORS.labels(error_type="request_error").inc()
            logger.error(
                "Upstream request error",
                extra={
                    "event": "upstream_error",
                    "tenant_id": tenant_id,
                    "error_type": "request_error",
                    "error": str(e),
                    "model": request.model,
                },
            )
            raise

        # Step 7: Deanonymize response
        choices = []
        for choice_data in data.get("choices", []):
            message_data = choice_data.get("message", {})
            original_content = message_data.get("content", "")
            deanonymized_content = self._deanonymize_content(original_content, mapping)

            choices.append(
                Choice(
                    index=choice_data.get("index", 0),
                    message=Message(
                        role=message_data.get("role", "assistant"),
                        content=deanonymized_content,
                    ),
                    finish_reason=choice_data.get("finish_reason"),
                )
            )

        # Step 8: Clean up mapping
        self.store.delete(request_id, tenant_id=tenant_id)

        # Build response
        usage_data = data.get("usage")
        usage = None
        if usage_data:
            total_tokens = usage_data.get("total_tokens", 0)
            usage = Usage(
                prompt_tokens=usage_data.get("prompt_tokens", 0),
                completion_tokens=usage_data.get("completion_tokens", 0),
                total_tokens=total_tokens,
            )
            # Record token quota usage
            self._check_and_record_quota(tenant_id, token_count=total_tokens)

        # Step 9: Store in cache (before deanonymization)
        self._store_cache(cache_key, data, tenant_id, request.model)

        logger.info(
            "Chat completion completed",
            extra={
                "event": "chat_completion_completed",
                "tenant_id": tenant_id,
                "model": request.model,
                "pii_entities": len(mapping),
            },
        )

        return ChatCompletionResponse(
            id=data.get("id", f"chatcmpl-{request_id}"),
            created=data.get("created", int(time.time())),
            model=data.get("model", request.model),
            choices=choices,
            usage=usage,
        )

    async def chat_completion_stream(
        self,
        request: ChatCompletionRequest,
        tenant_id: str = "default",
    ) -> AsyncIterator[str]:
        """Process a streaming chat completion request.

        Yields SSE-formatted events with deanonymized content.
        Uses a sliding window buffer to handle placeholders split
        across chunk boundaries.

        Note: Streaming responses bypass cache for now.

        Args:
            request: The incoming chat completion request.
            tenant_id: Tenant identifier for multi-tenant isolation.

        Yields:
            SSE-formatted strings (data: {...}\\n\\n or data: [DONE]\\n\\n).

        Example:
            >>> async for event in proxy.chat_completion_stream(request):
            ...     print(event, end="")  # Already formatted as SSE
        """
        request_id = str(uuid.uuid4())

        logger.info(
            "Processing streaming chat completion request",
            extra={
                "event": "chat_completion_stream_started",
                "tenant_id": tenant_id,
                "model": request.model,
                "message_count": len(request.messages),
            },
        )

        # Step 1: Anonymize messages
        anonymized_messages, mapping = self._anonymize_messages(
            request.messages, request_id
        )

        # Step 2: Inject anti-hallucination prompt
        final_messages = self._inject_system_prompt(anonymized_messages, mapping)

        # Step 3: Store mapping with tenant_id
        self.store.save(request_id, mapping, tenant_id=tenant_id)

        # Step 4: Create stream buffer for deanonymization
        buffer = StreamBuffer(mapping, self.deanonymizer)

        # Step 5: Prepare request
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": request.model,
            "messages": [m.model_dump() for m in final_messages],
            "temperature": request.temperature,
            "top_p": request.top_p,
            "n": request.n,
            "stream": True,  # Enable streaming
            "max_tokens": request.max_tokens,
            "presence_penalty": request.presence_penalty,
            "frequency_penalty": request.frequency_penalty,
        }

        # Remove None values
        payload = {k: v for k, v in payload.items() if v is not None}

        # Track chunk metadata for response formatting
        chunk_id = f"chatcmpl-{request_id}"
        chunk_created = int(time.time())
        chunk_model = request.model

        # Track streaming metrics
        upstream_start = time.time()
        chunk_count = 0

        try:
            # Use shared HTTP client for connection pooling
            client = await self.get_http_client(self.timeout)

            logger.debug(
                "Starting streaming request to upstream",
                extra={
                    "event": "upstream_stream_request",
                    "tenant_id": tenant_id,
                    "upstream_url": self.upstream_url,
                    "model": request.model,
                },
            )

            async with client.stream(
                "POST",
                f"{self.upstream_url}/v1/chat/completions",
                headers=headers,
                json=payload,
            ) as response:
                response.raise_for_status()

                async for line in response.aiter_lines():
                    if not line:
                        continue

                    if line.startswith("data: "):
                        data_str = line[6:]  # Remove "data: " prefix

                        if data_str == "[DONE]":
                            # Stream ended, flush buffer
                            final_content = buffer.flush()
                            if final_content:
                                yield self._format_sse_chunk(
                                    final_content,
                                    chunk_id,
                                    chunk_created,
                                    chunk_model,
                                )
                            yield "data: [DONE]\n\n"

                            # Record upstream latency for streaming
                            upstream_duration = time.time() - upstream_start
                            UPSTREAM_LATENCY.labels(model=request.model).observe(upstream_duration)

                            logger.info(
                                "Streaming chat completion completed",
                                extra={
                                    "event": "chat_completion_stream_completed",
                                    "tenant_id": tenant_id,
                                    "model": request.model,
                                    "pii_entities": len(mapping),
                                    "chunk_count": chunk_count,
                                    "duration_ms": round(upstream_duration * 1000, 2),
                                },
                            )
                            break

                        try:
                            chunk_data = json.loads(data_str)
                        except json.JSONDecodeError:
                            # Skip malformed chunks
                            continue

                        # Update metadata from actual response
                        chunk_id = chunk_data.get("id", chunk_id)
                        chunk_created = chunk_data.get("created", chunk_created)
                        chunk_model = chunk_data.get("model", chunk_model)

                        # Extract content from delta
                        choices = chunk_data.get("choices", [])
                        if not choices:
                            continue

                        delta = choices[0].get("delta", {})
                        content = delta.get("content")
                        finish_reason = choices[0].get("finish_reason")

                        if content:
                            chunk_count += 1
                            # Process through buffer
                            safe_content = buffer.process_chunk(content)
                            if safe_content:
                                yield self._format_sse_chunk(
                                    safe_content,
                                    chunk_id,
                                    chunk_created,
                                    chunk_model,
                                )

                        # Handle finish_reason (usually "stop")
                        if finish_reason:
                            # Flush any remaining buffer
                            final_content = buffer.flush()
                            if final_content:
                                yield self._format_sse_chunk(
                                    final_content,
                                    chunk_id,
                                    chunk_created,
                                    chunk_model,
                                )
                            # Send the finish event
                            yield self._format_sse_chunk(
                                None,
                                chunk_id,
                                chunk_created,
                                chunk_model,
                                finish_reason=finish_reason,
                            )

        except httpx.HTTPStatusError as e:
            UPSTREAM_ERRORS.labels(error_type="http_error").inc()
            logger.error(
                "Upstream streaming HTTP error",
                extra={
                    "event": "upstream_stream_error",
                    "tenant_id": tenant_id,
                    "error_type": "http_error",
                    "status_code": e.response.status_code,
                    "model": request.model,
                },
            )
            raise
        except httpx.RequestError as e:
            UPSTREAM_ERRORS.labels(error_type="request_error").inc()
            logger.error(
                "Upstream streaming request error",
                extra={
                    "event": "upstream_stream_error",
                    "tenant_id": tenant_id,
                    "error_type": "request_error",
                    "error": str(e),
                    "model": request.model,
                },
            )
            raise
        finally:
            # Step 6: Clean up mapping with tenant_id
            self.store.delete(request_id, tenant_id=tenant_id)

    def _format_sse_chunk(
        self,
        content: Optional[str],
        chunk_id: str,
        created: int,
        model: str,
        finish_reason: Optional[str] = None,
    ) -> str:
        """Format a content piece as an SSE chunk.

        Args:
            content: The text content to include in delta.
            chunk_id: The chunk ID.
            created: Unix timestamp.
            model: Model name.
            finish_reason: Optional finish reason (e.g., "stop").

        Returns:
            SSE-formatted string: "data: {...}\\n\\n"
        """
        delta = {}
        if content is not None:
            delta["content"] = content

        chunk = ChatCompletionChunk(
            id=chunk_id,
            created=created,
            model=model,
            choices=[
                StreamChoice(
                    index=0,
                    delta=delta,
                    finish_reason=finish_reason,
                )
            ],
        )

        return f"data: {chunk.model_dump_json()}\n\n"
