"""
Pydantic models for OpenAI-compatible API.

These models are compatible with the OpenAI Chat Completions API format.
"""

from typing import Optional, Literal, Union, Any, Dict
from pydantic import BaseModel, Field


# ============================================================================
# Function Calling Models
# ============================================================================

class Function(BaseModel):
    """Function definition for function calling."""

    name: str = Field(..., description="The function name")
    description: Optional[str] = Field(None, description="Function description")
    parameters: Optional[Dict] = Field(None, description="Function parameters as JSON Schema")


class Tool(BaseModel):
    """Tool definition for function calling."""

    type: Literal["function"] = Field(default="function", description="Tool type")
    function: Function = Field(..., description="Function definition")


class ToolCall(BaseModel):
    """A function call in an assistant message."""

    id: str = Field(..., description="Tool call ID")
    type: Literal["function"] = Field(default="function", description="Tool call type")
    function: Dict[str, str] = Field(..., description="Function name and arguments")


class ToolCallOutput(BaseModel):
    """Output from a tool call (function result)."""

    tool_call_id: str = Field(..., description="ID of the tool call this output is for")
    role: Literal["tool"] = Field(default="tool", description="Message role")
    content: str = Field(..., description="Function output content")


# ============================================================================
# Message Models (with support for Vision and Function Calling)
# ============================================================================

class ImageContent(BaseModel):
    """Image content for vision inputs."""

    type: Literal["image_url"] = Field(default="image_url", description="Content type")
    image_url: Dict[str, str] = Field(..., description="Image URL or base64 data")


Content = Union[str, list[Union[str, Dict]]]


class Message(BaseModel):
    """A single message in the conversation.

    Supports text, function calls, and vision inputs.
    """

    role: Literal["system", "user", "assistant", "tool"] = Field(
        ..., description="The role of the message author"
    )
    content: Optional[Content] = Field(None, description="The content of the message (text, images, etc.)")
    name: Optional[str] = Field(None, description="Optional name for the participant")
    tool_calls: Optional[list[ToolCall]] = Field(None, description="Tool calls in assistant messages")
    tool_call_id: Optional[str] = Field(None, description="Tool call ID for tool role messages")

    class Config:
        # Allow Union types to work properly
        arbitrary_types_allowed = True


class ChatCompletionRequest(BaseModel):
    """Request body for chat completion endpoint.

    Compatible with OpenAI's /v1/chat/completions API.
    Supports function calling, vision inputs, and other modern features.
    """

    model: str = Field(..., description="ID of the model to use")
    messages: list[Message] = Field(
        ..., description="A list of messages comprising the conversation"
    )
    temperature: Optional[float] = Field(
        1.0, ge=0, le=2, description="Sampling temperature"
    )
    top_p: Optional[float] = Field(
        1.0, ge=0, le=1, description="Nucleus sampling parameter"
    )
    n: Optional[int] = Field(1, ge=1, description="Number of completions to generate")
    stream: Optional[bool] = Field(False, description="Whether to stream responses")
    stop: Optional[str | list[str]] = Field(
        None, description="Stop sequences"
    )
    max_tokens: Optional[int] = Field(
        None, description="Maximum tokens to generate"
    )
    presence_penalty: Optional[float] = Field(
        0, ge=-2, le=2, description="Presence penalty"
    )
    frequency_penalty: Optional[float] = Field(
        0, ge=-2, le=2, description="Frequency penalty"
    )
    user: Optional[str] = Field(None, description="Unique user identifier")

    # Function calling support
    tools: Optional[list[Tool]] = Field(
        None, description="List of tools/functions available to the model"
    )
    tool_choice: Optional[Union[str, Dict]] = Field(
        None, description="Tool choice strategy: 'none', 'auto', 'required', or specific tool"
    )

    # Additional parameters
    response_format: Optional[Dict] = Field(
        None, description="Format specification for response (e.g., JSON mode)"
    )
    seed: Optional[int] = Field(
        None, description="Seed for deterministic sampling"
    )


class Choice(BaseModel):
    """A single completion choice."""

    index: int
    message: Message
    finish_reason: Optional[str] = None
    # Note: tool_calls is handled via the Message model for assistant messages


class Usage(BaseModel):
    """Token usage statistics."""

    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class ChatCompletionResponse(BaseModel):
    """Response body for chat completion endpoint.

    Compatible with OpenAI's response format.
    """

    id: str = Field(..., description="Unique identifier for the completion")
    object: str = Field(default="chat.completion")
    created: int = Field(..., description="Unix timestamp of creation")
    model: str = Field(..., description="Model used for completion")
    choices: list[Choice]
    usage: Optional[Usage] = None


class StreamChoice(BaseModel):
    """A single streaming choice delta."""

    index: int
    delta: dict
    finish_reason: Optional[str] = None


class ChatCompletionChunk(BaseModel):
    """Streaming response chunk."""

    id: str
    object: str = Field(default="chat.completion.chunk")
    created: int
    model: str
    choices: list[StreamChoice]


class ErrorResponse(BaseModel):
    """Error response body."""

    error: dict = Field(..., description="Error details")


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str


class TestAnonymizeRequest(BaseModel):
    """Request body for test anonymization endpoint."""

    text: str = Field(..., description="Text to anonymize")
    strategy: Optional[str] = Field(
        None,
        description="Anonymization strategy: placeholder, hash, mask, redact",
    )
    entity_strategies: Optional[dict[str, str]] = Field(
        None,
        description="Per-entity strategy mapping, e.g., {'PERSON': 'mask', 'PHONE': 'redact'}",
    )


class TestAnonymizeResponse(BaseModel):
    """Response body for test anonymization endpoint."""

    original: str = Field(..., description="Original input text")
    anonymized: str = Field(..., description="Anonymized text with placeholders")
    mapping: dict[str, str] = Field(
        ..., description="Mapping from placeholder to original value"
    )
    strategy: str = Field(..., description="The anonymization strategy used")


class TestDeanonymizeRequest(BaseModel):
    """Request body for test deanonymization endpoint."""

    text: str = Field(..., description="Text with placeholders to deanonymize")
    mapping: dict[str, str] = Field(
        ..., description="Mapping from placeholder to original value"
    )


class TestDeanonymizeResponse(BaseModel):
    """Response body for test deanonymization endpoint."""

    original: str = Field(..., description="Original text with placeholders")
    deanonymized: str = Field(..., description="Text with placeholders replaced")


# ============================================================================
# Embeddings API Models
# ============================================================================

class EmbeddingRequest(BaseModel):
    """Request body for embeddings endpoint.

    Compatible with OpenAI's /v1/embeddings API.
    """

    input: Union[str, list[str]] = Field(
        ..., description="Input text(s) to embed"
    )
    model: str = Field(..., description="ID of the embedding model to use")
    encoding_format: Optional[Literal["float", "base64"]] = Field(
        "float", description="Format for embedding output"
    )
    dimensions: Optional[int] = Field(
        None, description="Number of dimensions for output embeddings"
    )
    user: Optional[str] = Field(None, description="Unique user identifier")


class EmbeddingData(BaseModel):
    """A single embedding result."""

    index: int = Field(..., description="Index of the embedding in the results")
    object: str = Field(default="embedding", description="Object type")
    embedding: list[float] = Field(..., description="Embedding vector")
    # Note: for base64 encoding, embedding would be a string instead


class EmbeddingUsage(BaseModel):
    """Token usage for embeddings."""

    prompt_tokens: int
    total_tokens: int


class EmbeddingResponse(BaseModel):
    """Response body for embeddings endpoint."""

    object: str = Field(default="list", description="Object type")
    data: list[EmbeddingData] = Field(..., description="List of embeddings")
    model: str = Field(..., description="Model used for embeddings")
    usage: EmbeddingUsage
