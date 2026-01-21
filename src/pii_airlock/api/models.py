"""
Pydantic models for OpenAI-compatible API.

These models are compatible with the OpenAI Chat Completions API format.
"""

from typing import Optional, Literal
from pydantic import BaseModel, Field


class Message(BaseModel):
    """A single message in the conversation."""

    role: Literal["system", "user", "assistant"] = Field(
        ..., description="The role of the message author"
    )
    content: str = Field(..., description="The content of the message")
    name: Optional[str] = Field(None, description="Optional name for the participant")


class ChatCompletionRequest(BaseModel):
    """Request body for chat completion endpoint.

    Compatible with OpenAI's /v1/chat/completions API.
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


class Choice(BaseModel):
    """A single completion choice."""

    index: int
    message: Message
    finish_reason: Optional[str] = None


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


class TestAnonymizeResponse(BaseModel):
    """Response body for test anonymization endpoint."""

    original: str = Field(..., description="Original input text")
    anonymized: str = Field(..., description="Anonymized text with placeholders")
    mapping: dict[str, str] = Field(
        ..., description="Mapping from placeholder to original value"
    )


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
