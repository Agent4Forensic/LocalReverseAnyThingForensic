"""LLM contract. The orchestrator talks to the model only through this interface."""
from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: str            # "system" | "user" | "assistant"
    content: str


class LLMResponse(BaseModel):
    text: str
    thinking: str = ""
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    duration_ms: int = 0
    done_reason: str = ""   # "length" means the reply was cut by the token budget
    raw: dict = Field(default_factory=dict)


class LLMError(Exception):
    pass


class LLMClient(Protocol):
    model: str

    def chat(self, messages: list[ChatMessage], *, json_mode: bool = False,
             think: bool = True, max_tokens: int = 2048, temperature: float = 0.1) -> LLMResponse:
        """One chat turn. json_mode=True asks the model for a single JSON object.
        Must raise LLMError on transport problems."""
        ...
