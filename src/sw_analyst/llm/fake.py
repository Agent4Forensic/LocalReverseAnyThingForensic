"""Scriptable model for tests and demos: no GPU, deterministic."""
from __future__ import annotations

from typing import Callable

from sw_analyst.llm.base import ChatMessage, LLMError, LLMResponse


class ScriptedLLM:
    """responder(messages) -> reply text. Every call is recorded in .calls."""

    def __init__(self, responder: Callable[[list[ChatMessage]], str], model: str = "scripted-test-model"):
        self.model = model
        self.responder = responder
        self.calls: list[list[ChatMessage]] = []

    def chat(self, messages: list[ChatMessage], *, json_mode: bool = False, think: bool = True,
             max_tokens: int = 2048, temperature: float = 0.1) -> LLMResponse:
        self.calls.append(messages)
        text = self.responder(messages)
        if text is None:
            raise LLMError("scripted model has no answer")
        return LLMResponse(text=text, model=self.model, prompt_tokens=sum(len(m.content) // 4 for m in messages),
                           completion_tokens=len(text) // 4, duration_ms=1)
