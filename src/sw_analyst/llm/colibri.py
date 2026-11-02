"""Colibri `coli serve` client, OpenAI protocol (stdlib only). Loopback only, see ADR-0012.

Differences from Ollama that matter here:
- The engine ignores `seed` and DeepSeek V4 serves greedy only, so there is no seed attribute: reports must not name one.
  Same input, model, engine and backend give the same text; temperature is always 0 so other engines behave the same.
- A JSON schema is not enforced while sampling. validate_action stays the trust boundary.
- budget_factor stretches the time budget of a job: this model takes far longer per reply than the ones the budgets were set for.
- Replies are streamed, because one can take hours. The server sends a keepalive every 10 s, also during a prefill, so silence
  means a dead engine, and closing the connection makes it send CANCEL to the engine, so a cancelled job frees the GPU at once.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

from sw_analyst.llm.base import ChatMessage, LLMError, LLMResponse
from sw_analyst.llm.ollama import _LOCAL_HOSTS


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None   # a 3xx then surfaces as HTTPError


# No proxy and no redirects, whatever the environment or a reply says: the bearer key must not leave the machine.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _with_json_instruction(messages: list[dict]) -> list[dict]:
    """The prompts describe the allowed replies as text. The JSON schema is not added: on Ollama it steers sampling and costs no
    tokens, here it would only lengthen every prompt, and a prefill costs minutes on a disk-streamed model."""
    text = "Reply with exactly one JSON object and nothing else, no code fence and no text around it."
    if messages and messages[0]["role"] == "system":
        return [{**messages[0], "content": messages[0]["content"] + "\n\n" + text}, *messages[1:]]
    return [{"role": "system", "content": text}, *messages]


def _set_read_timeout(response, seconds: float) -> None:
    """shortcut: urllib has no public way to change the timeout of an open response. If this ever fails, only the detection of a
    dead engine gets slower (timeout_s instead of stall_s); upgrade to http.client if that matters."""
    try:
        response.fp.raw._sock.settimeout(seconds)
    except AttributeError:
        pass


class ColibriClient:
    def __init__(self, model: str, base_url: str = "http://127.0.0.1:11436", api_key: str = "", num_ctx: int = 16384,
                 timeout_s: int = 36000, allow_think: bool = False, stall_s: int = 300):
        host = urllib.parse.urlparse(base_url).hostname
        if host not in _LOCAL_HOSTS:
            raise ValueError(f"refusing non-local LLM endpoint: {base_url}")  # offline platform: loopback only
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.num_ctx = num_ctx
        self.timeout_s = timeout_s      # whole reply: 3000 tokens at 0.1 tok/s; a keepalive alone never ends a stuck prefill
        self.stall_s = stall_s          # nothing at all, not even a keepalive: the engine is gone
        self.budget_factor = 30
        self.allow_think = allow_think  # off by default: thinking tokens cost minutes each on a disk-streamed model
        self.should_cancel: Callable[[], bool] | None = None   # set by JobEngine while a job runs
        self.cancel_poll_s = 5.0

    def reachable(self) -> bool:
        """True once the engine has loaded: /health answers 503 while it loads."""
        try:
            with _OPENER.open(self.base_url + "/health", timeout=2) as r:
                return r.status == 200
        except Exception:
            return False

    def chat(self, messages: list[ChatMessage], *, json_mode: bool | dict = False, think: bool = True,
             max_tokens: int = 2048, temperature: float = 0.1) -> LLMResponse:
        wire = [m.model_dump() for m in messages]
        body = {"model": self.model, "stream": True, "stream_options": {"include_usage": True}, "temperature": 0,
                "max_tokens": max_tokens, "enable_thinking": bool(think and self.allow_think),
                "messages": _with_json_instruction(wire) if json_mode else wire}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(self.base_url + "/v1/chat/completions", data=json.dumps(body).encode("utf-8"),
                                     headers=headers, method="POST")
        t0 = time.monotonic()
        try:
            # Before the engine accepts a request nothing is sent, also not a keepalive: a request queued behind a long reply
            # is silent for hours and alive. Silence only means a dead engine once the stream has begun.
            with _OPENER.open(req, timeout=self.timeout_s) as r:
                _set_read_timeout(r, self.stall_s)
                return self._read_stream(r, t0)
        except urllib.error.HTTPError as e:
            raise LLMError(f"colibri HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:500]}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, ValueError) as e:
            raise LLMError(f"colibri unreachable or silent at {self.base_url}: {e}") from e

    def _read_stream(self, stream, t0: float) -> LLMResponse:
        """Leaving this function closes the connection, which is what cancels the generation in the engine."""
        text: list[str] = []
        thinking: list[str] = []
        usage: dict = {}
        model, finish = self.model, ""
        polled = t0
        for raw in stream:
            now = time.monotonic()
            if now - t0 > self.timeout_s:
                raise LLMError(f"colibri reply took longer than {self.timeout_s} s")
            if self.should_cancel and now - polled >= self.cancel_poll_s:
                polled = now
                if self.should_cancel():
                    raise LLMError("cancelled while the model was answering")
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue     # SSE comments and blank lines
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            chunk = json.loads(payload)
            if chunk.get("error"):
                raise LLMError(f"colibri error in the stream: {str(chunk['error'])[:300]}")
            model = str(chunk.get("model") or model)
            usage = chunk.get("usage") or usage
            for choice in chunk.get("choices") or []:
                delta = choice.get("delta") or {}
                text.append(delta.get("content") or "")
                thinking.append(delta.get("reasoning_content") or "")
                finish = choice.get("finish_reason") or finish
        if not finish:   # a stream that just ended is a lost reply, never a short answer
            raise LLMError(f"colibri stream ended without a finish reason after {sum(map(len, text))} characters")
        return LLMResponse(text="".join(text), thinking="".join(thinking), model=model,
                           prompt_tokens=int(usage.get("prompt_tokens") or 0),
                           completion_tokens=int(usage.get("completion_tokens") or 0),
                           duration_ms=int((time.monotonic() - t0) * 1000), done_reason=finish)
