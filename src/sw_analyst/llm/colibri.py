"""Colibri `coli serve` client, OpenAI protocol (stdlib only). Loopback only, see ADR-0012.

Differences from Ollama that matter here:
- The engine ignores `seed` and DeepSeek V4 serves greedy only, so there is no seed attribute: reports must not name one.
  Same input, model, engine and backend give the same text; temperature is always 0 so other engines behave the same.
- A JSON schema is not enforced while sampling, it only goes into the prompt. validate_action stays the trust boundary.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from sw_analyst.llm.base import ChatMessage, LLMError, LLMResponse
from sw_analyst.llm.ollama import _LOCAL_HOSTS

# No proxy, whatever the environment says: the bearer key must not leave the machine.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _with_json_instruction(messages: list[dict], json_mode: bool | dict) -> list[dict]:
    text = "Reply with exactly one JSON object and nothing else, no code fence and no text around it."
    if isinstance(json_mode, dict):
        text += " It must match this JSON schema: " + json.dumps(json_mode, separators=(",", ":"))
    if messages and messages[0]["role"] == "system":
        return [{**messages[0], "content": messages[0]["content"] + "\n\n" + text}, *messages[1:]]
    return [{"role": "system", "content": text}, *messages]


class ColibriClient:
    def __init__(self, model: str, base_url: str = "http://127.0.0.1:11436", api_key: str = "", num_ctx: int = 20000,
                 timeout_s: int = 14400, allow_think: bool = False):
        host = urllib.parse.urlparse(base_url).hostname
        if host not in _LOCAL_HOSTS:
            raise ValueError(f"refusing non-local LLM endpoint: {base_url}")  # offline platform: loopback only
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.num_ctx = num_ctx
        self.timeout_s = timeout_s      # at 1 tok/s one long reply takes most of an hour
        self.allow_think = allow_think  # off by default: thinking tokens cost minutes each on a disk-streamed model

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
        body = {"model": self.model, "stream": False, "temperature": 0, "max_tokens": max_tokens,
                "enable_thinking": bool(think and self.allow_think),
                "messages": _with_json_instruction(wire, json_mode) if json_mode else wire}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(self.base_url + "/v1/chat/completions", data=json.dumps(body).encode("utf-8"),
                                     headers=headers, method="POST")
        t0 = time.monotonic()
        try:
            with _OPENER.open(req, timeout=self.timeout_s) as r:
                data = json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise LLMError(f"colibri HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:500]}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, ValueError) as e:
            raise LLMError(f"colibri unreachable at {self.base_url}: {e}") from e
        try:
            choice = data["choices"][0]
            msg = choice["message"]
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"colibri reply without a choice: {str(data)[:300]}") from e
        usage = data.get("usage") or {}
        return LLMResponse(text=msg.get("content") or "", thinking=msg.get("reasoning_content") or "",
                           model=str(data.get("model") or self.model),
                           prompt_tokens=int(usage.get("prompt_tokens") or 0),
                           completion_tokens=int(usage.get("completion_tokens") or 0),
                           duration_ms=int((time.monotonic() - t0) * 1000),
                           done_reason=str(choice.get("finish_reason") or ""))
