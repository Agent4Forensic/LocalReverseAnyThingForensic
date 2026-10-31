"""Ollama /api/chat client (stdlib only). Loopback only: refuses non-local base URLs."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from sw_analyst.llm.base import ChatMessage, LLMError, LLMResponse

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


class OllamaClient:
    def __init__(self, model: str, base_url: str = "http://127.0.0.1:11435", num_ctx: int = 16384,
                 timeout_s: int = 600, seed: int = 42):
        host = urllib.parse.urlparse(base_url).hostname
        if host not in _LOCAL_HOSTS:
            raise ValueError(f"refusing non-local LLM endpoint: {base_url}")  # offline platform: loopback only
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.num_ctx = num_ctx
        self.timeout_s = timeout_s
        self.seed = seed      # fixed seed: same prompt, model and version give the same reply (reproducibility)

    def _post(self, path: str, body: dict) -> dict:
        req = urllib.request.Request(self.base_url + path, data=json.dumps(body).encode("utf-8"),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:500]
            raise LLMError(f"ollama HTTP {e.code}: {detail}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, ValueError) as e:
            raise LLMError(f"ollama unreachable at {self.base_url}: {e}") from e

    def reachable(self) -> bool:
        try:
            with urllib.request.urlopen(self.base_url + "/api/version", timeout=2) as r:
                return r.status == 200
        except Exception:
            return False

    def chat(self, messages: list[ChatMessage], *, json_mode: bool = False, think: bool = True,
             max_tokens: int = 2048, temperature: float = 0.1) -> LLMResponse:
        body = {"model": self.model, "stream": False,
                "messages": [m.model_dump() for m in messages],
                "options": {"temperature": temperature, "num_predict": max_tokens, "num_ctx": self.num_ctx,
                            "seed": self.seed}}
        if json_mode:
            body["format"] = "json"
        body["think"] = think
        t0 = time.monotonic()
        try:
            data = self._post("/api/chat", body)
        except LLMError as e:
            if "think" in str(e).lower():          # model without thinking support: retry plain
                body.pop("think", None)
                data = self._post("/api/chat", body)
            else:
                raise
        msg = data.get("message", {})
        return LLMResponse(text=msg.get("content", ""), thinking=msg.get("thinking", "") or "",
                           model=data.get("model", self.model),
                           prompt_tokens=int(data.get("prompt_eval_count", 0) or 0),
                           completion_tokens=int(data.get("eval_count", 0) or 0),
                           duration_ms=int((time.monotonic() - t0) * 1000),
                           done_reason=str(data.get("done_reason", "") or ""))
