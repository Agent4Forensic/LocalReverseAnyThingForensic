"""Start the platform: python -m sw_analyst --model <ollama tag> [--data-dir data] [--port 8765]

Binds to 127.0.0.1 only. The LLM endpoint must also be loopback (OllamaClient refuses anything else).
"""
from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from sw_analyst.common.store import Store
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.llm.ollama import OllamaClient
from sw_analyst.orchestrator.engine import JobEngine
from sw_analyst.orchestrator.worker import Worker
from sw_analyst.translate import Translator
from sw_analyst.webui.app import create_app


def main() -> None:
    ap = argparse.ArgumentParser(prog="sw_analyst")
    ap.add_argument("--model", required=True, help="Ollama model tag, see docs/adr/0001-modellwahl.md")
    ap.add_argument("--ollama-url", default="http://127.0.0.1:11435")
    ap.add_argument("--num-ctx", type=int, default=16384)
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()

    data = Path(args.data_dir).resolve()
    store = Store(data / "sw_analyst.db", data / "logs")
    gateway = DevGateway(data)
    llm = OllamaClient(args.model, args.ollama_url, num_ctx=args.num_ctx)
    translator = Translator(llm, cache=store)
    worker = Worker(store, JobEngine(store, llm, gateway, translator))
    worker.start()
    app = create_app(store, worker, gateway, llm, translator, report_model=args.model)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
