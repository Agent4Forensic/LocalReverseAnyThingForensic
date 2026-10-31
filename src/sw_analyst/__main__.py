"""Start the platform: python -m sw_analyst --model <ollama tag> [--data-dir data] [--port 8765]
Preflight only:       python -m sw_analyst --check [--json]   (exit code 1 on FEHLER)

Binds to 127.0.0.1 only. The LLM endpoint must also be loopback (OllamaClient refuses anything else).
Normally started through scripts\\start.ps1, which sets SW_LOG_FILE so stage lines land in data/logs/start-<date>.log.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

from sw_analyst.preflight import log, main_check


def main() -> None:
    ap = argparse.ArgumentParser(prog="sw_analyst")
    ap.add_argument("--model", help="Ollama model tag, see docs/adr/0001-modellwahl.md")
    ap.add_argument("--ollama-url", default="http://127.0.0.1:11435")
    ap.add_argument("--num-ctx", type=int, default=16384)
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--check", action="store_true", help="run the preflight checks and exit")
    ap.add_argument("--json", action="store_true", help="with --check: machine-readable output")
    args = ap.parse_args()

    data = Path(args.data_dir).resolve()
    if args.check:
        root = Path(__file__).resolve().parents[2]
        sys.exit(main_check(root, data, args.port, urlparse(args.ollama_url).port or 11435, args.model, args.json))
    if not args.model:
        ap.error("--model is required (unless --check)")

    # Heavy imports only after the cheap paths above, so --check works with a half-installed environment.
    import uvicorn

    from sw_analyst.common.hostguard import HostGuard
    from sw_analyst.common.store import Store
    from sw_analyst.gateway.container_tools import attach_container_tools
    from sw_analyst.gateway.dev_gateway import DevGateway
    from sw_analyst.llm.ollama import OllamaClient
    from sw_analyst.orchestrator.engine import JobEngine
    from sw_analyst.orchestrator.worker import Worker
    from sw_analyst.translate import Translator
    from sw_analyst.webui.app import create_app

    store = Store(data / "sw_analyst.db", data / "logs")
    gateway = DevGateway(data)
    container_tools = attach_container_tools(gateway)
    log("GUARD", f"gateway ready with {len(gateway.list_tools())} read-only tools, "
                 f"{len(container_tools)} of them in offline containers")
    log("GUARD", "DevGateway parses samples on this host: harmless test samples only, real samples need the VM gateway",
        "WARN")
    llm = OllamaClient(args.model, args.ollama_url, num_ctx=args.num_ctx)
    translator = Translator(llm, cache=store)
    worker = Worker(store, JobEngine(store, llm, gateway, translator, host_guard=HostGuard(data, ollama_url=args.ollama_url)))
    worker.start()
    log("WORKER", f"worker started (model {args.model}, num_ctx {args.num_ctx})")
    app = create_app(store, worker, gateway, llm, translator, report_model=args.model, port=args.port)
    log("APP", f"listening on http://127.0.0.1:{args.port}/")
    try:
        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    finally:
        worker.stop()
        log("APP", "stopped")


if __name__ == "__main__":
    main()
