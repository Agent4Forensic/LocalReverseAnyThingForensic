"""First real test of colibri with DeepSeek V4 Flash (ADR-0012): tempo, repeatability, JSON, memory, network, one real job.

Started by `scripts\\start.ps1 -Llm colibri -ColibriGate`, which loads the engine first and passes the key in SW_COLIBRI_KEY.
Steps run cheapest first, and results are written after each step, so a long run that dies still leaves its numbers.
Exit code 0 only if every step passed. Harmless self-made prompts and samples only; nothing here runs a sample.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from sw_analyst.gateway.dev_gateway import DevGateway  # noqa: E402
from sw_analyst.guard import SYSTEM_RULES_EN, validate_action  # noqa: E402
from sw_analyst.llm.base import ChatMessage, LLMError  # noqa: E402
from sw_analyst.llm.colibri import ColibriClient  # noqa: E402
from sw_analyst.orchestrator.runner import _tools_block  # noqa: E402
from sw_analyst.preflight import _ram_gb  # noqa: E402
from sw_analyst.prompts.registry import ACTION_SCHEMA, SYSTEM_BASE  # noqa: E402

MIN_FREE_RAM_GB = 3.0      # below this HostGuard pauses a job
HARD_LIMIT_GB = 24.0       # WSL, Docker and models together
GOALS = ["Find out the file type of the sample.", "List the printable strings of the sample.",
         "Check whether the sample holds base64 data.", "Read the first lines of the sample.",
         "Name the size and the hash of the sample."]


def check_repeat(llm, max_tokens: int) -> dict:
    """The same prompt twice must give the same text: reports rest on this, the engine has no seed."""
    msgs = [ChatMessage(role="user", content="Name three common static analysis steps for an unknown file, in one short sentence.")]
    first = llm.chat(msgs, think=False, max_tokens=max_tokens)
    second = llm.chat(msgs, think=False, max_tokens=max_tokens)
    decode = second.completion_tokens / max(second.duration_ms / 1000, 0.001)   # the prompt is cached by now
    return {"passed": bool(first.text.strip()) and first.text == second.text, "first": first.text[:300], "second": second.text[:300],
            "first_s": round(first.duration_ms / 1000, 1), "second_s": round(second.duration_ms / 1000, 1),
            "prompt_tokens": first.prompt_tokens, "completion_tokens": second.completion_tokens, "tok_s": round(decode, 3)}


def check_json(llm, tools: list, goals: list[str], max_tokens: int) -> dict:
    """Prompts built like the runner's, judged by the runner's own check, with its one correction. No schema is enforced here."""
    block = _tools_block(tools)
    rows = []
    for goal in goals:
        msgs = [ChatMessage(role="system", content=SYSTEM_BASE + "\n" + SYSTEM_RULES_EN),
                ChatMessage(role="user", content=f"## Goal\n{goal}\n\n## Tools\n{block}\n\n{ACTION_SCHEMA}")]
        r = llm.chat(msgs, json_mode=True, think=False, max_tokens=max_tokens)
        first = validate_action(r.text, tools)
        retried = None
        if not first.ok:
            msgs += [ChatMessage(role="assistant", content=r.text[:1500] or "(no output)"),
                     ChatMessage(role="user", content=f"INVALID ACTION: {first.error}. Reply with exactly one valid JSON object as specified.")]
            r2 = llm.chat(msgs, json_mode=True, think=False, max_tokens=max_tokens)
            retried = validate_action(r2.text, tools).ok
        rows.append({"goal": goal, "first_try": first.ok, "after_retry": first.ok or bool(retried), "error": "" if first.ok else first.error[:160],
                     "seconds": round(r.duration_ms / 1000, 1), "prompt_tokens": r.prompt_tokens, "reply": r.text[:200]})
    n = len(rows) or 1
    after = sum(x["after_retry"] for x in rows) / n
    return {"passed": after >= 0.95, "first_try_rate": sum(x["first_try"] for x in rows) / n, "after_retry_rate": after, "rows": rows}


def _own_processes() -> list[dict]:
    code = ("Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'deepseek_v4.exe' -or ($_.Name -like 'python*' -and "
            "$_.CommandLine -match 'colibri-[\\d.]+.coli') } | ForEach-Object { '{0} {1}' -f $_.ProcessId, $_.WorkingSetSize }")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", code], capture_output=True, text=True, errors="replace", timeout=60)
    return [{"pid": int(a), "ws": int(b)} for a, b in (ln.split() for ln in r.stdout.splitlines() if ln.strip())]


def _external_connections(pids: set[int]) -> list[str]:
    """Connections of the engine that leave this machine. shortcut: netstat misses rows on this PC, so an empty list is no proof."""
    out = []
    for ln in subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True, errors="replace", timeout=60).stdout.splitlines():
        f = ln.split()
        if len(f) >= 5 and f[0] == "TCP" and f[-1].isdigit() and int(f[-1]) in pids:
            remote = f[2]
            if not remote.startswith(("127.", "[::1]", "0.0.0.0", "[::]", "*")):
                out.append(remote)
    return out


class Sampler(threading.Thread):
    def __init__(self, every_s: int = 30):
        super().__init__(daemon=True)
        self.every_s, self.halt = every_s, threading.Event()
        self.min_free_ram = 999.0
        self.engine_peak_gb = 0.0
        self.vram_peak_mib = 0
        self.external: set[str] = set()
        self.samples = 0      # samples that saw the engine; without any, this step has no evidence and cannot pass
        self.failures = 0

    def sample(self) -> None:
        ram = _ram_gb()
        if not ram:
            raise ValueError("free RAM could not be read")
        self.min_free_ram = min(self.min_free_ram, ram[1])
        procs = _own_processes()
        if not procs:
            raise ValueError("engine process not found")
        self.engine_peak_gb = max(self.engine_peak_gb, sum(p["ws"] for p in procs) / 2**30)
        self.external |= set(_external_connections({p["pid"] for p in procs}))
        r = subprocess.run(["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"], capture_output=True, text=True, errors="replace", timeout=30)
        self.vram_peak_mib = max(self.vram_peak_mib, int(r.stdout.split()[0]))
        self.samples += 1

    def run(self) -> None:
        first = True
        while not self.halt.wait(0 if first else self.every_s):
            first = False
            try:
                self.sample()
            except Exception:  # noqa: BLE001 - one failed sample must not end a run of many hours; they are counted and judged
                self.failures += 1

    def result(self) -> dict:
        seen = self.samples > 0 and self.failures <= self.samples // 10   # a rare failed sample is tolerated, a blind run is not
        ok_mem = seen and self.min_free_ram >= MIN_FREE_RAM_GB and self.engine_peak_gb <= HARD_LIMIT_GB
        return {"memory_passed": ok_mem, "network_passed": seen and not self.external, "samples": self.samples, "failed_samples": self.failures,
                "min_free_ram_gb": round(self.min_free_ram, 1), "engine_peak_gb": round(self.engine_peak_gb, 1),
                "vram_peak_mib": self.vram_peak_mib, "external_connections": sorted(self.external),
                "network_note": "netstat TCP samples every 30 s: finds connections, cannot prove there were none (no UDP, short ones are missed)"}


def run_job(challenge: str, model: str, url: str, out: Path) -> dict:
    """One real job through the whole chain, by the existing example runner (its time budget grows with the engine)."""
    rc = subprocess.run([sys.executable, str(ROOT / "example" / "run_eval.py"), "--llm", "colibri", "--url", url, "--model", model,
                         "--challenge", challenge, "--out", str(out / "job")], cwd=ROOT).returncode
    return {"passed": rc == 0, "exit_code": rc, "challenge": challenge, "dir": str(out / "job")}


def verdict(results: dict) -> bool:
    return all(v.get("passed", False) if "passed" in v else (v["memory_passed"] and v["network_passed"]) for v in results["steps"].values())


def write(out: Path, results: dict) -> None:
    (out / "gate.json").write_text(json.dumps(results, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--settings", default="", help="the file start.ps1 wrote with the chosen settings")
    ap.add_argument("--challenge", default="01-layered-flag", help="empty: skip the real job")
    ap.add_argument("--max-tokens", type=int, default=300)
    a = ap.parse_args()
    out = ROOT / "data" / "eval" / ("colibri-gate-" + time.strftime("%Y%m%d-%H%M%S"))
    out.mkdir(parents=True)
    key = os.environ.pop("SW_COLIBRI_KEY", "")
    llm = ColibriClient(a.model, a.url, key)
    results: dict = {"model": a.model, "started": time.strftime("%Y-%m-%dT%H:%M:%S"), "steps": {},
                     "settings": json.loads(Path(a.settings).read_text(encoding="utf-8")) if a.settings else None}
    sampler = Sampler()
    sampler.start()
    t0 = time.monotonic()
    with tempfile.TemporaryDirectory(dir=out) as d:
        tools = DevGateway(d).list_tools()
    try:
        for name, step in (("repeat", lambda: check_repeat(llm, a.max_tokens)), ("json", lambda: check_json(llm, tools, GOALS, a.max_tokens))):
            print(f"[{time.strftime('%H:%M:%S')}] {name} ...", flush=True)
            results["steps"][name] = step()
            print(f"[{time.strftime('%H:%M:%S')}] {name}: {'PASS' if results['steps'][name]['passed'] else 'FAIL'}", flush=True)
            write(out, results)
    except LLMError as e:
        results["error"] = str(e)[:500]
        print(f"LLM error: {e}", flush=True)
    if a.challenge and "error" not in results:
        os.environ["SW_COLIBRI_KEY"] = key    # only for the job runner, which reads and removes it
        print(f"[{time.strftime('%H:%M:%S')}] job {a.challenge} ...", flush=True)
        results["steps"]["job"] = run_job(a.challenge, a.model, a.url, out)
        os.environ.pop("SW_COLIBRI_KEY", None)
    sampler.halt.set()
    sampler.join(60)
    results["steps"]["resources"] = sampler.result()
    results["minutes"] = round((time.monotonic() - t0) / 60, 1)
    results["passed"] = "error" not in results and verdict(results)
    write(out, results)
    print(json.dumps({k: results[k] for k in ("passed", "minutes")}), "->", out / "gate.json", flush=True)
    for k, v in results["steps"].items():
        print(f"  {k}: " + json.dumps({x: v[x] for x in v if x not in ("rows", "first", "second", "dir")}, ensure_ascii=False)[:300], flush=True)
    return 0 if results["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
