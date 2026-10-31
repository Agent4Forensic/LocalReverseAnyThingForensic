"""Model arena (M1): every model and seed on every harmless sample of run_live.py, one comparison table.

Not collected by pytest. Run it alone on the GPU: a second model run distorts durations and can break the time budget.

    python tests/bench/run_arena.py --models qwen3:8b,qwen3:14b --seeds 42,7 --out <dir>
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_live import run_one, samples  # noqa: E402


def gpu_used_mib() -> int | None:
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=10, check=True).stdout
        return int(out.split()[0])
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return None


def loaded_model(url: str) -> dict:
    """Size and VRAM share of the loaded model. size_mib > vram_mib means partial CPU offload."""
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/api/ps", timeout=5) as r:
            models = json.loads(r.read().decode("utf-8")).get("models", [])
    except (OSError, ValueError):
        return {}
    return {"name": models[0].get("name"), "size_mib": models[0].get("size", 0) // 2**20,
            "vram_mib": models[0].get("size_vram", 0) // 2**20} if models else {}


def summarize(runs: list[dict]) -> dict:
    """Totals per model. Evidence rate: confirmed findings among all findings the chain kept or refused."""
    out: dict[str, dict] = {}
    for r in runs:
        m = out.setdefault(r["model"], dict(runs=0, answers_ok=0, answers_total=0, confirmed=0, findings=0, invalid=0,
                                            calls=0, cut=0, llm_errors=0, minutes=0.0, tok_out=0, llm_seconds=0.0,
                                            failed_tasks=0, audit_bad=0, guard_high=0, peak_gpu_mib=0, offload=False))
        m["runs"] += 1
        m["answers_ok"] += r["answers_ok"]
        m["answers_total"] += r["answers_total"]
        m["confirmed"] += r["findings"].get("confirmed", 0)
        m["findings"] += sum(r["findings"].values())
        m["invalid"] += r["invalid_actions"]
        m["calls"] += r["llm_calls"]
        m["cut"] += r["cut_replies"]
        m["llm_errors"] += r["llm_errors"]
        m["minutes"] = round(m["minutes"] + r["minutes"], 1)
        m["tok_out"] += r["tok_out"]
        m["llm_seconds"] = round(m["llm_seconds"] + r["llm_seconds"], 1)
        m["failed_tasks"] += r["tasks"].get("failed", 0) + r["tasks"].get("blocked", 0)
        m["audit_bad"] += not r["audit_valid"]
        m["guard_high"] += r["guard_high"]
        m["peak_gpu_mib"] = max(m["peak_gpu_mib"], r.get("gpu_used_mib") or 0)
        loaded = r.get("loaded") or {}
        m["offload"] = m["offload"] or loaded.get("size_mib", 0) > loaded.get("vram_mib", 0)
    return out


def table(summary: dict) -> str:
    rows = ["| Modell | Treffer | Belegquote | ungültig/Aufrufe | abgeschnitten | Serverfehler | fehlgeschl. Tasks | Minuten | Token/s | GPU MiB (max. nach Lauf) | Offload |",
            "|---|---|---|---|---|---|---|---|---|---|---|"]
    for name, m in summary.items():
        evidence = f"{m['confirmed']}/{m['findings']}"
        tps = round(m["tok_out"] / m["llm_seconds"], 1) if m["llm_seconds"] else 0
        rows.append(f"| {name} | {m['answers_ok']}/{m['answers_total']} | {evidence} | {m['invalid']}/{m['calls']} | {m['cut']} "
                    f"| {m['llm_errors']} | {m['failed_tasks']} | {m['minutes']} | {tps} | {m['peak_gpu_mib']} | {'ja' if m['offload'] else 'nein'} |")
    return "\n".join(rows)


def report(summary: dict, crashed: list[dict]) -> str:
    lines = [table(summary), ""]
    lines += [f"Abgebrochen: {c['model']} seed={c['seed']} {c['sample']}: {c['error']}" for c in crashed]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="qwen3:8b,qwen3:14b")
    ap.add_argument("--seeds", default="42,7")
    ap.add_argument("--url", default="http://127.0.0.1:11435")
    ap.add_argument("--num-ctx", type=int, default=16384)
    ap.add_argument("--minutes", type=int, default=10, help="time budget per sample")
    ap.add_argument("--only", default="")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    all_s = samples()
    chosen = [x for x in a.only.split(",") if x] or list(all_s)
    runs: list[dict] = []
    crashed: list[dict] = []
    for model in a.models.split(","):
        for seed in (int(x) for x in a.seeds.split(",")):
            for sid in chosen:
                t = time.strftime("%H:%M:%S")
                print(f"[{t}] {model} seed={seed} {sid} ...", flush=True)
                try:
                    r = run_one(sid, all_s[sid], out / model.replace(":", "_") / str(seed), model, a.url, a.num_ctx,
                                a.minutes, seed=seed)
                except Exception as e:  # one broken run must not hide the others, but must stay visible
                    crashed.append({"model": model, "seed": seed, "sample": sid, "error": f"{type(e).__name__}: {e}"})
                    print(f"    CRASH {crashed[-1]['error']}", flush=True)
                else:
                    r.update(model=model, gpu_used_mib=gpu_used_mib(), loaded=loaded_model(a.url))
                    runs.append(r)
                    print(f"    answers {r['answers_ok']}/{r['answers_total']} status={r['status']} {r['minutes']} min "
                          f"invalid={r['invalid_actions']} llm_errors={r['llm_errors']}", flush=True)
                summary = summarize(runs)
                (out / "arena.json").write_text(json.dumps({"params": vars(a), "summary": summary, "runs": runs,
                                                            "crashed": crashed}, indent=1), encoding="utf-8")
                (out / "arena.md").write_text(report(summary, crashed), encoding="utf-8")
    print(report(summarize(runs), crashed))


if __name__ == "__main__":
    main()
