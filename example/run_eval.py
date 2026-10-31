"""Run example challenges end to end with the real local model and check the final report for the flag.

    python example/run_eval.py --challenge all|<id>[,<id>...] [--model qwen3:8b] [--out <dir>]

Per challenge: build the harmless sample -> create job -> run the full chain -> write report.md -> grep report.md for the
challenge flag. The expected value is deliberately NOT passed to the job: the report prints it in its "expected" line,
which would make the grep pass without any analysis. Exit code 0 only if every selected challenge passed.
Everything lands in the output directory (default data/eval/<timestamp>, git-ignored); the application DB is never touched.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(Path(__file__).resolve().parent)]

from samples import BUILDERS  # noqa: E402
from sw_analyst.common.audit import verify_file  # noqa: E402
from sw_analyst.common.models import JobSpec, TargetQuestion  # noqa: E402
from sw_analyst.common.store import Store  # noqa: E402
from sw_analyst.common.util import sha256_hex  # noqa: E402
from sw_analyst.gateway.dev_gateway import DevGateway  # noqa: E402
from sw_analyst.llm.ollama import OllamaClient  # noqa: E402
from sw_analyst.orchestrator.engine import JobEngine  # noqa: E402
from sw_analyst.report.builder import build_report  # noqa: E402

CHALLENGES = Path(__file__).resolve().parent / "challenges"


def load_challenges() -> dict[str, dict]:
    found = {}
    for f in sorted(CHALLENGES.glob("*/challenge.json")):
        c = json.loads(f.read_text(encoding="utf-8"))
        if c["id"] != f.parent.name or c["sample"]["builder"] not in BUILDERS:
            sys.exit(f"{f}: id must equal the folder name and sample.builder must exist in samples.BUILDERS")
        if c["sample"].get("file") and not (f.parent / c["sample"]["file"]).is_file():
            print(f"skip {c['id']}: {c['sample']['file']} missing (git-ignored third-party file, see README)")
            continue
        found[c["id"]] = c
    return found


def run_one(c: dict, out: Path, model: str, url: str, num_ctx: int, minutes: int) -> dict:
    d = out / c["id"]
    d.mkdir(parents=True, exist_ok=True)
    data = BUILDERS[c["sample"]["builder"]]()
    store = Store(d / "t.db", d / "logs")
    spec = JobSpec(title=c["title"], description=c["job_description"], context_info="harmless self-made sample",
                   target_questions=[TargetQuestion(id=f"Q{i}", text_orig=q, text_en=q)
                                     for i, q in enumerate(c["questions"], 1)],
                   budget_max_tasks=20, budget_max_steps=200, budget_max_minutes=minutes)
    job = store.create_job(spec, c["sample"]["name"], sha256_hex(data))
    gw = DevGateway(d)
    gw.store_sample(job["id"], data)
    t0 = time.monotonic()
    status = JobEngine(store, OllamaClient(model, url, num_ctx=num_ctx), gw).run_job(job["id"])
    report = build_report(store, job["id"], "en", model)
    (d / "report.md").write_text(report, encoding="utf-8")
    found = c["flag"] in report
    return {"id": c["id"], "flag": c["flag"], "passed": found, "job_status": status,
            "minutes": round((time.monotonic() - t0) / 60, 1),
            "audit_valid": verify_file(store.audit_path(job["id"])).valid, "report": str(d / "report.md")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge", default="all")
    ap.add_argument("--model", default="qwen3:8b")
    ap.add_argument("--url", default="http://127.0.0.1:11435")
    ap.add_argument("--num-ctx", type=int, default=16384)
    ap.add_argument("--minutes", type=int, default=10, help="time budget per challenge")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    all_c = load_challenges()
    ids = list(all_c) if a.challenge == "all" else [x for x in a.challenge.split(",") if x]
    unknown = [i for i in ids if i not in all_c]
    if unknown:
        sys.exit(f"unknown challenge: {', '.join(unknown)}. Known: {', '.join(all_c)}")
    out = Path(a.out) if a.out else ROOT / "data" / "eval" / time.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for i in ids:
        print(f"== {i}: {all_c[i]['title']} ...", flush=True)
        try:
            r = run_one(all_c[i], out, a.model, a.url, a.num_ctx, a.minutes)
        except Exception as e:  # one broken challenge must not hide the others
            r = {"id": i, "flag": all_c[i]["flag"], "passed": False, "job_status": f"error: {e}", "minutes": 0,
                 "audit_valid": None, "report": ""}
        results.append(r)
        print(f"   {'PASS' if r['passed'] else 'FAIL'}  flag={r['flag']}  job={r['job_status']}  {r['minutes']} min"
              f"  audit={'ok' if r['audit_valid'] else r['audit_valid']}", flush=True)
        (out / "summary.json").write_text(json.dumps({"model": a.model, "results": results}, indent=1), encoding="utf-8")
    ok = sum(r["passed"] for r in results)
    print(f"\n{ok}/{len(results)} passed. Reports and summary: {out}")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
