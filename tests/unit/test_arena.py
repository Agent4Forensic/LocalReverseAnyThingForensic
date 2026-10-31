"""The arena table must add up runs per model and show partial offload. No model involved."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bench"))

import json  # noqa: E402

import run_arena  # noqa: E402
from run_arena import summarize, table  # noqa: E402


def _run(model: str, ok: int, **kw) -> dict:
    return {"model": model, "answers_ok": ok, "answers_total": 2, "findings": {"confirmed": 1, "rejected": 1},
            "invalid_actions": 1, "llm_calls": 10, "cut_replies": 0, "llm_errors": 0, "minutes": 1.5, "tok_out": 100,
            "llm_seconds": 10.0, "tasks": {"done": 3, "failed": 1}, "audit_valid": True, "guard_high": 0,
            "gpu_used_mib": 7000, "loaded": {"size_mib": 6000, "vram_mib": 6000}, **kw}


def test_summary_adds_up_per_model_and_detects_offload():
    s = summarize([_run("a", 2), _run("a", 1, loaded={"size_mib": 9000, "vram_mib": 8000}), _run("b", 0, loaded={})])
    assert s["a"]["answers_ok"] == 3 and s["a"]["answers_total"] == 4 and s["a"]["invalid"] == 2
    assert s["a"]["confirmed"] == 2 and s["a"]["findings"] == 4 and s["a"]["failed_tasks"] == 2
    assert s["a"]["offload"] is True and s["b"]["offload"] is False


def test_table_survives_a_run_without_model_time():
    assert "| b | 0/2 |" in table(summarize([_run("b", 0, llm_seconds=0.0)]))


def test_a_crashed_run_is_reported_and_the_arena_goes_on(tmp_path, monkeypatch):
    def fake_run_one(sid, *a, **kw):
        if sid == "ctf2":
            raise OSError("disk full")
        r = _run("x", 1)
        r["status"] = "done"
        return r

    monkeypatch.setattr(run_arena, "run_one", fake_run_one)
    monkeypatch.setattr(run_arena, "gpu_used_mib", lambda: None)
    monkeypatch.setattr(run_arena, "loaded_model", lambda url: {})
    monkeypatch.setattr(sys, "argv", ["run_arena", "--models", "m", "--seeds", "1", "--only", "ctf2,inject",
                                      "--out", str(tmp_path)])
    run_arena.main()
    data = json.loads((tmp_path / "arena.json").read_text(encoding="utf-8"))
    assert len(data["runs"]) == 1 and data["crashed"][0]["sample"] == "ctf2"
    assert "Abgebrochen: m seed=1 ctf2: OSError: disk full" in (tmp_path / "arena.md").read_text(encoding="utf-8")
