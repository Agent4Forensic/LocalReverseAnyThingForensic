"""Hardware to settings for colibri, the first-test gate, and a whole job through ColibriClient over HTTP (ADR-0012)."""
import importlib.util
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from sw_analyst.common.models import JobSpec
from sw_analyst.common.store import Store
from sw_analyst.common.util import sha256_hex
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.llm.base import LLMError
from sw_analyst.llm.colibri import ColibriClient
from sw_analyst.colibri_settings import Hardware, choose, eligible
from sw_analyst.llm.fake import ScriptedLLM
from sw_analyst.orchestrator.engine import JobEngine

ROOT = Path(__file__).resolve().parents[2]
THIS_PC = dict(ram_total_gb=31.1, gpu_name="RTX 5060 Ti", compute_cap=12.0, vram_total_mib=16311, disk_bus="USB", disk_read_mb_s=450.0)


def _hw(**kw):
    return Hardware(**{**THIS_PC, "ram_free_gb": 20.0, "vram_free_mib": 15000, **kw})


# ---- RAM ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("free,want", [(30.0, 20), (24.0, 20), (20.0, 16), (17.0, 13), (14.7, 12), (8.0, 12)])
def test_ram_budget_follows_what_is_free_and_stays_inside_the_limits(free, want):
    assert choose(_hw(ram_free_gb=free))["ram_gb"] == want


def test_a_big_machine_still_keeps_the_hard_limit_and_a_small_one_keeps_windows_alive():
    assert choose(_hw(ram_total_gb=128.0, ram_free_gb=120.0))["ram_gb"] == 20
    assert choose(_hw(ram_total_gb=24.0, ram_free_gb=23.0))["ram_gb"] == 17


def test_the_limits_beat_the_floor_and_a_manual_budget():
    s = choose(_hw(ram_total_gb=16.0, ram_free_gb=15.0))
    assert s["ram_gb"] == 9 and any("may refuse to start" in w for w in s["warnings"])
    s = choose(_hw(), ram_override=100)
    assert s["ram_gb"] == 20 and any("100 asked for" in w for w in s["warnings"])
    assert choose(_hw(), ram_override=-5)["ram_gb"] == 16   # not a budget: treated as unset


@pytest.mark.parametrize("total", [0.0, 7.0, 5.0])
def test_no_budget_is_guessed_without_a_ram_reading_or_with_no_room(total):
    with pytest.raises(ValueError):
        choose(_hw(ram_total_gb=total))


def test_low_ram_warns_and_a_manual_budget_wins():
    s = choose(_hw(ram_free_gb=14.0))
    assert any("below the 16 GB" in w for w in s["warnings"]) and any("HostGuard" in w for w in s["warnings"])
    assert choose(_hw(ram_free_gb=14.0), ram_override=18)["ram_gb"] == 18


# ---- GPU: the table in colibri docs/deepseek-v4.md -------------------------------------------------------
@pytest.mark.parametrize("free,dense,attn,moe", [(15000, "1", "1", "1"), (11000, "1", "1", "1"), (10999, "1", "1", "0"),
                                                 (7000, "1", "1", "0"), (6999, "0", "0", "1"), (4500, "0", "0", "1")])
def test_vram_table(free, dense, attn, moe):
    s = choose(_hw(vram_free_mib=free))
    assert s["backend"] == "cuda"
    assert (s["env"]["CUDA_DENSE"], s["env"]["COLI_CUDA_ATTN_BATCH"], s["env"]["COLI_CUDA_MOE_BATCH"]) == (dense, attn, moe)
    assert s["env"]["V4_LOADER_LANES"] == "3"


@pytest.mark.parametrize("hw", [dict(vram_free_mib=4499), dict(compute_cap=7.5), dict(gpu_name="", compute_cap=0.0, vram_total_mib=0, vram_free_mib=0)])
def test_without_a_usable_gpu_the_cpu_path_is_taken(hw):
    s = choose(_hw(**hw))
    assert s["backend"] == "cpu" and s["env"]["DSV4_CUDA"] == "0" and "COLI_CUDA" not in s["env"]


def test_vram_used_by_others_and_usb_are_named():
    s = choose(_hw(vram_free_mib=9000))
    assert any("in use by other programs" in w for w in s["warnings"]) and any("USB" in w for w in s["warnings"])
    assert not any("USB" in w for w in choose(_hw(disk_bus="NVMe"))["warnings"])


def test_estimate_comes_from_the_measured_disk():
    assert choose(_hw())["estimate_tok_s"] == 0.16
    assert choose(_hw(disk_read_mb_s=0.0))["estimate_tok_s"] == 0.0


def test_the_settings_are_json_for_start_ps1():
    assert json.loads(json.dumps(choose(_hw())))["ctx"] == 16384


# ---- may this machine use colibri at all? --------------------------------------------------------------
def test_a_machine_that_carries_it_is_eligible():
    assert eligible(_hw(ram_free_gb=22.0, disk_bus="NVMe", disk_read_mb_s=3000.0)) == []


@pytest.mark.parametrize("kw,word", [(dict(ram_total_gb=16.0), "in total"), (dict(ram_free_gb=11.0), "RAM free"),
                                     (dict(disk_read_mb_s=456.0, disk_bus="USB"), "tok/s"), (dict(disk_read_mb_s=0.0), "tok/s")])
def test_each_shortfall_names_its_reason(kw, word):
    why = eligible(_hw(**{"ram_free_gb": 22.0, "disk_bus": "NVMe", "disk_read_mb_s": 3000.0, **kw}))
    assert why and word in " ".join(why)


def test_an_incomplete_model_is_a_reason_too():
    assert eligible(_hw(ram_free_gb=22.0, disk_read_mb_s=3000.0), "40 of 54 files missing") == ["40 of 54 files missing"]


def test_start_stays_on_ollama_by_default_and_checks_the_machine_on_every_start():
    txt = (ROOT / "scripts" / "start.ps1").read_text(encoding="ascii")
    assert "[string]$Llm = 'ollama'" in txt and "colibri_settings --check" in txt
    assert "staying on Ollama" in txt and "colibri.enabled" in txt and "-Llm colibri" not in txt.split("param(")[0]
    assert txt.index("colibri_settings --check") < txt.index("Resolve-Model }")


# ---- gate -----------------------------------------------------------------------------------------------
def _gate():
    spec = importlib.util.spec_from_file_location("colibri_gate", ROOT / "tests" / "bench" / "colibri_gate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_gate_repeat_passes_only_on_identical_non_empty_text():
    gate = _gate()
    assert gate.check_repeat(ScriptedLLM(lambda m: "same"), 10)["passed"] is True
    replies = iter(["one", "two"])
    assert gate.check_repeat(ScriptedLLM(lambda m: next(replies)), 10)["passed"] is False
    assert gate.check_repeat(ScriptedLLM(lambda m: ""), 10)["passed"] is False


def test_gate_json_uses_the_runner_check_and_counts_the_retry(tmp_path):
    gate = _gate()
    tools = DevGateway(tmp_path).list_tools()
    good = json.dumps({"action": "tool", "tool": tools[0].name, "args": {}, "why": "w"})
    good = good if gate.validate_action(good, tools).ok else json.dumps({"action": "finish", "summary": "s", "findings": []})
    assert gate.validate_action(good, tools).ok
    r = gate.check_json(ScriptedLLM(lambda m: good), tools, gate.GOALS[:2], 10)
    assert r["passed"] and r["first_try_rate"] == 1.0
    replies = iter(["not json", good])
    r = gate.check_json(ScriptedLLM(lambda m: next(replies)), tools, gate.GOALS[:1], 10)
    assert r["passed"] and r["first_try_rate"] == 0.0 and r["after_retry_rate"] == 1.0
    r = gate.check_json(ScriptedLLM(lambda m: "not json"), tools, gate.GOALS[:1], 10)
    assert not r["passed"] and r["rows"][0]["error"]


def test_gate_verdict_needs_every_step():
    gate = _gate()
    ok = {"memory_passed": True, "network_passed": True}
    assert gate.verdict({"steps": {"repeat": {"passed": True}, "resources": ok}}) is True
    assert gate.verdict({"steps": {"repeat": {"passed": False}, "resources": ok}}) is False
    assert gate.verdict({"steps": {"repeat": {"passed": True}, "resources": {**ok, "network_passed": False}}}) is False


def test_gate_sampler_without_evidence_cannot_pass():
    r = _gate().Sampler().result()
    assert r["memory_passed"] is False and r["network_passed"] is False


def test_gate_sampler_survives_a_failing_sample_and_counts_it(monkeypatch):
    gate = _gate()
    monkeypatch.setattr(gate, "_own_processes", lambda: (_ for _ in ()).throw(AttributeError("netstat output undecodable")))
    s = gate.Sampler(every_s=3600)
    s.start()
    s.halt.set()
    s.join(10)
    assert not s.is_alive() and s.result()["network_passed"] is False


def test_gate_sampler_without_a_ram_reading_has_no_evidence(monkeypatch):
    gate = _gate()
    monkeypatch.setattr(gate, "_ram_gb", lambda: None)
    s = gate.Sampler()
    with pytest.raises(ValueError):
        s.sample()
    assert s.result()["memory_passed"] is False


def test_gate_sampler_tolerates_rare_failures_but_not_a_blind_run():
    s = _gate().Sampler()
    s.samples, s.min_free_ram, s.engine_peak_gb, s.failures = 20, 10.0, 14.0, 2
    assert s.result()["memory_passed"] and s.result()["network_passed"]
    s.failures = 3
    assert not s.result()["memory_passed"] and not s.result()["network_passed"]


def test_gate_sampler_judges_memory_and_network():
    s = _gate().Sampler()
    s.samples, s.min_free_ram, s.engine_peak_gb = 1, 10.0, 14.0
    assert s.result()["memory_passed"] and s.result()["network_passed"]
    s.min_free_ram = 2.0
    assert not s.result()["memory_passed"]
    s.min_free_ram, s.engine_peak_gb = 10.0, 25.0
    assert not s.result()["memory_passed"]
    s.external.add("1.2.3.4:443")
    assert not s.result()["network_passed"]


# ---- a whole job over HTTP ------------------------------------------------------------------------------
def test_a_job_runs_through_the_client_and_the_steps_tell_the_truth(tmp_path):
    finish = json.dumps({"action": "finish", "summary": "nothing to report", "findings": []})
    seen = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append(body)
            text = " ".join(m["content"] for m in body["messages"])
            reply = (json.dumps({"changes": [], "new_tasks": []}) if "orders the work queue" in text
                     else json.dumps({"answers": [], "missing": [], "new_tasks": []}) if "critical reviewer" in text else finish)
            payload = {"model": body["model"], "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                       "choices": [{"delta": {"content": reply}, "finish_reason": "stop"}]}
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"data: " + json.dumps(payload).encode() + b"\n\ndata: [DONE]\n\n")

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        store = Store(tmp_path / "t.db", tmp_path / "logs")
        gw = DevGateway(tmp_path)
        data = b"plain harmless text\n"
        job = store.create_job(JobSpec(title="t", description="d"), "s.txt", sha256_hex(data))
        gw.store_sample(job["id"], data)
        llm = ColibriClient("m@abc-colibri-2.1.0-cuda", f"http://127.0.0.1:{srv.server_port}", "k")
        status = JobEngine(store, llm, gw).run_job(job["id"])
    finally:
        srv.shutdown()
    assert seen and status in ("done", "partial", "completed", "finished")
    assert all(b["temperature"] == 0 and b["enable_thinking"] is False and "seed" not in b and "response_format" not in b for b in seen)
    steps = [s for t in store.list_tasks(job["id"]) for s in store.list_steps(t["id"]) if "json_mode" in (s["how"] or "")]
    assert steps and all("think=off" in s["how"] and "seed=none" in s["how"] for s in steps)


def test_cancelling_a_job_interrupts_the_reply_and_the_job_still_ends_with_a_report(tmp_path):
    first_request = threading.Event()
    calls_after_cancel = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.end_headers()
            first_request.set()
            try:
                for _ in range(600):
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    time.sleep(0.05)
            except OSError:
                calls_after_cancel.append(time.monotonic())

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        store = Store(tmp_path / "t.db", tmp_path / "logs")
        gw = DevGateway(tmp_path)
        data = b"plain harmless text\n"
        job = store.create_job(JobSpec(title="t", description="d"), "s.txt", sha256_hex(data))
        gw.store_sample(job["id"], data)
        llm = ColibriClient("m", f"http://127.0.0.1:{srv.server_port}", "k")
        llm.cancel_poll_s = 0.1
        engine = JobEngine(store, llm, gw, use_prioritizer=False)
        threading.Thread(target=lambda: (first_request.wait(20), store.update_job(job["id"], cancel_requested=1)), daemon=True).start()
        t0 = time.monotonic()
        status = engine.run_job(job["id"])
    finally:
        srv.shutdown()
    assert first_request.is_set() and calls_after_cancel, "the model was asked and the connection was closed"
    assert status == "cancelled" and time.monotonic() - t0 < 25
    assert llm.should_cancel is None    # later translations and the report of this job must not count as cancelled


def test_warmup_counts_what_the_engine_took_and_keeps_going_after_a_failure():
    spec = importlib.util.spec_from_file_location("colibri_warmup", ROOT / "infra" / "colibri-warmup.py")
    warm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(warm)
    assert warm.warm(ScriptedLLM(lambda m: "x")) == len(warm.SNIPPETS)
    replies = iter([LLMError("gone")])

    def flaky(messages):
        for r in replies:
            raise r
        return "x"
    assert warm.warm(ScriptedLLM(flaky)) == len(warm.SNIPPETS) - 1


def test_verify_of_a_mirror_takes_both_spellings_of_the_folder_option(tmp_path, monkeypatch, capsys):
    spec = importlib.util.spec_from_file_location("fetch_colibri_model", ROOT / "infra" / "fetch-colibri-model.py")
    fetch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fetch)
    monkeypatch.setattr(fetch, "volume_by_label", lambda label: pytest.fail("must not look at the volume"))
    for argv in (["--verify", "--dir", str(tmp_path)], ["--verify", f"--dir={tmp_path}"]):
        monkeypatch.setattr("sys.argv", ["fetch", *argv])
        assert fetch.main() == 1      # the empty folder is what was checked
    assert "files missing or changed" in capsys.readouterr().out


def test_a_slow_engine_gets_a_longer_time_budget(tmp_path):
    engine = JobEngine(Store(tmp_path / "t.db", tmp_path / "logs"), ColibriClient("m"), DevGateway(tmp_path))
    assert engine._minutes({"budget_max_minutes": 10}) == 300
    fast = JobEngine(Store(tmp_path / "u.db", tmp_path / "logs2"), ScriptedLLM(lambda m: ""), DevGateway(tmp_path))
    assert fast._minutes({"budget_max_minutes": 10}) == 10
