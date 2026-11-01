"""Expert review of the analysis loop (2026-11-01, ADR-0012): deterministic decoding of scripts and text, custody
findings for derived files, GAP statements as open points, answers resting on listed findings, cut-off helper
replies, budget stops that name what was not run, and the report appendix of rejected claims."""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

from sw_analyst.common.models import JobSpec, TargetQuestion
from sw_analyst.common.store import Store
from sw_analyst.common.util import sha256_hex
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.guard import validate_action
from sw_analyst.llm.base import LLMResponse
from sw_analyst.llm.fake import ScriptedLLM
from sw_analyst.orchestrator.agents import HelperAgents
from sw_analyst.orchestrator.engine import JobEngine, blob_hits, top_functions
from sw_analyst.orchestrator.runner import context_limits
from sw_analyst.orchestrator.verifier import verify_finding
from sw_analyst.report.builder import build_report

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "example"))
from samples import layered_flag, prompt_injection, script_three_layers  # noqa: E402

EVAL = json.dumps({"goal_reached": True, "assessment": "ok", "gaps": [], "followups": []})
NOTHING = json.dumps({"action": "finish", "summary": "nothing", "findings": []})


def _text(messages):
    return "\n".join(m.content for m in messages)


def _helpers(messages):
    t = _text(messages)
    if "critical reviewer" in t:
        return EVAL
    if "orders the work queue" in t:
        return json.dumps({"changes": [], "new_tasks": []})
    return None


def _job(tmp_path, data, questions=(), responder=None, name="s.bin", **budget):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    gw = DevGateway(tmp_path)
    spec = JobSpec(title="t", description="d", target_questions=list(questions), **budget)
    job = store.create_job(spec, name, sha256_hex(data))
    gw.store_sample(job["id"], data)
    llm = ScriptedLLM(responder or (lambda m: _helpers(m) or NOTHING))
    return store, gw, llm, JobEngine(store, llm, gw), job["id"]


def _derived_texts(store, gw, jid):
    root = gw._ctx(jid).root
    return {f["path"]: (root / f["path"]).read_bytes() for f in gw.list_files(jid) if f["kind"] == "derived"}


# ---- deterministic decoding of scripts and text ---------------------------------------------------------------------

def test_script_blob_is_peeled_to_the_inner_script_before_any_model_call(tmp_path):
    store, gw, llm, engine, jid = _job(tmp_path, script_three_layers(), name="bench.ps1")
    engine.run_job(jid)
    layers = _derived_texts(store, gw, jid)
    inner = next((t for t in layers.values() if b"MARKER{three_layers}" in t), None)
    assert inner is not None and b"https://example.invalid/update" in inner
    decode = [t for t in store.list_tasks(jid) if t["title"].startswith("Deterministic: decode run")]
    assert len(decode) == 3 and all(t["status"] == "done" for t in decode)
    first_model_call = llm.calls[0]
    assert "Derived files" in _text(first_model_call) and "derived/layer01.bin" in _text(first_model_call)
    custody = [f for f in store.list_findings(jid, "confirmed") if f["statement_en"].startswith("Derived file ")]
    assert len(custody) == 3 and all(f["quotes"][0]["quote"].startswith("SHA-256: ") for f in custody)
    ev = store.get_evidence(custody[0]["evidence_ids"][0])
    assert ev["source_ref"]["source_ref"] == {"file": "sample", "offset": 37, "length": 256}   # the run, not the line


def test_text_of_two_base64_layers_is_decoded_to_the_flag(tmp_path):
    store, gw, _, engine, jid = _job(tmp_path, layered_flag(), name="ctf.txt")
    engine.run_job(jid)
    layers = _derived_texts(store, gw, jid)
    assert layers.get("derived/layer02.bin") == b"FLAG{layered_ok}"
    titles = [t["title"] for t in store.list_tasks(jid)]
    assert "Deterministic: decode run at 0x0 layer 2" in titles and "Triage artifact: derived/layer02.bin" in titles


def test_injection_sample_payload_is_decoded_and_the_text_never_becomes_a_task(tmp_path):
    store, gw, _, engine, jid = _job(tmp_path, prompt_injection(), name="note.txt")
    engine.run_job(jid)
    assert b"MARKER{not_fooled}" in b"".join(_derived_texts(store, gw, jid).values())
    assert not any("Ignore all previous" in t["goal"] for t in store.list_tasks(jid))


def test_blob_hits_take_the_longest_run_first_and_extend_a_cut_string():
    text = ("Strings in s (min length 64, encoding ascii, from offset 0x0): 2 shown\n"
            "offset      len     enc  string   [A=ASCII, W=UTF-16LE; len = characters]\n"
            "0x00000010  80      A    x = '" + "A" * 70 + "'\n"
            "0x00000100  400     A    " + "B" * 300 + "...[+100 chars]\n"
            "0x00000200  20      A    short line here!\n")
    assert blob_hits(text) == [(0x100, 400), (0x10 + 5, 70)]


@pytest.mark.parametrize("chunk,method,cut", [
    (b"eyJpZCI6ICJCRU5DSC00MiJ9" + b"'\n# comment", "auto", b"'\n# comment"),
    (b"eyJpZCI6ICJCRU5DSC00MiJ9" + b"'\n# comment", "base64", b"'\n# comment"),
    (b"eyJpZCI6ICJCRU5DSC00MiJ9\n", "auto", b""),              # a whole blob plus newline is not cut
    (b"eyJpZCI6ICJCRU5D\nSC00MiJ9'\nx", "auto", b""),          # wrapped blobs are never cut to their first line
    (b"MZ\x90\x00\x03" + bytes(range(60)), "auto", b""),       # binary input stays whole
    (b"abc'rest of the line", "base64", b""),                  # a run shorter than 16 proves nothing
])
def test_decode_layer_trims_only_a_single_line_run_followed_by_a_delimiter(chunk, method, cut):
    kept, tail = DevGateway._trim_tail(chunk, method)
    assert tail == cut and kept + tail == chunk


def test_decode_layer_evidence_names_the_trimmed_range(tmp_path):
    data = b"$b = '" + base64.b64encode(b"hello world, this is long enough") + b"'\nWrite-Output $b\n"
    store, gw, _, _, jid = _job(tmp_path, data, name="a.ps1")
    r = gw.call(jid, "decode_layer", {"method": "base64", "offset": 6, "length": 0})
    assert r.ok, r.error
    assert "Ignored 18 trailing byte(s)" in r.text and r.meta["source_ref"]["length"] == 44
    assert b"hello world" in (gw._ctx(jid).root / r.meta["derived"]).read_bytes()


def test_strings_extract_reports_the_length_of_a_cut_string(tmp_path):
    store, gw, _, _, jid = _job(tmp_path, b"x" * 350 + b"\n", name="a.txt")
    r = gw.call(jid, "strings_extract", {"min_len": 64})
    assert "0x00000000  350     A    " in r.text and "...[+50 chars]" in r.text


# ---- GAP statements and answers --------------------------------------------------------------------------------------

def test_gap_without_evidence_is_an_open_point_not_a_rejected_claim(tmp_path):
    store, _, _, _, jid = _job(tmp_path, b"plain\n")
    gap = {"statement": "GAP: static analysis could not determine the C2 schedule.", "status": "hypothesis", "evidence": []}
    vf = verify_finding(store, jid, gap)
    assert vf.status == "open" and not vf.reject_reason
    claim = {"statement": "The sample beacons every hour.", "status": "hypothesis", "evidence": []}
    assert verify_finding(store, jid, claim).status == "rejected"


def test_model_gap_reaches_the_report_once(tmp_path):
    gap = "GAP: static analysis could not determine the sleep interval."

    def model(messages):
        h = _helpers(messages)
        if h:
            return h
        return json.dumps({"action": "finish", "summary": "s", "findings": [
            {"statement": gap, "status": "hypothesis", "evidence": [{"id": "EV-000001", "quote": ""}]},
            {"statement": gap, "status": "hypothesis", "evidence": [{"id": "EV-999999", "quote": ""}]}]})

    store, _, llm, engine, jid = _job(tmp_path, b"plain\n", responder=model)
    engine.run_job(jid)
    kinds = [f["status"] for f in store.list_findings(jid) if f["statement_en"] == gap]
    assert kinds.count("open") == 1 and "rejected" not in kinds      # existing evidence keeps it a hypothesis, the rest is open
    assert gap in build_report(store, jid, "en", "m")
    assert not any("CHECK FAILED" in _text(c) for c in llm.calls)    # no repair round spent on a gap


def test_answer_rests_on_listed_confirmed_findings(tmp_path):
    q = TargetQuestion(id="Q1", text_orig="Which URL is referenced?")

    def model(messages):
        h = _helpers(messages)
        if h:
            return h
        t = _text(messages)
        if "answers one target question" in t:
            fid = [line.split(":")[0].strip("- ") for line in t.splitlines() if line.startswith("- F-")][0]
            return json.dumps({"action": "finish", "summary": "from F", "findings": [],
                               "answer": {"text": "The script references https://example.invalid/update", "based_on": [fid]}})
        if "is stored as" not in t:
            return json.dumps({"action": "tool", "tool": "read_lines", "args": {"path": "sample"}, "why": "read"})
        ev = t.split("is stored as ")[-1][:9]
        return json.dumps({"action": "finish", "summary": "s", "findings": [
            {"statement": "The script sets $u to https://example.invalid/update.", "status": "confirmed",
             "evidence": [{"id": ev, "quote": '$u = "https://example.invalid/update"'}]}]})

    data = b'$u = "https://example.invalid/update"\n'
    store, _, _, engine, jid = _job(tmp_path, data, questions=(q,), responder=model, name="a.ps1")
    engine.run_job(jid)
    ans = store.get_answer(jid, "Q1")
    assert ans["status"] == "answered", ans["evaluation_en"]
    assert ans["finding_ids"] and store.get_finding(ans["finding_ids"][0])["status"] == "confirmed"


def test_based_on_is_validated_and_unproven_ids_do_not_count(tmp_path):
    bad = json.dumps({"action": "finish", "summary": "s", "findings": [], "answer": {"text": "x", "based_on": ["EV-000001"]}})
    assert not validate_action(bad, []).ok
    good = json.dumps({"action": "finish", "summary": "s", "findings": [], "answer": {"text": "x", "based_on": ["F-000001", "F-000001"]}})
    res = validate_action(good, [])
    assert res.ok and res.action["answer"]["based_on"] == ["F-000001"]
    store, _, _, engine, jid = _job(tmp_path, b"plain\n")
    task = store.add_task(jid, title="x", goal="g", kind="analyze", origin="recipe", priority=1)
    hyp = store.add_finding(jid, task["id"], "maybe", "hypothesis", [], [], "")
    assert engine.runner._based_on(jid, {"answer": {"based_on": [hyp["id"], "F-424242"]}}) == []


# ---- helpers, budget, context ----------------------------------------------------------------------------------------

def test_helper_retries_once_with_more_room_after_a_cut_off_reply(tmp_path):
    store, _, _, _, jid = _job(tmp_path, b"plain\n")
    task = store.add_task(jid, title="x", goal="g", kind="analyze", origin="recipe", priority=1)

    class Cut:
        model = "m"

        def __init__(self):
            self.budgets = []

        def chat(self, messages, *, json_mode=False, think=True, max_tokens=2048, temperature=0.1):
            self.budgets.append(max_tokens)
            if len(self.budgets) == 1:
                return LLMResponse(text='{"goal_reached": tr', model="m", done_reason="length")
            return LLMResponse(text=EVAL, model="m", done_reason="stop")

    llm = Cut()
    ev = HelperAgents(store, llm).evaluate(store.get_job(jid), task, "s", [], [], "(none)", "(none)")
    assert ev["goal_reached"] is True and llm.budgets == [3000, 4096]
    step = store._q("SELECT how FROM steps WHERE job_id=? AND kind='evaluate'", (jid,))[0]["how"]
    assert "retried once" in step


def test_budget_stop_names_the_tasks_that_were_not_run(tmp_path):
    q = TargetQuestion(id="Q1", text_orig="Flag?")
    store, _, _, engine, jid = _job(tmp_path, b"plain\n", questions=(q,), budget_max_steps=6)
    assert engine.run_job(jid) == "partial"
    tasks = [t for t in store.list_tasks(jid) if t["kind"] != "group"]
    assert not any(t["status"] == "pending" for t in tasks)
    assert any(t["status"] == "skipped" and "step budget exhausted" in t["summary_en"] for t in tasks)


def test_context_limits_scale_with_the_model_context():
    small, big = context_limits(16384), context_limits(32768)
    assert small["context_chars"] == 36000 and small["reply_tokens"] == 3000
    assert big["context_chars"] == 72000 and big["evidence_chars"] == 12000 and big["reply_tokens_max"] == 8192
    assert context_limits(4096)["context_chars"] == 36000          # never below the tuned minimum


def test_top_functions_prefer_large_named_code_and_skip_thunks_and_the_entry():
    text = ("Functions in s: 4 match(es) of 4; PE, x86:LE:32:default, image base 0x400000\n"
            "entry | size | name | signature\n"
            "0x401010 | 17 | entry | undefined entry(void)\n"
            "0x401100 | 240 | FUN_00401100 | int FUN_00401100(void)\n"
            "0x401400 | 900 | decode_config | void decode_config(char *)\n"
            "0x402000 | 6 | thunk_FUN [thunk] | void thunk_FUN(void)\n")
    assert top_functions(text, 0x401010) == [("0x401400", "decode_config"), ("0x401100", "FUN_00401100")]


# ---- report ------------------------------------------------------------------------------------------------------------

def test_report_lists_derived_files_and_rejected_claims(tmp_path):
    def model(messages):
        h = _helpers(messages)
        if h:
            return h
        return json.dumps({"action": "finish", "summary": "s", "findings": [
            {"statement": "The file is a dropper.", "status": "confirmed", "evidence": [{"id": "EV-999999", "quote": "nothing here"}]}]})

    store, _, _, engine, jid = _job(tmp_path, layered_flag(), responder=model, name="ctf.txt")
    engine.run_job(jid)
    de, en = build_report(store, jid, "de", "m"), build_report(store, jid, "en", "m")
    assert "Abgeleitete Dateien" in de and "| derived/layer01.bin | sample @0+" in de and "| derived/layer02.bin | derived/layer01.bin @0+" in de
    assert "## Appendix: rejected statements of the model" in en and "The file is a dropper." in en
    assert en.index("## R4") < en.index("## Appendix: rejected") and "evidence does not exist in this job" in en
    assert "The file is a dropper." not in en.split("## R4")[1].split("## R5")[0]
