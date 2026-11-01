"""Dynamic-analysis plan: parsed from stored GAP findings only, execution stays off (ADR-0005). Harmless made-up data."""
from __future__ import annotations

from sw_analyst.common.models import JobSpec
from sw_analyst.common.store import Store
from sw_analyst.common.util import sha256_hex
from sw_analyst.report.builder import build_report
from sw_analyst.webui.dynamic import dynamic_plan, parse_gap

GAP = ("GAP: static analysis could not determine which host the sample contacts. Would be closed by a network capture "
       "in the analysis VM; question: Which host is contacted?; input: overlay offset 0x400.")


def _job(tmp_path):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    job = store.create_job(JobSpec(title="t"), "s.txt", sha256_hex(b"x"))
    task = store.add_task(job["id"], title="T", goal="g", kind="analyze", origin="recipe", priority=1)
    return store, job["id"], task["id"]


def test_parse_full_format():
    assert parse_gap(GAP) == {"what": "which host the sample contacts", "close_by": "a network capture in the analysis VM",
                              "question": "Which host is contacted?", "input": "overlay offset 0x400"}


def test_parse_is_tolerant():
    assert parse_gap("not a gap") is None and parse_gap(None) is None
    g = parse_gap("gap: could be anything")
    assert g["what"] == "could be anything" and g["close_by"] == g["question"] == g["input"] == ""
    g = parse_gap("GAP: X. input: line 4; question: why?")        # reordered parts
    assert g["input"] == "line 4" and g["question"] == "why?"


def test_plan_is_disabled_and_lists_gaps(tmp_path):
    store, jid, tid = _job(tmp_path)
    f = store.add_finding(jid, tid, GAP, "hypothesis", [], [], "")
    store.add_finding(jid, tid, "Plain finding.", "open", [], [], "")
    store.add_finding(jid, tid, "GAP: rejected one.", "rejected", [], [], "")
    p = dynamic_plan(store, jid)
    assert p["enabled"] is False and "ADR-0005" in p["reason"] and p["requirements"]
    assert [g["finding_id"] for g in p["gaps"]] == [f["id"]]
    assert p["gaps"][0]["status"] == "not_executed" and p["gaps"][0]["question"] == "Which host is contacted?"


def test_plan_defangs_and_report_shows_gap_section(tmp_path):
    store, jid, tid = _job(tmp_path)
    store.add_finding(jid, tid, "GAP: static analysis could not determine X. Would be closed by a run; "
                                "question: does it call http://evil.example/a?; input: none.", "hypothesis", [], [], "")
    p = dynamic_plan(store, jid)
    assert "http://evil.example" not in str(p)
    rep = build_report(store, jid, "de")
    sec = rep[rep.index("### Dynamische Analyse"):]
    assert "nicht ausgeführt, Analyse-VM fehlt (ADR-0005)" in sec
    assert "http://evil.example" not in rep
