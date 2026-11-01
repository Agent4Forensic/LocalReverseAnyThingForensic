"""Forensic test plan blocks 1 and 2 (docs/testing/forensic-test-plan.md): C4, C8, G2, G3, I4. No model needed."""
from __future__ import annotations

import json

import pytest

from sw_analyst.common.audit import AuditLog, verify_file
from sw_analyst.common.models import JobSpec
from sw_analyst.common.store import Store
from sw_analyst.llm.ollama import OllamaClient
from sw_analyst.orchestrator.verifier import verify_finding
from sw_analyst.report.builder import build_report


def _log(tmp_path, n=5):
    p = tmp_path / "audit.jsonl"
    a = AuditLog(p)
    for i in range(n):
        a.append({"type": "event", "i": i})
    return p


# ---- C4: audit chain detects every kind of manipulation, and reports the right line --------------------------------

def test_c4_untouched_chain_is_valid(tmp_path):
    v = verify_file(_log(tmp_path))
    assert v.valid and v.entries == 5 and v.broken_at is None


@pytest.mark.parametrize("op, broken_line", [
    ("edit", 3),      # content of line 3 changed
    ("delete", 3),    # line 3 removed: line 4 no longer follows its predecessor
    ("swap", 2),      # lines 2 and 3 exchanged
    ("insert", 3),    # forged line inserted at position 3
])
def test_c4_manipulation_is_detected_at_the_right_line(tmp_path, op, broken_line):
    p = _log(tmp_path)
    lines = p.read_text(encoding="utf-8").splitlines()
    if op == "edit":
        obj = json.loads(lines[2])
        obj["i"] = 999
        lines[2] = json.dumps(obj)
    elif op == "delete":
        del lines[2]
    elif op == "swap":
        lines[1], lines[2] = lines[2], lines[1]
    else:
        forged = json.loads(lines[1])
        lines.insert(2, json.dumps(forged))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    v = verify_file(p)
    assert not v.valid and v.broken_at == broken_line


def test_c4_truncated_tail_still_verifies_but_reopening_continues_the_chain(tmp_path):
    # Limit of the design (documented): dropping the LAST lines is not detectable from the file alone.
    # The head hash kept elsewhere (store/report header) is what exposes it.
    p = _log(tmp_path)
    head_before = verify_file(p).head_hash
    p.write_text("\n".join(p.read_text(encoding="utf-8").splitlines()[:-1]) + "\n", encoding="utf-8")
    v = verify_file(p)
    assert v.valid and v.entries == 4 and v.head_hash != head_before


def test_c4_corrupt_log_is_not_silently_reopened(tmp_path):
    p = _log(tmp_path)
    p.write_text(p.read_text(encoding="utf-8").replace('"i":1', '"i":7'), encoding="utf-8")
    with pytest.raises(ValueError):
        AuditLog(p)


# ---- G2 / G3: grounding rejects foreign, unknown and too short evidence --------------------------------------------

def _job(store, title="t"):
    return store.create_job(JobSpec(title=title), "s.bin", "0" * 64)


def _ev(store, job_id, text):
    return store.add_evidence(job_id, None, "strings_extract", "1", {}, text)


def test_g2_evidence_of_another_job_or_unknown_id_is_not_proof(tmp_path):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    j1, j2 = _job(store, "one"), _job(store, "two")
    foreign = _ev(store, j2["id"], "secret value ABCDEF12345")
    for eid in (foreign["id"], "EV-999999"):
        vf = verify_finding(store, j1["id"], {"statement": "value found", "status": "confirmed",
                                              "evidence": [{"id": eid, "quote": "ABCDEF12345"}]})
        assert vf.status == "rejected" and "does not exist in this job" in vf.reject_reason


def test_g3_short_quote_never_confirms(tmp_path):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    j = _job(store)
    ev = _ev(store, j["id"], "the answer is 42 and more text")
    vf = verify_finding(store, j["id"], {"statement": "x", "status": "confirmed",
                                         "evidence": [{"id": ev["id"], "quote": "42"}]})
    assert vf.status == "hypothesis" and "shorter than" in vf.reject_reason


def test_g1_quote_is_whitespace_normalised_but_otherwise_verbatim(tmp_path):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    j = _job(store)
    ev = _ev(store, j["id"], "key =\n   VALUE_ONE")
    ok = verify_finding(store, j["id"], {"statement": "key holds VALUE_ONE", "status": "confirmed",
                                         "evidence": [{"id": ev["id"], "quote": "key = VALUE_ONE"}]})
    bad = verify_finding(store, j["id"], {"statement": "key holds VALUE_TWO", "status": "confirmed",
                                          "evidence": [{"id": ev["id"], "quote": "key = VALUE_TWO"}]})
    assert ok.status == "confirmed" and bad.status == "hypothesis"


# ---- C8: same database state gives a byte-identical report ---------------------------------------------------------

def test_c8_report_is_reproducible(tmp_path):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    j = _job(store)
    ev = _ev(store, j["id"], "evidence text with FLAG{abc_def}")
    vf = verify_finding(store, j["id"], {"statement": "flag present", "status": "confirmed",
                                         "evidence": [{"id": ev["id"], "quote": "FLAG{abc_def}"}]})
    t = store.add_task(j["id"], title="t", goal="g", kind="analysis", origin="recipe", priority=1)
    store.add_finding(j["id"], t["id"], vf.statement, vf.status, vf.evidence_ids, vf.quotes)
    for lang in ("en", "de"):
        assert build_report(store, j["id"], lang, "m") == build_report(store, j["id"], lang, "m")


# ---- I4: the model endpoint is loopback only ----------------------------------------------------------------------

@pytest.mark.parametrize("url", ["http://example.com:11434", "http://10.0.0.5:11435", "https://api.openai.com",
                                 "http://127.0.0.1.evil.example:11435"])
def test_i4_non_loopback_llm_endpoint_is_refused(url):
    with pytest.raises(ValueError):
        OllamaClient("m", url)


def test_i4_loopback_is_accepted():
    assert OllamaClient("m", "http://127.0.0.1:11435").base_url == "http://127.0.0.1:11435"
