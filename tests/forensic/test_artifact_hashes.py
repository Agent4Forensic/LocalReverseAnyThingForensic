"""Forensic test plan C1/C2/C3 (docs/testing/forensic-test-plan.md): artifact hash reconciliation. No model needed.

Harmless, self-made sample (a doubly base64-encoded string). The scripted model decodes two layers, so the job
produces derived/layer01.bin and derived/layer02.bin plus evidence for every tool call.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re

import pytest

from sw_analyst.common.models import JobSpec, TargetQuestion
from sw_analyst.common.store import Store
from sw_analyst.common.util import sha256_hex
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.llm.fake import ScriptedLLM
from sw_analyst.orchestrator.engine import JobEngine
from sw_analyst.report.builder import build_report

FLAG = "FLAG{hash_check_ok}"


class _Tr:
    class _R:
        def __init__(self, text):
            self.text, self.ok = text, True

    def to_en(self, text):
        return self._R(text)

    def to_de(self, text):
        return self._R("DE: " + text)


def _model(messages):
    text = "\n".join(m.content for m in messages)
    if "critical reviewer" in text:
        return json.dumps({"goal_reached": True, "assessment": "ok", "gaps": [], "followups": []})
    if "orders the work queue" in text:
        return json.dumps({"changes": [], "new_tasks": []})
    if "answers one target question" in text:
        ids = re.findall(r"is stored as (EV-\d{6})", text)
        if len(ids) == 0:
            return json.dumps({"action": "tool", "tool": "decode_layer", "args": {"path": "sample", "method": "base64"},
                               "why": "layer 1"})
        if len(ids) == 1:
            return json.dumps({"action": "tool", "tool": "decode_layer",
                               "args": {"path": "derived/layer01.bin", "method": "base64"}, "why": "layer 2"})
        return json.dumps({"action": "finish", "summary": "decoded",
                           "findings": [{"statement": "flag " + FLAG, "status": "confirmed",
                                         "evidence": [{"id": ids[-1], "quote": FLAG}]}],
                           "answer": {"text": "The flag is " + FLAG}})
    return json.dumps({"action": "finish", "summary": "nothing", "findings": []})


@pytest.fixture
def run(tmp_path):
    """Full scripted job; returns (store, gateway, job_id, sample_bytes, report_text)."""
    data = base64.b64encode(base64.b64encode(FLAG.encode())) + b"\n"
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    gw = DevGateway(tmp_path)
    job = store.create_job(JobSpec(title="hash test", description="find the flag", context_info="harmless",
                                   target_questions=[TargetQuestion(id="Q1", text_orig="Flag?", expected=FLAG)]),
                           "sample.txt", sha256_hex(data))
    gw.store_sample(job["id"], data)
    status = JobEngine(store, ScriptedLLM(_model), gw, _Tr(), use_prioritizer=True).run_job(job["id"])
    assert status == "done"
    return store, gw, job["id"], data, build_report(store, job["id"], "en", "scripted")


def _derived(store, jid):
    return [e for e in (store.get_evidence(x["id"]) for x in store.list_evidence(jid))
            if e["tool"] == "decode_layer" and e["source_ref"].get("derived")]


# ---- C1 / C2: sample hash is identical in job, file and report; sample unchanged -----------------------------------

def test_c1_sample_hash_job_file_report_agree(run, tmp_path):
    store, gw, jid, data, report = run
    on_disk = hashlib.sha256((tmp_path / "jobs" / jid / "sample").read_bytes()).hexdigest()
    assert store.get_job(jid)["sample_sha256"] == on_disk == hashlib.sha256(data).hexdigest()
    assert f"| SHA-256 | `{on_disk}` |" in report
    hf = [e for e in (store.get_evidence(x["id"]) for x in store.list_evidence(jid)) if e["tool"] == "hash_file" and e["params"].get("path", "sample") == "sample"]
    assert hf and all(f"SHA256: {on_disk}" in e["text"] for e in hf)      # the hash_file evidence agrees too
    assert gw.list_files(jid)[0] == {"path": "sample", "kind": "sample", "size": len(data), "sha256": on_disk}


def test_c2_sample_is_byte_identical_and_read_only_after_job(run, tmp_path):
    _, _, jid, data, _ = run
    p = tmp_path / "jobs" / jid / "sample"
    assert p.read_bytes() == data
    assert p.stat().st_mode & 0o222 == 0     # no write bit (on Windows this maps to the read-only attribute)


# ---- C3: every stored evidence hash and every derived artifact hash can be recomputed -------------------------------

def test_c3_every_evidence_hash_matches_its_text(run):
    store, _, jid, _, _ = run
    rows = [store.get_evidence(x["id"]) for x in store.list_evidence(jid)]
    assert rows
    for e in rows:
        assert e["result_sha256"] == hashlib.sha256(e["text"].encode("utf-8")).hexdigest(), e["id"]


def test_c3_derived_artifact_hash_in_evidence_equals_recomputed_file_hash(run, tmp_path):
    store, gw, jid, _, _ = run
    ders = _derived(store, jid)
    assert len(ders) == 2
    for e in ders:
        path = tmp_path / "jobs" / jid / e["source_ref"]["derived"]
        h = hashlib.sha256(path.read_bytes()).hexdigest()
        assert e["source_ref"]["sha256"] == h
        assert f"SHA-256: {h}" in e["text"]
    listed = {f["path"]: f["sha256"] for f in gw.list_files(jid) if f["kind"] == "derived"}
    assert listed == {e["source_ref"]["derived"]: e["source_ref"]["sha256"] for e in ders}


@pytest.mark.xfail(strict=True, reason="Finding: the report's custody hash table prints evidence.result_sha256 (hash of the "
                   "tool OUTPUT TEXT) for decode_layer rows under the heading 'SHA-256'; the derived file hash itself "
                   "appears nowhere in the report. Plan C3 requires it in the report.")
def test_c3_derived_artifact_hash_appears_in_report(run):
    store, _, jid, _, report = run
    for e in _derived(store, jid):
        assert e["source_ref"]["sha256"] in report


# ---- tamper detection: there is no dedicated integrity function; reconciliation against the evidence is the check ----

def _tamper(path, same_size=False):
    path.chmod(0o666)
    raw = path.read_bytes()
    path.write_bytes(b"X" + raw[1:] if same_size else raw + b"!")


def test_tampered_derived_file_is_detected_by_reconciling_with_evidence(run, tmp_path):
    store, gw, jid, _, _ = run
    e = _derived(store, jid)[0]
    _tamper(tmp_path / "jobs" / jid / e["source_ref"]["derived"])
    listed = {f["path"]: f["sha256"] for f in gw.list_files(jid)}
    assert listed[e["source_ref"]["derived"]] != e["source_ref"]["sha256"]


@pytest.mark.xfail(strict=True, reason="Finding: DevGateway.list_files caches hashes by (path, size, mtime_ns); a same-size "
                   "rewrite with the mtime restored returns the stale hash, so list_files cannot serve as integrity check.")
def test_tampered_same_size_file_with_restored_mtime_is_detected(run, tmp_path):
    store, gw, jid, _, _ = run
    e = _derived(store, jid)[0]
    p = tmp_path / "jobs" / jid / e["source_ref"]["derived"]
    gw.list_files(jid)                      # fill the cache
    st = p.stat()
    _tamper(p, same_size=True)
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
    listed = {f["path"]: f["sha256"] for f in gw.list_files(jid)}
    assert listed[e["source_ref"]["derived"]] != e["source_ref"]["sha256"]


def test_tampered_evidence_text_is_detected_by_stored_hash(run):
    store, _, jid, _, _ = run
    eid = store.list_evidence(jid)[0]["id"]
    store._x("UPDATE evidence SET text=? WHERE id=?", ("forged", eid))   # direct DB manipulation
    e = store.get_evidence(eid)
    assert e["result_sha256"] != hashlib.sha256(e["text"].encode()).hexdigest()
