"""Gutachten structure of the report: abstract, question table, methodology, results by topic, appendix."""
from __future__ import annotations

import re

from sw_analyst.common.models import JobSpec, TargetQuestion
from sw_analyst.common.store import Store
from sw_analyst.common.util import sha256_hex
from sw_analyst.report.builder import build_report


def _setup(tmp_path):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    spec = JobSpec(title="t", target_questions=[TargetQuestion(id="Q1", text_orig="Was ist die Flagge?", text_en="Flag?"),
                                                 TargetQuestion(id="Q2", text_orig="Wohin | verbindet es?", text_en="C2?")])
    job = store.create_job(spec, "s.txt", sha256_hex(b"x"))
    t = store.add_task(job["id"], title="Strings", goal="g", kind="analyze", origin="recipe", priority=1)
    ev = store.add_evidence(job["id"], t["id"], "strings_extract", "1", {"path": "sample"}, "x flag{a} y")
    f = store.add_finding(job["id"], t["id"], "Holds the flag.", "confirmed", [ev["id"]], [{"evidence_id": ev["id"], "quote": "flag{a}"}])
    store.update_answer(job["id"], "Q1", status="answered", answer_en="flag{a}", answer_de="flag{a}", finding_ids=[f["id"]])
    return store, job["id"]


def test_de_report_has_gutachten_order(tmp_path):
    store, jid = _setup(tmp_path)
    rep = build_report(store, jid, "de")
    heads = [l[3:] for l in rep.splitlines() if l.startswith("## ")]
    order = ["Kurzfassung", "Fragestellungen und Kurzantworten", "R6 ", "R7 ", "R4 ", "R5 ", "R5a ", "Indikatoren", "Grenzen und offene", "Anhang"]
    pos = [next(i for i, h in enumerate(heads) if h.startswith(o)) for o in order]
    assert pos == sorted(pos)
    assert "### Begriffe in diesem Bericht" in rep and "### Dynamische Analyse" in rep
    assert "| Q1 | Was ist die Flagge? | flag{a} | beantwortet |" in rep
    assert "Wohin \\| verbindet es?" in rep                      # pipe in a question cannot break the table
    assert "### Strings (" in rep and "| strings_extract | 1 |" in rep
    assert re.search(r"Von 2 Zielfragen sind 1 beantwortet und 1 ungeklärt", rep)


def test_en_report_keeps_headings_used_elsewhere(tmp_path):
    store, jid = _setup(tmp_path)
    rep = build_report(store, jid, "en")
    for h in ("## Abstract", "## Open questions and limits", "## R4 Results by topic", "### R2 Hand-over and chain of custody"):
        assert h in rep
