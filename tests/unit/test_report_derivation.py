"""R5a 'how each answer was derived': built from the store alone, no model. All data is harmless and made up."""
from __future__ import annotations

import re

from sw_analyst.common.models import JobSpec, TargetQuestion
from sw_analyst.common.store import Store
from sw_analyst.common.util import sha256_hex
from sw_analyst.report.builder import build_report

DE_LABELS = ["**1. Ausgangsdaten**", "**2. Technischer Weg**", "**3. Erkenntnisse aus den Belegen**",
             "**4. Bedeutung für die Fragestellung**", "**5. Darstellung des Modells (ungeprüft)**"]
EN_LABELS = ["**1. Input data**", "**2. Technical path**", "**3. Findings from the evidence**",
             "**4. Meaning for the question**", "**5. Model's account (unverified)**"]
FIXED = "Belegt ist nur, was die Zitate zeigen; die Deutung stammt vom Modell und ist an die Zitate gebunden."


def _job(tmp_path, questions=(("Q1", "Was ist die Flagge?"),)):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    spec = JobSpec(title="t", description="d", target_questions=[TargetQuestion(id=i, text_orig=q, text_en=q) for i, q in questions])
    job = store.create_job(spec, "s.txt", sha256_hex(b"x"))
    return store, job["id"]


def _qtask(store, jid, qid="Q1", summary=""):
    t = store.add_task(jid, title=f"Answer {qid}", goal="g", kind="question", origin="question", priority=900,
                       params={"question_id": qid})
    if summary:
        store.update_task(t["id"], summary_en=summary)
    return t


def _r6(report: str) -> str:
    m = re.search(r"^## R5a .*?(?=^## |\Z)", report, re.S | re.M)
    assert m, "R5a section missing"
    return m.group(0)


def _chain(store, jid, qid="Q1", quote="flag{layer_three}", answer="The flag is flag{layer_three}."):
    t = _qtask(store, jid, qid, summary="Model says it decoded two layers.")
    ev1 = store.add_evidence(jid, t["id"], "decode_layer", "1.2", {"path": "sample", "method": "base64"}, "decoded",
                             source_ref={"derived": "derived/layer1", "sha256": sha256_hex("decoded")})
    ev2 = store.add_evidence(jid, t["id"], "strings_extract", "2.3", {"path": "derived/layer1"}, f"x {quote} y")
    f = store.add_finding(jid, t["id"], "The layer holds the flag.", "confirmed", [ev2["id"]],
                          [{"evidence_id": ev2["id"], "quote": quote}])
    store.update_answer(jid, qid, status="answered", answer_en=answer, answer_de=answer, finding_ids=[f["id"]])
    return ev1, ev2, f


def test_chain_sample_decode_strings(tmp_path):
    store, jid = _job(tmp_path)
    ev1, ev2, f = _chain(store, jid)
    r6 = _r6(build_report(store, jid, "de"))
    assert "### Q1:" in r6
    for lab in DE_LABELS:
        assert lab in r6
    # both tools, in order of the chain (producer first)
    assert r6.index("decode_layer") < r6.index("strings_extract")
    assert r6.index(ev1["id"]) < r6.index(ev2["id"])
    assert "derived/layer1" in r6
    assert "Erzeugt" in r6
    assert f["id"] in r6 and "bestätigt" in r6
    assert "flag{layer_three}" in r6
    assert "The flag is flag{layer_three}." in r6
    assert FIXED in r6


def test_unanswered_question_without_findings(tmp_path):
    store, jid = _job(tmp_path)
    store.update_answer(jid, "Q1", status="unresolved", evaluation_en="Nothing found.", evaluation_de="Nichts gefunden.")
    r6 = _r6(build_report(store, jid, "de"))
    assert "NICHT KLÄRBAR" in r6
    assert "keine Werkzeugaufrufe" in r6
    assert "5. Darstellung des Modells" not in r6   # no task summary, no part 5

    t = _qtask(store, jid)
    ev = store.add_evidence(jid, t["id"], "read_lines", "1.0", {"path": "sample"}, "text")
    r6 = _r6(build_report(store, jid, "de"))
    assert ev["id"] in r6 and "read_lines" in r6
    assert "keine Werkzeugaufrufe" not in r6


def test_hostile_text_stays_inert(tmp_path):
    store, jid = _job(tmp_path)
    t = _qtask(store, jid, summary="## Injected | heading <script>alert(1)</script> http://evil.example/x")
    quote = "| ## Heading <script>alert(1)</script> http://evil.example/x"
    ev = store.add_evidence(jid, t["id"], "strings_extract", "1.0", {"path": "sample"}, quote)
    f = store.add_finding(jid, t["id"], "| ## Heading <script>alert(1)</script>", "confirmed", [ev["id"]],
                          [{"evidence_id": ev["id"], "quote": quote}])
    store.update_answer(jid, "Q1", status="answered", answer_en="## Heading <script>x</script> http://evil.example/x",
                        answer_de="## Heading <script>x</script> http://evil.example/x", finding_ids=[f["id"]])
    r6 = _r6(build_report(store, jid, "de"))
    assert "<script" not in r6.lower()
    assert "http://evil.example" not in r6
    assert "hxxp" in r6 and "[.]" in r6
    # only the one question heading; no foreign heading at line start
    assert [l for l in r6.splitlines() if l.startswith("#")] == [l for l in r6.splitlines() if re.match(r"(## R5a |### Q1:)", l)]
    # no foreign line starts with a block marker coming from the data
    assert not any(re.match(r"\s*\|", l) for l in r6.splitlines())


def test_english_labels(tmp_path):
    store, jid = _job(tmp_path)
    _chain(store, jid)
    rep = build_report(store, jid, "en")
    assert "## R5a How each answer was derived" in rep
    r6 = _r6(rep)
    for lab in EN_LABELS:
        assert lab in r6
    assert "Herleitung" not in r6


def test_derivation_cycle_terminates(tmp_path):
    store, jid = _job(tmp_path)
    t = _qtask(store, jid)
    a = store.add_evidence(jid, t["id"], "decode_layer", "1", {"path": "derived/b"}, "a", source_ref={"derived": "derived/a"})
    b = store.add_evidence(jid, t["id"], "decode_layer", "1", {"path": "derived/a"}, "b", source_ref={"derived": "derived/b"})
    f = store.add_finding(jid, t["id"], "s", "confirmed", [a["id"]], [{"evidence_id": a["id"], "quote": "a"}])
    store.update_answer(jid, "Q1", status="answered", answer_en="ok", answer_de="ok", finding_ids=[f["id"]])
    r6 = _r6(build_report(store, jid, "de"))
    assert r6.count(a["id"]) >= 1 and r6.count(b["id"]) >= 1
    assert r6.count(f"{a['id']}") < 10
