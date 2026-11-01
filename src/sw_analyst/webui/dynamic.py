"""Dynamic-analysis plan (ADR-0005): the gaps from stored GAP findings and what was done about them.

A GAP finding is written by the model in the format (prompts/registry.py SYSTEM_BASE rule f):
  "GAP: static analysis could not determine <X>. Would be closed by <dynamic step>; question: <q>; input: <i>."
The parser is tolerant: missing or reordered parts leave the field empty. The app never runs anything: a dynamic run
happens on the separate detonation host (detonation.py). All texts are defanged and shortened because they derive from
sample content and model output.
"""
from __future__ import annotations

import re

from sw_analyst.common.store import Store
from sw_analyst.detonation import PROFILES
from sw_analyst.report.defang import defang_text, redact_payloads

REASON = "nicht ausgeführt (ADR-0005)"
REQUIREMENTS = [
    "Schalter „Dynamische Analyse“ in der Übersicht ist an; Standard ist aus.",
    "Eigener Detonationsrechner mit Hyper-V-VM ohne Netzwerkkarte; die Probe wird nie auf dem Entwicklungsrechner gestartet.",
    "Bestandene Isolationsabnahme (infra/detonation/Test-DetonationIsolation.ps1) und sauberer Prüfpunkt mit gleichem Hash vor und nach jedem Lauf.",
    "Ausdrückliche Freigabe je Lauf mit Begründung und festem Profil. Das Modell kann keinen Lauf starten.",
    "Jeder Schritt landet im hash-verketteten Audit-Log; Laufergebnisse bleiben Hypothesen, bis Code sie belegt.",
]
_GAP = re.compile(r"^\s*GAP\s*:\s*", re.I)
_LABELS = (("close_by", re.compile(r"would\s+be\s+closed\s+by\b[:\s]*", re.I)),
           ("question", re.compile(r"\bquestion\s*:\s*", re.I)),
           ("input", re.compile(r"\binput\s*:\s*", re.I)))
_WHAT = re.compile(r"^\s*static\s+analysis\s+could\s+not\s+determine\b[:\s]*", re.I)


def _clean(s: str, limit: int = 400) -> str:
    s = re.sub(r"\s+", " ", defang_text(redact_payloads(s or ""))).strip(" \t;,")
    s = s[:limit]
    return s.rstrip(".").strip() if s.endswith(".") and not s.endswith("..") else s


def parse_gap(statement: str) -> dict | None:
    """Return {what, close_by, question, input} for a GAP statement, else None. Never raises."""
    if not isinstance(statement, str) or not _GAP.match(statement):
        return None
    body = _GAP.sub("", statement, count=1)
    hits = []
    for name, rx in _LABELS:
        m = rx.search(body)
        if m:
            hits.append((m.start(), m.end(), name))
    hits.sort()
    parts = {"what": body[:hits[0][0]] if hits else body}
    for i, (_, end, name) in enumerate(hits):
        parts[name] = body[end:hits[i + 1][0] if i + 1 < len(hits) else len(body)]
    parts["what"] = _WHAT.sub("", parts["what"], count=1)
    return {k: _clean(parts.get(k, "")) for k in ("what", "close_by", "question", "input")}


def dynamic_plan(store: Store, rid: str, enabled: bool = False) -> dict:
    runs = store.list_detonation_runs(rid)
    run_of = {r["finding_id"]: r for r in runs}
    gaps, seen = [], set()
    for f in store.list_findings(rid):
        if f["status"] == "rejected" or f["id"] in seen:
            continue
        g = parse_gap(f["statement_en"]) or parse_gap(f["statement_de"])
        if g is None:
            continue
        seen.add(f["id"])
        run = run_of.get(f["id"])
        gaps.append({"finding_id": f["id"], **g, "status": run["status"] if run else "not_executed",
                     "run_id": run["id"] if run else None})
    return {"enabled": bool(enabled), "reason": "freigeschaltet (ADR-0005)" if enabled else REASON,
            "requirements": list(REQUIREMENTS), "gaps": gaps,
            "emulation": {"opted_in": (store.get_job(rid) or {}).get("spec", {}).get("emulation_opt_in") is True,
                          "calls": len(store._q("SELECT id FROM evidence WHERE job_id=? AND tool='emulate_function' AND text NOT LIKE '[tool error]%'", (rid,)))},
            "runs": [{k: r[k] for k in ("id", "finding_id", "status", "profile", "reason", "input_sha256", "evidence_id",
                                        "clock_offset_s", "created_at", "updated_at", "folder")} for r in runs],
            "profiles": [{"id": k, "label": v["label"], "platform": v["platform"], "max_seconds": v["max_seconds"]}
                         for k, v in PROFILES.items()]}
