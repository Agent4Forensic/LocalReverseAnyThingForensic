"""Dynamic-analysis plan (execution OFF, decision Jan 2026-11-01, ADR-0005): built only from stored GAP findings.

A GAP finding is written by the model in the format (prompts/registry.py SYSTEM_BASE rule f):
  "GAP: static analysis could not determine <X>. Would be closed by <dynamic step>; question: <q>; input: <i>."
The parser is tolerant: missing or reordered parts leave the field empty, and nothing is ever run. All texts are
defanged and shortened because they derive from sample content and model output.
"""
from __future__ import annotations

import re

from sw_analyst.common.store import Store
from sw_analyst.report.defang import defang_text, redact_payloads

REASON = "nicht ausgeführt, Analyse-VM fehlt (ADR-0005)"
REQUIREMENTS = [
    "Isolierte Analyse-VM (Hyper-V) ohne Netzwerkkarte; die Probe wird nie auf dem Host gestartet.",
    "Sauberer Snapshot der VM, auf den nach jedem Lauf zurückgesetzt wird.",
    "Ausdrückliche Freigabe durch Jan je Lauf (ADR-0005); ohne Freigabe bleibt die Ausführung AUS.",
    "Werkzeuge laufen in Containern (--network none, read-only, --cap-drop ALL, Ressourcenlimits) hinter dem Gateway.",
    "Jeder Schritt landet im hash-verketteten Audit-Log; Ergebnisse werden wie statische Belege mit Hash gespeichert.",
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


def dynamic_plan(store: Store, rid: str) -> dict:
    gaps, seen = [], set()
    for f in store.list_findings(rid):
        if f["status"] == "rejected" or f["id"] in seen:
            continue
        g = parse_gap(f["statement_en"]) or parse_gap(f["statement_de"])
        if g is None:
            continue
        seen.add(f["id"])
        gaps.append({"finding_id": f["id"], **g, "status": "not_executed"})
    return {"enabled": False, "reason": REASON, "requirements": list(REQUIREMENTS), "gaps": gaps}
