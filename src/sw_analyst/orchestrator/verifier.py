"""Grounding check: findings must be backed by stored evidence and verbatim quotes (chain.md section 4).

confirmed  -> every cited evidence id exists in this job AND every quote occurs verbatim
              (whitespace-normalised) in that evidence text; at least one quote.
hypothesis -> at least one existing evidence id as basis; quotes optional, only verified ones are kept.
anything else -> rejected with a stored reason (kept for the audit trail, never used in answers).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from sw_analyst.common.store import Store
from sw_analyst.report.defang import defang_text, find_iocs

_WS = re.compile(r"\s+")
MIN_QUOTE = 4


def norm(s: str) -> str:
    return _WS.sub(" ", (s or "")).strip()


def _ioc_form(s: str) -> str:
    return defang_text(s).lower()


def _iocs_missing_from(text: str, source: str) -> list[str]:
    """Indicators named in text that the source does not contain, live or defanged."""
    plain = _ioc_form(source)
    return [i["value"] for i in find_iocs(text) if _ioc_form(i["value"]) not in plain]


@dataclass
class VerifiedFinding:
    statement: str
    status: str            # confirmed | hypothesis | rejected
    evidence_ids: list[str]
    quotes: list[dict]
    reject_reason: str = ""


def verify_finding(store: Store, job_id: str, raw: dict) -> VerifiedFinding:
    statement = norm(str(raw.get("statement", "")))
    claimed = "confirmed" if raw.get("status") == "confirmed" else "hypothesis"
    ev_items = raw.get("evidence") or []
    if not statement:
        return VerifiedFinding("(empty)", "rejected", [], [], "empty statement")
    ids: list[str] = []
    good_quotes: list[dict] = []
    problems: list[str] = []
    for item in ev_items:
        eid = str(item.get("id", ""))
        quote = norm(str(item.get("quote", "")))
        ev = store.get_evidence(eid)
        if not ev or ev["job_id"] != job_id:
            problems.append(f"{eid}: evidence does not exist in this job")
            continue
        ids.append(eid)
        if len(quote) < MIN_QUOTE:
            problems.append(f"{eid}: quote missing or shorter than {MIN_QUOTE} characters")
        elif quote in norm(ev["text"]):
            good_quotes.append({"evidence_id": eid, "quote": quote})
        else:
            problems.append(f"{eid}: quote not found verbatim in the evidence")
    ids = list(dict.fromkeys(ids))
    if claimed == "confirmed":
        if good_quotes and not problems:
            # A true quote proves only itself: an indicator it does not show stays unproven.
            unquoted = _iocs_missing_from(statement, " ".join(q["quote"] for q in good_quotes))
            if unquoted:
                return VerifiedFinding(statement, "hypothesis", ids, good_quotes,
                                       "downgraded from confirmed: not in the quotes: " + ", ".join(unquoted))
            return VerifiedFinding(statement, "confirmed", ids, good_quotes)
        reason = "; ".join(problems) or "no evidence cited"
        # Unverifiable claim is not kept as fact. If evidence exists it survives as a hypothesis.
        if ids:
            return VerifiedFinding(statement, "hypothesis", ids, good_quotes,
                                   f"downgraded from confirmed: {reason}")
        return VerifiedFinding(statement, "rejected", [], [], reason)
    if ids:
        return VerifiedFinding(statement, "hypothesis", ids, good_quotes)
    return VerifiedFinding(statement, "rejected", [], [], "; ".join(problems) or "hypothesis without any evidence")


_VALUE_TOKEN = re.compile(r"[A-Za-z0-9_]{2,24}\{[^{}\s][^{}]{2,200}\}")


def answer_values_grounded(store: Store, job_id: str, answer_text: str) -> tuple[bool, list[str]]:
    """Flag-like values (WORD{...}) and indicators in an answer must occur in some stored evidence of the job."""
    tokens = _VALUE_TOKEN.findall(answer_text or "")
    if not tokens and not find_iocs(answer_text or ""):
        return True, []
    corpus = " ".join(norm(r["text"]) for r in store._q("SELECT text FROM evidence WHERE job_id=?", (job_id,)))
    missing = [t for t in tokens if norm(t) not in corpus] + _iocs_missing_from(answer_text, corpus)
    return (not missing), missing
