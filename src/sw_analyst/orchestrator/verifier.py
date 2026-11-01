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
# Whitespace and JSON-style escapes differ between what a model copies and what a tool printed.
_QUOTE_NOISE = re.compile(r"\s+|\\[nrt]|\\")
# A value a statement asserts: mixes letters and digits (BENCH-42, KERNEL32.dll). Hex offsets may come from other evidence.
_VALUE = re.compile(r"(?<![\w.-])(?=[\w.-]*[A-Za-z])(?=[\w.-]*\d)[A-Za-z0-9][\w.-]*[A-Za-z0-9](?![\w-])")
_NOT_A_VALUE = re.compile(r"(?:0x[0-9a-f]+|(?:ev|f|t)-\d+|q\d+|layer\d+\.bin|\d+-bit|\d+(?:\.\d+)*[a-z]{0,3}|"
                          r"base(?:32|64|85)|sha-?\d+|md5|utf-?\d+|x86|x64|i386|amd64|pe32\+?|win32|win64|rc4|aes-?\d*)", re.I)
_ABSENCE_CLAIM = re.compile(r"^(?:no|none|not|nothing)\b|\b(?:contains?|has|have|shows?|found|are|is|were|was)\s+(?:no|none|nothing)\b", re.I)
_ABSENCE_SHOWN = re.compile(r"\b(?:0|none|no|not|nothing|empty|absent)\b", re.I)
_FIELD = re.compile(r"\b([A-Za-z_][\w-]{1,30})(?:\s+value\s+(?:is|of)\s+|\s+value\s*[=:]\s*|\s*[=:]\s*|\s+is\s+)[`'\"]?([\w.-]+)")
_GENERIC_FIELDS = {"type", "name", "file", "value", "machine", "section", "sections", "size", "offset", "version", "hash",
                   "sha256", "import", "imports", "dll", "function", "functions", "entry", "string", "strings", "address",
                   "rva", "timestamp", "subsystem"}


def norm(s: str) -> str:
    return _WS.sub(" ", (s or "")).strip()


def _ioc_form(s: str) -> str:
    return defang_text(s).lower()


def _iocs_missing_from(text: str, source: str) -> list[str]:
    """Indicators named in text that the source does not contain, live or defanged."""
    plain = _ioc_form(source)
    return [i["value"] for i in find_iocs(text) if _ioc_form(i["value"]) not in plain]


def claimed_values(text: str) -> list[str]:
    return [v for v in _VALUE.findall(text or "") if not _NOT_A_VALUE.fullmatch(v)]


def _has_value(value: str, text: str) -> bool:
    """The whole value: BENCH-4 is not proven by BENCH-42."""
    return re.search(rf"(?<![\w.-]){re.escape(value)}(?![\w-])", text, re.I) is not None


def field_values(statement: str) -> list[tuple[str, str]]:
    """(field, value) pairs such as 'id=BENCH-42' or 'the id value is BENCH-42', for finding two values of one field."""
    return [(m.group(1).lower(), m.group(2).rstrip(".")) for m in _FIELD.finditer(statement or "")
            if m.group(1).lower() not in _GENERIC_FIELDS and claimed_values(m.group(2).rstrip("."))]


def evidence_body(ev: dict) -> str:
    """What the tool found. The first line of grep repeats the model's own pattern and proves nothing (F-01)."""
    text = ev["text"]
    return text.split("\n", 1)[1] if ev["tool"] == "grep" and "\n" in text else ("" if ev["tool"] == "grep" else text)


def locate_quote(quote: str, text: str) -> str | None:
    """The stretch of the evidence a quote refers to, ignoring whitespace and escapes. The stored quote is always the
    tool's own text, so the tolerance never puts words of the model into a proof."""
    needle = _QUOTE_NOISE.sub("", quote)
    if not needle:
        return None
    kept: list[int] = []
    pos = 0
    for m in _QUOTE_NOISE.finditer(text):
        kept.extend(range(pos, m.start()))
        pos = m.end()
    kept.extend(range(pos, len(text)))
    at = "".join(text[i] for i in kept).find(needle)
    return None if at < 0 else norm(text[kept[at]:kept[at + len(needle) - 1] + 1])


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
    cited: list[str] = []
    problems: list[str] = []
    for item in ev_items:
        eid = str(item.get("id", ""))
        quote = norm(str(item.get("quote", "")))
        ev = store.get_evidence(eid)
        if not ev or ev["job_id"] != job_id:
            problems.append(f"{eid}: evidence does not exist in this job")
            continue
        ids.append(eid)
        cited.append(evidence_body(ev))
        long_enough = len(_QUOTE_NOISE.sub("", quote)) >= MIN_QUOTE
        found = locate_quote(quote, evidence_body(ev)) if long_enough else None
        if not long_enough:
            problems.append(f"{eid}: quote missing or shorter than {MIN_QUOTE} characters")
        elif found:
            good_quotes.append({"evidence_id": eid, "quote": found})
        else:
            problems.append(f"{eid}: quote not found verbatim in the evidence")
    ids = list(dict.fromkeys(ids))
    if claimed == "confirmed":
        if good_quotes and not problems:
            shown = " ".join(q["quote"] for q in good_quotes)
            # A true quote proves only itself: an indicator it does not show stays unproven.
            unquoted = _iocs_missing_from(statement, shown)
            if unquoted:
                return VerifiedFinding(statement, "hypothesis", ids, good_quotes,
                                       "downgraded from confirmed: not in the quotes: " + ", ".join(unquoted))
            # A value worked out by the model (decoded in its head) must stand in the output of a tool it cites.
            source = norm(" ".join(cited))
            unseen = [v for v in claimed_values(statement) if not _has_value(v, source)]
            if unseen:
                return VerifiedFinding(statement, "hypothesis", ids, good_quotes,
                                       "downgraded from confirmed: not in the cited evidence: " + ", ".join(unseen))
            if _ABSENCE_CLAIM.search(statement) and not _ABSENCE_SHOWN.search(shown):
                return VerifiedFinding(statement, "hypothesis", ids, good_quotes,
                                       "downgraded from confirmed: the quote does not show the stated absence")
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
    """Flag-like values (WORD{...}), other values and indicators in an answer must occur in stored evidence of the job."""
    tokens = _VALUE_TOKEN.findall(answer_text or "")
    values = claimed_values(_VALUE_TOKEN.sub(" ", answer_text or ""))
    if not tokens and not values and not find_iocs(answer_text or ""):
        return True, []
    corpus = " ".join(norm(evidence_body(r)) for r in store._q("SELECT tool, text FROM evidence WHERE job_id=?", (job_id,)))
    missing = ([t for t in tokens if norm(t) not in corpus] + [v for v in values if not _has_value(v, corpus)]
               + _iocs_missing_from(answer_text, corpus))
    return (not missing), missing
