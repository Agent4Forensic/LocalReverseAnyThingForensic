"""Grounding check: findings must be backed by stored evidence and verbatim quotes (chain.md section 4).

confirmed  -> every cited evidence id exists in this job AND every quote occurs verbatim
              (whitespace-normalised) in that evidence text; at least one quote.
hypothesis -> at least one existing evidence id as basis; quotes optional, only verified ones are kept.
anything else -> rejected with a stored reason (kept for the audit trail, never used in answers).

Only the part of a tool result that shows the sample counts as quotable (quotable_text): the header line loses the
echo of the model's own string arguments (grep pattern, member name, key), and a tool error is not evidence at all.
Otherwise a model could grep for a value it invented and "quote" the echo of its own search (finding F-01).
A confirmed quote must also share a content word with the statement, so a true but unrelated line cannot carry
a claim (F-02). When a quote is not found, the closest line of that evidence is offered as a repair hint.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

from sw_analyst.common.store import Store
from sw_analyst.report.defang import defang_text, find_iocs

_WS = re.compile(r"\s+")
MIN_QUOTE = 8                 # the prompt promises 8 to 120 characters (ACTION_SCHEMA)
TOOL_ERROR = "[tool error]"
NOTE_PREFIX = "[note]"
HINT_LINE_CHARS = 300        # lines are cut before the similarity search (cost cap)
_WORD = re.compile(r"[a-z0-9_$]+")
_STOP = frozenset("""a an and are as at be been by can could did do does for from has have in into is it its may might
no not of on or so than that the then there these this those to was were which will with without would
sample file files line lines evidence quote shows shown value contains contain found uses use""".split())
HINT_LINES_SCAN = 4000        # lines searched for a repair hint (cost cap)
HINT_CHARS = 160


def norm(s: str) -> str:
    return _WS.sub(" ", (s or "")).strip()


def _echo_forms(params: dict) -> list[str]:
    """How the gateway may print the model's own arguments: full or clipped strings, numbers in decimal and hex."""
    forms: set[str] = set()
    for k, v in params.items():
        if k == "path" or isinstance(v, bool):
            continue
        if isinstance(v, str) and len(v) >= 2:
            forms.update({v, v[:200], v[:40]})
        elif isinstance(v, int) and abs(v) >= 10:
            forms.update({str(v), f"0x{v:x}", f"0x{v:02x}"})
    return sorted((f for f in forms if len(f) >= 2), key=len, reverse=True)


def quotable_text(ev: dict) -> str:
    """Evidence text a quote may come from: no tool error, no platform note, no echo of the model's own arguments.
    The gateway keeps string arguments on one line (control characters are refused), so the echo can only stand in
    the header line; notes ('[note] ...') and an explicitly given key are platform text, not sample content."""
    text = ev.get("text") or ""
    if text.startswith(TOOL_ERROR):
        return ""
    lines = [ln for ln in text.split("\n") if not ln.startswith(NOTE_PREFIX) and "(given) used" not in ln]
    if not lines:
        return ""
    head = lines[0]
    for v in _echo_forms(ev.get("params") or {}):
        head = head.replace(v, " ")
    return "\n".join([head] + lines[1:])


def content_words(s: str) -> set[str]:
    return {w for w in _WORD.findall((s or "").lower()) if w not in _STOP and (len(w) >= 3 or any(c.isdigit() for c in w))}


def relevant(statement: str, quote: str) -> bool:
    """A quote carries a statement only if both talk about the same thing: two shared content words, or one shared
    specific value (contains a digit or is at least 8 characters long)."""
    shared = content_words(statement) & content_words(quote)
    return len(shared) >= 2 or any(len(w) >= 8 or any(c.isdigit() for c in w) for w in shared)


def closest_line(quote: str, text: str) -> str:
    """Most similar line of the evidence for a quote that was not found verbatim, or '' if nothing is close."""
    lines = [norm(x)[:HINT_LINE_CHARS] for x in text.splitlines()[:HINT_LINES_SCAN]]
    lines = [x for x in lines if len(x) >= MIN_QUOTE]
    q = norm(quote)
    if not q or not lines:
        return ""
    # Cheap prefilter by shared words, then a precise ratio on the few candidates.
    qw = content_words(q)
    cand = [x for x in lines if qw & content_words(x)][:200] or lines[:200]
    best = difflib.get_close_matches(q, cand, n=1, cutoff=0.55)
    return best[0][:HINT_CHARS] if best else ""


def _ioc_form(s: str) -> str:
    return defang_text(s).lower()


def _iocs_missing_from(text: str, source: str) -> list[str]:
    """Indicators named in text that the source does not contain, live or defanged."""
    plain = _ioc_form(source)
    return [i["value"] for i in find_iocs(text) if _ioc_form(i["value"]) not in plain]


DYNAMIC_EVIDENCE = {"emulate_function", "detonation_run"}


@dataclass
class VerifiedFinding:
    statement: str
    status: str            # confirmed | hypothesis | rejected
    evidence_ids: list[str]
    quotes: list[dict]
    reject_reason: str = ""
    hints: list[str] = field(default_factory=list)   # closest real lines for refused quotes (sample text!)


def verify_finding(store: Store, job_id: str, raw: dict) -> VerifiedFinding:
    statement = norm(str(raw.get("statement", "")))
    claimed = "confirmed" if raw.get("status") == "confirmed" else "hypothesis"
    ev_items = raw.get("evidence") or []
    if not statement:
        return VerifiedFinding("(empty)", "rejected", [], [], "empty statement")
    ids: list[str] = []
    good_quotes: list[dict] = []
    problems: list[str] = []
    hints: list[str] = []
    for item in ev_items:
        eid = str(item.get("id", ""))
        quote = norm(str(item.get("quote", "")))
        ev = store.get_evidence(eid)
        if not ev or ev["job_id"] != job_id:
            problems.append(f"{eid}: evidence does not exist in this job")
            continue
        ids.append(eid)
        source = quotable_text(ev)
        if not source:
            problems.append(f"{eid}: a tool error is not evidence for a statement")
        elif len(quote) < MIN_QUOTE:
            problems.append(f"{eid}: quote missing or shorter than {MIN_QUOTE} characters")
        elif quote in norm(source):
            good_quotes.append({"evidence_id": eid, "quote": quote})
        else:
            in_echo = quote in norm(ev.get("text") or "")
            problems.append(f"{eid}: quote " + ("is only the echo of your own tool arguments, not sample content"
                                                if in_echo else "not found verbatim in the evidence"))
            near = "" if in_echo else closest_line(quote, source)
            if near:
                hints.append(f"{eid}: closest real line: {near}")
    ids = list(dict.fromkeys(ids))
    if claimed == "confirmed":
        if good_quotes and not problems:
            # A true quote proves only itself: an indicator it does not show stays unproven.
            joined = " ".join(q["quote"] for q in good_quotes)
            unquoted = _iocs_missing_from(statement, joined)
            if unquoted:
                return VerifiedFinding(statement, "hypothesis", ids, good_quotes,
                                       "downgraded from confirmed: not in the quotes: " + ", ".join(unquoted))
            if not relevant(statement, joined):
                return VerifiedFinding(statement, "hypothesis", ids, good_quotes,
                                       "downgraded from confirmed: the quote shares too little with the statement "
                                       "(two words, or one value such as a name with digits, an address or a long "
                                       "identifier); quote the line that shows the stated fact")
            # ADR-0005: what a simulated or real run showed stays a hypothesis until a quote from static evidence backs it.
            if all(store.get_evidence(q["evidence_id"])["tool"] in DYNAMIC_EVIDENCE for q in good_quotes):
                return VerifiedFinding(statement, "hypothesis", ids, good_quotes,
                                       "downgraded from confirmed: dynamic evidence alone; quote code that supports it")
            return VerifiedFinding(statement, "confirmed", ids, good_quotes)
        reason = "; ".join(problems) or "no evidence cited"
        # Unverifiable claim is not kept as fact. If evidence exists it survives as a hypothesis.
        if ids:
            return VerifiedFinding(statement, "hypothesis", ids, good_quotes,
                                   f"downgraded from confirmed: {reason}", hints)
        return VerifiedFinding(statement, "rejected", [], [], reason)
    if ids:
        return VerifiedFinding(statement, "hypothesis", ids, good_quotes, hints=hints)
    return VerifiedFinding(statement, "rejected", [], [], "; ".join(problems) or "hypothesis without any evidence")


_VALUE_TOKEN = re.compile(r"[A-Za-z0-9_]{2,24}\{[^{}\s][^{}]{2,200}\}")


def answer_values_grounded(store: Store, job_id: str, answer_text: str) -> tuple[bool, list[str]]:
    """Flag-like values (WORD{...}) and indicators in an answer must occur in some stored evidence of the job."""
    tokens = _VALUE_TOKEN.findall(answer_text or "")
    if not tokens and not find_iocs(answer_text or ""):
        return True, []
    rows = store._q("SELECT text, params_json FROM evidence WHERE job_id=?", (job_id,))
    corpus = " ".join(norm(quotable_text(r)) for r in rows)  # _q parses params_json into params
    missing = [t for t in tokens if norm(t) not in corpus] + _iocs_missing_from(answer_text, corpus)
    return (not missing), missing

