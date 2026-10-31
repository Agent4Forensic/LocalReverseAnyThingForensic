"""Per-task tripwire (chain.md 5.4).

If the input of a task contained high-severity injection and the model then tries an
invalid/non-allowed action, repeats injection text, or names tools/arguments that stem
from the injected text (and not from the task statement), the task is blocked.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from sw_analyst.guard.actions import ActionResult
from sw_analyst.guard.sanitize import SanitizedBlock
from sw_analyst.guard.scanner import GUARD_VERSION, Detection, normalize_text, scan

_SNIP = 200
_MIN_REPEAT = 16        # normalised characters of a snippet that count as "repeated"
_MIN_ARG = 6            # shortest string argument compared against snippets
# raw-output categories that signal repeated injection text; fake_action is excluded because
# every legitimate answer of the model is itself an action JSON
_REPEAT_CATEGORIES = {"override", "persona", "chat_marker", "ai_address", "encoded", "exfil_exec"}


@dataclass
class GuardVerdict:
    blocked: bool
    reason: str
    events: list = field(default_factory=list)


def _ev(stage: str, rule: str, severity: str, action: str, snippet: str) -> dict:
    return {"stage": stage, "rule": rule, "severity": severity, "action": action,
            "snippet": (snippet or "")[:_SNIP]}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", normalize_text(s)).strip()


class TaskGuard:
    def __init__(self, task_id: str, task_text: str = ""):
        self.task_id = task_id
        self._task_norm = _norm(task_text or "")
        self._high: list[tuple[Detection, str, str]] = []   # (detection, normalised snippet, evidence id)
        self._redacted_norm: list[str] = []                  # normalised original text of redacted spans
        self._counts = {"low": 0, "medium": 0, "high": 0}
        self._by_cat: dict[str, int] = {}
        self._inputs = 0
        self._redacted_blocks = 0
        self._outputs = 0
        self._invalid = 0
        self._blocked = False
        self._reason = ""
        self._events_total = 0

    # ------------------------------------------------------------------ input
    def observe_input(self, block: SanitizedBlock) -> list:
        """Remember the detections of one sanitized block. Returns the guard events."""
        self._inputs += 1
        if getattr(block, "redacted", False):
            self._redacted_blocks += 1
        events = []
        for t in getattr(block, "redacted_texts", None) or []:
            self._redacted_norm.append(_norm(re.sub(r"<U\+[0-9A-F]{4,6}>", "", t)))
        for d in getattr(block, "detections", None) or []:
            self._counts[d.severity] = self._counts.get(d.severity, 0) + 1
            self._by_cat[d.category] = self._by_cat.get(d.category, 0) + 1
            if d.severity == "high":
                visible = re.sub(r"<U\+[0-9A-F]{4,6}>", "", d.snippet)
                self._high.append((d, _norm(visible), getattr(block, "evidence_id", "")))
                events.append(_ev("input", d.rule, "high", "redacted", d.snippet))
            elif d.severity == "medium":
                events.append(_ev("input", d.rule, "medium", "flagged", d.snippet))
        self._events_total += len(events)
        return events

    @property
    def has_injection(self) -> bool:
        return bool(self._high)

    # ------------------------------------------------------------------ output
    def check_output(self, action_result: ActionResult, raw: str) -> GuardVerdict:
        self._outputs += 1
        ok = bool(getattr(action_result, "ok", False))
        events: list = []
        if not ok:
            self._invalid += 1
            events.append(_ev("output", "invalid_action", "low", "flagged",
                              getattr(action_result, "error", "") or "invalid action"))
        if not self._high:
            self._events_total += len(events)
            return GuardVerdict(False, "", events)

        reasons: list[str] = []
        if not ok:
            reasons.append("invalid or not allowed action after high-severity injection in the input")
        rep = self._repeats_injection(raw or "")
        if rep:
            reasons.append("model output repeats injection text (%s)" % rep)
        if ok and getattr(action_result, "kind", None) == "tool":
            hit = self._tool_from_injection(action_result.action or {})
            if hit:
                reasons.append("model uses %s that appears only in injected text" % hit)
        if reasons:
            self._blocked = True
            self._reason = "; ".join(reasons)
            events.append(_ev("output", "tripwire", "high", "blocked", (raw or "")[:_SNIP]))
        self._events_total += len(events)
        return GuardVerdict(self._blocked, self._reason, events)

    # ------------------------------------------------------------------ helpers
    def _repeats_injection(self, raw: str) -> str:
        nraw = _norm(raw)
        if not nraw:
            return ""
        for d, nsnip, _eid in self._high:
            core = nsnip.split(" => ", 1)[-1] if d.rule == "encoded_instruction" else nsnip
            core = core.rstrip(". ")
            if len(core) >= _MIN_REPEAT and core in nraw:
                return d.rule
        for d in scan(raw):
            if d.severity == "high" and d.category in _REPEAT_CATEGORIES:
                return d.rule
        return ""

    def _in_task(self, needle: str) -> bool:
        return bool(self._task_norm) and needle in self._task_norm

    def _tool_from_injection(self, action: dict) -> str:
        corpus = " \n ".join([nsnip for _d, nsnip, _e in self._high] + self._redacted_norm)
        if not corpus:
            return ""
        tool = str(action.get("tool", "")).lower()
        if tool and re.search(r"(?<![a-z0-9_])" + re.escape(tool) + r"(?![a-z0-9_])", corpus) \
                and not self._in_task(tool):
            return "tool %r" % tool
        for k, v in (action.get("args") or {}).items():
            if isinstance(v, str) and len(v) >= _MIN_ARG:
                nv = _norm(v)
                if nv and nv in corpus and not self._in_task(nv):
                    return "argument %r" % k
        return ""

    # ------------------------------------------------------------------ report
    def summary(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "guard_version": GUARD_VERSION,
            "inputs_observed": self._inputs,
            "redacted_blocks": self._redacted_blocks,
            "detections_total": sum(self._counts.values()),
            "detections_low": self._counts["low"],
            "detections_medium": self._counts["medium"],
            "detections_high": self._counts["high"],
            "by_category": dict(self._by_cat),
            "outputs_checked": self._outputs,
            "invalid_actions": self._invalid,
            "events": self._events_total,
            "blocked": self._blocked,
            "block_reason": self._reason,
        }
