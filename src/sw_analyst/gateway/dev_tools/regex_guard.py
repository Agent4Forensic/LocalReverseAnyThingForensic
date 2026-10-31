"""ReDoS guard for model-supplied regular expressions.

The check is a conservative static scan: nested unbounded quantifiers such as (a+)+, quantified
alternations with overlapping branches such as (a|aa)* and too many unbounded quantifiers are
rejected. Callers additionally limit the matched line length and use a total time budget.
"""
from __future__ import annotations

import re

from sw_analyst.gateway.base import ToolError

MAX_PATTERN_LEN = 200
MAX_UNBOUNDED = 4

_GROUP_OPEN = re.compile(r"\((?:\?(?:P<\w+>|<\w+>|<[=!]|[:=!>]|[aiLmsux-]+:?|P=\w+\)|#[^)]*\)))?")
_BRACES = re.compile(r"\{(\d*)(,?)(\d*)\}")


def _quant_at(p: str, i: int):
    """Return (end, big) if a quantifier starts at p[i], else None. big = unbounded or > 10."""
    c = p[i]
    if c in "*+":
        end, big = i + 1, True
    elif c == "?":
        end, big = i + 1, False
    elif c == "{":
        m = _BRACES.match(p, i)
        if not m or (m.group(1) == "" and m.group(3) == ""):
            return None
        lo, comma, hi = m.groups()
        if comma:
            big = hi == "" or int(hi) > 10
        else:
            big = int(lo) > 10
        end = m.end()
    else:
        return None
    if end < len(p) and p[end] in "?+":
        end += 1
    return end, big


class _Frame:
    __slots__ = ("big_inner", "has_alt", "firsts", "expect_first", "any_inner")

    def __init__(self):
        self.big_inner = False
        self.any_inner = False
        self.has_alt = False
        self.firsts: list[str] = []
        self.expect_first = True


def _note_atom(frame: _Frame, kind: str) -> None:
    if frame.expect_first:
        frame.firsts.append(kind)
        frame.expect_first = False


def check_pattern(pattern: str, flags: int = 0) -> "re.Pattern[str]":
    """Validate and compile. Raises ToolError with an English message for unsafe/invalid patterns."""
    if not isinstance(pattern, str) or not pattern:
        raise ToolError("Regex pattern must be a non-empty string")
    if len(pattern) > MAX_PATTERN_LEN:
        raise ToolError(f"Regex pattern too long ({len(pattern)} > {MAX_PATTERN_LEN} characters)")
    _scan(pattern)
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise ToolError(f"Invalid regular expression: {exc}") from None
    except (RecursionError, OverflowError):
        raise ToolError("Regular expression is too complex") from None


def _scan(p: str) -> None:
    n = len(p)
    stack: list[_Frame] = [_Frame()]
    unbounded = 0
    i = 0
    while i < n:
        c = p[i]
        frame = stack[-1]
        if c == "\\":
            _note_atom(frame, "<meta>")
            i += 2
            continue
        if c == "[":
            j = i + 1
            if j < n and p[j] == "^":
                j += 1
            if j < n and p[j] == "]":
                j += 1
            while j < n and p[j] != "]":
                j += 2 if p[j] == "\\" else 1
            _note_atom(frame, "<meta>")
            i = j + 1
            continue
        if c == "(":
            m = _GROUP_OPEN.match(p, i)
            text = m.group(0) if m else "("
            i += len(text)
            if text.startswith("(?#") or text.startswith("(?P="):
                continue
            _note_atom(frame, "<meta>")
            stack.append(_Frame())
            continue
        if c == ")":
            i += 1
            if len(stack) == 1:
                continue
            inner = stack.pop()
            if inner.expect_first and inner.has_alt:
                inner.firsts.append("")
            parent = stack[-1]
            q = _quant_at(p, i) if i < n else None
            if q is not None:
                end, big = q
                if big:
                    unbounded += 1
                    if inner.big_inner:
                        raise ToolError("Regex rejected (ReDoS protection): nested quantifiers "
                                        "like (a+)+ are not allowed")
                    if inner.has_alt:
                        f = inner.firsts
                        if len(set(f)) < len(f) or ("<meta>" in f and len(f) > 1):
                            raise ToolError("Regex rejected (ReDoS protection): quantified "
                                            "alternation with overlapping branches like (a|aa)+")
                parent.big_inner = parent.big_inner or inner.big_inner or big
                parent.any_inner = True
                i = end
            else:
                parent.big_inner = parent.big_inner or inner.big_inner
                parent.any_inner = parent.any_inner or inner.any_inner
            continue
        if c == "|":
            frame.has_alt = True
            if frame.expect_first:
                frame.firsts.append("")
            frame.expect_first = True
            i += 1
            continue
        q = _quant_at(p, i) if c in "*+?{" else None
        if q is not None:
            end, big = q
            frame.any_inner = True
            if big:
                frame.big_inner = True
                unbounded += 1
            i = end
            continue
        _note_atom(frame, "<meta>" if c in ".^$" else c.lower())
        i += 1
    if unbounded > MAX_UNBOUNDED:
        raise ToolError(f"Regex rejected (ReDoS protection): more than {MAX_UNBOUNDED} unbounded quantifiers")
