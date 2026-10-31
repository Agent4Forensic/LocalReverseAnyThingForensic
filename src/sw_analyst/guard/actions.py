"""Strict validation of the model's action JSON (chain.md sections 3 and 5.3)."""
from __future__ import annotations

import json
import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Optional

MAX_RAW_BYTES = 64 * 1024
MAX_INT = 10**9
MAX_STR = 4000
_EV_ID = re.compile(r"EV-[0-9]{6}")
_FENCE = re.compile(r"\A```(?:json|JSON)?[ \t]*\r?\n(.*?)\r?\n?[ \t]*```\Z", re.S)
_PATH_PARAMS = {"path", "file", "member"}
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_RESERVED = {"con", "prn", "aux", "nul", "clock$", *{"com%d" % i for i in range(1, 10)},
             *{"lpt%d" % i for i in range(1, 10)}}


@dataclass
class ActionResult:
    ok: bool
    action: Optional[dict]
    error: str
    kind: Optional[str]  # 'tool' | 'finish' | None


class _Bad(Exception):
    pass


def _fail(msg: str) -> ActionResult:
    return ActionResult(False, None, msg, None)


def _dup_pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise _Bad("duplicate key %r in JSON object" % k)
        d[k] = v
    return d


def _bad_const(name):
    raise _Bad("non-finite number %s is not allowed" % name)


def _parse_single_object(raw: str) -> dict:
    text = raw.strip()
    m = _FENCE.match(text)
    if m:
        text = m.group(1).strip()
    elif text.startswith("```"):
        raise _Bad("malformed code fence")
    if not text.startswith("{"):
        raise _Bad("response must be exactly one JSON object (no surrounding text)")
    dec = json.JSONDecoder(object_pairs_hook=_dup_pairs, parse_constant=_bad_const)
    try:
        obj, end = dec.raw_decode(text)
    except _Bad:
        raise
    except RecursionError:
        raise _Bad("JSON nesting too deep")
    except ValueError as e:
        raise _Bad("invalid JSON: %s" % str(e)[:120])
    if text[end:].strip():
        raise _Bad("extra text or more than one JSON object after the first object")
    if not isinstance(obj, dict):
        raise _Bad("top-level JSON value must be an object")
    return obj


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _str(v: Any, what: str, maxlen: int, *, required_nonblank: bool = False) -> str:
    if not isinstance(v, str):
        raise _Bad("%s must be a string" % what)
    if len(v) > maxlen:
        raise _Bad("%s too long (max %d characters)" % (what, maxlen))
    if "\x00" in v:
        raise _Bad("%s contains NUL" % what)
    v = _CTRL.sub("", v)
    if required_nonblank and not v.strip():
        raise _Bad("%s must not be empty" % what)
    return v


def _int(v: Any, what: str, *, minimum: Optional[int] = None) -> int:
    if not _is_int(v):
        raise _Bad("%s must be an integer" % what)
    if abs(v) > MAX_INT:
        raise _Bad("%s out of plausible range" % what)
    if minimum is not None and v < minimum:
        raise _Bad("%s must be >= %d" % (what, minimum))
    return v


def _keys(d: dict, allowed: set, what: str) -> None:
    extra = [k for k in d if k not in allowed]
    if extra:
        raise _Bad("unknown key(s) in %s: %s" % (what, ", ".join(sorted(map(str, extra))[:5])))


def _logical_path(v: str, what: str) -> str:
    if v == "" or not v.strip():
        raise _Bad("%s must not be empty" % what)
    for form in (v, unicodedata.normalize("NFKC", v)):
        if "\x00" in form or _CTRL.search(form):
            raise _Bad("%s contains control characters" % what)
        if re.search(r"%[0-9a-fA-F]{2}", form):
            raise _Bad("%s: percent-encoding is not allowed" % what)
        if form[0] in "/\\~$%" or form.startswith("//") or re.match(r"^[A-Za-z]:", form):
            raise _Bad("%s must be a logical name, not an absolute, drive, UNC or home path" % what)
        if ":" in form or re.search(r'[<>|"*?]', form):
            raise _Bad("%s contains forbidden characters" % what)
        for comp in re.split(r"[/\\]", form):
            if comp == "":
                continue
            if comp.strip(" .") == "":
                raise _Bad("%s must not contain '.' or '..' components" % what)
            if comp.rstrip(" .").split(".")[0].lower() in _RESERVED:
                raise _Bad("%s uses a reserved device name" % what)
    return v


def _check_param_value(name: str, spec: Any, val: Any) -> Any:
    if isinstance(spec, str):
        spec = {"type": spec}
    if not isinstance(spec, dict):
        raise _Bad("tool parameter %r has no usable schema" % name)
    typ = str(spec.get("type", "string")).lower()
    if typ in ("int", "integer"):
        v = _int(val, "argument %r" % name)
        if "min" in spec and _is_int(spec["min"]) and v < spec["min"]:
            raise _Bad("argument %r must be >= %s" % (name, spec["min"]))
        if "max" in spec and _is_int(spec["max"]) and v > spec["max"]:
            raise _Bad("argument %r must be <= %s" % (name, spec["max"]))
    elif typ in ("str", "string"):
        v = _str(val, "argument %r" % name, MAX_STR)
        ml = spec.get("max_length")
        if _is_int(ml) and len(v) > ml:
            raise _Bad("argument %r too long (max %d)" % (name, ml))
        if name.lower() in _PATH_PARAMS:
            v = _logical_path(v, "argument %r" % name)
    elif typ in ("bool", "boolean"):
        if not isinstance(val, bool):
            raise _Bad("argument %r must be a boolean" % name)
        v = val
    elif typ in ("float", "number"):
        if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val) \
                or abs(val) > MAX_INT:
            raise _Bad("argument %r must be a plausible number" % name)
        v = val
    else:
        raise _Bad("tool parameter %r has unsupported type %r" % (name, typ))
    enum = spec.get("enum")
    if isinstance(enum, (list, tuple)) and v not in enum:
        raise _Bad("argument %r must be one of %s" % (name, list(enum)[:10]))
    return v


def _validate_tool(obj: dict, tools: list) -> dict:
    _keys(obj, {"action", "tool", "args", "why"}, "tool action")
    name = obj.get("tool")
    if not isinstance(name, str) or not name or len(name) > 100:
        raise _Bad("'tool' must be a tool name string")
    spec_by_name = {}
    for t in tools or []:
        spec_by_name.setdefault(getattr(t, "name", None), t)
    spec = spec_by_name.get(name)
    if spec is None:
        raise _Bad("tool %r is not in the allowlist" % name[:60])
    why = _str(obj.get("why"), "'why'", 500, required_nonblank=True) if "why" in obj else None
    if why is None:
        raise _Bad("'why' is required")
    args = obj.get("args", {})
    if not isinstance(args, dict):
        raise _Bad("'args' must be an object")
    params = getattr(spec, "params", None) or {}
    extra = [k for k in args if k not in params]
    if extra:
        raise _Bad("unknown argument(s) for tool %r: %s (allowed: %s)" % (
            name, ", ".join(sorted(map(str, extra))[:5]), ", ".join(sorted(params)) or "none"))
    clean = {}
    for pname, pspec in params.items():
        required = bool(pspec.get("required", False)) if isinstance(pspec, dict) else False
        if pname not in args:
            if required:
                raise _Bad("missing required argument %r for tool %r" % (pname, name))
            continue
        clean[pname] = _check_param_value(pname, pspec, args[pname])
    return {"action": "tool", "tool": name, "args": clean, "why": why}


def _validate_finding(f: Any, i: int) -> dict:
    if not isinstance(f, dict):
        raise _Bad("finding %d must be an object" % i)
    _keys(f, {"statement", "status", "evidence"}, "finding %d" % i)
    st = _str(f.get("statement"), "finding %d statement" % i, 1000, required_nonblank=True)
    status = f.get("status")
    if status not in ("confirmed", "hypothesis"):
        raise _Bad("finding %d status must be 'confirmed' or 'hypothesis'" % i)
    ev = f.get("evidence")
    if not isinstance(ev, list) or not ev:
        raise _Bad("finding %d needs at least one evidence entry" % i)
    if len(ev) > 10:
        raise _Bad("finding %d has more than 10 evidence entries" % i)
    out_ev = []
    for j, e in enumerate(ev):
        if not isinstance(e, dict):
            raise _Bad("finding %d evidence %d must be an object" % (i, j))
        _keys(e, {"id", "quote"}, "finding %d evidence %d" % (i, j))
        eid = e.get("id")
        if not isinstance(eid, str) or not _EV_ID.fullmatch(eid):
            raise _Bad("finding %d evidence %d: id must match EV-000000" % (i, j))
        if "quote" not in e and status == "confirmed":
            raise _Bad("finding %d evidence %d: confirmed findings need a verbatim quote" % (i, j))
        q = _str(e.get("quote", ""), "finding %d evidence %d quote" % (i, j), 1000,
                 required_nonblank=(status == "confirmed"))
        out_ev.append({"id": eid, "quote": q})
    return {"statement": st, "status": status, "evidence": out_ev}


_ANN_KINDS = {"finding", "note", "ioc", "warning"}


def _validate_annotation(a: Any, i: int) -> dict:
    if not isinstance(a, dict):
        raise _Bad("annotation %d must be an object" % i)
    _keys(a, {"file", "line_start", "line_end", "text", "evidence_id", "kind"}, "annotation %d" % i)
    f = _logical_path(_str(a.get("file"), "annotation %d file" % i, 260, required_nonblank=True),
                      "annotation %d file" % i)
    ls = _int(a.get("line_start"), "annotation %d line_start" % i, minimum=1)
    le = _int(a.get("line_end"), "annotation %d line_end" % i, minimum=ls)
    out = {"file": f, "line_start": ls, "line_end": le,
           "text": _str(a.get("text"), "annotation %d text" % i, 500, required_nonblank=True)}
    if a.get("evidence_id") is not None:
        eid = a["evidence_id"]
        if not isinstance(eid, str) or not _EV_ID.fullmatch(eid):
            raise _Bad("annotation %d evidence_id must match EV-000000" % i)
        out["evidence_id"] = eid
    if a.get("kind") is not None:
        if a["kind"] not in _ANN_KINDS:
            raise _Bad("annotation %d kind must be one of %s" % (i, sorted(_ANN_KINDS)))
        out["kind"] = a["kind"]
    return out


def _validate_subtask(s: Any, i: int) -> dict:
    if not isinstance(s, dict):
        raise _Bad("subtask %d must be an object" % i)
    _keys(s, {"title", "goal", "reason"}, "subtask %d" % i)
    return {
        "title": _str(s.get("title"), "subtask %d title" % i, 120, required_nonblank=True),
        "goal": _str(s.get("goal"), "subtask %d goal" % i, 500, required_nonblank=True),
        "reason": _str(s.get("reason"), "subtask %d reason" % i, 500, required_nonblank=True),
    }


def _list(v: Any, what: str, maxn: int) -> list:
    if not isinstance(v, list):
        raise _Bad("%s must be a list" % what)
    if len(v) > maxn:
        raise _Bad("%s has too many entries (max %d)" % (what, maxn))
    return v


def _validate_finish(obj: dict) -> dict:
    _keys(obj, {"action", "summary", "findings", "annotations", "subtasks", "answer"}, "finish action")
    if "summary" not in obj:
        raise _Bad("'summary' is required")
    out: dict = {"action": "finish", "summary": _str(obj["summary"], "'summary'", 4000)}
    if "findings" not in obj:
        raise _Bad("'findings' is required (may be an empty list)")
    out["findings"] = [_validate_finding(f, i) for i, f in enumerate(_list(obj["findings"], "'findings'", 30))]
    if "annotations" in obj:
        out["annotations"] = [_validate_annotation(a, i)
                              for i, a in enumerate(_list(obj["annotations"], "'annotations'", 50))]
    if "subtasks" in obj:
        out["subtasks"] = [_validate_subtask(s, i) for i, s in enumerate(_list(obj["subtasks"], "'subtasks'", 8))]
    if "answer" in obj and obj["answer"] is not None:
        ans = obj["answer"]
        if not isinstance(ans, dict):
            raise _Bad("'answer' must be an object")
        _keys(ans, {"text"}, "answer")
        out["answer"] = {"text": _str(ans.get("text"), "answer text", 4000, required_nonblank=True)}
    return out


def validate_action(raw: str, tools: list) -> ActionResult:
    """Validate the raw model answer. Never raises."""
    try:
        if not isinstance(raw, str):
            return _fail("response must be text")
        if len(raw.encode("utf-8", errors="replace")) > MAX_RAW_BYTES:
            return _fail("response too large (max 64 KiB)")
        obj = _parse_single_object(raw)
        kind = obj.get("action")
        if kind == "tool":
            act = _validate_tool(obj, tools)
        elif kind == "finish":
            act = _validate_finish(obj)
        else:
            raise _Bad("'action' must be 'tool' or 'finish'")
        return ActionResult(True, act, "", kind)
    except _Bad as e:
        return _fail(str(e))
    except (RecursionError, MemoryError):
        return _fail("response too complex")
    except Exception as e:  # defensive: validation must never crash the runner
        return _fail("validation error: %s" % type(e).__name__)
