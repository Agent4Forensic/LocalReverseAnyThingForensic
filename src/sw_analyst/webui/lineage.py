"""Conversion lineage of a job: which file was derived from which, by which tool, with which evidence.

Read-only. The producer of a file is the evidence whose source_ref["derived"] is the file path; the input is
params["path"] (default "sample"). Cycles in the data cannot loop: nothing here recurses.
"""
from __future__ import annotations

from typing import Any

from sw_analyst.gateway.base import ToolError
from sw_analyst.webui import inspect as insp

PREVIEW_CHARS = 400
_PREVIEW_BYTES = 1200
_PARAM_KEYS = 60
_PARAM_VALUE = 200


def preview_text(data: bytes, limit: int = PREVIEW_CHARS) -> str:
    """Printable preview: control and replacement characters become '.', newlines and tabs stay."""
    text = data.decode("utf-8", errors="replace")
    out = []
    for ch in text:
        if ch in "\n\t" or (ch.isprintable() and ch != "�"):
            out.append(ch)
        else:
            out.append(".")
        if len(out) >= limit:
            break
    return "".join(out)


def _clean_params(params: Any) -> dict:
    if not isinstance(params, dict):
        return {}
    out = {}
    for k in list(params)[:_PARAM_KEYS]:
        v = params[k]
        out[str(k)] = v if isinstance(v, (int, float, bool)) or v is None else str(v)[:_PARAM_VALUE]
    return out


def lineage(store, gateway, rid: str) -> dict:
    try:
        files = list(gateway.list_files(rid))
    except ToolError:
        files = []
    by_path = {f["path"]: f for f in files}

    edges: dict[tuple, dict] = {}
    rows = store._q("SELECT id, tool, params_json, source_ref_json FROM evidence WHERE job_id=? ORDER BY id", (rid,))
    for ev in rows:
        sref = ev.get("source_ref") if isinstance(ev.get("source_ref"), dict) else {}
        dst = sref.get("derived")
        if not isinstance(dst, str) or not dst:
            continue
        params = ev.get("params") if isinstance(ev.get("params"), dict) else {}
        src = params.get("path") if isinstance(params.get("path"), str) and params.get("path") else "sample"
        key = (src, dst)
        if key in edges:
            edges[key]["evidence_ids"].append(ev["id"])
            continue
        method = sref.get("method") or params.get("method") or ""
        edges[key] = {"from": src, "to": dst, "evidence_id": ev["id"], "evidence_ids": [ev["id"]],
                      "tool": ev["tool"], "params": _clean_params(params), "method": str(method)}

    paths = list(by_path)
    for (a, b) in edges:
        for p in (a, b):
            if p not in by_path and p not in paths:
                paths.append(p)

    nodes = []
    for p in paths:
        f = by_path.get(p)
        node = {"path": p, "size": f["size"] if f else 0, "sha256": f["sha256"] if f else "",
                "kind": "", "label": "", "preview": "", "missing": f is None}
        if f:
            try:
                head = gateway.read_bytes(rid, p, 0, _PREVIEW_BYTES)["data"]
            except ToolError:
                head = b""
            k = insp.file_kind(head)
            node.update(kind=k["kind"], label=k["label"], preview=preview_text(head))
        nodes.append(node)

    has_out = {a for (a, _b) in edges}
    final = [n["path"] for n in nodes if n["path"] not in has_out and not n["missing"]]
    return {"nodes": nodes, "edges": list(edges.values()), "final": final}
