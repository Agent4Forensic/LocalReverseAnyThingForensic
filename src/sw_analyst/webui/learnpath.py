"""Deterministic learning path (walkthrough) of one Ghidra function. No model, no execution of sample code.

Input: one function dict of the Ghidra export (name, entry, disasm rows [address, bytes, text] or dicts, blocks
[{start, end, succ: [[dest, flow]]}]). Output: ordered steps; line_start/line_end are 1-based rows of the disassembly.
"""
from __future__ import annotations

import bisect

from sw_analyst.webui import inspect as insp

MAX_STEPS = 200
_PROLOG_MAX = 6


def _rows(fn: dict) -> list[dict]:
    out = []
    for r in fn.get("disasm") or []:
        if isinstance(r, dict):
            addr, hx, text = r.get("address", ""), r.get("bytes", ""), r.get("text", "")
        else:
            addr, hx, text = (list(r) + ["", "", ""])[:3]
        out.append({"address": str(addr), "bytes": str(hx), "text": str(text)})
    return out


def _mnem(text: str) -> str:
    return insp.explain(text).get("mnemonic", "")


def _addr(a: str) -> int | None:
    try:
        return int(str(a), 16)
    except (TypeError, ValueError):
        return None


def _target(text: str) -> int | None:
    parts = " ".join(text.split()).split(" ", 1)
    return _addr(parts[1].strip()) if len(parts) > 1 and parts[1].strip().lower().startswith("0x") else None


def walkthrough(fn: dict) -> dict:
    rows = _rows(fn)[:4000]          # same limit as the dashboard (hostile export: bounded work)
    name = str(fn.get("name") or fn.get("entry") or "?")
    by_addr = {}
    for i, r in enumerate(rows, 1):
        a = _addr(r["address"])
        if a is not None:
            by_addr.setdefault(a, i)
    mn = [_mnem(r["text"]) for r in rows]
    steps: list[dict] = []

    def add(kind: str, title: str, expl: str, a: int, b: int | None = None):
        if len(steps) >= MAX_STEPS or not (1 <= a <= len(rows)):
            return
        b = min(max(b or a, a), len(rows))
        steps.append({"n": len(steps) + 1, "kind": kind, "title": title, "explanation": expl,
                      "address": rows[a - 1]["address"], "line_start": a, "line_end": b})

    if rows:
        end = 0
        while end < min(len(rows), _PROLOG_MAX) and mn[end] in ("push", "mov", "sub", "endbr64"):
            end += 1
            if mn[end - 1] == "sub" and "sp" in rows[end - 1]["text"].lower():
                break
        if end:
            add("prolog", "Prolog: Stack-Rahmen einrichten",
                "Die Funktion sichert Register und reserviert Platz für lokale Variablen. "
                + " ".join(insp.explain(rows[i]["text"]).get("explain", "") for i in range(min(end, 2))).strip(), 1, end)
        else:
            add("prolog", "Einstieg", f"Die Funktion {name} beginnt hier.", 1)

        blocks = [b for b in (fn.get("blocks") or []) if isinstance(b, dict)][:500]
        addrs = sorted(by_addr)
        for bi, b in enumerate(blocks, 1):
            s = by_addr.get(_addr(b.get("start")) or -1)
            ea = _addr(b.get("end"))
            k = bisect.bisect_right(addrs, ea) - 1 if ea is not None else -1
            e = by_addr[addrs[k]] if k >= 0 else None
            if s is None:
                continue
            raw = b.get("succ") if isinstance(b.get("succ"), list) else []
            succ = [str(x[0] if isinstance(x, (list, tuple)) and x else x) for x in raw[:16]]
            tail = ("Folgt: " + ", ".join(succ[:4]) + ".") if succ else "Kein Nachfolger: die Funktion endet hier."
            add("block", f"Block {bi}: {b.get('start')}", f"Zusammenhängender Codeabschnitt ohne Verzweigung im Inneren. {tail}",
                s, e or s)

        for i, r in enumerate(rows, 1):
            m = mn[i - 1]
            ex = insp.explain(r["text"]).get("explain", "")
            a = _addr(r["address"])
            t = _target(r["text"])
            if m == "call":
                ops = r["text"].split(None, 1)[1] if len(r["text"].split(None, 1)) > 1 else "?"
                add("call", f"Aufruf: {ops}", ex or "Ruft eine andere Funktion auf.", i)
            elif m in ("cmp", "test"):
                nxt = mn[i] if i < len(mn) else ""
                add("compare", "Vergleich" + (" mit Sprung" if nxt.startswith("j") else ""),
                    ex + (" Das Ergebnis steuert den folgenden Sprung." if nxt.startswith("j") else ""), i, i + 1 if nxt.startswith("j") else i)
            elif m.startswith("j") and m != "jmp" and not (i > 1 and mn[i - 2] in ("cmp", "test")):
                add("jump", "Bedingter Sprung" + (f" nach {r['text'].split()[-1]}" if t is not None else ""), ex, i)
            elif m == "jmp":
                add("jump", "Unbedingter Sprung" + (f" nach {r['text'].split()[-1]}" if t is not None else ""), ex or "Springt ohne Bedingung.", i)
            if m.startswith("j") and t is not None and a is not None and t <= a and t in by_addr:
                add("loop", "Schleife: Rücksprung", f"Der Sprung geht zurück zu {hex(t)}; der Abschnitt dazwischen wird wiederholt, bis die Bedingung nicht mehr zutrifft.",
                    by_addr[t], i)
            if m in ("ret", "retn", "leave") and m != "leave":
                add("return", "Rückkehr", ex or "Kehrt zum Aufrufer zurück.", i)

    steps.sort(key=lambda s: (s["line_start"], {"prolog": 0, "block": 1}.get(s["kind"], 2)))
    for i, s in enumerate(steps, 1):
        s["n"] = i
    fid = str(fn.get("entry") or name)
    return {"id": "wt-" + fid, "function_id": fid, "function": name, "path": fn.get("path") or "",
            "title_en": f"Walkthrough of {name}", "title_de": f"Lernpfad zu {name}",
            "summary_en": f"{len(steps)} steps through {name}.",
            "summary_de": f"{len(steps)} Schritte durch {name}: Prolog, Blöcke, Aufrufe, Schleifen und Vergleiche. "
                          "Die Erklärungen beschreiben nur, was ein Befehl allgemein tut; was die Funktion im Sample bewirkt, belegen die Befunde.",
            "instructions": len(rows), "steps": steps}
