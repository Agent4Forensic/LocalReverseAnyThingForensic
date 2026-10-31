"""Named analysis tools backed by the tool containers (ADR-0006, package B).

A file goes through a container once per tool: the fixed batch result lands in <job>/tool-cache/, outside derived/, and the
tools filter that result in plain Python. So model arguments never reach Ghidra, capa, FLOSS, YARA or jadx.
capa and YARA hits are hypotheses until code confirms them.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import zipfile
from typing import Any, Optional

from sw_analyst.gateway.base import ToolError
from sw_analyst.gateway.container_runner import ContainerError, ContainerRunner
from sw_analyst.gateway.dev_gateway import _PATH, DevGateway, _Ctx, _Out, _p, _Tool
from sw_analyst.gateway.dev_tools.util import clip

MAX_JADX_TOTAL = 128 * 1024 * 1024
MAX_JADX_FILES = 20000
HYPOTHESIS = "Hits are hypotheses until code confirms them: name the code location that supports each one."

GHIDRA_TOOLS = {"list_functions", "disassemble", "decompile", "xrefs", "basic_blocks"}
TRIAGE_TOOLS = {"capa_scan", "floss_decode", "yara_scan"}
JADX_TOOLS = {"jadx_decompile"}
ALL_TOOLS = GHIDRA_TOOLS | TRIAGE_TOOLS | JADX_TOOLS


def _hex_addr(value: Any) -> int:
    try:
        return int(str(value).strip(), 16)
    except ValueError:
        raise ToolError("Address must be hexadecimal, e.g. 0x401000") from None


class ContainerTools:
    def __init__(self, runner: ContainerRunner):
        self.runner = runner
        self._loaded: tuple[str, Any] = ("", None)   # the last parsed result; Ghidra exports can be large

    # ---- batch result ---------------------------------------------------------------------------------------
    def _result(self, ctx: _Ctx, op: str, logical: Any, parse=None) -> tuple[Any, str, str]:
        """Returns (parsed result, logical name, version). Runs the container only on the first call per file."""
        data, name = ctx.read_all(logical)
        sha = hashlib.sha256(data).hexdigest()
        version = self.runner.version(op)
        cache_dir = ctx.root / "tool-cache"
        path = cache_dir / f"{op}-{version.rsplit(':', 1)[-1]}-{sha}.json"
        key = str(path)
        if self._loaded[0] == key:
            return self._loaded[1], name, version
        if path.is_file():
            parsed = json.loads(path.read_text(encoding="utf-8"))
        else:
            try:
                raw = self.runner.run(op, data)
            except ContainerError as exc:
                raise ToolError(str(exc)) from None
            try:
                parsed = parse(raw) if parse else json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                raise ToolError(f"Tool '{op}' produced output that could not be read") from None
            cache_dir.mkdir(exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(parsed), encoding="utf-8")
            os.replace(tmp, path)
        self._loaded = (key, parsed)
        return parsed, name, version

    # ---- Ghidra ---------------------------------------------------------------------------------------------
    def _ghidra(self, ctx: _Ctx, a: dict) -> tuple[dict, str, str]:
        res, name, version = self._result(ctx, "ghidra", a["path"])
        if not isinstance(res, dict) or not isinstance(res.get("functions"), list):
            raise ToolError("Ghidra result has an unexpected shape")
        return res, name, version

    @staticmethod
    def _find_function(res: dict, query: str) -> dict:
        query = query.strip()
        if not query:
            raise ToolError("Argument 'function' is required: a name or an address from list_functions")
        for f in res["functions"]:
            if f["name"] == query:
                return f
        if query.lower().startswith("0x"):
            addr = _hex_addr(query)
            for f in res["functions"]:
                if int(f["start"], 16) <= addr <= int(f["end"], 16):
                    return f
        raise ToolError(f"No function '{clip(query, 80)}'; use list_functions")

    def t_list_functions(self, ctx: _Ctx, a: dict) -> _Out:
        res, name, version = self._ghidra(ctx, a)
        needle = a["name_contains"].lower()
        hits = [f for f in res["functions"] if needle in f["name"].lower()]
        page = hits[a["offset"]:a["offset"] + a["limit"]]
        prog = res.get("program", {})
        L = [f"Functions in {name}: {len(hits)} match(es) of {len(res['functions'])}; "
             f"{prog.get('format')}, {prog.get('language')}, image base {prog.get('image_base')}",
             "entry | size | name | signature"]
        L += [f"{f['entry']} | {f['size']} | {f['name']}{' [thunk]' if f.get('thunk') else ''} | {clip(f.get('signature') or '', 160)}"
              for f in page]
        more = a["offset"] + len(page) < len(hits)
        if more:
            L.append(f"[more available: continue with offset={a['offset'] + len(page)}]")
        if res.get("truncated"):
            L.append("[export limit reached: not every function or reference of the file is listed]")
        return _Out("\n".join(L), {"source_ref": {"file": name}, "count": len(hits)}, truncated=more, version=version)

    def t_disassemble(self, ctx: _Ctx, a: dict) -> _Out:
        res, name, version = self._ghidra(ctx, a)
        f = self._find_function(res, a["function"])
        rows = f.get("disasm", [])
        page = rows[a["offset"]:a["offset"] + a["limit"]]
        L = [f"Disassembly of {f['name']} at {f['entry']} in {name}: {len(rows)} instruction(s)"]
        L += [f"{addr}  {hx:<20} {text}" for addr, hx, text in page]
        more = a["offset"] + len(page) < len(rows)
        if more:
            L.append(f"[more available: continue with offset={a['offset'] + len(page)}]")
        if f.get("disasm_truncated"):
            L.append("[function is longer than the export limit of 4000 instructions]")
        return _Out("\n".join(L), {"source_ref": {"file": name, "function": f["name"], "address": f["entry"]}},
                    truncated=more, version=version)

    def t_decompile(self, ctx: _Ctx, a: dict) -> _Out:
        res, name, version = self._ghidra(ctx, a)
        f = self._find_function(res, a["function"])
        ref = {"source_ref": {"file": name, "function": f["name"], "address": f["entry"]}}
        if not f.get("decompiled"):
            msg = f"No decompiler output for {f['name']} (thunk, timeout or export budget). Use disassemble instead."
            return _Out(msg, ref, ok=False, error=msg, version=version)
        return _Out(f"Decompiled {f['name']} at {f['entry']} in {name}. Decompiler output approximates the code.\n"
                    f"{f['decompiled']}", ref, version=version)

    def t_xrefs(self, ctx: _Ctx, a: dict) -> _Out:
        res, name, version = self._ghidra(ctx, a)
        query = a["target"].strip()
        addr = int(self._find_function(res, query)["entry"], 16) if not query.lower().startswith("0x") else _hex_addr(query)
        refs = res.get("refs", [])
        to = [r for r in refs if int(r[1], 16) == addr]
        frm = [r for r in refs if int(r[0], 16) == addr]
        L = [f"References for 0x{addr:x} in {name}: {len(to)} to it, {len(frm)} from it"]
        L += [f"to:   from {r[0]} ({r[2]})" for r in to[:a["limit"]]]
        L += [f"from: to {r[1]} ({r[2]})" for r in frm[:a["limit"]]]
        cut = len(to) > a["limit"] or len(frm) > a["limit"]
        if cut:
            L.append(f"[listing limited to {a['limit']} per direction]")
        return _Out("\n".join(L), {"source_ref": {"file": name, "address": f"0x{addr:x}"}, "to": len(to), "from": len(frm)},
                    truncated=cut, version=version)

    def t_basic_blocks(self, ctx: _Ctx, a: dict) -> _Out:
        res, name, version = self._ghidra(ctx, a)
        f = self._find_function(res, a["function"])
        blocks = f.get("blocks", [])
        L = [f"Basic blocks of {f['name']} at {f['entry']} in {name}: {len(blocks)}", "start - end -> successors"]
        for b in blocks[:500]:
            succ = ", ".join(f"{d} ({flow})" for d, flow in b.get("succ", [])) or "(none)"
            L.append(f"{b['start']} - {b['end']} -> {succ}")
        return _Out("\n".join(L), {"source_ref": {"file": name, "function": f["name"], "address": f["entry"]},
                                   "blocks": blocks[:500]}, truncated=len(blocks) > 500, version=version)

    # ---- capa, FLOSS, YARA ----------------------------------------------------------------------------------
    def t_capa_scan(self, ctx: _Ctx, a: dict) -> _Out:
        res, name, version = self._result(ctx, "capa", a["path"])
        rows = []
        for rule, body in sorted((res.get("rules") or {}).items()):
            meta = body.get("meta", {})
            if meta.get("lib"):
                continue
            attack = ", ".join(x.get("id", "") for x in meta.get("attack", []) if x.get("id"))
            where = []
            for match in body.get("matches", [])[:5]:
                loc = match[0] if match else {}
                if isinstance(loc, dict) and isinstance(loc.get("value"), int):
                    where.append(f"0x{loc['value']:x}")
            rows.append((rule, meta.get("namespace") or "", attack, where))
        L = [f"capa on {name}: {len(rows)} capability rule(s) matched. {HYPOTHESIS}", "rule | namespace | ATT&CK | locations"]
        L += [f"{r} | {n} | {t} | {' '.join(w)}" for r, n, t, w in rows]
        return _Out("\n".join(L), {"source_ref": {"file": name}, "count": len(rows), "hypothesis": True,
                                   "rules": [r[0] for r in rows][:200]}, version=version)

    def t_floss_decode(self, ctx: _Ctx, a: dict) -> _Out:
        kinds = {"decoded": "decoded_strings", "stack": "stack_strings", "tight": "tight_strings", "static": "static_strings"}
        kind = a["kind"].strip().lower()
        if kind != "all" and kind not in kinds:
            raise ToolError("Argument 'kind' must be one of: all, decoded, stack, tight, static")
        res, name, version = self._result(ctx, "floss", a["path"])
        strings = res.get("strings") or {}
        # 'all' leaves out static strings: strings_extract already shows those.
        wanted = [k for k in kinds if k != "static"] if kind == "all" else [kind]
        L = [f"FLOSS on {name}, kind {kind}. A decoded string shows what the code would produce, not that it runs."]
        total, shown, limit = 0, 0, a["limit"]
        for k in wanted:
            rows = strings.get(kinds[k]) or []
            total += len(rows)
            L.append(f"{k}: {len(rows)}")
            for row in rows[:max(0, limit - shown)]:
                loc = row.get("function") or row.get("address") or row.get("offset") or row.get("decoding_routine")
                where = f"0x{loc:x}" if isinstance(loc, int) else "-"
                L.append(f"  {where}  {clip(str(row.get('string', '')), 300)}")
                shown += 1
        cut = total > shown
        if cut:
            L.append(f"[listing limited to {limit} strings of {total}]")
        return _Out("\n".join(L), {"source_ref": {"file": name}, "count": total}, truncated=cut, version=version)

    def t_yara_scan(self, ctx: _Ctx, a: dict) -> _Out:
        res, name, version = self._result(ctx, "yara", a["path"])
        rules = res.get("matches") or []
        L = [f"YARA (pinned own rule set) on {name}: {len(rules)} rule(s) matched. {HYPOTHESIS}"]
        for rule in rules:
            meta = rule.get("meta")
            desc = meta.get("description", "") if isinstance(meta, dict) else ""
            hits = rule.get("strings") or []
            where = " ".join(f"0x{h['offset']:x}" for h in hits[:10] if isinstance(h.get("offset"), int))
            L.append(f"{rule.get('rule')}: {desc} | offsets: {where or '-'}")
        return _Out("\n".join(L), {"source_ref": {"file": name}, "count": len(rules), "hypothesis": True,
                                   "rules": [r.get("rule") for r in rules]}, version=version)

    # ---- jadx -----------------------------------------------------------------------------------------------
    @staticmethod
    def parse_jadx_tar(raw: bytes) -> dict:
        """Reads the tar in memory and never unpacks it to disk, so names inside cannot escape anywhere."""
        files: dict[str, str] = {}
        total = 0
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            for member in tar:
                if not member.isreg() or not member.name.endswith(".java"):
                    continue
                if len(files) >= MAX_JADX_FILES or total + member.size > MAX_JADX_TOTAL:
                    return {"files": files, "truncated": True}
                body = tar.extractfile(member)
                files[member.name.removeprefix("./")] = body.read().decode("utf-8", "replace") if body else ""
                total += member.size
        return {"files": files, "truncated": False}

    def t_jadx_decompile(self, ctx: _Ctx, a: dict) -> _Out:
        data, _name = ctx.read_all(a["path"])
        if data[:4] == b"dex\n":
            op = "jadx-dex"
        elif data[:2] == b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    op = "jadx-apk" if "classes.dex" in zf.namelist() else "jadx-jar"
            except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError, EOFError):
                raise ToolError(f"File '{_name}' is not a readable ZIP archive") from None
        else:
            raise ToolError("jadx_decompile needs an APK, JAR or DEX file")
        res, name, version = self._result(ctx, op, a["path"], self.parse_jadx_tar)
        files = res.get("files", {})
        cap = " [not every class is included: size limit]" if res.get("truncated") else ""
        ref: dict[str, Any] = {"file": name}
        if a["class_file"]:
            src = files.get(a["class_file"])
            if src is None:
                raise ToolError(f"No class file '{clip(a['class_file'], 100)}'; list them without class_file")
            ref["class_file"] = a["class_file"]
            lines = src.splitlines()
            page = lines[a["offset"]:a["offset"] + a["limit"]]
            more = a["offset"] + len(page) < len(lines)
            text = f"{a['class_file']} lines {a['offset'] + 1}-{a['offset'] + len(page)} of {len(lines)}. " \
                   "Decompiler output approximates the code.\n" + "\n".join(page)
            if more:
                text += f"\n[more available: continue with offset={a['offset'] + len(page)}]"
            return _Out(text, {"source_ref": ref}, truncated=more, version=version)
        if a["search"]:
            needle = a["search"].lower()
            L, hits = [f"Search for '{clip(a['search'], 80)}' in {len(files)} decompiled class file(s){cap}"], 0
            for fname in sorted(files):
                for no, line in enumerate(files[fname].splitlines(), 1):
                    if needle in line.lower():
                        hits += 1
                        if hits <= a["limit"]:
                            L.append(f"{fname}:{no}: {clip(line.strip(), 240)}")
            cut = hits > a["limit"]
            if cut:
                L.append(f"[listing limited to {a['limit']} of {hits} hits]")
            return _Out("\n".join(L), {"source_ref": ref, "count": hits}, truncated=cut, version=version)
        names = sorted(files)
        page = names[a["offset"]:a["offset"] + a["limit"]]
        more = a["offset"] + len(page) < len(names)
        L = [f"{len(names)} decompiled class file(s) in {name}{cap}"] + page
        if more:
            L.append(f"[more available: continue with offset={a['offset'] + len(page)}]")
        return _Out("\n".join(L), {"source_ref": ref, "count": len(names)}, truncated=more, version=version)


def attach_container_tools(gateway: DevGateway, runner: Optional[ContainerRunner] = None) -> list[str]:
    """Adds the tools whose image exists; returns their names. Without images the allowlist stays as it was."""
    runner = runner or ContainerRunner.detect()
    t = ContainerTools(runner)
    limit = _p("int", "Maximum rows returned.", default=200, min=1, max=2000)
    offset = _p("int", "Skip this many rows (for paging).", default=0, min=0)
    func = _p("str", "Function name or an address inside it, from list_functions.", required=True)
    specs = [
        ("ghidra", "list_functions", "List functions found by Ghidra: entry, size, name, signature. The first Ghidra call on a "
         "file can take minutes; later ones are instant.",
         {"path": _PATH, "name_contains": _p("str", "Only names containing this text.", default=""), "limit": limit,
          "offset": offset}, t.t_list_functions),
        ("ghidra", "disassemble", "Disassembly of one function with addresses and bytes.",
         {"function": func, "path": _PATH, "limit": limit, "offset": offset}, t.t_disassemble),
        ("ghidra", "decompile", "Ghidra decompiler output of one function. Quote it as evidence; it approximates the code.",
         {"function": func, "path": _PATH}, t.t_decompile),
        ("ghidra", "xrefs", "References to and from an address or function (callers, callees, data use).",
         {"target": _p("str", "Function name or hex address such as 0x401000.", required=True), "path": _PATH, "limit": limit},
         t.t_xrefs),
        ("ghidra", "basic_blocks", "Basic blocks and control-flow edges of one function, the facts behind a flow diagram.",
         {"function": func, "path": _PATH}, t.t_basic_blocks),
        ("capa", "capa_scan", "capa capability rules matched in a PE or ELF, with ATT&CK ids and code locations. Hits are "
         "hypotheses until code confirms them.", {"path": _PATH}, t.t_capa_scan),
        ("floss", "floss_decode", "FLOSS: decoded, stack and tight strings recovered from code by emulating it inside the "
         "container, without running the file. Can take minutes.",
         {"path": _PATH, "kind": _p("str", "all (without static), decoded, stack, tight or static.", default="all"),
          "limit": limit}, t.t_floss_decode),
        ("yara", "yara_scan", "Scan with the pinned own YARA rule set (crypto constants, packer markers, embedded PE, encoded "
         "PowerShell). Hits are hypotheses until code confirms them.", {"path": _PATH}, t.t_yara_scan),
        ("jadx-apk", "jadx_decompile", "Decompile an APK, JAR or DEX with jadx. Without arguments lists class files; search "
         "finds text in all classes; class_file reads one class. The first call can take minutes.",
         {"path": _PATH, "class_file": _p("str", "Class file from the listing, e.g. com/example/Main.java.", default=""),
          "search": _p("str", "Case-insensitive text to find in all classes.", default=""), "limit": limit, "offset": offset},
         t.t_jadx_decompile),
    ]
    added = []
    for op, name, desc, params, handler in specs:
        if runner.has(op):
            gateway._tools[name] = _Tool(name, desc, params, handler)
            added.append(name)
    return added
