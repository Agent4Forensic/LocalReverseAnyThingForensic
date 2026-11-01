"""Named analysis tools backed by the tool containers (ADR-0006, package B).

A file goes through a container once per tool: the fixed batch result lands in <job>/tool-cache/, outside derived/, and the
tools filter that result in plain Python. So model arguments never reach Ghidra, capa, FLOSS, YARA or jadx.
capa and YARA hits are hypotheses until code confirms them.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import struct
import tarfile
import threading
import zipfile
from typing import Any, Optional

from sw_analyst.gateway.base import ToolError
from sw_analyst.gateway.container_runner import ContainerError, ContainerRunner
from sw_analyst.gateway.dev_gateway import _PATH, DevGateway, _Ctx, _Out, _p, _Tool
from sw_analyst.gateway.dev_tools.util import clip

MAX_JADX_TOTAL = 128 * 1024 * 1024
MAX_JADX_FILES = 20000
MAX_TAR_MEMBERS = 100000
HYPOTHESIS = "Hits are hypotheses until code confirms them: name the code location that supports each one."

GHIDRA_TOOLS = {"list_functions", "disassemble", "decompile", "xrefs", "basic_blocks"}
TRIAGE_TOOLS = {"capa_scan", "floss_decode", "yara_scan"}
JADX_TOOLS = {"jadx_decompile"}
ALL_TOOLS = GHIDRA_TOOLS | TRIAGE_TOOLS | JADX_TOOLS
MAX_EMU_ARGS = 8
EMU_ARCHES = {"auto", "x86", "x64", "arm", "arm64"}
EMU_LAYERS = 5               # written regions saved as derived files per call; the rest stays visible by address and hash
EMU_MIN_REGION = 4           # a saved register or a counter is no result worth a derived file
MAX_CACHE_BYTES = 160 * 1024 * 1024   # a cached result is read into memory; jadx results are the largest (128 MiB text)
RUN_SLOTS = threading.BoundedSemaphore(1)   # one container run at a time across every gateway of the process


def _hex_addr(value: Any) -> int:
    try:
        return int(str(value).strip(), 16)
    except ValueError:
        raise ToolError("Address must be hexadecimal, e.g. 0x401000") from None


class ContainerTools:
    def __init__(self, runner: ContainerRunner):
        self.runner = runner
        self._loaded: tuple[str, Any] = ("", None)   # the last parsed result; Ghidra exports can be large
        # A sample that hangs Ghidra must not cost 10 minutes on every call. In memory: a restart may try again.
        self._failed: dict[str, str] = {}
        self._lock = threading.Lock()                      # guards _loaded and _file_locks
        self._file_locks: dict[str, threading.Lock] = {}

    # ---- batch result ---------------------------------------------------------------------------------------
    def _result(self, ctx: _Ctx, op: str, logical: Any, parse=None) -> tuple[Any, str, str]:
        """Returns (parsed result, logical name, version). Runs the container only on the first call per file.

        One lock per result file: worker and dashboard asking for the same file wait for one run, then both read
        the cache. Container runs of all gateways (also those of imports) share one slot, because each can take
        several GB of the 24 GB budget (ADR-0000). Cache reads never wait for a run."""
        data, name = ctx.read_all(logical)
        sha = hashlib.sha256(data).hexdigest()
        version = self.runner.version(op)
        path = ctx.root / "tool-cache" / f"{op}-{version.rsplit(':', 1)[-1]}-{sha}.json"
        key = str(path)
        with self._lock:
            if self._loaded[0] == key:
                return self._loaded[1], name, version
            file_lock = self._file_locks.setdefault(key, threading.Lock())
        with file_lock:
            parsed = self._cached_or_run(op, data, path, key, parse)
        with self._lock:
            self._loaded = (key, parsed)
        return parsed, name, version

    def _cached_or_run(self, op: str, data: bytes, path, key: str, parse) -> Any:
        if path.is_file():
            # A cache file can come from an imported bundle: same size cap as container output, then parse.
            if path.stat().st_size > MAX_CACHE_BYTES:
                raise ToolError(f"Cached result of '{op}' is larger than {MAX_CACHE_BYTES // 2**20} MiB; refused")
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise ToolError(f"Cached result of '{op}' could not be read") from None
        if key in self._failed:
            raise ToolError(self._failed[key])
        try:
            with RUN_SLOTS:
                raw = self.runner.run(op, data)
        except ContainerError as exc:
            if exc.final:
                self._failed[key] = str(exc)
            raise ToolError(str(exc)) from None
        try:
            parsed = parse(raw) if parse else json.loads(raw)
        except (ValueError, UnicodeDecodeError, tarfile.TarError):
            self._failed[key] = f"Tool '{op}' produced output that could not be read"
            raise ToolError(self._failed[key]) from None
        path.parent.mkdir(exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(parsed), encoding="utf-8")
        os.replace(tmp, path)
        return parsed

    # ---- Ghidra ---------------------------------------------------------------------------------------------
    def ghidra_export(self, ctx: _Ctx, path: str) -> tuple[dict, str, str]:
        return self._ghidra(ctx, {"path": path})

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
        cut = len(blocks) > 500 or bool(f.get("blocks_truncated"))
        if cut:
            L.append("[not every block of this function is listed: the control flow shown is incomplete]")
        return _Out("\n".join(L), {"source_ref": {"file": name, "function": f["name"], "address": f["entry"]},
                                   "blocks": blocks[:500]}, truncated=cut, version=version)

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
        last_offset = -1
        try:
            return ContainerTools._read_jadx_tar(raw, files, total, last_offset)
        except tarfile.TarError as exc:   # Python 3.12+ raises ReadError where 3.11 loops: same refusal on every version
            raise ValueError(f"tar output unreadable: {exc}") from None

    @staticmethod
    def _read_jadx_tar(raw: bytes, files: dict, total: int, last_offset: int) -> dict:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            for count, member in enumerate(tar):
                # A negative size moves tarfile backwards and it loops forever (Python 3.11.9). The tar comes from the container.
                if member.size < 0 or member.offset <= last_offset:
                    raise ValueError("tar members do not advance")
                last_offset = member.offset
                if count >= MAX_TAR_MEMBERS:
                    return {"files": files, "truncated": True}
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

    # ---- Unicorn (ADR-0005 stage 2) ---------------------------------------------------------------------------
    @staticmethod
    def _emu_args(raw: str) -> list:
        """Only numbers and two fixed words pass, so no model text reaches the container."""
        out: list = []
        for part in filter(None, (p.strip() for p in raw.split(","))):
            if part in ("input", "input_len"):
                out.append(part)
                continue
            try:
                value = int(part, 0)
            except ValueError:
                raise ToolError("call_args takes numbers, input and input_len, separated by commas") from None
            if not 0 <= value < 2 ** 64:
                raise ToolError("call_args numbers must fit in 64 bits")
            out.append(value)
        if len(out) > MAX_EMU_ARGS:
            raise ToolError(f"call_args takes at most {MAX_EMU_ARGS} values")
        return out

    def t_emulate_function(self, ctx: _Ctx, a: dict) -> _Out:
        data, name = ctx.read_all(a["path"])
        arch = a["arch"].strip().lower()
        if arch not in EMU_ARCHES:
            raise ToolError("Argument 'arch' must be one of: auto, x86, x64, arm, arm64")
        start = _hex_addr(a["start"])
        end = _hex_addr(a["end"]) if a["end"].strip() else None
        call_args = self._emu_args(a["call_args"])
        header = {"start": start, "end": end, "arch": arch, "args": call_args, "input_offset": a["input_offset"],
                  "input_length": a["input_length"], "max_instructions": a["max_instructions"]}
        head = json.dumps(header, sort_keys=True).encode("ascii")
        frame = struct.pack("<I", len(head)) + head + data
        version = self.runner.version("emulate")
        digest = hashlib.sha256(frame).hexdigest()
        path = ctx.root / "tool-cache" / f"emulate-{version.rsplit(':', 1)[-1]}-{digest}.json"
        with self._lock:
            file_lock = self._file_locks.setdefault(str(path), threading.Lock())
        with file_lock:
            res = self._cached_or_run("emulate", frame, path, str(path), None)
        return self._emu_out(ctx, res, name, version, header)

    def _emu_out(self, ctx: _Ctx, res: Any, name: str, version: str, header: dict) -> _Out:
        ref = {"source_ref": {"file": name, "address": f"0x{header['start']:x}"}, "emulated": True, "hypothesis": True}
        if not isinstance(res, dict):
            raise ToolError("Emulator result has an unexpected shape")
        if res.get("error"):
            msg = f"Emulation refused: {clip(str(res['error']), 400)}"
            return _Out(msg, ref, ok=False, error=msg, version=version)
        regions = res.get("regions")
        registers = res.get("registers")
        if not isinstance(regions, list) or not isinstance(registers, dict):
            raise ToolError("Emulator result has an unexpected shape")
        fault = res.get("fault") if isinstance(res.get("fault"), dict) else None
        L = [f"Emulation of {name} from 0x{header['start']:x} ({res.get('format')}, {res.get('arch')}, load base "
             f"0x{int(res.get('load_base') or 0):x}). This is a simulated CPU without operating system, not a run of the "
             "program. Treat every value as a hypothesis until code at a named address supports it.",
             f"Stopped: {res.get('stop_reason')} at pc 0x{int(res.get('pc') or 0):x} after {res.get('elapsed_s')} s "
             f"(budget {res.get('budget')} instructions)"]
        if res.get("api"):
            L.append(f"Call into an import, not emulated: {clip(str(res['api']), 160)}")
        if fault:
            L.append(f"Fault: {clip(str(res.get('engine_error')), 120)}; unmapped or protected access at "
                     f"0x{int(fault.get('address') or 0):x}, size {fault.get('size')}")
        L.append(f"Return register: 0x{int(res.get('return_value') or 0):x}")
        L.append("Registers: " + " ".join(f"{k}=0x{int(v):x}" for k, v in registers.items() if isinstance(v, int)))
        if isinstance(res.get("input"), dict) and res["input"].get("length"):
            i = res["input"]
            L.append(f"Input buffer: {i['length']} bytes from file offset {i['offset']}, mapped at 0x{int(i['address']):x}, "
                     f"SHA-256 {i['sha256']}")
        L.append(f"Memory written: {len(regions)} region(s)")
        derived: list[str] = []
        for r in sorted(regions, key=lambda x: x["kind"] == "stack"):     # results before scratch space
            raw = base64.b64decode(r["data_b64"], validate=True)
            if hashlib.sha256(raw).hexdigest() != r["sha256"]:
                raise ToolError("Emulator result failed its hash check")
            line = f"- {r['kind']} 0x{int(r['address']):x}, {len(raw)} bytes, SHA-256 {r['sha256']}"
            if len(raw) >= EMU_MIN_REGION and len(derived) < EMU_LAYERS:
                logical, _sha, _reused = ctx.write_layer(raw)
                derived.append(logical)
                line += f", saved as {logical}"
            L.append(line)
            shown = raw[:160].decode("latin-1").translate(_EMU_PRINTABLE)
            L.append(f"  bytes: {shown}{' ...' if len(raw) > 160 else ''}")
        if res.get("regions_truncated"):
            L.append("[not every written byte is listed: output limit reached]")
        ref.update({"stop_reason": res.get("stop_reason"), "derived_files": derived})
        if derived:
            ref["derived"] = derived[0]     # webui/lineage.py follows one producer per evidence
        return _Out("\n".join(L), ref, truncated=bool(res.get("regions_truncated")), version=version)


_EMU_PRINTABLE = {c: (c if 32 <= c < 127 else ord(".")) for c in range(256)}


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
        ("emulate", "emulate_function", "Run ONE routine in a simulated CPU without operating system (decryptor, API hash, "
         "unpack loop), never the program itself. Calls into imports stop the run. Returns the stop reason, registers and "
         "written memory; written regions are saved as derived files. Results are hypotheses until code confirms them.",
         {"start": _p("str", "Hex address of the routine, from list_functions, e.g. 0x401000. For raw code: 0x10000 plus the "
                             "offset. Odd ARM addresses mean Thumb.", required=True),
          "end": _p("str", "Hex address to stop at. Empty: run until the routine returns.", default=""),
          "path": _PATH,
          "call_args": _p("str", "Call arguments, comma separated: numbers, input (address of the input buffer), input_len.",
                          default=""),
          "input_offset": _p("int", "File offset of the input buffer, e.g. of an encrypted blob.", default=0, min=0),
          "input_length": _p("int", "Length of the input buffer in bytes, 0 for none.", default=0, min=0, max=16 * 1024 * 1024),
          "arch": _p("str", "auto reads PE or ELF headers; x86, x64, arm or arm64 treat the file as raw code.", default="auto"),
          "max_instructions": _p("int", "Instruction budget.", default=1_000_000, min=1, max=20_000_000)},
         t.t_emulate_function),
    ]
    added = []
    for op, name, desc, params, handler in specs:
        if runner.has(op):
            gateway._tools[name] = _Tool(name, desc, params, handler)
            added.append(name)
    if added:
        gateway.container_tools = t     # read access for the dashboard file view (DevGateway.ghidra_export)
    return added
