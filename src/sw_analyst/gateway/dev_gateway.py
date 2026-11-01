"""DevGateway: host-side, pure-Python static analysis tools behind the ToolGateway contract.

Safety rules (PROJEKTPLAN 2.3-2.5, docs/architecture/chain.md):
- fixed allowlist of read-only tools with validated arguments, no generic command execution
- the sample is DATA: it is only ever read as bytes, never started, imported or evaluated
- path jail: tool arguments are logical names ('sample' or 'derived/<name>'), never host paths
- limits on sample size, output size, regex complexity, run time and decompressed size

Workspace layout::

    <data_dir>/jobs/<job_id>/sample      the sample (a single file)
    <data_dir>/jobs/<job_id>/derived/    artifacts written by tools (decoded layers), never executable
"""
from __future__ import annotations

import hashlib
import heapq
import io
import json
import math
import os
import re
import time
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from sw_analyst.common.models import ToolResult, ToolSpec
from sw_analyst.gateway.base import ToolError
from sw_analyst.gateway.dev_tools import decoders
from sw_analyst.gateway.dev_tools.axml import AxmlError, parse_axml
from sw_analyst.gateway.dev_tools.decoders import DecodeError
from sw_analyst.gateway.dev_tools.filetype import identify, sniff_magic
from sw_analyst.gateway.dev_tools.pe import format_pe, parse_pe, parse_resources
from sw_analyst.gateway.dev_tools.regex_guard import check_pattern
from sw_analyst.gateway.dev_tools.scripts import (
    detect_language, find_indicators, indicator_description, MAX_INDICATORS)
from sw_analyst.gateway.dev_tools.util import (
    alnum_space_ratio, clip, decode_text_bytes, entropy_from_counts, hex_bytes, hexdump,
    looks_utf16le, printable_ratio, split_lines)

TOOL_VERSION = "dev-2"
MAX_KEYS_PER_JOB = 5                         # ADR-0006: keys come from evidence, trying key lists is not allowed
MAX_SAMPLE_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_CHARS = 20000
MAX_READ_LINES = 400
MAX_HEXDUMP = 512
MAX_DECODE_INPUT = decoders.MAX_OUT          # 8 MiB
MAX_ZIP_ENTRIES = 500
MAX_LAYERS = 99
LINE_MATCH_LIMIT = 2000                      # regex only sees this many chars of a line
LINE_DISPLAY_LIMIT = 2000
TIME_BUDGET_S = 5.0
HIGH_ENTROPY = 7.2
ENTROPY_MAX_ROWS = 256
PACKED_ENTROPY = HIGH_ENTROPY
PACKED_MIN_RAW = 4096
PACKER_SECTION = re.compile(r"^\.?(?:upx\d*|aspack|adata|mpress\d*|nsp\d|themida|vmp\d*|petite)$", re.I)
MAX_JSON_FIELD_INPUT = 1024 * 1024
MAX_JSON_FIELDS = 50
_BLOBS = {"base64": re.compile(rb"[A-Za-z0-9+/_\-]{8,}={0,2}"),
          "base32": re.compile(rb"[A-Z2-7]{8,}={0,6}"),
          "hex": re.compile(rb"(?:[0-9A-Fa-f]{2}){4,}")}
_LABEL = re.compile(rb"\s*[A-Za-z][A-Za-z0-9_.-]{1,15}[:=](?![/\\])\s*")

_JOB_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_DERIVED_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,99}")
_RESERVED_RE = re.compile(r"(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?", re.IGNORECASE)
_LAYER_RE = re.compile(r"layer(\d{2,3})\.bin")
_META_TYPES = frozenset({
    "pe", "elf", "apk", "jar", "zip", "dex", "pdf", "macho", "gzip", "7z", "rar", "ole2",
    "powershell", "vbscript", "javascript", "python", "bash", "batch", "html", "text", "unknown"})
_BINARY_HINT = ("File '{p}' appears to be binary (NUL bytes or many non-text bytes). "
                "Use hexdump(path, offset, length) or strings_extract instead.")
_KEYWORDS = re.compile(
    rb"(?i)(\bthe\b|\band\b|http|function|flag\{|eval|powershell|\bvar |import |echo |password)")


# ---------------------------------------------------------------------------- path jail
def validate_logical_path(p: Any) -> str:
    """Syntactic jail check of a logical path. Returns the normalized logical name."""
    if not isinstance(p, str):
        raise ToolError("Path must be a string")
    if "\x00" in p:
        raise ToolError("Path contains a NUL byte")
    if len(p) > 128:
        raise ToolError("Path is too long (max 128 characters)")
    if p.startswith("\\\\") or p.startswith("//"):
        raise ToolError("UNC paths are not allowed; use 'sample' or 'derived/<name>'")
    if ":" in p:
        raise ToolError("Drive letters and ':' are not allowed in paths; use 'sample' or 'derived/<name>'")
    if p.startswith("/") or p.startswith("\\"):
        raise ToolError("Absolute paths are not allowed; use 'sample' or 'derived/<name>'")
    if "\\" in p:
        raise ToolError("Backslashes are not allowed in paths; use 'sample' or 'derived/<name>'")
    parts = p.split("/")
    if ".." in parts or "." in parts:
        raise ToolError("Path traversal ('..' or '.') is not allowed")
    if p == "sample":
        return p
    if len(parts) == 2 and parts[0] == "derived":
        name = parts[1]
        if _DERIVED_NAME_RE.fullmatch(name) and not name.endswith(".") and not _RESERVED_RE.fullmatch(name):
            return p
        raise ToolError("Invalid derived file name; allowed: letters, digits, '_', '-', '.' (max 100)")
    raise ToolError("Invalid path; only 'sample' or 'derived/<name>' are allowed")


# ---------------------------------------------------------------------------- tool framework
@dataclass
class _Out:
    text: str
    meta: dict = field(default_factory=dict)
    truncated: bool = False
    ok: bool = True
    error: str = ""
    version: str = ""       # container tools report their own version and image id as evidence


@dataclass
class _Tool:
    name: str
    description: str
    params: dict[str, dict]
    handler: Callable[["_Ctx", dict], _Out]


def _p(type_: str, description: str, *, required: bool = False, default: Any = None,
       min: Optional[int] = None, max: Optional[int] = None) -> dict:
    d: dict[str, Any] = {"type": type_, "required": required, "description": description, "default": default}
    if min is not None:
        d["min"] = min
    if max is not None:
        d["max"] = max
    return d


_PATH = _p("str", "Logical file name: 'sample' (default) or 'derived/<name>' (e.g. a decoded layer).",
           default="sample")


class _Ctx:
    """Per-call context: jailed file access, time budget and notes."""

    def __init__(self, job_id: str, root: Path):
        self.job_id = job_id
        self.root = root                       # resolved job root
        self.deadline = time.monotonic() + TIME_BUDGET_S
        self.notes: list[str] = []

    # -- jail -------------------------------------------------------------
    def resolve(self, logical: Any) -> tuple[Path, str]:
        name = validate_logical_path(logical)
        phys = self.root / name
        try:
            real = phys.resolve(strict=True)
        except FileNotFoundError:
            raise ToolError(f"File not found: {name}") from None
        except (OSError, RuntimeError, ValueError):
            raise ToolError(f"Cannot access: {name}") from None
        try:
            real.relative_to(self.root)
        except ValueError:
            raise ToolError(f"Jail violation: '{name}' resolves outside the job workspace "
                            "(symlink or junction); access denied") from None
        if not real.is_file():
            raise ToolError(f"Not a regular file: {name}")
        return real, name

    def size(self, logical: Any) -> int:
        real, name = self.resolve(logical)
        size = real.stat().st_size
        if size > MAX_SAMPLE_BYTES:
            raise ToolError(f"File '{name}' exceeds the {MAX_SAMPLE_BYTES // (1024 * 1024)} MiB limit")
        return size

    def read_all(self, logical: Any) -> tuple[bytes, str]:
        real, name = self.resolve(logical)
        size = real.stat().st_size
        if size > MAX_SAMPLE_BYTES:
            raise ToolError(f"File '{name}' exceeds the {MAX_SAMPLE_BYTES // (1024 * 1024)} MiB limit")
        try:
            return real.read_bytes(), name
        except OSError:
            raise ToolError(f"I/O error while reading {name}") from None

    def read_range(self, logical: Any, offset: int, length: int) -> tuple[bytes, int, str]:
        real, name = self.resolve(logical)
        size = real.stat().st_size
        if size > MAX_SAMPLE_BYTES:
            raise ToolError(f"File '{name}' exceeds the {MAX_SAMPLE_BYTES // (1024 * 1024)} MiB limit")
        try:
            with open(real, "rb") as f:
                f.seek(max(0, offset))
                return f.read(max(0, length)), size, name
        except OSError:
            raise ToolError(f"I/O error while reading {name}") from None

    def text(self, logical: Any) -> tuple[str, str, str]:
        data, name = self.read_all(logical)
        dec = decode_text_bytes(data)
        if dec is None:
            raise ToolError(_BINARY_HINT.format(p=name))
        return dec[0], dec[1], name

    def check_time(self) -> bool:
        return time.monotonic() <= self.deadline

    # -- derived artifacts --------------------------------------------------
    def write_layer(self, data: bytes) -> tuple[str, str, bool]:
        """Write derived/layerNN.bin (non-executable). Identical content reuses the existing file."""
        derived = self.root / "derived"
        derived.mkdir(parents=True, exist_ok=True)
        try:
            derived.resolve(strict=True).relative_to(self.root)
        except ValueError:
            raise ToolError("Jail violation: derived directory resolves outside the job workspace") from None
        sha = hashlib.sha256(data).hexdigest()
        nums = []
        for entry in sorted(os.listdir(derived)):
            m = _LAYER_RE.fullmatch(entry)
            if not m:
                continue
            nums.append(int(m.group(1)))
            p = derived / entry
            try:
                if (p.is_file() and not p.is_symlink() and p.stat().st_size == len(data)
                        and hashlib.sha256(p.read_bytes()).hexdigest() == sha):
                    return f"derived/{entry}", sha, True
            except OSError:
                continue
        n = max(nums, default=0) + 1
        if n > MAX_LAYERS:
            raise ToolError(f"Too many derived layers (max {MAX_LAYERS})")
        name = f"layer{n:02d}.bin"
        try:
            with open(derived / name, "xb") as f:
                f.write(data)
            os.chmod(derived / name, 0o644)      # explicitly not executable
        except OSError:
            raise ToolError("Could not write derived artifact") from None
        return f"derived/{name}", sha, False


def _lines_fmt(lines: list[str], first_no: int, clip_at: int = LINE_DISPLAY_LIMIT) -> str:
    return "\n".join(f"{first_no + i:>6} | {clip(ln, clip_at)}" for i, ln in enumerate(lines))


def _clean(s: str) -> str:
    return "".join(c if (c in "\n\t" or 32 <= ord(c) < 0x2FFF or ord(c) > 0xA0) else "." for c in s)


# ---------------------------------------------------------------------------- the gateway
class DevGateway:
    def __init__(self, data_dir: str | Path):
        self._data_dir = Path(data_dir)
        self._jobs = self._data_dir / "jobs"
        self._hash_cache: dict[tuple, str] = {}
        # shortcut: in memory, a restart resets the count; persist it when jobs survive restarts
        self._keys_used: dict[str, set[bytes]] = {}
        self._tools: dict[str, _Tool] = {}
        self._register_tools()

    # ------------------------------------------------------------------ protocol
    def list_tools(self) -> list[ToolSpec]:
        return [ToolSpec(name=t.name, description=t.description,
                         params={k: dict(v) for k, v in t.params.items()}, read_only=True)
                for t in self._tools.values()]

    def sample_path(self, job_id: str) -> str:
        self._check_job_id(job_id)
        return str(self._jobs / job_id / "sample")

    def call(self, job_id: str, name: str, args: dict) -> ToolResult:
        try:
            return self._call(job_id, name, args)
        except ToolError as exc:
            return self._error(str(exc))
        except MemoryError:
            return self._error(f"Tool '{name}' ran out of memory")
        except Exception as exc:  # noqa: BLE001 - a tool must never raise out of call()
            return self._error(f"Internal error in tool '{name}' ({type(exc).__name__})")

    def store_sample(self, job_id: str, data: bytes) -> dict:
        """Write the sample bytes to <data_dir>/jobs/<job_id>/sample (read-only where possible).

        Creates the job workspace. Raises ToolError for an invalid job id, oversized data or an
        existing sample. Returns {name, size, md5, sha1, sha256}.
        """
        self._check_job_id(job_id)
        if not isinstance(data, (bytes, bytearray)):
            raise ToolError("Sample data must be bytes")
        if len(data) > MAX_SAMPLE_BYTES:
            raise ToolError(f"Sample exceeds the {MAX_SAMPLE_BYTES // (1024 * 1024)} MiB limit")
        self._jobs.mkdir(parents=True, exist_ok=True)
        jobs_real = self._jobs.resolve()
        root = self._jobs / job_id
        try:
            root.resolve().relative_to(jobs_real)
        except ValueError:
            raise ToolError("Jail violation: job directory resolves outside the data directory") from None
        root.mkdir(parents=True, exist_ok=True)
        (root / "derived").mkdir(exist_ok=True)
        target = root / "sample"
        try:
            with open(target, "xb") as f:      # never overwrite or follow an existing entry
                f.write(bytes(data))
        except FileExistsError:
            raise ToolError(f"Job '{job_id}' already has a sample") from None
        except OSError:
            raise ToolError("Could not write the sample") from None
        try:
            os.chmod(target, 0o444)
        except OSError:
            pass
        md5, sha1, sha256 = self._digest_all(bytes(data))
        return {"name": "sample", "size": len(data), "md5": md5, "sha1": sha1, "sha256": sha256}

    # ------------------------------------------------------------------ extras for the code viewer
    def list_files(self, job_id: str) -> list[dict]:
        ctx = self._ctx(job_id)
        out = []
        candidates = ["sample"]
        derived = ctx.root / "derived"
        if derived.is_dir():
            candidates += [f"derived/{n}" for n in sorted(os.listdir(derived))]
        for logical in candidates:
            try:
                real, name = ctx.resolve(logical)
            except ToolError:
                continue
            st = real.stat()
            key = (str(real), st.st_size, st.st_mtime_ns)
            sha = self._hash_cache.get(key)
            if sha is None:
                h = hashlib.sha256()
                with open(real, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                sha = self._hash_cache[key] = h.hexdigest()
            out.append({"path": name, "kind": "sample" if name == "sample" else "derived",
                        "size": st.st_size, "sha256": sha})
        return out

    def read_file_lines(self, job_id: str, path: str, start: int = 1, end: Optional[int] = None) -> dict:
        """Lines [start, end] (1-based, max 400) of a text file. Raises ToolError on problems."""
        ctx = self._ctx(job_id)
        text, enc, name = ctx.text(path)
        lines = split_lines(text)
        start = max(1, int(start))
        end = start + MAX_READ_LINES - 1 if end is None else int(end)
        end = min(max(end, start), start + MAX_READ_LINES - 1, len(lines))
        if start > len(lines):
            raise ToolError(f"File has {len(lines)} lines; start {start} is beyond the end")
        return {"path": name, "start": start, "end": end, "total_lines": len(lines),
                "encoding": enc, "lines": lines[start - 1:end]}

    def read_bytes(self, job_id: str, path: str, offset: int, length: int) -> dict:
        """Raw bytes for the hex view of the dashboard (jailed like every tool). Not offered to the model."""
        ctx = self._ctx(job_id)
        offset, length = max(0, int(offset)), max(0, min(int(length), 64 * 1024))
        data, size, name = ctx.read_range(path, offset, length)
        return {"path": name, "size": size, "offset": offset, "data": data}

    def ghidra_export(self, job_id: str, path: str = "sample") -> tuple[dict, str, str]:
        """Parsed Ghidra batch export (functions, disassembly, decompiler output) for the dashboard file view.

        Uses the same cache as the model tools, so a function the analysis already read costs nothing. Raises
        ToolError when the Ghidra image is not loaded (no Docker or image missing)."""
        tools = getattr(self, "container_tools", None)
        if tools is None or "list_functions" not in self._tools:
            raise ToolError("Ghidra tools are not loaded (Docker not running or image missing)")
        return tools.ghidra_export(self._ctx(job_id), path)

    # ------------------------------------------------------------------ internals
    @staticmethod
    def _check_job_id(job_id: Any) -> None:
        if not isinstance(job_id, str) or not _JOB_ID_RE.fullmatch(job_id):
            raise ToolError("Invalid job id (allowed: letters, digits, '_' and '-', 1-64 characters)")

    def _ctx(self, job_id: str) -> _Ctx:
        self._check_job_id(job_id)
        jobs_real = self._jobs.resolve()
        root = (self._jobs / job_id).resolve()
        try:
            root.relative_to(jobs_real)
        except ValueError:
            raise ToolError("Jail violation: job directory resolves outside the data directory") from None
        if not root.is_dir():
            raise ToolError(f"Unknown job '{job_id}'")
        return _Ctx(job_id, root)

    @staticmethod
    def _error(msg: str) -> ToolResult:
        return ToolResult(ok=False, text=f"Error: {msg}", tool_version=TOOL_VERSION, error=msg)

    def _call(self, job_id: str, name: str, args: Any) -> ToolResult:
        if not isinstance(name, str) or name not in self._tools:
            known = ", ".join(self._tools)
            raise ToolError(f"Unknown tool '{clip(str(name), 60)}'. Available tools: {known}")
        tool = self._tools[name]
        ctx = self._ctx(job_id)
        clean = self._validate_args(tool, args, ctx)
        out = tool.handler(ctx, clean)
        text, trunc = out.text, out.truncated
        if ctx.notes:
            text += "\n" + "\n".join(f"[note] {n}" for n in ctx.notes)
        if len(text) > MAX_OUTPUT_CHARS:
            note = f"\n[output truncated at {MAX_OUTPUT_CHARS} characters; narrow the request]"
            text = text[:MAX_OUTPUT_CHARS - len(note)] + note
            trunc = True
        # Container JSON can carry lone surrogates ("\\ud800"), which would break hashing and storage of the evidence.
        text = text.encode("utf-8", "replace").decode("utf-8")
        version = out.version or TOOL_VERSION
        if not out.ok:
            error = (out.error or "tool failed").encode("utf-8", "replace").decode("utf-8")
            return ToolResult(ok=False, text=text, tool_version=version, meta=out.meta, error=error, truncated=trunc)
        return ToolResult(ok=True, text=text, tool_version=version, meta=out.meta, truncated=trunc)

    @staticmethod
    def _validate_args(tool: _Tool, args: Any, ctx: _Ctx) -> dict:
        if args is None:
            args = {}
        if not isinstance(args, dict):
            raise ToolError("Arguments must be an object (dict)")
        unknown = [k for k in args if k not in tool.params]
        if unknown:
            raise ToolError(f"Unknown argument(s) for tool '{tool.name}': "
                            f"{', '.join(repr(clip(str(k), 40)) for k in sorted(map(str, unknown)))}. "
                            f"Allowed: {', '.join(tool.params) or '(none)'}")
        out: dict[str, Any] = {}
        for pname, spec in tool.params.items():
            val = args.get(pname)
            if val is None:
                if spec["required"]:
                    raise ToolError(f"Missing required argument '{pname}' for tool '{tool.name}'")
                out[pname] = spec.get("default")
                continue
            typ = spec["type"]
            if typ == "int":
                if isinstance(val, bool):
                    raise ToolError(f"Argument '{pname}' must be an integer")
                if isinstance(val, str) and re.fullmatch(r"-?\d{1,18}", val.strip()):
                    val = int(val.strip())
                if not isinstance(val, int):
                    raise ToolError(f"Argument '{pname}' must be an integer")
                lo, hi = spec.get("min"), spec.get("max")
                clamped = val
                if lo is not None:
                    clamped = max(lo, clamped)
                if hi is not None:
                    clamped = min(hi, clamped)
                if clamped != val:
                    ctx.notes.append(f"argument '{pname}' = {val} was clamped to {clamped} "
                                     f"(allowed {lo}..{hi})")
                val = clamped
            elif typ == "bool":
                if isinstance(val, str) and val.lower() in ("true", "false"):
                    val = val.lower() == "true"
                if not isinstance(val, bool):
                    raise ToolError(f"Argument '{pname}' must be a boolean")
            else:
                if not isinstance(val, str):
                    raise ToolError(f"Argument '{pname}' must be a string")
                if "\x00" in val:
                    raise ToolError(f"Argument '{pname}' contains a NUL byte")
                if len(val) > 1024:
                    raise ToolError(f"Argument '{pname}' is too long (max 1024 characters)")
            out[pname] = val
        return out

    def _register_tools(self) -> None:
        def reg(name, description, params, handler):
            self._tools[name] = _Tool(name, description, params, handler)

        reg("sample_info", "Basic facts about a file: logical name, size, MD5/SHA1/SHA256 and the first 16 bytes.",
            {"path": _PATH}, self._t_sample_info)
        reg("hash_file", "MD5, SHA1 and SHA256 of the sample or a derived file.",
            {"path": _PATH}, self._t_hash_file)
        reg("identify_type",
            "Identify the file type from magic bytes (PE/MZ, ELF, ZIP/APK/JAR, DEX, PDF, Mach-O, GZIP, 7z, RAR, OLE2) "
            "or script heuristics (powershell, vbscript, javascript, python, bash, batch, html, text, unknown), "
            "with the evidence used.",
            {"path": _PATH}, self._t_identify_type)
        reg("entropy_map",
            "Shannon entropy per block (bits/byte, 0-8) with a table and a list of suspicious regions > 7.2 "
            "(packed/encrypted/compressed data).",
            {"path": _PATH,
             "block_size": _p("int", "Block size in bytes.", default=4096, min=64, max=1048576)},
            self._t_entropy_map)
        reg("strings_extract",
            "Extract printable strings with byte offsets (ASCII and/or UTF-16LE).",
            {"path": _PATH,
             "min_len": _p("int", "Minimum string length.", default=6, min=3, max=200),
             "encoding": _p("str", "ascii, utf16le or both.", default="both"),
             "max_results": _p("int", "Maximum number of strings returned.", default=200, min=1, max=2000),
             "offset": _p("int", "Start scanning at this byte offset (for paging).", default=0, min=0)},
            self._t_strings_extract)
        reg("hexdump", "Hex dump of a byte range (max 512 bytes per call) with offsets and ASCII column.",
            {"path": _PATH,
             "offset": _p("int", "Start offset in bytes.", default=0, min=0),
             "length": _p("int", "Number of bytes (max 512).", default=256, min=1, max=MAX_HEXDUMP)},
            self._t_hexdump)
        reg("read_lines", "Read numbered lines of a text file (max 400 lines per call). Binary files are refused.",
            {"path": _PATH,
             "start": _p("int", "First line (1-based).", default=1, min=1),
             "end": _p("int", "Last line (inclusive); default start+99, max start+399.", default=0, min=0)},
            self._t_read_lines)
        reg("grep",
            "Regex search over the lines of a text file; returns matching line numbers with optional context. "
            "Pattern max 200 chars; nested quantifiers such as (a+)+ are rejected.",
            {"pattern": _p("str", "Python regular expression.", required=True),
             "path": _PATH,
             "max_results": _p("int", "Maximum number of matching lines.", default=50, min=1, max=500),
             "context": _p("int", "Context lines before/after each match.", default=0, min=0, max=5),
             "ignore_case": _p("bool", "Case-insensitive matching.", default=False)},
            self._t_grep)
        reg("script_detect",
            "Detect the script language and list obfuscation indicators with line numbers (base64 blobs, "
            "-EncodedCommand, FromBase64String, eval/atob/fromCharCode, chr() chains, XOR loops, long "
            "concatenations, download/exec APIs).",
            {"path": _PATH}, self._t_script_detect)
        reg("decode_layer",
            "Decode data (never executes it) and save the result as derived/layerNN.bin. Methods: base64, base32, "
            "base85, hex, url, rot13, charcode, xor_single_byte, xor_key, rc4, gzip, zlib, auto (tries plausible "
            "methods and lists candidates with scores). Returns a preview, the SHA-256 and meta.derived.",
            {"path": _PATH,
             "method": _p("str", "base64|base32|base85|hex|url|rot13|charcode|xor_single_byte|xor_key|rc4|gzip|zlib|auto.",
                          required=True),
             "offset": _p("int", "Start offset of the input slice.", default=0, min=0),
             "length": _p("int", "Length of the input slice; 0 = until end (max 8 MiB).", default=0, min=0),
             "key": _p("int", "xor_single_byte only: key 0-255, -1 = pick the best automatically.",
                       default=-1, min=-1, max=255),
             "key_hex": _p("str", "xor_key and rc4 only: key as hex digits, max 64 bytes. It must come from evidence you "
                                  f"already hold; at most {MAX_KEYS_PER_JOB} different keys per job, do not try key lists.",
                           default="")},
            self._t_decode_layer)
        reg("extract_range",
            "Save a byte range (overlay, resource, embedded file) as derived/layerNN.bin so the platform can triage it. "
            "Nothing is executed. Returns the SHA-256, the magic and a preview.",
            {"offset": _p("int", "Start offset in bytes.", required=True, min=0),
             "length": _p("int", "Number of bytes (max 8 MiB).", required=True, min=1, max=MAX_DECODE_INPUT),
             "path": _PATH},
            self._t_extract_range)
        reg("zip_extract",
            "Save one member of a ZIP/APK/JAR as derived/layerNN.bin (max 8 MiB, the gateway picks the name). "
            "Nothing is executed. Returns the SHA-256, the magic and a preview.",
            {"member": _p("str", "Exact member name as shown by zip_list.", required=True), "path": _PATH},
            self._t_zip_extract)
        reg("pe_resources",
            "List the PE resource tree: type/name/language, file offset, size, entropy and first bytes. "
            "Use extract_range with the offset and size to look inside a resource.",
            {"path": _PATH}, self._t_pe_resources)
        reg("apk_manifest",
            "Decode the binary AndroidManifest.xml of an APK (or a derived binary XML file) to text and list package, "
            "permissions and components with their exported flag.",
            {"path": _PATH}, self._t_apk_manifest)
        reg("pe_headers",
            "Parse PE headers with an own parser: machine, timestamp, subsystem, entry point, image base, "
            "sections (size, flags, entropy), overlay, imports (max 300 functions) and exports.",
            {"path": _PATH}, self._t_pe_headers)
        reg("zip_list", "List ZIP/APK/JAR entries with sizes and CRC (max 500 entries). Nothing is extracted.",
            {"path": _PATH}, self._t_zip_list)
        reg("zip_read_text",
            "Read a text member of a ZIP/APK/JAR archive in memory (binary members are refused).",
            {"member": _p("str", "Exact member name as shown by zip_list.", required=True),
             "path": _PATH,
             "max_chars": _p("int", "Maximum characters returned.", default=4000, min=1, max=MAX_OUTPUT_CHARS)},
            self._t_zip_read_text)

    # ------------------------------------------------------------------ tools: basics
    @staticmethod
    def _digest_all(data: bytes) -> tuple[str, str, str]:
        return (hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest(),
                hashlib.sha256(data).hexdigest())

    def _t_sample_info(self, ctx: _Ctx, a: dict) -> _Out:
        data, name = ctx.read_all(a["path"])
        md5, sha1, sha256 = self._digest_all(data)
        head = data[:16]
        text = (f"Name: {name}\n"
                f"Size: {len(data)} bytes (0x{len(data):x})\n"
                f"MD5: {md5}\nSHA1: {sha1}\nSHA256: {sha256}\n"
                f"First {len(head)} bytes (hex): {hex_bytes(head, 16) if head else '(empty file)'}")
        return _Out(text, {"source_ref": {"file": name, "offset": 0, "length": len(head)},
                           "size": len(data), "md5": md5, "sha1": sha1, "sha256": sha256})

    def _t_hash_file(self, ctx: _Ctx, a: dict) -> _Out:
        data, name = ctx.read_all(a["path"])
        md5, sha1, sha256 = self._digest_all(data)
        text = f"File: {name}\nSize: {len(data)} bytes\nMD5: {md5}\nSHA1: {sha1}\nSHA256: {sha256}"
        return _Out(text, {"source_ref": {"file": name, "offset": 0, "length": len(data)},
                           "md5": md5, "sha1": sha1, "sha256": sha256})

    def _t_identify_type(self, ctx: _Ctx, a: dict) -> _Out:
        data, name = ctx.read_all(a["path"])
        res = identify(data)
        lines = [f"File: {name} ({len(data)} bytes)",
                 f"Type: {res['type']} (confidence: {res['confidence']})", "Evidence:"]
        lines += [f"  - {r}" for r in res["reasons"]]
        if res["details"]:
            lines.append("Details:")
            lines += [f"  - {d}" for d in res["details"]]
        # meta['type'] is limited to the orchestrator's vocabulary (e.g. java_class -> unknown)
        mtype = res["type"] if res["type"] in _META_TYPES else "unknown"
        return _Out("\n".join(lines),
                    {"type": mtype, "confidence": res["confidence"],
                     "source_ref": {"file": name, "offset": 0, "length": min(len(data), 64)}})

    # ------------------------------------------------------------------ tools: byte views
    def _t_entropy_map(self, ctx: _Ctx, a: dict) -> _Out:
        data, name = ctx.read_all(a["path"])
        bs = a["block_size"]
        size = len(data)
        sref = {"file": name, "offset": 0, "length": size}
        if size == 0:
            return _Out(f"File {name} is empty; no entropy to compute.", {"source_ref": sref})
        nblocks = -(-size // bs)
        group = -(-nblocks // ENTROPY_MAX_ROWS)
        rows: list[tuple[int, int, float]] = []
        regions: list[list] = []        # [start, end, weighted_sum]
        total = Counter()
        gcount, glen, gstart = Counter(), 0, 0
        for bi in range(nblocks):
            off = bi * bs
            blk = data[off:off + bs]
            c = Counter(blk)
            e = entropy_from_counts(c.values(), len(blk))
            total.update(c)
            if e > HIGH_ENTROPY:
                if regions and regions[-1][1] == off:
                    regions[-1][1] = off + len(blk)
                    regions[-1][2] += e * len(blk)
                else:
                    regions.append([off, off + len(blk), e * len(blk)])
            if group == 1:
                rows.append((off, len(blk), e))
            else:
                if glen == 0:
                    gstart = off
                gcount.update(c)
                glen += len(blk)
                if (bi + 1) % group == 0 or bi == nblocks - 1:
                    rows.append((gstart, glen, entropy_from_counts(gcount.values(), glen)))
                    gcount, glen = Counter(), 0
        overall = entropy_from_counts(total.values(), size)
        verdict = ("very high (compressed, encrypted or packed)" if overall > HIGH_ENTROPY
                   else "high-ish (mixed or compressed content)" if overall > 6.0
                   else "medium (typical code/data)" if overall > 3.0
                   else "low (text, padding or sparse data)")
        L = [f"Entropy map of {name}: {size} bytes, block size {bs}, {nblocks} block(s)",
             f"Overall entropy: {overall:.3f} bits/byte - {verdict}"]
        if group > 1:
            L.append(f"Table rows group {group} blocks each ({bs * group} bytes per row) to stay within "
                     f"{ENTROPY_MAX_ROWS} rows; regions below use single blocks.")
        shown = regions[:50]
        if shown:
            L.append(f"Suspicious regions with entropy > {HIGH_ENTROPY} ({len(regions)} found):")
            for s, e, w in shown:
                L.append(f"  0x{s:08x} - 0x{e:08x} ({e - s} bytes), avg entropy {w / (e - s):.3f}")
            if len(regions) > len(shown):
                L.append(f"  ... {len(regions) - len(shown)} more region(s) not listed")
        else:
            L.append(f"Suspicious regions with entropy > {HIGH_ENTROPY}: none")
        L.append("")
        L.append("offset       length  entropy")
        for off, ln, e in rows:
            bar = "#" * int(round(e / 8 * 24))
            L.append(f"0x{off:08x} {ln:>9}  {e:5.3f}  {bar}{' *' if e > HIGH_ENTROPY else ''}")
        return _Out("\n".join(L), {
            "source_ref": sref, "overall_entropy": round(overall, 3), "block_size": bs,
            "high_entropy_regions": [[s, e] for s, e, _ in shown]})

    def _t_strings_extract(self, ctx: _Ctx, a: dict) -> _Out:
        enc = a["encoding"].lower()
        if enc not in ("ascii", "utf16le", "both"):
            raise ToolError("Argument 'encoding' must be one of: ascii, utf16le, both")
        data, name = ctx.read_all(a["path"])
        n, limit, start = a["min_len"], a["max_results"], a["offset"]
        sref = {"file": name, "offset": start, "length": max(0, len(data) - start)}
        if start >= len(data) and len(data) > 0:
            raise ToolError(f"Offset {start} is beyond end of file (size {len(data)})")
        rx_a = re.compile(rb"[\x20-\x7e\t]{%d,}" % n)
        rx_w = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % n)

        def gen_a():
            for m in rx_a.finditer(data, start):
                yield (m.start(), "A", m.group().decode("ascii"))

        def gen_w():
            for m in rx_w.finditer(data, start):
                yield (m.start(), "W", m.group().decode("utf-16le"))

        streams = {"ascii": [gen_a()], "utf16le": [gen_w()], "both": [gen_a(), gen_w()]}[enc]
        merged = heapq.merge(*streams, key=lambda t: (t[0], t[1]))
        found, more, next_off = [], False, start
        for item in merged:
            if len(found) >= limit:
                more, next_off = True, item[0]
                break
            found.append(item)
        L = [f"Strings in {name} (min length {n}, encoding {enc}, from offset 0x{start:x}): "
             f"{len(found)} shown" + (" (limit reached, more exist)" if more else "")]
        L.append("offset      enc  string   [A=ASCII, W=UTF-16LE]")
        for off, kind, s in found:
            L.append(f"0x{off:08x}  {kind}    {clip(s, 300)}")
        if not found:
            L.append("(no strings found)")
        if more:
            L.append(f"[more strings available: continue with offset={next_off}]")
        meta = {"source_ref": sref, "count": len(found)}
        if found:
            meta["source_ref"] = {"file": name, "offset": found[0][0],
                                  "length": found[-1][0] - found[0][0] + len(found[-1][2])}
        return _Out("\n".join(L), meta, truncated=more)

    def _t_hexdump(self, ctx: _Ctx, a: dict) -> _Out:
        offset, length = a["offset"], a["length"]
        chunk, size, name = ctx.read_range(a["path"], offset, length)
        if size == 0:
            return _Out(f"File {name} is empty.", {"source_ref": {"file": name, "offset": 0, "length": 0}})
        if offset >= size:
            raise ToolError(f"Offset {offset} is beyond end of file (size {size})")
        text = (f"Hexdump of {name}, offset 0x{offset:x}, {len(chunk)} byte(s) of {size}\n"
                + hexdump(chunk, offset))
        return _Out(text, {"source_ref": {"file": name, "offset": offset, "length": len(chunk)}})

    # ------------------------------------------------------------------ tools: text views
    def _t_read_lines(self, ctx: _Ctx, a: dict) -> _Out:
        text, enc, name = ctx.text(a["path"])
        lines = split_lines(text)
        total = len(lines)
        start = a["start"]
        end = a["end"] if a["end"] else start + 99
        if end < start:
            raise ToolError("Argument 'end' must be >= 'start'")
        if end > start + MAX_READ_LINES - 1:
            end = start + MAX_READ_LINES - 1
            ctx.notes.append(f"at most {MAX_READ_LINES} lines per call; range cut to {start}-{end}")
        if total == 0:
            return _Out(f"File {name} is empty (0 lines).", {"source_ref": {"file": name, "line_start": 0, "line_end": 0}})
        if start > total:
            raise ToolError(f"File has {total} lines; start {start} is beyond the end")
        end = min(end, total)
        body = _lines_fmt(lines[start - 1:end], start)
        more = f"\n[{total - end} more line(s) after line {end}]" if end < total else ""
        text_out = f"{name} lines {start}-{end} of {total} ({enc})\n{body}{more}"
        return _Out(text_out, {"source_ref": {"file": name, "line_start": start, "line_end": end},
                               "total_lines": total})

    def _t_grep(self, ctx: _Ctx, a: dict) -> _Out:
        rx = check_pattern(a["pattern"], re.IGNORECASE if a["ignore_case"] else 0)
        text, enc, name = ctx.text(a["path"])
        lines = split_lines(text)
        limit, cx = a["max_results"], a["context"]
        matches: list[int] = []
        more = timed_out = False
        for i, line in enumerate(lines):
            if i % 256 == 0 and not ctx.check_time():
                timed_out = True
                break
            if rx.search(line[:LINE_MATCH_LIMIT]):
                if len(matches) >= limit:
                    more = True
                    break
                matches.append(i)
        if not matches:
            note = " (time budget exceeded, search incomplete)" if timed_out else ""
            return _Out(f"No matches for /{a['pattern']}/ in {name} ({len(lines)} lines){note}.",
                        {"source_ref": {"file": name, "line_start": 0, "line_end": 0}, "matches": []},
                        truncated=timed_out)
        mset = set(matches)
        shown: list[int] = []
        seen = set()
        for m in matches:
            for j in range(max(0, m - cx), min(len(lines), m + cx + 1)):
                if j not in seen:
                    seen.add(j)
                    shown.append(j)
        shown.sort()
        out = [f"grep /{a['pattern']}/ in {name}: {len(matches)} matching line(s)"
               + (" (limit reached, more exist)" if more else "")
               + (" (time budget exceeded, results partial)" if timed_out else "")]
        prev = None
        for j in shown:
            if prev is not None and j != prev + 1:
                out.append("--")
            out.append(f"{j + 1:>6}{':' if j in mset else '-'} {clip(lines[j], 500)}")
            prev = j
        if any(len(lines[m]) > LINE_MATCH_LIMIT for m in matches):
            out.append(f"[lines longer than {LINE_MATCH_LIMIT} chars were matched on their first "
                       f"{LINE_MATCH_LIMIT} chars only]")
        return _Out("\n".join(out), {
            "source_ref": {"file": name, "line_start": matches[0] + 1, "line_end": matches[-1] + 1},
            "matches": [m + 1 for m in matches]}, truncated=more or timed_out)

    def _t_script_detect(self, ctx: _Ctx, a: dict) -> _Out:
        text, enc, name = ctx.text(a["path"])
        lines = split_lines(text)
        lang, score, why = detect_language(text)
        hits, timed_out = find_indicators(lines, ctx.deadline)
        counts = Counter(h[1] for h in hits)
        level = "high" if len(counts) >= 5 else "medium" if len(counts) >= 2 else "low"
        L = [f"Script analysis of {name} ({enc}, {len(lines)} lines)",
             f"Language: {lang} (score {score})"]
        L += [f"  - {r}" for r in why]
        L.append(f"Obfuscation level: {level} ({len(counts)} distinct indicator type(s), {len(hits)} hit(s))")
        if counts:
            L.append("Indicator summary:")
            for nm in sorted(counts):
                L.append(f"  {nm} x{counts[nm]}: {indicator_description(nm)}")
            L.append("Indicator hits (line: indicator: snippet):")
            for no, nm, snip in hits[:MAX_INDICATORS]:
                L.append(f"  L{no}: {nm}: {clip(snip, 140)}")
            if len(hits) > MAX_INDICATORS:
                L.append(f"  ... {len(hits) - MAX_INDICATORS} more hit(s) not listed")
        else:
            L.append("No obfuscation indicators found.")
        if timed_out:
            L.append("[time budget exceeded; analysis incomplete]")
        first = hits[0][0] if hits else 1
        last = hits[-1][0] if hits else max(1, len(lines))
        return _Out("\n".join(L), {
            "source_ref": {"file": name, "line_start": first, "line_end": last},
            "language": lang, "obfuscation_level": level, "indicators": dict(sorted(counts.items()))},
            truncated=timed_out or len(hits) > MAX_INDICATORS)

    # ------------------------------------------------------------------ tools: decode_layer
    METHODS = ("base64", "base32", "base85", "hex", "url", "rot13", "charcode", "xor_single_byte", "xor_key", "rc4",
               "gzip", "zlib", "auto")

    def _t_decode_layer(self, ctx: _Ctx, a: dict) -> _Out:
        method = a["method"].strip().lower()
        if method not in self.METHODS:
            raise ToolError(f"Unknown method '{clip(method, 40)}'. Allowed: {', '.join(self.METHODS)}")
        size = ctx.size(a["path"])
        offset = a["offset"]
        if size and offset >= size:
            raise ToolError(f"Offset {offset} is beyond end of file (size {size})")
        want = a["length"] if a["length"] > 0 else size - offset
        take = min(want, MAX_DECODE_INPUT, size - offset)
        chunk, _size, name = ctx.read_range(a["path"], offset, take)
        if want > take and take == MAX_DECODE_INPUT:
            ctx.notes.append(f"input limited to {MAX_DECODE_INPUT // (1024 * 1024)} MiB")
        if not chunk:
            raise ToolError("No input bytes to decode")
        pre: list[str] = []
        chunk, skipped = self._strip_label(chunk, method)
        if skipped:
            offset += len(skipped)
            pre.append(f"Skipped label {_clean(skipped.decode('latin-1'))!r} ({len(skipped)} bytes) in front of the data; "
                       f"decoding starts at offset {offset} (0x{offset:x})")
        sref = {"file": name, "offset": offset, "length": len(chunk)}
        meta_extra: dict[str, Any] = {}
        if method == "auto":
            cands = self._auto_candidates(chunk)
            pre.append("Auto-detection candidates (best first; score = share of printable characters):")
            for i, c in enumerate(cands, 1):
                pre.append(f"  {i}. {c['method']:<16} score {c['score']:.3f}  {len(c['data'])} bytes"
                           f"{'  ' + c['note'] if c['note'] else ''}  plausible={'yes' if c['plausible'] else 'no'}"
                           f"  preview: {self._short(c['data'])}")
            if not cands:
                pre.append("  (no method produced output)")
            chosen = next((c for c in cands if c["plausible"]), None)
            meta_extra["candidates"] = [{"method": c["method"], "score": round(c["score"], 3),
                                         "plausible": c["plausible"]} for c in cands]
            if chosen is None:
                best = f" Best candidate: {cands[0]['method']} (score {cands[0]['score']:.3f})." if cands else ""
                msg = "auto: no plausible decoding found." + best
                return _Out("\n".join([msg] + pre), {"source_ref": sref, **meta_extra}, ok=False, error=msg)
            out, used, extra = chosen["data"], chosen["method"], ([chosen["note"]] if chosen["note"] else [])
            if used == "xor_single_byte":
                meta_extra["xor_key"] = chosen["key"]
        else:
            used = method
            if method in decoders.KEYED:
                out, extra, kv = self._apply_keyed(ctx.job_id, method, chunk, a["key_hex"])
            else:
                out, extra, kv = self._apply(method, chunk, a["key"])
            meta_extra.update(kv)
        if not out:
            raise ToolError("Decoding produced no data")
        if len(out) > decoders.MAX_OUT:
            raise ToolError(f"Decoded data exceeds the {decoders.MAX_OUT // (1024 * 1024)} MiB limit")
        logical, sha, reused = ctx.write_layer(out)
        magic = sniff_magic(out)
        kind, preview = self._preview(out)
        L = [f"decode_layer: {used}{' (auto)' if method == 'auto' else ''} on {name} offset {offset}, "
             f"{len(chunk)} input byte(s) -> {len(out)} byte(s)",
             f"Saved: {logical}",
             f"SHA-256: {sha}",
             f"Result: {kind}" + (f"; magic suggests {magic[0]} ({magic[1]})" if magic else "")]
        L += pre
        L += extra
        L.append("Preview:")
        L.append(preview)
        if kind.endswith("text"):
            L.append(f"Hex (first {min(32, len(out))} of {len(out)} bytes): {out[:32].hex(' ')}")
        fields, total = self._json_fields(out)
        if fields:
            L.append(f"JSON fields ({len(fields)} of {total}; nested, long or multi-line values only in the preview):")
            L += [f"  {k} = {v}" for k, v in fields.items()]
        meta = {"source_ref": sref, "derived": logical, "sha256": sha, "size": len(out),
                "method": used, "reused_existing": reused, "result_kind": "text" if kind.endswith("text") else "binary",
                "magic": magic[0] if magic else None, "json_fields": fields,
                "looks_encoded": len(out.strip()) % 4 == 0 and self._is_blob("base64", out)}
        meta.update(meta_extra)
        return _Out("\n".join(L), meta)

    @staticmethod
    def _is_blob(name: str, data: bytes) -> bool:
        return _BLOBS[name].fullmatch(b"".join(data.split())) is not None

    @staticmethod
    def _strip_label(chunk: bytes, method: str) -> tuple[bytes, bytes]:
        """'CFG:eyJ...' fails the decoder because of the label. Removed only when exactly a clean blob stays behind."""
        names = list(_BLOBS) if method == "auto" else [method] if method in _BLOBS else []
        m = _LABEL.match(chunk)
        is_blob = DevGateway._is_blob
        if m and any(not is_blob(n, chunk) and is_blob(n, chunk[m.end():]) for n in names):
            return chunk[m.end():], m.group(0)
        return chunk, b""

    @staticmethod
    def _json_fields(out: bytes) -> tuple[dict[str, str], int]:
        """Flat key = value lines of a decoded JSON object, so the value is read and not worked out. A value is listed
        whole or not at all, and an object with a repeated key gives none: which value counts is not a fact."""
        if len(out) > MAX_JSON_FIELD_INPUT or out.lstrip()[:1] != b"{":
            return {}, 0

        def unique(pairs: list) -> dict:
            if len({k for k, _ in pairs}) != len(pairs):
                raise ValueError("repeated key")
            return dict(pairs)
        try:
            obj = json.loads(out, object_pairs_hook=unique)
        except (ValueError, RecursionError):
            return {}, 0
        fields: dict[str, str] = {}
        for k, v in list(obj.items())[:MAX_JSON_FIELDS]:
            key, text = _clean(str(k)), _clean(str(v))
            if isinstance(v, (str, int, float, bool)) and len(key) <= 60 and len(text) <= 300 and "\n" not in key + text:
                fields[key] = text
        return fields, len(obj)

    @staticmethod
    def _short(data: bytes, n: int = 40) -> str:
        s = _clean(DevGateway._as_text(data)[:n]).replace("\n", " ")
        return repr(s)

    @staticmethod
    def _as_text(data: bytes) -> str:
        if data.startswith(b"\xff\xfe") or looks_utf16le(data):
            body = data[2:] if data.startswith(b"\xff\xfe") else data
            return body.decode("utf-16le", errors="replace")
        return data.decode("latin-1")

    @staticmethod
    def _score(data: bytes) -> float:
        if data.startswith(b"\xff\xfe") or looks_utf16le(data):
            t = DevGateway._as_text(data)[:32768]
            if not t:
                return 0.0
            return sum(1 for c in t if c in "\t\r\n" or 32 <= ord(c) < 127) / len(t)
        return printable_ratio(data[:65536])

    def _apply(self, method: str, chunk: bytes, key: int) -> tuple[bytes, list[str], dict]:
        try:
            if method == "xor_single_byte":
                ranked = decoders.xor_rank(chunk, 5)
                use = ranked[0][0] if key < 0 else key
                if use == 0:
                    raise ToolError("XOR key 0 is the identity; choose a key from 1 to 255")
                lines = ["Best XOR keys (rank by printable/alphanumeric share):"]
                for k, _r, pr in ranked:
                    prev = self._short(decoders.xor_with(chunk[:64], k))
                    lines.append(f"  key 0x{k:02x}  printable {pr:.3f}  {prev}"
                                 + ("  <- used" if k == use else ""))
                if key >= 0 and key not in [r[0] for r in ranked]:
                    lines.append(f"  key 0x{key:02x} (given) used")
                return decoders.xor_with(chunk, use), lines, {"xor_key": use}
            return decoders.SIMPLE[method](chunk), [], {}
        except DecodeError as exc:
            raise ToolError(f"{method} decoding failed: {exc}") from None

    def _apply_keyed(self, job_id: str, method: str, chunk: bytes, key_hex: str) -> tuple[bytes, list[str], dict]:
        try:
            key = decoders.parse_key_hex(key_hex)
        except DecodeError as exc:
            raise ToolError(f"{method}: {exc}") from None
        used = self._keys_used.setdefault(job_id, set())
        if key not in used and len(used) >= MAX_KEYS_PER_JOB:
            raise ToolError(f"Limit of {MAX_KEYS_PER_JOB} different keys per job reached. Keys must come from evidence; "
                            "trying key lists is not allowed. Name the missing key as a gap.")
        used.add(key)
        return decoders.KEYED[method](chunk, key), [f"Key (hex): {key.hex()}"], {"key_hex": key.hex()}

    def _artifact_out(self, ctx: _Ctx, data: bytes, head: str, sref: dict, extra: Optional[dict] = None) -> _Out:
        logical, sha, reused = ctx.write_layer(data)
        magic = sniff_magic(data)
        kind, preview = self._preview(data)
        text = "\n".join([head, f"Saved: {logical}", f"SHA-256: {sha}",
                          f"Result: {kind}" + (f"; magic suggests {magic[0]} ({magic[1]})" if magic else ""),
                          "Preview:", preview])
        return _Out(text, {"source_ref": sref, "derived": logical, "sha256": sha, "size": len(data),
                           "reused_existing": reused, "magic": magic[0] if magic else None, **(extra or {})})

    def _t_extract_range(self, ctx: _Ctx, a: dict) -> _Out:
        offset, length = a["offset"], a["length"]
        chunk, size, name = ctx.read_range(a["path"], offset, length)
        if offset >= size:
            raise ToolError(f"Offset {offset} is beyond end of file (size {size})")
        return self._artifact_out(ctx, chunk, f"extract_range: {len(chunk)} byte(s) of {name} at offset 0x{offset:x}",
                                  {"file": name, "offset": offset, "length": len(chunk)})

    @staticmethod
    def _check_member(member: str) -> None:
        if (member.startswith("/") or member.startswith("\\") or "\\" in member or ":" in member
                or ".." in member.split("/")):
            raise ToolError("Member name rejected: absolute paths, drive letters, backslashes and '..' "
                            "are not allowed")

    def _read_member(self, ctx: _Ctx, logical: Any, member: str) -> tuple[bytes, str, zipfile.ZipInfo]:
        """One archive member in memory. file_size in the archive can lie, so the read itself is bounded."""
        self._check_member(member)
        zf, name = self._open_zip(ctx, logical)
        with zf:
            try:
                info = zf.getinfo(member)
            except KeyError:
                raise ToolError(f"Member '{clip(member, 100)}' not found in archive; use zip_list") from None
            if info.is_dir():
                raise ToolError(f"Member '{clip(member, 100)}' is a directory")
            if info.flag_bits & 1:
                raise ToolError(f"Member '{clip(member, 100)}' is encrypted")
            try:
                with zf.open(info) as f:
                    raw = f.read(MAX_DECODE_INPUT + 1)
            except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError, EOFError, ValueError, zlib.error):
                raise ToolError(f"Member '{clip(member, 100)}' cannot be read (corrupt or unsupported)") from None
        if len(raw) > MAX_DECODE_INPUT:
            raise ToolError(f"Member '{clip(member, 100)}' exceeds the {MAX_DECODE_INPUT // (1024 * 1024)} MiB limit "
                            "(possible decompression bomb)")
        return raw, name, info

    def _t_zip_extract(self, ctx: _Ctx, a: dict) -> _Out:
        raw, name, _info = self._read_member(ctx, a["path"], a["member"])
        if not raw:
            raise ToolError(f"Member '{clip(a['member'], 100)}' is empty")
        return self._artifact_out(ctx, raw, f"zip_extract: {name}!{clip(a['member'], 200)}, {len(raw)} byte(s)",
                                  {"file": name, "member": a["member"]}, {"member": a["member"]})

    def _t_pe_resources(self, ctx: _Ctx, a: dict) -> _Out:
        data, name = ctx.read_all(a["path"])
        info = parse_pe(data)
        sref = {"file": name, "offset": 0, "length": min(len(data), 64)}
        if not info.get("is_pe"):
            msg = f"Not a valid PE file: {info.get('error') or 'unknown error'}"
            return _Out(msg, {"source_ref": sref}, ok=False, error=msg)
        tree = parse_resources(data, info)
        res = tree["resources"]
        L = [f"PE resources of {name}: {len(res)} found"]
        if res:
            L.append("path | file offset | size | entropy | first bytes")
        for r in res:
            off = "unmapped" if r["file_offset"] is None else f"0x{r['file_offset']:x}"
            flag = " [extends beyond file]" if r["truncated"] else ""
            entropy = "n/a" if r["entropy"] is None else f"{r['entropy']:.3f}"
            L.append(f"{r['path']} | {off} | {r['size']} | {entropy} | {r['head'].hex()}{flag}")
        L += [f"[warning] {w}" for w in tree["warnings"]]
        rows = [{k: v for k, v in r.items() if k != "head"} for r in res[:100]]
        return _Out("\n".join(L), {"source_ref": sref, "count": len(res), "resources": rows})

    def _t_apk_manifest(self, ctx: _Ctx, a: dict) -> _Out:
        data, name = ctx.read_all(a["path"])
        if data[:2] == b"PK":
            raw, _name, _info = self._read_member(ctx, a["path"], "AndroidManifest.xml")
            sref = {"file": name, "member": "AndroidManifest.xml"}
        else:
            raw, sref = data, {"file": name, "offset": 0, "length": len(data)}
        try:
            mf = parse_axml(raw)
        except AxmlError as exc:
            msg = f"AndroidManifest could not be decoded: {exc}"
            return _Out(msg, {"source_ref": sref}, ok=False, error=msg)
        L = [f"Package: {mf['package'] or '(not stated)'}", f"Permissions ({len(mf['permissions'])}):"]
        L += [f"  {p}" for p in mf["permissions"]]
        L.append(f"Components ({len(mf['components'])}):")
        L += [f"  {c['kind']} {c['name']} exported={c['exported'] if c['exported'] is not None else 'unset'}"
              for c in mf["components"]]
        L += ["Manifest:", mf["xml"]]
        if mf["truncated"]:
            L.append("[manifest is longer than the parser limit: later elements are not listed]")
        return _Out("\n".join(L), {"source_ref": sref, "package": mf["package"], "permissions": mf["permissions"][:200],
                                   "components": mf["components"][:200]}, truncated=mf["truncated"])

    def _auto_candidates(self, chunk: bytes) -> list[dict]:
        in_pr = printable_ratio(chunk[:65536])
        in_magic = sniff_magic(chunk)
        order = ["base64", "hex", "url", "gzip", "zlib", "rot13", "xor_single_byte"]
        cands = []
        for idx, m in enumerate(order):
            if m == "rot13" and (in_pr < 0.9 or not re.search(rb"[A-Za-z]{3}", chunk[:65536])):
                continue
            if m == "xor_single_byte" and alnum_space_ratio(chunk[:65536]) >= 0.75:
                continue  # already looks like plain text
            key, note = None, ""
            try:
                if m == "xor_single_byte":
                    key = decoders.xor_rank(chunk, 1)[0][0]
                    out = decoders.xor_with(chunk, key)
                    note = f"key 0x{key:02x}"
                else:
                    out = decoders.SIMPLE[m](chunk)
            except DecodeError:
                continue
            if not out or out == chunk or len(out) > decoders.MAX_OUT:
                continue
            score = self._score(out)
            magic = sniff_magic(out)
            if magic is not None and in_magic is not None and magic[0] == in_magic[0]:
                magic = None  # input already has this magic; the "decoding" changed nothing useful
            rank = score + (0.1 if m in ("base64", "hex", "url", "gzip", "zlib") else 0.0) + (0.2 if magic else 0.0)
            if m == "rot13" and not _KEYWORDS.search(out[:65536]):
                rank *= 0.5
                score_pl = False
            else:
                score_pl = True
            plausible = (score >= 0.85 or magic is not None) and score_pl
            if m == "xor_single_byte":
                plausible = (score >= 0.95 or magic is not None)
            if magic:
                note = (note + " " if note else "") + f"magic: {magic[0]}"
            cands.append({"method": m, "data": out, "score": score, "rank": rank,
                          "plausible": plausible, "note": note, "key": key, "order": idx})
        cands.sort(key=lambda c: (-c["rank"], c["order"]))
        return cands

    @staticmethod
    def _preview(data: bytes) -> tuple[str, str]:
        if data.startswith(b"\xff\xfe") or looks_utf16le(data):
            t = DevGateway._as_text(data)
            kind = "UTF-16LE text"
        elif printable_ratio(data[:65536]) >= 0.85:
            t = data.decode("utf-8", errors="replace")
            kind = "text"
        else:
            return "binary data", hexdump(data[:256], 0) + (
                f"\n[... {len(data) - 256} more byte(s)]" if len(data) > 256 else "")
        t = _clean(t)
        if len(t) > 2000:
            return kind, t[:2000] + f"\n[... {len(t) - 2000} more character(s)]"
        return kind, t

    # ------------------------------------------------------------------ tools: PE / ZIP
    def _t_pe_headers(self, ctx: _Ctx, a: dict) -> _Out:
        data, name = ctx.read_all(a["path"])
        info = parse_pe(data)
        if not info.get("is_pe"):
            msg = f"Not a valid PE file: {info.get('error') or 'unknown error'}"
            return _Out(msg, {"source_ref": {"file": name, "offset": 0, "length": min(len(data), 64)}},
                        ok=False, error=msg)
        try:
            text = format_pe(info, len(data))
            signs = self._packing_signs(info)
        except Exception:  # noqa: BLE001 - formatting must not leak exceptions either
            msg = "PE headers could not be formatted (corrupt structure)"
            return _Out(msg, {}, ok=False, error=msg)
        text += "\nPacking check: " + (f"{len(signs)} sign(s): " + "; ".join(signs) if signs else "no sign found") + "."
        end = info.get("section_table_offset", 0) + 40 * len(info.get("sections", []))
        meta = {"source_ref": {"file": name, "offset": 0, "length": min(len(data), max(end, 64))},
                "machine": info["machine_name"], "is_dll": info["is_dll"], "image_base": info.get("image_base"),
                "entry_rva": info.get("entry_rva"), "sections": [s["name"] for s in info.get("sections", [])],
                "overlay_offset": info.get("overlay_offset"), "overlay_size": info.get("overlay_size", 0),
                "packing_signs": signs}
        return _Out(text, meta)

    @staticmethod
    def _packing_signs(info: dict) -> list[str]:
        """Recipe exe, step static_triage. Entropy of a small section says little, so it needs a minimum size."""
        sections = info.get("sections", [])
        out = [f"section {s['name']} has entropy {s['entropy']} on {s['raw_size']} raw bytes" for s in sections
               if s["entropy"] > PACKED_ENTROPY and s["raw_size"] >= PACKED_MIN_RAW]
        out += [f"section name {s['name']}" for s in sections if PACKER_SECTION.search(s["name"])]
        imported = {fn for i in info.get("imports", []) for fn in i["functions"]}
        if len(imported) <= 8 and imported & {"LoadLibraryA", "GetProcAddress", "VirtualAlloc"}:
            out.append("few imports including a loader API")
        rva = info.get("entry_rva") or 0
        if sections and not any(s["virtual_address"] <= rva < s["virtual_address"] + max(s["virtual_size"], s["raw_size"])
                                and s["flags"] & 0x20000000 for s in sections):
            out.append("entry point outside the executable sections")
        return out

    def _open_zip(self, ctx: _Ctx, logical: Any) -> tuple[zipfile.ZipFile, str]:
        data, name = ctx.read_all(logical)
        try:
            return zipfile.ZipFile(io.BytesIO(data)), name
        except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError, EOFError):
            raise ToolError(f"File '{name}' is not a readable ZIP archive") from None

    def _t_zip_list(self, ctx: _Ctx, a: dict) -> _Out:
        zf, name = self._open_zip(ctx, a["path"])
        with zf:
            infos = zf.infolist()
            total = len(infos)
            L = [f"ZIP archive {name}: {total} entr{'y' if total == 1 else 'ies'}"
                 + (f" (listing limited to {MAX_ZIP_ENTRIES})" if total > MAX_ZIP_ENTRIES else "")]
            usize = sum(i.file_size for i in infos)
            csize = sum(i.compress_size for i in infos)
            L.append(f"Total uncompressed: {usize} bytes, compressed: {csize} bytes")
            L.append("idx size packed crc32 name")
            unsafe = 0
            for idx, i in enumerate(infos[:MAX_ZIP_ENTRIES]):
                flags = ""
                if i.flag_bits & 1:
                    flags += " [encrypted]"
                if i.filename.startswith("/") or ".." in i.filename.split("/") or "\\" in i.filename:
                    flags += " [unsafe name]"
                    unsafe += 1
                L.append(f"{idx} {i.file_size} {i.compress_size} {i.CRC:08x} "
                         f"{clip(i.filename, 200)}{flags}")
            if total > MAX_ZIP_ENTRIES:
                L.append(f"[listing limited to {MAX_ZIP_ENTRIES} of {total} entries]")
            names = {i.filename for i in infos}
            hints = []
            if "AndroidManifest.xml" in names and "classes.dex" in names:
                hints.append("contains AndroidManifest.xml and classes.dex (APK structure)")
            if "META-INF/MANIFEST.MF" in names:
                hints.append("contains META-INF/MANIFEST.MF (JAR/APK signing or manifest)")
            if unsafe:
                hints.append(f"{unsafe} entr(y/ies) with unsafe names (path traversal attempt?)")
            if csize and usize / max(csize, 1) > 1000:
                hints.append("extreme compression ratio (possible zip bomb)")
            if hints:
                L.append("Notes: " + "; ".join(hints))
        return _Out("\n".join(L), {"source_ref": {"file": name, "offset": 0, "length": 0},
                                   "entries": total}, truncated=total > MAX_ZIP_ENTRIES)

    def _t_zip_read_text(self, ctx: _Ctx, a: dict) -> _Out:
        member, max_chars = a["member"], a["max_chars"]
        self._check_member(member)
        zf, name = self._open_zip(ctx, a["path"])
        with zf:
            try:
                info = zf.getinfo(member)
            except KeyError:
                raise ToolError(f"Member '{clip(member, 100)}' not found in archive; use zip_list") from None
            if info.is_dir():
                raise ToolError(f"Member '{clip(member, 100)}' is a directory")
            if info.flag_bits & 1:
                raise ToolError(f"Member '{clip(member, 100)}' is encrypted")
            try:
                with zf.open(info) as f:
                    raw = f.read(max_chars * 4 + 4)
                    more_data = bool(f.read(1))
            except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError, EOFError, ValueError):
                raise ToolError(f"Member '{clip(member, 100)}' cannot be read (corrupt or unsupported)") from None
        dec = decode_text_bytes(raw)
        if dec is None:
            raise ToolError(f"Member '{clip(member, 100)}' is binary (e.g. compiled XML or classes); "
                            "only text members can be read")
        text = dec[0]
        cut = len(text) > max_chars or more_data
        text = text[:max_chars]
        lines = split_lines(text)
        header = f"{name}!{member} ({info.file_size} bytes uncompressed, {dec[1]})"
        body = _lines_fmt(lines, 1)
        tail = f"\n[truncated: showing first {max_chars} characters]" if cut else ""
        return _Out(f"{header}\n{body}{tail}", {
            "source_ref": {"file": name, "member": member, "line_start": 1, "line_end": max(1, len(lines))},
            "member": member}, truncated=cut)
