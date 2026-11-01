"""Export of one finished job as a ZIP bundle and its read-only import on another installation.

Bundle format sw-analyst-export/1::

    manifest.json    format, exported_at, app_version, model, prompt_pack, job_id, status, sample_name,
                     sample_sha256, include_files, audit {entries, head_hash}, files {name: {sha256, size}}
    job.json         Store.export_rows(): the raw rows of the job, JSON columns as stored strings
    audit.jsonl      the hash-chained audit log of the job, byte-exact
    report.de.md     build_report() output at export time
    report.en.md
    files/sample, files/derived/<name>, files/tool-cache/<name>      only with include_files

Job, task, evidence and finding ids are counters of one installation, so an import never enters the main
database: every import gets a directory ``<data>/imports/I0001/`` with a Store of its own and keeps the original
ids; the public id is ``I0001-J-0003``. Import directory layout::

    import.json                    bundle_sha256, imported_at, manifest, checks
    sw_analyst.db                  the imported rows (opened read-only by the registry)
    logs/<job>/audit.jsonl         the audit log as bundled
    jobs/<job>/sample, derived/, tool-cache/     the files (with include_files), for the gateway factory
    bundle/                        manifest.json, job.json, report.de.md, report.en.md as handed over

A bundle is hostile input: size and entry limits, an allowlist of entry names, no extractall, fixed write targets,
sha256 of every entry, the audit chain and the link of every event row to its audit entry are checked before the
import becomes visible. The bundle is NOT signed: proof of origin needs the sha256 of the bundle (import.json,
info()) compared with the value recorded on the exporting side.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import threading
import time
import zipfile
import zlib
from pathlib import Path
from typing import Any, Callable, Optional

from sw_analyst.common.audit import verify_file
from sw_analyst.common.store import EXPORT_TABLES, Store
from sw_analyst.common.util import sha256_hex, utcnow
from sw_analyst.prompts.registry import PROMPT_PACK_VERSION
from sw_analyst.report.builder import build_report

FORMAT = "sw-analyst-export/1"
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 2000
MAX_TOTAL_BYTES = 1024 * 1024 * 1024          # sum of the uncompressed entries
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_MEMORY_ENTRY = 64 * 1024 * 1024           # job.json, audit.jsonl and the reports are read into memory and parsed
ACTIVE = ("queued", "running", "uploading")
LANGS = ("de", "en")
DB_NAME = "sw_analyst.db"

_JOB_ID_RE = re.compile(r"J-[0-9]{4,12}")
_IMPORT_ID_RE = re.compile(r"I([0-9]{4,6})")
_PUBLIC_ID_RE = re.compile(r"(I[0-9]{4,6})-(J-[0-9]{4,12})")
_TMP_RE = re.compile(r"\.tmp-[0-9a-f]{16}")
_FILE_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,199}")
_RESERVED_RE = re.compile(r"(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?", re.IGNORECASE)
_SHA_RE = re.compile(r"[0-9a-f]{64}")
_LABEL_RE = re.compile(r"[A-Za-z0-9._:/@+-]{0,200}")   # model and versions land unescaped in the report header
_FIXED = ("job.json", "audit.jsonl", "report.de.md", "report.en.md")
_FILE_DIRS = ("derived", "tool-cache")
_STATUS = {"bad_bundle": 400, "too_large": 413, "checksum_mismatch": 422, "audit_invalid": 422, "wrong_format": 422}
_READ_ERRORS = (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError, ValueError,
                NotImplementedError, KeyError, OverflowError)
_ZIP_ERRORS = (*_READ_ERRORS, OSError)


class BundleError(Exception):
    """Refused export or import. ``status`` is the HTTP status, ``code`` a stable machine-readable reason."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def _fail(code: str, message: str) -> BundleError:
    return BundleError(_STATUS[code], code, message)


def _short(s: Any) -> str:
    return repr(str(s)[:80])


def _name_ok(name: str) -> bool:
    return (bool(_FILE_NAME_RE.fullmatch(name)) and ".." not in name and not name.endswith(".")
            and not _RESERVED_RE.fullmatch(name))


def _member_ok(name: Any) -> bool:
    """Allowlist of entry names besides manifest.json; anything else is refused before it is read."""
    if not isinstance(name, str):
        return False
    if name in _FIXED or name == "files/sample":
        return True
    if "\\" in name or ".." in name or ":" in name or "\x00" in name or name.startswith("/"):
        return False
    parts = name.split("/")
    return len(parts) == 3 and parts[0] == "files" and parts[1] in _FILE_DIRS and _name_ok(parts[2])


def _rmtree(path: Path) -> None:
    """Remove a directory this module created; read-only files (the sample) must not block it on Windows."""
    for dirpath, _dirs, files in os.walk(path):
        for n in files:
            p = os.path.join(dirpath, n)
            if not os.path.islink(p):
                try:
                    os.chmod(p, 0o644)
                except OSError:
                    pass
    shutil.rmtree(path, ignore_errors=True)


# ---------------------------------------------------------------------------- audit link
def _audit_index(audit: bytes) -> tuple[dict[int, dict], int]:
    """seq -> audit entry, plus the number of repeated seqs. Lines are split like verify_file() splits them."""
    index: dict[int, dict] = {}
    dup = 0
    for raw in io.TextIOWrapper(io.BytesIO(audit), encoding="utf-8"):
        raw = raw.rstrip("\n")
        if not raw:
            continue
        obj = json.loads(raw)
        seq = obj.get("seq") if isinstance(obj, dict) else None
        if type(seq) is int:
            dup += seq in index
            index[seq] = obj
    return index, dup


def _event_mismatches(events: list[dict], audit: bytes) -> int:
    """Event rows without an audit entry of the same seq, data hash, time, level, type and message."""
    index, bad = _audit_index(audit)
    for ev in events:
        seq, data = ev.get("seq"), ev.get("data_json")
        entry = index.get(seq) if type(seq) is int else None
        if (entry is None or not isinstance(data, str) or entry.get("data_sha256") != sha256_hex(data)
                or any(entry.get(k) != ev.get(k) for k in ("ts", "level", "type", "message"))):
            bad += 1
    return bad


def _verify(path: Path):
    try:
        return verify_file(path)
    except Exception:  # noqa: BLE001 - verify_file raises on non-UTF-8 or non-object lines; that is a broken chain
        return None


# ---------------------------------------------------------------------------- export
def _read_or_empty(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return b""


def _snapshot(store: Store, job_id: str, model: str) -> tuple[dict, bytes, Any, dict[str, bytes]]:
    """Rows, audit bytes, audit verdict and both reports from one unchanged state of the job."""
    path = store.audit_path(job_id)
    for _ in range(3):
        rows = store.export_rows(job_id)
        audit = _read_or_empty(path)
        verdict = _verify(path)
        reports = {lang: build_report(store, job_id, lang, model).encode("utf-8") for lang in LANGS}
        if store.export_rows(job_id) == rows and _read_or_empty(path) == audit:
            break
        time.sleep(0.05)
    else:
        raise BundleError(409, "busy", "The job changed during the export; try again")
    if verdict is None or not verdict.valid:
        at = verdict.broken_at if verdict else "?"
        raise BundleError(409, "audit_invalid", f"The audit chain of the job is broken at entry {at}; not exported")
    bad = _event_mismatches(rows["events"], audit)
    if bad:
        raise BundleError(409, "audit_invalid", f"{bad} event(s) of the job have no matching audit entry; not exported")
    return rows, audit, verdict, reports


def _lstat_kind(p: Path) -> int:
    try:
        return stat.S_IFMT(os.lstat(p).st_mode)
    except OSError:
        return 0


def _job_files(gateway: Any, job_id: str) -> list[tuple[str, Path]]:
    """Sample, derived artifacts and tool cache of the job; regular files only, symlinks are never followed."""
    try:
        root = Path(gateway.sample_path(job_id)).parent
    except Exception:  # noqa: BLE001 - ToolError or a gateway without a workspace
        raise BundleError(409, "files_missing", "The gateway has no workspace for this job") from None
    if _lstat_kind(root / "sample") != stat.S_IFREG:
        raise BundleError(409, "files_missing", "The sample of this job is missing")
    out = [("files/sample", root / "sample")]
    for sub in _FILE_DIRS:
        d = root / sub
        if _lstat_kind(d) != stat.S_IFDIR:
            continue
        for name in sorted(os.listdir(d)):
            if _name_ok(name) and _lstat_kind(d / name) == stat.S_IFREG:
                out.append((f"files/{sub}/{name}", d / name))
    return out


def _zinfo(name: str, stamp: tuple) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo(name, date_time=stamp)
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.external_attr = (stat.S_IFREG | 0o644) << 16      # plain file, never executable, never a link
    return zi


def _copy_into(zf: zipfile.ZipFile, zi: zipfile.ZipInfo, path: Path, budget: int) -> tuple[str, int]:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    h, n = hashlib.sha256(), 0
    with os.fdopen(fd, "rb") as src, zf.open(zi, "w") as dst:
        while chunk := src.read(1 << 20):
            n += len(chunk)
            if n > budget:
                raise BundleError(413, "too_large", f"The job files exceed {MAX_TOTAL_BYTES // 2**20} MiB")
            h.update(chunk)
            dst.write(chunk)
    return h.hexdigest(), n


def export_bundle(store: Store, gateway: Any, job_id: str, *, model: str, app_version: str,
                  include_files: bool) -> tuple[bytes, str]:
    """ZIP bundle of one finished job and its file name ``sw-analyst-<job>-<sha8>.zip``. Raises BundleError."""
    job = store.get_job(job_id) if isinstance(job_id, str) and _JOB_ID_RE.fullmatch(job_id) else None
    if not job:
        raise BundleError(404, "not_found", "Unknown job")
    if job["status"] in ACTIVE:
        raise BundleError(409, "job_active", f"Job {job_id} is {job['status']}; only finished jobs can be exported")
    for label, value in (("model", model), ("app_version", app_version)):
        if not isinstance(value, str) or not _LABEL_RE.fullmatch(value):
            raise BundleError(400, "bad_request", f"The {label} name has characters a bundle does not allow")
    rows, audit, verdict, reports = _snapshot(store, job_id, model)
    row = rows["jobs"][0]
    if row["status"] in ACTIVE:
        raise BundleError(409, "job_active", f"Job {job_id} was restarted; only finished jobs can be exported")
    file_list = _job_files(gateway, job_id) if include_files else []
    if len(file_list) + 5 > MAX_ENTRIES:
        raise BundleError(413, "too_large", f"The job has more than {MAX_ENTRIES - 5} files")
    try:
        job_json = json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError):
        raise BundleError(500, "export_failed", "The job rows could not be serialized") from None

    exported_at = utcnow()
    stamp = time.strptime(exported_at, "%Y-%m-%dT%H:%M:%SZ")[:6]
    files: dict[str, dict] = {}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        def put(name: str, data: bytes) -> None:
            if len(data) > MAX_MEMORY_ENTRY:    # the import refuses larger entries, so never write one
                raise BundleError(413, "too_large", f"{name} exceeds {MAX_MEMORY_ENTRY // 2**20} MiB")
            zf.writestr(_zinfo(name, stamp), data)
            files[name] = {"sha256": sha256_hex(data), "size": len(data)}

        put("job.json", job_json)
        put("audit.jsonl", audit)
        for lang in LANGS:
            put(f"report.{lang}.md", reports[lang])
        total = sum(v["size"] for v in files.values())
        for name, path in file_list:
            sha, size = _copy_into(zf, _zinfo(name, stamp), path, MAX_TOTAL_BYTES - total)
            total += size
            files[name] = {"sha256": sha, "size": size}
        if include_files and files["files/sample"]["sha256"] != row["sample_sha256"]:
            raise BundleError(409, "checksum_mismatch", "The sample on disk does not match the recorded sha256")
        manifest = {"format": FORMAT, "exported_at": exported_at, "app_version": app_version, "model": model,
                    "prompt_pack": PROMPT_PACK_VERSION, "job_id": job_id, "status": row["status"],
                    "sample_name": row["sample_name"], "sample_sha256": row["sample_sha256"],
                    "include_files": bool(include_files),
                    "audit": {"entries": verdict.entries, "head_hash": verdict.head_hash}, "files": files}
        zf.writestr(_zinfo("manifest.json", stamp),
                    json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"))
    data = buf.getvalue()
    if len(data) > MAX_BUNDLE_BYTES:
        raise BundleError(413, "too_large", f"The bundle exceeds {MAX_BUNDLE_BYTES // 2**20} MiB; export without files")
    return data, f"sw-analyst-{job_id}-{sha256_hex(data)[:8]}.zip"


# ---------------------------------------------------------------------------- import: checks
def _stream(zf: zipfile.ZipFile, zi: zipfile.ZipInfo, limit: int, sink: Callable[[bytes], Any]) -> tuple[str, int]:
    """sha256 and length of one entry, read in chunks and never past ``limit`` bytes."""
    h, n = hashlib.sha256(), 0
    try:
        with zf.open(zi) as src:
            while chunk := src.read(1 << 20):
                n += len(chunk)
                if n > limit:
                    raise _fail("checksum_mismatch", f"Entry {_short(zi.filename)} is larger than declared")
                h.update(chunk)
                sink(chunk)
    except zipfile.BadZipFile as exc:
        if str(exc).startswith("Bad CRC-32"):
            raise _fail("checksum_mismatch", f"Entry {_short(zi.filename)} fails its CRC check") from None
        raise _fail("bad_bundle", f"Entry {_short(zi.filename)} could not be read") from None
    except BundleError:
        raise
    except _READ_ERRORS:        # OSError is left out: a failing write of the sink is a disk problem
        raise _fail("bad_bundle", f"Entry {_short(zi.filename)} could not be read") from None
    return h.hexdigest(), n


def _parse_manifest(raw: bytes) -> dict:
    try:
        m = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _fail("wrong_format", "manifest.json is not valid JSON") from None
    if not isinstance(m, dict) or m.get("format") != FORMAT:
        fmt = m.get("format") if isinstance(m, dict) else None
        raise _fail("wrong_format", f"Unsupported bundle format {_short(fmt)}; expected {FORMAT}")

    def need(ok: bool, field: str) -> None:
        if not ok:
            raise _fail("bad_bundle", f"manifest field '{field}' is missing or invalid")

    def label(v: Any) -> bool:
        return isinstance(v, str) and bool(_LABEL_RE.fullmatch(v))

    need(isinstance(m.get("job_id"), str) and bool(_JOB_ID_RE.fullmatch(m["job_id"])), "job_id")
    need(isinstance(m.get("status"), str) and m["status"] not in ACTIVE and len(m["status"]) <= 40, "status")
    need(isinstance(m.get("sample_name"), str) and len(m["sample_name"]) <= 1000, "sample_name")
    need(isinstance(m.get("sample_sha256"), str) and bool(_SHA_RE.fullmatch(m["sample_sha256"])), "sample_sha256")
    need(type(m.get("include_files")) is bool, "include_files")
    need(isinstance(m.get("exported_at"), str) and len(m["exported_at"]) <= 40, "exported_at")
    need(label(m.get("model")), "model")
    need(label(m.get("app_version")), "app_version")
    need("prompt_pack" not in m or label(m["prompt_pack"]), "prompt_pack")
    a = m.get("audit")
    need(isinstance(a, dict) and type(a.get("entries")) is int and a["entries"] >= 0
         and isinstance(a.get("head_hash"), str) and bool(_SHA_RE.fullmatch(a["head_hash"])), "audit")
    files = m.get("files")
    need(isinstance(files, dict), "files")
    for name, v in files.items():
        if not _member_ok(name):
            raise _fail("bad_bundle", f"Entry name not allowed: {_short(name)}")
        need(isinstance(v, dict) and isinstance(v.get("sha256"), str) and bool(_SHA_RE.fullmatch(v["sha256"]))
             and type(v.get("size")) is int and v["size"] >= 0, f"files.{name}")
    for name in _FIXED:
        need(name in files, f"files.{name}")
    if m["include_files"]:
        need("files/sample" in files, "files.files/sample")
    else:
        need(not any(n.startswith("files/") for n in files), "include_files")
    return m


def _parse_rows(raw: bytes, manifest: dict) -> dict[str, list[dict]]:
    try:
        rows = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _fail("bad_bundle", "job.json is not valid JSON") from None
    if not isinstance(rows, dict):
        raise _fail("bad_bundle", "job.json must map table names to rows")
    unknown = [t for t in rows if t not in EXPORT_TABLES]
    if unknown:
        raise _fail("bad_bundle", f"job.json has an unknown table {_short(unknown[0])}")
    job_id = manifest["job_id"]
    for table in EXPORT_TABLES:
        items = rows.get(table)
        if not isinstance(items, list) or not all(isinstance(r, dict) for r in items):
            raise _fail("bad_bundle", f"job.json table {table} is missing or not a list of rows")
        key = "id" if table == "jobs" else "job_id"
        for r in items:
            if r.get(key) != job_id:
                raise _fail("bad_bundle", f"A row of {table} belongs to another job than {job_id}")
            for col, val in r.items():
                if col.endswith("_json") and val is not None:
                    if not isinstance(val, str):
                        raise _fail("bad_bundle", f"{table}.{_short(col)} is not a JSON string")
                    try:
                        json.loads(val)
                    except (ValueError, RecursionError):
                        raise _fail("bad_bundle", f"{table}.{_short(col)} is not valid JSON") from None
    if len(rows["jobs"]) != 1:
        raise _fail("bad_bundle", "job.json must hold exactly one job row")
    job = rows["jobs"][0]
    for k in ("status", "sample_name", "sample_sha256"):
        if job.get(k) != manifest[k]:
            raise _fail("bad_bundle", f"manifest and job row disagree on {k}")
    return rows


def _target(tmp: Path, job_id: str, name: str) -> Path:
    """Fixed write target of a files/ entry under the new import directory."""
    root = tmp / "jobs" / job_id
    if name == "files/sample":
        parent, leaf = root, "sample"
    else:
        _, sub, leaf = name.split("/")
        parent = root / sub
    parent.mkdir(parents=True, exist_ok=True)
    target = parent / leaf
    if target.parent.resolve() != parent.resolve() or not parent.resolve().is_relative_to(tmp.resolve()):
        raise _fail("bad_bundle", f"Entry {_short(name)} leaves the import directory")
    return target


def _write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "xb") as f:
        f.write(data)


def _unpack(data: bytes, tmp: Path) -> tuple[dict, dict]:
    """Check the bundle completely and build the import directory in ``tmp``. Returns (manifest, checks)."""
    if not data.startswith(b"PK\x03\x04"):
        raise _fail("bad_bundle", "Not a ZIP bundle")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except _ZIP_ERRORS:
        raise _fail("bad_bundle", "Not a readable ZIP bundle") from None
    with zf:
        if len(infos) > MAX_ENTRIES:
            raise _fail("too_large", f"Bundle has more than {MAX_ENTRIES} entries")
        by_name: dict[str, zipfile.ZipInfo] = {}
        declared = 0
        for zi in infos:
            name = zi.filename
            if name in by_name:
                raise _fail("bad_bundle", f"Entry {_short(name)} appears twice")
            if name != "manifest.json" and not _member_ok(name):
                raise _fail("bad_bundle", f"Entry name not allowed: {_short(name)}")
            if zi.flag_bits & 0x1:
                raise _fail("bad_bundle", f"Entry {_short(name)} is encrypted")
            if zi.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise _fail("bad_bundle", f"Entry {_short(name)} uses an unsupported compression")
            declared += zi.file_size
            by_name[name] = zi
        if declared > MAX_TOTAL_BYTES:
            raise _fail("too_large", f"Bundle unpacks to more than {MAX_TOTAL_BYTES // 2**20} MiB")
        mi = by_name.pop("manifest.json", None)
        if mi is None:
            raise _fail("wrong_format", "Bundle has no manifest.json")
        if mi.file_size > MAX_MANIFEST_BYTES:
            raise _fail("too_large", "manifest.json is too large")
        chunks: list[bytes] = []
        _stream(zf, mi, MAX_MANIFEST_BYTES, chunks.append)
        manifest_raw = b"".join(chunks)
        manifest = _parse_manifest(manifest_raw)
        files, job_id = manifest["files"], manifest["job_id"]

        missing, extra = set(files) - set(by_name), set(by_name) - set(files)
        if missing or extra:
            raise _fail("bad_bundle", f"{len(missing)} manifest entries are missing from the ZIP, "
                                      f"{len(extra)} ZIP entries are not in the manifest")
        if sum(v["size"] for v in files.values()) > MAX_TOTAL_BYTES:
            raise _fail("too_large", f"Manifest declares more than {MAX_TOTAL_BYTES // 2**20} MiB")
        for name, zi in by_name.items():      # size check before anything is read
            if zi.file_size != files[name]["size"]:
                raise _fail("checksum_mismatch", f"Size of {_short(name)} differs from the manifest")
            if not name.startswith("files/") and zi.file_size > MAX_MEMORY_ENTRY:
                raise _fail("too_large", f"Entry {_short(name)} is too large")

        mem: dict[str, bytes] = {}
        total = 0
        for name in sorted(by_name):
            zi, want = by_name[name], files[name]
            if name.startswith("files/"):
                target = _target(tmp, job_id, name)
                try:
                    with open(target, "xb") as out:
                        sha, n = _stream(zf, zi, want["size"], out.write)
                except FileExistsError:
                    raise _fail("bad_bundle", f"Entry {_short(name)} collides with another file name") from None
            else:
                chunks = []
                sha, n = _stream(zf, zi, want["size"], chunks.append)
                mem[name] = b"".join(chunks)
            if n != want["size"] or sha != want["sha256"]:
                raise _fail("checksum_mismatch", f"sha256 of {_short(name)} differs from the manifest")
            total += n

    rows = _parse_rows(mem["job.json"], manifest)
    audit_path = tmp / "logs" / job_id / "audit.jsonl"
    _write_new(audit_path, mem["audit.jsonl"])
    verdict = _verify(audit_path)
    if verdict is None:
        raise _fail("audit_invalid", "audit.jsonl is not a readable hash chain (UTF-8 JSON objects, one per line)")
    if not verdict.valid:
        raise _fail("audit_invalid", f"Audit chain is broken at entry {verdict.broken_at}")
    if verdict.entries != manifest["audit"]["entries"] or verdict.head_hash != manifest["audit"]["head_hash"]:
        raise _fail("audit_invalid", f"Audit chain ends at entry {verdict.entries}, not where the manifest says")
    bad = _event_mismatches(rows["events"], mem["audit.jsonl"])
    if bad:
        raise _fail("audit_invalid", f"{bad} event row(s) have no matching audit entry")
    sample_ok = None
    if manifest["include_files"]:
        sample_ok = files["files/sample"]["sha256"] == manifest["sample_sha256"]
        if not sample_ok:
            raise _fail("checksum_mismatch", "files/sample does not match sample_sha256 of the job")

    (tmp / "jobs" / job_id / "derived").mkdir(parents=True, exist_ok=True)   # the gateway expects the workspace
    store = Store(tmp / DB_NAME, tmp / "logs")
    try:
        try:
            store.import_rows(rows)
        except ValueError as exc:
            raise _fail("bad_bundle", f"job.json rows refused: {exc}") from None
        same: dict[str, bool] = {}
        for lang in LANGS:
            try:
                rebuilt = build_report(store, job_id, lang, manifest["model"]).encode("utf-8")
            except Exception as exc:  # noqa: BLE001 - rows the report cannot read would break every later view
                raise _fail("bad_bundle", f"The report cannot be rebuilt from the rows ({type(exc).__name__})") from None
            same[lang] = rebuilt == mem[f"report.{lang}.md"]
    finally:
        store.close()

    for name in ("manifest.json", *_FIXED):
        if name != "audit.jsonl":
            _write_new(tmp / "bundle" / name, manifest_raw if name == "manifest.json" else mem[name])
    sample = tmp / "jobs" / job_id / "sample"
    if sample.is_file():
        os.chmod(sample, 0o444)
    checks = {
        "format": FORMAT, "entries": len(infos), "entries_verified": len(by_name), "bytes_verified": total,
        "include_files": manifest["include_files"], "rows": {t: len(rows[t]) for t in EXPORT_TABLES},
        "audit_valid": True, "audit_entries": verdict.entries, "audit_head_hash": verdict.head_hash,
        "events_checked": len(rows["events"]), "event_mismatches": 0, "sample_sha256_ok": sample_ok,
        "report_reproducible": all(same.values()), "reports_reproducible": same,
        "prompt_pack_bundle": manifest.get("prompt_pack", ""), "prompt_pack_local": PROMPT_PACK_VERSION,
    }
    return manifest, checks


# ---------------------------------------------------------------------------- import: registry
def _load_meta(d: Path) -> Optional[dict]:
    try:
        meta = json.loads((d / "import.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    ok = (isinstance(meta, dict) and meta.get("import_id") == d.name
          and isinstance(meta.get("original_id"), str) and bool(_JOB_ID_RE.fullmatch(meta["original_id"]))
          and meta.get("job_id") == f"{d.name}-{meta['original_id']}"
          and isinstance(meta.get("bundle_sha256"), str) and isinstance(meta.get("checks"), dict))
    return meta if ok else None


class ImportRegistry:
    """Imported bundles under ``<data_dir>/imports/I0001/``; each with its own read-only Store and gateway."""

    def __init__(self, data_dir: Path, gateway_factory: Callable[[Path], Any]):
        self._root = Path(data_dir) / "imports"
        self._factory = gateway_factory        # called with the import directory; jobs live in <dir>/jobs/<job>/
        self._lock = threading.RLock()
        self._open: dict[str, tuple[Store, Any]] = {}
        self._meta: dict[str, dict] = {}
        self._root.mkdir(parents=True, exist_ok=True)
        for p in self._root.iterdir():
            if p.is_symlink() or not p.is_dir():
                continue
            if _TMP_RE.fullmatch(p.name):
                _rmtree(p)                     # left behind by an import that was cut off
            elif _IMPORT_ID_RE.fullmatch(p.name):
                meta = _load_meta(p)
                if meta:
                    self._meta[p.name] = meta

    def _handles(self, iid: str) -> tuple[Store, Any]:
        h = self._open.get(iid)
        if h is None:
            d = self._root / iid
            store = Store(d / DB_NAME, d / "logs")
            store.make_read_only()
            h = self._open[iid] = (store, self._factory(d))
        return h

    def _lookup(self, public_id: Any) -> Optional[tuple[str, dict]]:
        m = _PUBLIC_ID_RE.fullmatch(public_id) if isinstance(public_id, str) else None
        meta = self._meta.get(m.group(1)) if m else None
        if not meta or meta["original_id"] != m.group(2):
            return None
        return m.group(1), meta

    def list_jobs(self) -> list[dict]:
        out = []
        with self._lock:
            for iid in sorted(self._meta, key=lambda s: int(s[1:]), reverse=True):
                meta = self._meta[iid]
                try:
                    job = self._handles(iid)[0].get_job(meta["original_id"])
                except (sqlite3.Error, OSError):
                    continue      # a damaged import directory must not break the job list
                if job:
                    out.append({**job, "id": meta["job_id"], "imported": True, "import_id": iid,
                                "original_id": meta["original_id"]})
        return out

    def resolve(self, public_id: str) -> Optional[tuple[Store, Any, str]]:
        with self._lock:
            hit = self._lookup(public_id)
            if not hit:
                return None
            store, gateway = self._handles(hit[0])
            return store, gateway, hit[1]["original_id"]

    def info(self, public_id: str) -> Optional[dict]:
        with self._lock:
            hit = self._lookup(public_id)
            return json.loads(json.dumps(hit[1])) if hit else None    # a copy, callers cannot change the cache

    def _next_id(self) -> str:
        nums = [int(m.group(1)) for p in self._root.iterdir() if (m := _IMPORT_ID_RE.fullmatch(p.name))]
        return f"I{max(nums, default=0) + 1:04d}"

    def import_bundle(self, data: bytes) -> dict:
        """Check a bundle and add it as a new read-only import. Raises BundleError; nothing is left on failure."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise _fail("bad_bundle", "Bundle must be bytes")
        if len(data) > MAX_BUNDLE_BYTES:
            raise _fail("too_large", f"Bundle exceeds {MAX_BUNDLE_BYTES // 2**20} MiB")
        data = bytes(data)
        bundle_sha = sha256_hex(data)
        with self._lock:
            dup = self._duplicate(bundle_sha)
        if dup:
            return dup
        tmp = self._root / f".tmp-{secrets.token_hex(8)}"         # inside imports/, never the system temp
        tmp.mkdir()
        try:
            manifest, checks = _unpack(data, tmp)                 # slow part, outside the lock: the UI keeps working
            with self._lock:
                dup = self._duplicate(bundle_sha)                  # the same bundle may have arrived meanwhile
                if dup:
                    _rmtree(tmp)
                    return dup
                iid = self._next_id()
                meta = {"import_id": iid, "job_id": f"{iid}-{manifest['job_id']}", "original_id": manifest["job_id"],
                        "bundle_sha256": bundle_sha, "bundle_size": len(data), "imported_at": utcnow(),
                        "manifest": manifest, "checks": checks}
                with open(tmp / "import.json", "x", encoding="utf-8", newline="\n") as f:
                    f.write(json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
                os.rename(tmp, self._root / iid)
                self._meta[iid] = meta
        except BundleError:
            _rmtree(tmp)
            raise
        except OSError as exc:
            _rmtree(tmp)
            raise BundleError(500, "io_error", f"The import could not be written ({type(exc).__name__})") from None
        except Exception as exc:  # noqa: BLE001 - a hostile bundle must never surface as a crash
            _rmtree(tmp)
            raise _fail("bad_bundle", f"The bundle could not be read ({type(exc).__name__})") from None
        return {"job_id": meta["job_id"], "import_id": iid, "checks": checks, "duplicate": False}

    def _duplicate(self, bundle_sha: str) -> Optional[dict]:
        for iid, meta in self._meta.items():
            if meta["bundle_sha256"] == bundle_sha:
                return {"job_id": meta["job_id"], "import_id": iid, "checks": meta["checks"], "duplicate": True}
        return None
