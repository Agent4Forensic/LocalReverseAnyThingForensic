"""Dashboard API (contract: docs/architecture/api.md). Loopback only; sample text is only ever returned as data.

Jobs come from two places: the main store (own analyses, the worker runs them) and imported analyses
(webui/bundle.py, one read-only store per import, original IDs untouched). `resolve()` hides the difference.
"""
from __future__ import annotations

import asyncio
import base64
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from sw_analyst.common.audit import verify_file
from sw_analyst.common.models import JobSpec, TargetQuestion
from sw_analyst.common.paths import PROJECT_ROOT
from sw_analyst.common.store import Store
from sw_analyst.common.util import sha256_hex
from sw_analyst.gateway.base import ToolError
from sw_analyst.guard import GUARD_VERSION, rule_count
from sw_analyst.prompts.registry import PROMPTS, list_prompts
from sw_analyst.report.builder import build_report
from sw_analyst.webui import hexmap
from sw_analyst.webui import inspect as insp
from sw_analyst.webui.examples import KNOWN_REQUIREMENTS, Examples, example_summary

APP_VERSION = "0.1.0"
MAX_SAMPLE = 64 * 1024 * 1024
MAX_BUNDLE = 256 * 1024 * 1024
STATIC_DIR = Path(__file__).resolve().parent / "static"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
_FN_LIMIT = 2000          # functions listed in the file view
_ROW_LIMIT = 4000         # instructions per function (the Ghidra export stops there as well)
MAX_OFFSET = 2 ** 40      # query bounds: a huge int must give 422, not a ValueError deep in seek()
MAX_LINE = 2 ** 31
MAX_SEQ = 2 ** 53


class QuestionIn(BaseModel):
    id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,20}$")
    text: str = Field(min_length=1, max_length=2000)
    expected: str | None = Field(default=None, max_length=500)


class JobIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=8000)
    context_info: str = Field(default="", max_length=8000)
    focus: str = Field(default="", max_length=2000)
    target_questions: list[QuestionIn] = Field(default_factory=list, max_length=20)
    emulation_opt_in: bool = False
    budget_max_tasks: int = Field(default=60, ge=5, le=300)
    budget_max_steps: int = Field(default=600, ge=20, le=5000)
    budget_max_minutes: int = Field(default=120, ge=1, le=1440)


class ExampleStart(BaseModel):
    budget_max_minutes: int | None = Field(default=None, ge=1, le=240)   # None: the example's recommended budget
    force: bool = False          # start although a requirement is missing or a run of it is still active


class ExampleBatch(BaseModel):
    ids: list[str] | None = Field(default=None, max_length=50)   # None: every example that is ready
    force: bool = False


def _err(status: int, code: str, msg: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": {"code": code, "message": msg}})


def safe_sample_name(raw: str | None) -> str:
    """Last path element under both separators, whatever the host OS is (a Linux host keeps '\\' otherwise)."""
    name = re.split(r"[\\/]", raw or "")[-1]
    # control and format characters (NUL, CR, RTLO and other bidi overrides) would spoof the name in the dashboard
    name = "".join(c for c in name if unicodedata.category(c) not in ("Cc", "Cf")).strip()
    if name in ("", ".", ".."):
        name = "sample"
    return name[:120]


# log messages that explain an end other than "all tasks done" (orchestrator/engine.py, orchestrator/worker.py)
END_REASONS = ("stopping: ", "job crashed: ", "job interrupted by restart", "upload interrupted by restart",
               "worker caught an error: ")


def job_summary(j: dict) -> dict:
    keys = ("id", "title", "status", "sample_name", "sample_sha256", "detected_type", "recipe", "created_at",
            "started_at", "finished_at", "duration_ms")
    return {k: j.get(k) for k in keys}


@dataclass
class JobRef:
    store: Store
    gateway: Any
    rid: str            # id inside its own store
    public: str         # id the dashboard uses
    job: dict
    imported: bool = False
    model: str = ""


def create_app(store: Store, worker, gateway, llm, translator=None, report_model: str = "", port: int = 8765,
               *, data_dir: Path | None = None, imports=None, examples: Examples | None = None) -> FastAPI:
    allowed_origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
    data_dir = Path(data_dir) if data_dir else store.db_path.parent
    examples = examples or Examples(registry_file=data_dir / "examples.json")
    app = FastAPI(title="sw-analyst", docs_url=None, redoc_url=None, openapi_url=None)
    import_slot = asyncio.Lock()

    @app.middleware("http")
    async def security(request: Request, call_next):
        # Cross-site requests: some GET routes have side effects (export writes a copy and an audit event,
        # inspect/functions starts Ghidra). Browsers mark every request with Sec-Fetch-Site; only the dashboard
        # itself (same-origin) or a typed URL (none) may reach /api. Clients without the header (scripts,
        # stop.ps1, tests) still pass the Host check below.
        if request.url.path.startswith("/api/"):
            site = request.headers.get("sec-fetch-site")
            origin = request.headers.get("origin")
            if (site and site not in ("same-origin", "none")) or (origin and origin not in allowed_origins):
                return JSONResponse({"error": {"code": "forbidden_origin", "message": "cross-site request refused"}},
                                    status_code=403)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin not in allowed_origins:
                return JSONResponse({"error": {"code": "forbidden_origin", "message": "invalid Origin"}}, status_code=403)
            # Refuse oversized uploads before Starlette spools them to disk (F-20). Without Content-Length
            # (chunked) the size is unknown until everything is spooled, so upload routes require it.
            limit = MAX_BUNDLE if request.url.path == "/api/imports" else MAX_SAMPLE
            raw_len = request.headers.get("content-length")
            if raw_len is None and request.url.path in ("/api/jobs", "/api/imports"):
                return JSONResponse({"error": {"code": "length_required", "message": "Content-Length is required"}},
                                    status_code=411)
            try:
                declared = int(raw_len or 0)
            except ValueError:
                declared = 0
            if declared > limit + 1024 * 1024:
                return JSONResponse({"error": {"code": "too_large", "message": f"upload larger than {limit // 2**20} MiB"}},
                                    status_code=413)
        host = (request.headers.get("host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost"):
            return JSONResponse({"error": {"code": "bad_host", "message": "invalid Host header"}}, status_code=400)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.exception_handler(HTTPException)
    async def http_exc(_, exc: HTTPException):
        body = exc.detail if isinstance(exc.detail, dict) and "error" in exc.detail else \
            {"error": {"code": "error", "message": str(exc.detail)}}
        return JSONResponse(body, status_code=exc.status_code)

    # ---- job resolution: own store or an imported, read-only store -----------------------------------------
    def resolve(job_id: str) -> JobRef:
        j = store.get_job(job_id)
        if j:
            return JobRef(store, gateway, job_id, job_id, j, False, report_model or llm.model)
        if imports is not None:
            hit = imports.resolve(job_id)
            if hit:
                s, g, rid = hit
                jj = s.get_job(rid)
                if jj:
                    info = imports.info(job_id) or {}
                    model = (info.get("manifest") or {}).get("model", "")
                    return JobRef(s, g, rid, job_id, {**jj, "id": job_id}, True, model)
        raise _err(404, "not_found", f"job {job_id} does not exist")

    def summary(ref: JobRef) -> dict:
        out = job_summary(ref.job)
        out["sample_size"] = sample_size(ref)
        out["imported"] = ref.imported
        if ref.imported:
            out["original_id"] = ref.rid
        ex = None if ref.imported else examples.example_of(ref.rid)
        if ex:
            out["example_id"] = ex
        return out

    def sample_size(ref: JobRef) -> Optional[int]:
        try:
            p = Path(ref.gateway.sample_path(ref.rid))
            return p.stat().st_size if p.is_file() else None
        except (ToolError, OSError):
            return None

    def writable(ref: JobRef) -> None:
        if ref.imported:
            raise _err(409, "read_only", "imported analyses are read-only")

    # ---- system --------------------------------------------------------------------------------------
    @app.get("/api/system")
    def system():
        reach = getattr(llm, "reachable", lambda: True)()
        names = {t.name for t in gateway.list_tools()}
        return {"version": APP_VERSION, "worker": {"state": worker.state, "job_id": worker.current_job},
                "llm": {"reachable": bool(reach), "model": llm.model, "base_url": getattr(llm, "base_url", "")},
                "guard": {"active": True, "rules": rule_count(), "version": GUARD_VERSION},
                "gateway": {"kind": "dev", "tools": len(names), "ghidra": "list_functions" in names,
                            "container_tools": sorted(names & {"list_functions", "decompile", "capa_scan",
                                                               "floss_decode", "yara_scan", "jadx_decompile"})},
                "storage": {"data_dir": _rel(data_dir), "inside_project": _inside(data_dir)},
                "queue_length": len([j for j in store.list_jobs() if j["status"] == "queued"])}

    # ---- jobs ----------------------------------------------------------------------------------------
    @app.get("/api/jobs")
    def jobs():
        own = [summary(JobRef(store, gateway, j["id"], j["id"], j)) for j in store.list_jobs()]
        imp = []
        if imports is not None:
            for j in imports.list_jobs():
                try:
                    imp.append(summary(resolve(j["id"])))
                except HTTPException:
                    continue
        return sorted(own + imp, key=lambda x: (x.get("created_at") or "", x["id"]), reverse=True)

    def _new_job(jspec: JobSpec, name: str, data: bytes) -> dict:
        # 'uploading' first: the worker only takes 'queued' jobs, so it never sees a job without its sample (F-10).
        job = store.create_job(jspec, name, sha256_hex(data), status="uploading")
        try:
            gateway.store_sample(job["id"], data)
        except (ToolError, OSError) as e:
            store.update_job(job["id"], status="failed", finished_at=job["created_at"])
            store.log(job["id"], f"sample could not be stored: {e}", level="error")
            raise _err(500, "sample_not_stored", str(e))
        return store.update_job(job["id"], status="queued")

    @app.post("/api/jobs")
    async def create_job(spec: str = Form(...), sample: UploadFile = File(...)):
        try:
            data_in = JobIn.model_validate_json(spec)
        except ValidationError as e:
            raise _err(422, "invalid_spec", e.errors()[0]["msg"] + " @ " + ".".join(map(str, e.errors()[0]["loc"])))
        if data_in.emulation_opt_in:
            raise _err(422, "emulation_disabled", "emulation is not available in this phase")
        data = bytearray()
        while chunk := await sample.read(1024 * 1024):
            data += chunk
            if len(data) > MAX_SAMPLE:
                raise _err(413, "too_large", "sample larger than 64 MiB")
        if not data:
            raise _err(422, "empty_sample", "the sample file is empty")
        qs = [TargetQuestion(id=q.id or f"Q{i + 1}", text_orig=q.text, expected=q.expected)
              for i, q in enumerate(data_in.target_questions)]
        if len({q.id for q in qs}) != len(qs):
            raise _err(422, "duplicate_question_id", "question ids must be unique")
        jspec = JobSpec(title=data_in.title, description=data_in.description, context_info=data_in.context_info,
                        focus=data_in.focus, target_questions=qs, emulation_opt_in=False,
                        budget_max_tasks=data_in.budget_max_tasks, budget_max_steps=data_in.budget_max_steps,
                        budget_max_minutes=data_in.budget_max_minutes)
        job = _new_job(jspec, safe_sample_name(sample.filename), bytes(data))
        return summary(resolve(job["id"]))

    @app.get("/api/jobs/{job_id}")
    def job_detail(job_id: str):
        ref = resolve(job_id)
        out = {"summary": summary(ref), "spec": ref.job["spec"], "progress": ref.store.progress(ref.rid),
               "totals": ref.store.totals(ref.rid)}
        if ref.imported:
            out["import"] = imports.info(job_id)
        ex = None if ref.imported else examples.example_of(ref.rid)
        if ex:
            e = examples.get(ex)
            out["example"] = {"id": ex, "title": e["title"] if e else ex, "level": e["level"] if e else "",
                              "flag_found": Examples._flag_found(store, ref.rid, e["flag"]) if e else None}
        return out

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel(job_id: str):
        ref = resolve(job_id)
        writable(ref)
        j = ref.job
        if j["status"] == "queued":
            store.update_job(job_id, status="cancelled", finished_at=j["created_at"])
        elif j["status"] == "running":
            store.update_job(job_id, cancel_requested=1)
        return summary(resolve(job_id))

    # ---- tree, queue, task -----------------------------------------------------------------------------
    def node(t: dict) -> dict:
        keys = ("id", "parent_id", "seq", "title", "kind", "origin", "status", "priority", "reason", "started_at",
                "finished_at", "duration_ms", "summary_en", "summary_de")
        params = t.get("params") or {}
        return {**{k: t.get(k) for k in keys}, "goal": t.get("goal") or "", "done_when": params.get("done_when") or "",
                "goal_reached": params.get("goal_reached"), "children": []}

    @app.get("/api/jobs/{job_id}/tree")
    def tree(job_id: str):
        ref = resolve(job_id)
        nodes = {t["id"]: node(t) for t in ref.store.list_tasks(ref.rid)}
        roots = []
        for n in nodes.values():
            parent = nodes.get(n["parent_id"])
            (parent["children"] if parent else roots).append(n)
        return roots

    @app.get("/api/jobs/{job_id}/queue")
    def queue(job_id: str):
        ref = resolve(job_id)
        return [{"task_id": t["id"], "title": t["title"], "origin": t["origin"], "status": t["status"],
                 "priority": t["priority"], "reason": t["reason"], "done_when": t["params"].get("done_when") or "",
                 "position": i + 1}
                for i, t in enumerate(ref.store.queue(ref.rid))]

    @app.get("/api/jobs/{job_id}/tasks/{task_id}")
    def task_detail(job_id: str, task_id: str):
        ref = resolve(job_id)
        t = ref.store.get_task(task_id)
        if not t or t["job_id"] != ref.rid:
            raise _err(404, "not_found", "task not found")
        steps = ref.store.list_steps(task_id)
        fids = [f["id"] for f in ref.store.list_findings(ref.rid) if f["task_id"] == task_id]
        eids = [s["evidence_id"] for s in steps if s["evidence_id"]]
        return {"task": node(t), "prompt": {"id": t["prompt_id"], "version": t["prompt_version"],
                                            "sha256": t["prompt_sha256"], "text": t["prompt_text"]},
                "steps": steps, "finding_ids": fids, "evidence_ids": eids}

    # ---- results -----------------------------------------------------------------------------------------
    @app.get("/api/jobs/{job_id}/findings")
    def findings(job_id: str):
        ref = resolve(job_id)
        return ref.store.list_findings(ref.rid)

    @app.get("/api/jobs/{job_id}/answers")
    def answers(job_id: str):
        ref = resolve(job_id)
        out = []
        for a in ref.store.list_answers(ref.rid):
            a["match"] = None if a["match"] is None else bool(a["match"])
            out.append(a)
        return out

    @app.get("/api/jobs/{job_id}/evidence")
    def evidence(job_id: str):
        ref = resolve(job_id)
        return ref.store.list_evidence(ref.rid)

    @app.get("/api/jobs/{job_id}/evidence/{eid}")
    def evidence_one(job_id: str, eid: str):
        ref = resolve(job_id)
        e = ref.store.get_evidence(eid)
        if not e or e["job_id"] != ref.rid:
            raise _err(404, "not_found", "evidence not found")
        return e

    # ---- code viewer -------------------------------------------------------------------------------------
    @app.get("/api/jobs/{job_id}/files")
    def files(job_id: str):
        ref = resolve(job_id)
        try:
            return ref.gateway.list_files(ref.rid)
        except ToolError:          # no workspace (e.g. import without files): an empty list, not a 500
            return []

    @app.get("/api/jobs/{job_id}/files/content")
    def file_content(job_id: str, path: str, start: int = Query(1, ge=1, le=MAX_LINE),
                     end: int = Query(400, ge=1, le=MAX_LINE)):
        """Contract: {path, total_lines, start, end, binary, encoding, lines:[{n, text}], annotations}.
        Binary files come as hex lines (16 bytes each), so line n covers offset (n-1)*16."""
        ref = resolve(job_id)
        start = max(start, 1)
        end = min(max(end, start), start + 399)
        try:
            res = ref.gateway.read_file_lines(ref.rid, path, start, end)
            out = {"path": res["path"], "total_lines": res["total_lines"], "start": res["start"], "end": res["end"],
                   "binary": False, "encoding": res.get("encoding", ""),
                   "lines": [{"n": res["start"] + i, "text": t} for i, t in enumerate(res["lines"])]}
        except ToolError as e:
            if "appears to be binary" not in str(e):
                raise _err(400, "bad_path", str(e))
            try:
                b = ref.gateway.read_bytes(ref.rid, path, (start - 1) * insp.HEX_ROW, (end - start + 1) * insp.HEX_ROW)
            except ToolError as e2:
                raise _err(400, "bad_path", str(e2))
            rows = insp.hex_rows(b["data"], b["offset"])
            total = max(1, math.ceil(b["size"] / insp.HEX_ROW))
            out = {"path": b["path"], "total_lines": total, "start": start, "end": start + len(rows) - 1,
                   "binary": True, "encoding": "hex",
                   "lines": [{"n": start + i, "text": f"{r['offset']:08x}  {r['hex']:<47}  |{r['ascii']}|"}
                             for i, r in enumerate(rows)]}
        out["annotations"] = [{"id": a["id"], "line_start": a["line_start"], "line_end": a["line_end"],
                               "text_en": a["text_en"], "text_de": a["text_de"], "finding_id": a["finding_id"],
                               "evidence_id": a["evidence_id"], "kind": a["kind"]}
                              for a in ref.store.list_annotations(ref.rid, out["path"])]
        return out

    # Learning path of dashboard V2 (docs/architecture/dashboard-v2.md): the model does not deliver functions and
    # walkthroughs yet. An empty list tells the code viewer "none yet" instead of a 404 in the browser console.
    @app.get("/api/jobs/{job_id}/functions")
    def functions_v2(job_id: str):
        resolve(job_id)
        return []

    @app.get("/api/jobs/{job_id}/walkthroughs")
    def walkthroughs_v2(job_id: str, path: str = "", function: str = ""):
        """Learning path through one Ghidra function: fixed steps and explanations, no model."""
        ref = resolve(job_id)
        if not path or not function:
            return []
        _file_entry(ref, path)
        res, _version = _ghidra(ref, path)
        fn = next((x for x in res["functions"] if x.get("name") == function or x.get("entry") == function), None)
        if not fn:
            raise _err(404, "not_found", "function not found; pick one from the list")
        from sw_analyst.webui import learnpath
        return learnpath.walkthrough({**fn, "path": path})

    # ---- transformation chain, dynamic analysis plan, replay export, delete ---------------------------------
    @app.get("/api/jobs/{job_id}/lineage")
    def lineage_route(job_id: str):
        """How each file of the job came from the sample: decoding layers, extracted members, ranges."""
        ref = resolve(job_id)
        from sw_analyst.webui import lineage
        return lineage.lineage(ref.store, ref.gateway, ref.rid)

    @app.get("/api/jobs/{job_id}/dynamic")
    def dynamic_route(job_id: str):
        """Dynamic analysis is shown but disabled (ADR-0005, decision of Jan 2026-11-01): the gaps and the plan."""
        ref = resolve(job_id)
        from sw_analyst.webui import dynamic
        return dynamic.dynamic_plan(ref.store, ref.rid)

    @app.get("/api/jobs/{job_id}/replay")
    def replay_route(job_id: str, include_sample: int = Query(0, ge=0, le=1)):
        """ZIP with a step-by-step replay script of the decoding chain; it never runs the sample."""
        ref = resolve(job_id)
        if ref.job["status"] in ("queued", "running", "uploading"):
            raise _err(409, "running", "the replay can be exported once the job has finished")
        from sw_analyst.report import replay
        data = replay.build_replay_zip(ref.store, ref.gateway, ref.rid, bool(include_sample))
        name = f"replay-{ref.public}.zip"
        if not ref.imported:
            ref.store.log(ref.rid, f"replay exported ({'with' if include_sample else 'without'} sample)",
                          bundle_sha256=sha256_hex(data), size=len(data))
        return Response(data, media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{name}"', "X-Bundle-SHA256": sha256_hex(data)})

    @app.delete("/api/jobs/{job_id}")
    def delete_route(job_id: str):
        ref = resolve(job_id)
        if ref.imported:
            raise _err(409, "imported", "imported analyses are read-only here")
        if ref.job["status"] in ("queued", "running", "uploading"):
            raise _err(409, "running", "cancel the job first; only finished jobs can be deleted")
        from sw_analyst.webui import jobdelete
        try:
            jobdelete.delete_job(store, gateway, data_dir, ref.rid)
        except ValueError as e:
            raise _err(409, "not_deletable", str(e))
        except KeyError:
            raise _err(404, "not_found", "job not found")
        return {"deleted": ref.public}

    # ---- file view: size, hex, assembler with explanation, pseudocode -------------------------------------
    def _file_entry(ref: JobRef, path: str) -> dict:
        try:
            listing = ref.gateway.list_files(ref.rid)
        except ToolError:
            listing = []
        entry = next((f for f in listing if f["path"] == path), None)
        if not entry:
            raise _err(404, "not_found", f"file {path} is not part of this job"
                       + (" (the export did not include files)" if ref.imported else ""))
        return entry

    def _ghidra(ref: JobRef, path: str) -> tuple[dict, str]:
        try:
            res, _name, version = ref.gateway.ghidra_export(ref.rid, path)
        except AttributeError:
            raise _err(409, "no_ghidra", "this gateway has no Ghidra tools")
        except ToolError as e:
            raise _err(409, "no_ghidra", str(e))
        return res, version

    @app.get("/api/jobs/{job_id}/inspect")
    def inspect_file(job_id: str, path: str = "sample"):
        ref = resolve(job_id)
        entry = _file_entry(ref, path)
        head = ref.gateway.read_bytes(ref.rid, path, 0, 4096)["data"]
        kind = insp.file_kind(head)
        names = {t.name for t in ref.gateway.list_tools()}
        ghidra = "list_functions" in names and kind["machine_code"]
        reason = ""
        if not kind["machine_code"]:
            reason = ("Kein Maschinencode: Assembler und Pseudocode gibt es nur für PE, ELF und Mach-O. "
                      "Text und Skripte zeigt der Tab Code, dekodierte Schichten stehen unter derived/.")
        elif "list_functions" not in names:
            reason = ("Ghidra-Werkzeuge sind nicht geladen: Docker läuft nicht oder das Image fehlt. "
                      "Einmalig bauen mit scripts/start.sh --setup (Linux) oder scripts\\start.ps1 -BuildTools (Windows), "
                      "danach den Server neu starten.")
        location = (f"data/imports/…/jobs/{ref.rid}/{path}" if ref.imported
                    else f"{_rel(data_dir)}/jobs/{ref.rid}/{path}")
        tool = ("Ghidra (Container, offline); bei importierten Analysen kann das Ergebnis aus dem Cache des Pakets "
                "stammen" if ref.imported else "Ghidra (Container, offline)")
        return {"path": path, "size": entry["size"], "sha256": entry["sha256"], "kind": kind,
                "location": location, "is_sample": path == "sample",
                "code": {"available": ghidra, "reason": reason, "tool": tool},
                "files": [{"path": f["path"], "size": f["size"]} for f in ref.gateway.list_files(ref.rid)]}

    @app.get("/api/jobs/{job_id}/inspect/hex")
    def inspect_hex(job_id: str, path: str = "sample", offset: int = Query(0, ge=0, le=MAX_OFFSET),
                    length: int = Query(1024, ge=1, le=10 ** 9), format: str = Query("rows", pattern="^(rows|b64)$")):
        ref = resolve(job_id)
        _file_entry(ref, path)
        length = max(16, min(length, insp.MAX_HEX_BYTES))
        try:
            b = ref.gateway.read_bytes(ref.rid, path, max(0, offset), length)
        except ToolError as e:
            raise _err(400, "bad_path", str(e))
        if format == "b64":   # the scrolling hex view formats the bytes itself: a quarter of the payload
            return {"path": b["path"], "size": b["size"], "offset": b["offset"], "length": len(b["data"]),
                    "data_b64": base64.b64encode(b["data"]).decode("ascii")}
        return {"path": b["path"], "size": b["size"], "offset": b["offset"], "length": len(b["data"]),
                "rows": insp.hex_rows(b["data"], b["offset"])}

    _structure_cache: dict[tuple, dict] = {}

    @app.get("/api/jobs/{job_id}/inspect/structure")
    def inspect_structure(job_id: str, path: str = "sample"):
        """What the bytes mean: format structure (fixed parsers) and where evidence and finding quotes lie."""
        ref = resolve(job_id)
        entry = _file_entry(ref, path)

        def read(off: int, ln: int) -> bytes:
            if ln <= 0:
                return b""
            try:
                return ref.gateway.read_bytes(ref.rid, path, off, ln)["data"]
            except ToolError:
                return b""
        evidence = ref.store._q("SELECT id, tool, params_json, source_ref_json FROM evidence WHERE job_id=? ORDER BY id",
                                (ref.rid,))
        findings = ref.store.list_findings(ref.rid)
        # Same file, same evidence and findings: same result. The cache spares repeated 16 MiB quote searches.
        key = (ref.public, path, entry["sha256"], len(evidence), len(findings),
               sum(len(f.get("statement_de") or "") for f in findings))   # translations arrive later
        hit = _structure_cache.get(key)
        if hit is None:
            kind = insp.file_kind(read(0, 4096))["kind"]
            hit = hexmap.build(kind, path, read, entry["size"], evidence, findings)
            if len(_structure_cache) >= 32:
                _structure_cache.pop(next(iter(_structure_cache)))
            _structure_cache[key] = hit
        return hit

    @app.get("/api/jobs/{job_id}/inspect/functions")
    def inspect_functions(job_id: str, path: str = "sample"):
        ref = resolve(job_id)
        _file_entry(ref, path)
        res, version = _ghidra(ref, path)
        if not ref.imported:
            ref.store.log(ref.rid, f"dashboard: Ghidra function list of {path}", level="debug", tool_version=version)
        prog = res.get("program") or {}
        fns = [{"name": f.get("name"), "entry": f.get("entry"), "size": f.get("size"),
                "signature": f.get("signature") or "", "thunk": bool(f.get("thunk")),
                "instructions": len(f.get("disasm") or []), "decompiled": bool(f.get("decompiled"))}
               for f in res["functions"][:_FN_LIMIT]]
        return {"path": path, "tool_version": version,
                "program": {k: prog.get(k) for k in ("format", "language", "compiler", "image_base", "entry")},
                "functions": fns, "total": len(res["functions"]),
                "truncated": len(res["functions"]) > _FN_LIMIT or bool(res.get("truncated"))}

    def _blocks(f: dict) -> list[dict]:
        out = []
        for b in (f.get("blocks") or [])[:500]:
            if isinstance(b, dict):
                out.append({"start": str(b.get("start", "")), "end": str(b.get("end", "")),
                            "succ": [[str(x) for x in (s if isinstance(s, (list, tuple)) else [s])][:2] for s in (b.get("succ") or [])][:16]})
        return out

    def _xrefs(res: dict, entry) -> dict:
        """References to and from the function entry, as the Ghidra export lists them: [from, to, type]."""
        try:
            addr = int(str(entry), 16)
        except (TypeError, ValueError):
            return {"to": [], "from": []}
        to, frm = [], []
        for r in res.get("refs") or []:
            try:
                a, b = int(str(r[0]), 16), int(str(r[1]), 16)
            except (TypeError, ValueError, IndexError):
                continue
            row = [str(r[0]), str(r[1]), str(r[2]) if len(r) > 2 else ""]
            if b == addr and len(to) < 300:
                to.append(row)
            if a == addr and len(frm) < 300:
                frm.append(row)
        return {"to": to, "from": frm}

    @app.get("/api/jobs/{job_id}/inspect/function")
    def inspect_function(job_id: str, function: str, path: str = "sample"):
        ref = resolve(job_id)
        _file_entry(ref, path)
        res, version = _ghidra(ref, path)
        f = next((x for x in res["functions"] if x.get("name") == function or x.get("entry") == function), None)
        if not f:
            raise _err(404, "not_found", "function not found; pick one from the list")
        if not ref.imported:
            ref.store.log(ref.rid, f"dashboard: Ghidra view of {f.get('name')} in {path}", level="debug",
                          tool_version=version)
        rows = []
        for row in (f.get("disasm") or [])[:_ROW_LIMIT]:
            addr, hx, text = (list(row) + ["", "", ""])[:3]
            rows.append({"address": addr, "bytes": hx, "text": text, **insp.explain(text)})
        needles = [n.lower() for n in (f.get("name"), f.get("entry")) if n]
        related = [{"id": x["id"], "status": x["status"], "statement_de": x.get("statement_de") or "",
                    "statement_en": x["statement_en"], "evidence_ids": x.get("evidence_ids") or []}
                   for x in ref.store.list_findings(ref.rid)
                   if any(n in (x["statement_en"] or "").lower() for n in needles)]
        return {"path": path, "tool_version": version, "name": f.get("name"), "entry": f.get("entry"),
                "size": f.get("size"), "signature": f.get("signature") or "", "thunk": bool(f.get("thunk")),
                "disasm": rows, "disasm_truncated": bool(f.get("disasm_truncated")) or len(f.get("disasm") or []) > _ROW_LIMIT,
                "decompiled": f.get("decompiled") or "", "blocks": _blocks(f), "xrefs": _xrefs(res, f.get("entry")),
                "findings": related[:50]}

    # ---- live activity: what is the AI doing right now -------------------------------------------------
    def phase_states(S, rid: str, j: dict, tasks: list[dict], current: Optional[str]) -> list[dict]:
        """Per phase: done (happened at least once), cur (happening now) or open (not reached), with a count.
        Evaluation, prioritisation and translation repeat per task, so done there means 'has happened'."""
        work = [t for t in tasks if t["kind"] != "group"]
        triage = [t for t in work if t["origin"] == "triage"]
        planned = [t for t in work if t["origin"] != "triage"]
        steps = S.step_counts(rid)
        ended = j["status"] not in ("queued", "running", "uploading")
        counts = {
            "triage": len([t for t in triage if t["status"] in ("done", "failed")]),
            "planning": len(planned),
            "analysis": len([t for t in planned if t["status"] in ("done", "failed", "skipped", "blocked")]),
            "evaluation": steps.get("evaluate", 0), "prioritization": steps.get("prioritize", 0),
            "translation": steps.get("translate", 0), "finalizing": 1 if ended else 0}
        totals = {"triage": len(triage), "analysis": len(planned)}
        out = []
        for pid in ("triage", "planning", "analysis", "evaluation", "prioritization", "translation", "finalizing"):
            n = counts[pid]
            st = "cur" if pid == current else ("done" if n else "open")
            out.append({"id": pid, "state": st, "count": n, "total": totals.get(pid)})
        return out

    def end_info(S, rid: str, j: dict) -> dict:
        """Why the job ended: engine and worker log one of END_REASONS before the job gets its final status."""
        reason = ""
        for e in S.events_after(rid, 0, 5000, "warn", ("log",)):
            m = e["message"] or ""
            if m.startswith(END_REASONS):
                reason = m
        return {"status": j["status"], "reason": reason, "finished_at": j.get("finished_at"),
                "summary_de": j.get("summary_de") or "", "summary_en": j.get("summary_en") or ""}

    @app.get("/api/jobs/{job_id}/activity")
    def activity(job_id: str):
        ref = resolve(job_id)
        S, rid, j = ref.store, ref.rid, ref.job

        def elapsed(ts):
            try:
                return int((datetime.now(timezone.utc) - datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)).total_seconds() * 1000)
            except (TypeError, ValueError):
                return 0
        tasks = S.list_tasks(rid)
        running = next((t for t in tasks if t["status"] == "running" and t["kind"] != "group"), None)
        step = None
        recent = []
        if running:
            steps = S.list_steps(running["id"])
            cur = next((s for s in reversed(steps) if s["status"] == "running"), None)
            if cur:
                step = {k: cur[k] for k in ("id", "kind", "what", "how", "why", "tool", "started_at", "input_preview")}
                step["elapsed_ms"] = elapsed(cur["started_at"])
            recent = [{"ts": s["started_at"], "kind": s["kind"], "what": s["what"], "status": s["status"],
                       "duration_ms": s["duration_ms"]} for s in steps[-10:]]
        phase = {"queued": "idle", "running": "analysis"}.get(j["status"], "finished")
        if running:
            phase = {"triage": "triage", "question": "analysis"}.get(running["kind"], "analysis")
            if step and step["kind"] in ("evaluate", "prioritize", "translate"):
                phase = {"evaluate": "evaluation", "prioritize": "prioritization", "translate": "translation"}[step["kind"]]
        state = "working" if j["status"] == "running" else ("idle" if j["status"] == "queued" else "finished")
        nxt = [{"task_id": t["id"], "title": t["title"]} for t in S.queue(rid) if t["status"] == "pending"][:3]
        phases = phase_states(S, rid, j, tasks, phase if state == "working" else None)
        return {"state": state, "phase": phase, "status": j["status"], "phases": phases,
                "end": end_info(S, rid, j) if state == "finished" else None,
                "task": ({"id": running["id"], "title": running["title"], "goal": running["goal"], "origin": running["origin"],
                          "started_at": running["started_at"], "elapsed_ms": elapsed(running["started_at"])} if running else None),
                "step": step, "model": {"name": ref.model}, "recent": recent,
                "queue_length": len(S.queue(rid)), "next": nxt}

    # ---- log, timeline, guard, audit ---------------------------------------------------------------------
    @app.get("/api/jobs/{job_id}/log")
    def log(job_id: str, after: int = Query(0, ge=0, le=MAX_SEQ), level: str = "info"):
        ref = resolve(job_id)
        ev = ref.store.events_after(ref.rid, after, 500, level, ("log",))
        last = ref.store.events_after(ref.rid, after, 5000, None)
        return {"events": [{"seq": e["seq"], "ts": e["ts"], "level": e["level"], "type": e["type"],
                            "message": e["message"], "data": e["data"]} for e in ev],
                "last_seq": last[-1]["seq"] if last else after}

    @app.get("/api/jobs/{job_id}/timeline")
    def timeline(job_id: str):
        ref = resolve(job_id)
        return [{"task_id": t["id"], "title": t["title"], "status": t["status"], "started_at": t["started_at"],
                 "duration_ms": t["duration_ms"]} for t in ref.store.list_tasks(ref.rid) if t["kind"] != "group"]

    @app.get("/api/jobs/{job_id}/guard")
    def guard(job_id: str):
        ref = resolve(job_id)
        return ref.store.list_guard_events(ref.rid)

    @app.get("/api/jobs/{job_id}/audit")
    def audit(job_id: str):
        ref = resolve(job_id)
        v = verify_file(ref.store.audit_path(ref.rid))
        return {"valid": v.valid, "entries": v.entries, "head_hash": v.head_hash, "broken_at": v.broken_at}

    # ---- live stream -------------------------------------------------------------------------------------
    @app.get("/api/jobs/{job_id}/stream")
    async def stream(job_id: str, request: Request, after: int = Query(0, ge=0, le=MAX_SEQ)):
        ref = resolve(job_id)
        last_id = request.headers.get("last-event-id")
        cursor = int(last_id) if last_id and last_id.isdigit() and len(last_id) <= 15 else after

        async def gen():
            nonlocal cursor
            idle = 0
            while not await request.is_disconnected():
                rows = ref.store.events_after(ref.rid, cursor, 200)
                for e in rows:
                    cursor = e["seq"]
                    data = e["data"]
                    if ref.imported and isinstance(data, dict) and data.get("id") == ref.rid:
                        data = {**data, "id": ref.public}
                    payload = json.dumps({"seq": e["seq"], "ts": e["ts"], "type": e["type"], "level": e["level"],
                                          "message": e["message"], "data": data}, ensure_ascii=False)
                    yield f"id: {e['seq']}\nevent: {e['type']}\ndata: {payload}\n\n"
                idle = 0 if rows else idle + 1
                if idle >= 30:
                    yield ": ping\n\n"
                    idle = 0
                await asyncio.sleep(0.5)
        return StreamingResponse(gen(), media_type="text/event-stream")

    # ---- report, prompts ---------------------------------------------------------------------------------
    @app.get("/api/jobs/{job_id}/report")
    def report(job_id: str, lang: str = "de", format: str = "md"):
        ref = resolve(job_id)
        if lang not in ("de", "en") or format not in ("md", "json"):
            raise _err(422, "bad_param", "lang is de|en, format is md|json")
        md = build_report(ref.store, ref.rid, lang, ref.model)
        if format == "json":
            return {"live": ref.job["status"] in ("queued", "running"), "lang": lang, "markdown": md}
        return PlainTextResponse(md, media_type="text/markdown; charset=utf-8")

    @app.get("/api/prompts")
    def prompts():
        return list_prompts()

    @app.get("/api/prompts/{pid}")
    def prompt_one(pid: str):
        p = PROMPTS.get(pid)
        if not p:
            raise _err(404, "not_found", "prompt not found")
        return {"id": p.id, "version": p.version, "sha256": p.sha256, "purpose": p.purpose, "text": p.body}

    # ---- examples (example/challenges) -------------------------------------------------------------------
    def _readiness(e: dict) -> dict:
        """What would make this example fail before it starts: no model, or a tool it needs is not loaded."""
        names = {t.name for t in gateway.list_tools()}
        missing = []
        if not getattr(llm, "reachable", lambda: True)():
            missing.append({"key": "llm", "text": "Sprachmodell nicht erreichbar (scripts/start.sh bzw. scripts\\start.ps1 starten)"})
        if "ghidra" in e.get("requires", []) and "list_functions" not in names:
            missing.append({"key": "ghidra", "text": KNOWN_REQUIREMENTS["ghidra"]})
        active = [r for r in e.get("runs", []) if r["status"] in ("uploading", "queued", "running")]
        return {"ready": not missing, "missing": missing, "active_job": active[0]["job_id"] if active else None}

    def _example_items() -> list[dict]:
        items = []
        for e in examples.list(store):
            items.append({**example_summary(e), **_readiness(e)})
        return items

    @app.get("/api/examples")
    def examples_list():
        items = _example_items()
        return {"available": examples.available(), "folder": _rel(examples.dir), "items": items,
                "queue_length": len([j for j in store.list_jobs() if j["status"] in ("queued", "uploading")]),
                "worker_busy": worker.state == "running"}

    @app.get("/api/examples/{cid}")
    def example_detail(cid: str):
        src = examples.source(cid)
        item = next((e for e in _example_items() if e["id"] == cid), None)
        if not src or not item:
            raise _err(404, "not_found", "example not found")
        built = examples.build(cid)
        data = built[1] if built else b""
        preview = {"kind": insp.file_kind(data[:4096]), "hex": insp.hex_rows(data[:512])}
        if preview["kind"]["kind"] == "text":
            preview["text"] = data[:4000].decode("utf-8", "replace")
        return {**item, "flag": built[0]["flag"] if built else "", **src, "preview": preview}

    def _start_example(cid: str, minutes: int | None, force: bool) -> dict:
        built = examples.build(cid)
        if not built:
            raise _err(404, "not_found", f"example {cid} not found")
        e, data = built
        state = next((x for x in _example_items() if x["id"] == cid), {"ready": True, "missing": [], "active_job": None})
        if not force and state["active_job"]:
            raise _err(409, "already_running", f"example {cid} already runs as {state['active_job']}")
        if not force and not state["ready"]:
            raise _err(409, "not_ready", "; ".join(m["text"] for m in state["missing"]))
        qs = [TargetQuestion(id=f"Q{i}", text_orig=q, text_en=q) for i, q in enumerate(e["questions"], 1)]
        # Tasks and steps like example/run_eval.py; minutes from challenge.json unless the user sets them.
        jspec = JobSpec(title=f"Beispiel {e['id']}: {e['title']}", description=e["job_description"],
                        context_info=f"harmless self-made sample (example/challenges/{e['id']})",
                        target_questions=qs, budget_max_tasks=20, budget_max_steps=200,
                        budget_max_minutes=minutes or e["budget_minutes"])
        job = _new_job(jspec, e["sample"]["name"], data)
        examples.remember(job["id"], e["id"])
        return summary(resolve(job["id"]))

    @app.post("/api/examples/{cid}/job")
    def example_start(cid: str, body: ExampleStart | None = None):
        body = body or ExampleStart()
        return _start_example(cid, body.budget_max_minutes, body.force)

    @app.post("/api/examples-batch")
    def example_batch(body: ExampleBatch | None = None):
        """Queue several examples in difficulty order; the worker runs them one after another."""
        body = body or ExampleBatch()
        items = _example_items()
        wanted = [e for e in items if body.ids is None or e["id"] in body.ids]
        started, skipped = [], []
        for e in wanted:
            if e["active_job"]:
                skipped.append({"id": e["id"], "reason": f"läuft bereits als {e['active_job']}"})
            elif not e["ready"] and not body.force:
                skipped.append({"id": e["id"], "reason": "; ".join(m["text"] for m in e["missing"])})
            else:
                started.append(_start_example(e["id"], None, True))
        return {"started": started, "skipped": skipped}

    # ---- export and import of a finished analysis --------------------------------------------------------
    @app.get("/api/jobs/{job_id}/export")
    def export(job_id: str, include_files: int = Query(0, ge=0, le=1)):
        ref = resolve(job_id)
        from sw_analyst.webui.bundle import BundleError, export_bundle
        try:
            data, filename = export_bundle(ref.store, ref.gateway, ref.rid, model=ref.model, app_version=APP_VERSION,
                                           include_files=bool(include_files))
        except BundleError as e:
            raise _err(e.status, e.code, e.message)
        # A copy stays in <data>/exports inside the project folder (virus scanner exception); the browser download
        # may land in a folder the scanner watches.
        copy = data_dir / "exports" / filename
        try:
            copy.parent.mkdir(parents=True, exist_ok=True)
            tmp = copy.with_name(copy.name + ".partial")
            tmp.write_bytes(data)
            tmp.replace(copy)
            copy_rel = f"exports/{filename}"          # relative to the data folder; ASCII by construction
        except OSError:
            copy_rel = ""
        if not ref.imported:
            ref.store.log(ref.rid, f"analysis exported ({'with' if include_files else 'without'} files)",
                          bundle_sha256=sha256_hex(data), size=len(data), copy=copy_rel)
        return Response(data, media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                                 "X-Bundle-SHA256": sha256_hex(data), "X-Export-Copy": copy_rel})

    @app.post("/api/imports")
    async def import_bundle(bundle: UploadFile = File(...)):
        if imports is None:
            raise _err(503, "no_imports", "import is not configured")
        from sw_analyst.webui.bundle import BundleError
        data = bytearray()
        while chunk := await bundle.read(1024 * 1024):
            data += chunk
            if len(data) > MAX_BUNDLE:
                raise _err(413, "too_large", f"bundle larger than {MAX_BUNDLE // 2**20} MiB")
        if import_slot.locked():
            raise _err(409, "busy", "another import is running; try again when it is done")
        async with import_slot:                    # one import at a time: each can hold several hundred MiB
            try:
                res = await asyncio.to_thread(imports.import_bundle, bytes(data))
            except BundleError as e:
                raise _err(e.status, e.code, e.message)
        return res

    @app.get("/api/imports/{job_id}")
    def import_info(job_id: str):
        info = imports.info(job_id) if imports is not None else None
        if not info:
            raise _err(404, "not_found", "import not found")
        return info

    # ---- static frontend ---------------------------------------------------------------------------------
    # Static files at the root so that relative references in index.html (app.js, styles.css) resolve.
    # Mounted last: every /api route above takes precedence.
    if STATIC_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

    return app


def _rel(p: Path) -> str:
    """Path for API responses, headers and the audit log: relative to the project, never an absolute host path."""
    try:
        return Path(p).resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return "<Datenordner außerhalb des Projekts>/" + Path(p).name


def _inside(p: Path) -> bool:
    try:
        Path(p).resolve().relative_to(PROJECT_ROOT)
        return True
    except ValueError:
        return False
