"""Dashboard API (contract: docs/architecture/api.md). Loopback only; sample text is only ever returned as data."""
from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from sw_analyst.common.audit import verify_file
from sw_analyst.common.models import JobSpec, TargetQuestion
from sw_analyst.common.store import Store
from sw_analyst.common.util import sha256_hex
from sw_analyst.guard import GUARD_VERSION, rule_count
from sw_analyst.prompts.registry import PROMPTS, list_prompts
from sw_analyst.report.builder import build_report

MAX_SAMPLE = 64 * 1024 * 1024
STATIC_DIR = Path(__file__).resolve().parent / "static"
EXAMPLES_DIR = Path(__file__).resolve().parents[3] / "example"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


class QuestionIn(BaseModel):
    id: str | None = None
    text: str = Field(min_length=1, max_length=2000)
    expected: str | None = Field(default=None, max_length=500)


class JobIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=8000)
    context_info: str = Field(default="", max_length=8000)
    focus: str = Field(default="", max_length=2000)
    target_questions: list[QuestionIn] = Field(default_factory=list, max_length=20)
    emulation_opt_in: bool = False
    # The dashboard sends no budget: the result counts, not the duration. Defaults are the upper limits.
    budget_max_tasks: int = Field(default=300, ge=5, le=300)
    budget_max_steps: int = Field(default=5000, ge=20, le=5000)
    budget_max_minutes: int = Field(default=1440, ge=1, le=1440)


def _err(status: int, code: str, msg: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": {"code": code, "message": msg}})


def job_summary(j: dict) -> dict:
    keys = ("id", "title", "status", "sample_name", "sample_sha256", "detected_type", "recipe", "created_at",
            "started_at", "finished_at", "duration_ms")
    return {k: j.get(k) for k in keys}


def load_examples(directory: Path) -> tuple[dict[str, dict], dict]:
    """Challenges from example/ with their harmless, in-memory sample builders. A missing or broken folder means
    no examples, never a startup error."""
    try:
        spec = importlib.util.spec_from_file_location("sw_example_samples", directory / "samples.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        found = {}
        for f in sorted(directory.glob("challenges/*/challenge.json")):
            c = json.loads(f.read_text(encoding="utf-8"))
            file_ok = not c["sample"].get("file") or (f.parent / c["sample"]["file"]).is_file()
            if c["id"] == f.parent.name and c["sample"]["builder"] in mod.BUILDERS and file_ok:
                found[c["id"]] = c
        return found, mod.BUILDERS
    except Exception as e:  # noqa: BLE001 - examples are optional
        logging.getLogger("sw_analyst").warning("examples not loaded from %s: %s", directory, e)
        return {}, {}


def example_view(c: dict) -> dict:
    """What the form may show. The flag, the goal and the test notes stay on the server."""
    return {"id": c["id"], "title": c["title"], "level": c.get("level", ""), "description": c["description"],
            "sample_name": c["sample"]["name"], "job_description": c["job_description"],
            "questions": list(c["questions"])}


SPA_ROUTES = ("new", "prompts", "job")  # first path segment of the client routes in static/app.js parseRoute()


class _SpaFiles(StaticFiles):
    """Static files plus index.html for client-side routes (/job/..., /new), so URLs need no '#'."""

    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as e:
            rel = path.replace(chr(92), "/")  # Starlette hands over OS separators (backslash on Windows)
            # Only the client routes of app.js fall back to index.html. Everything else (api, docs, traversal
            # paths that the client normalised) stays 404 (tests/forensic/test_api_security.py).
            if (e.status_code == 404 and rel.split("/")[0] in SPA_ROUTES
                    and "." not in rel.rsplit("/", 1)[-1]):
                return await super().get_response("index.html", scope)
            raise


def create_app(store: Store, worker, gateway, llm, translator=None, report_model: str = "", port: int = 8765,
               examples_dir: Path | None = None) -> FastAPI:
    examples, builders = load_examples(examples_dir or EXAMPLES_DIR)
    allowed_origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
    app = FastAPI(title="sw-analyst", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def security(request: Request, call_next):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin not in allowed_origins:
                return JSONResponse({"error": {"code": "forbidden_origin", "message": "invalid Origin"}}, status_code=403)
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

    def need_job(job_id: str) -> dict:
        j = store.get_job(job_id)
        if not j:
            raise _err(404, "not_found", f"job {job_id} does not exist")
        return j

    # ---- system --------------------------------------------------------------------------------------
    @app.get("/api/system")
    def system():
        reach = getattr(llm, "reachable", lambda: True)()
        return {"version": "0.1.0", "worker": {"state": worker.state, "job_id": worker.current_job},
                "llm": {"reachable": bool(reach), "model": llm.model, "base_url": getattr(llm, "base_url", "")},
                "guard": {"active": True, "rules": rule_count(), "version": GUARD_VERSION},
                "gateway": {"kind": "dev", "tools": len(gateway.list_tools())},
                "queue_length": len([j for j in store.list_jobs() if j["status"] == "queued"])}

    # ---- jobs ----------------------------------------------------------------------------------------
    @app.get("/api/jobs")
    def jobs():
        return [job_summary(j) for j in store.list_jobs()]

    @app.get("/api/examples")
    def example_list():
        return [example_view(c) for c in examples.values()]

    @app.post("/api/jobs")
    async def create_job(spec: str = Form(...), sample: UploadFile | None = File(None),
                         example: str | None = Form(None)):
        try:
            data_in = JobIn.model_validate_json(spec)
        except ValidationError as e:
            raise _err(422, "invalid_spec", e.errors()[0]["msg"] + " @ " + ".".join(map(str, e.errors()[0]["loc"])))
        if data_in.emulation_opt_in:
            raise _err(422, "emulation_disabled", "emulation is not available in this phase")
        data = bytearray()
        if example:
            c = examples.get(example)
            if not c:
                raise _err(422, "unknown_example", f"example {example} does not exist")
            data = bytearray(builders[c["sample"]["builder"]]())
            sample_name = c["sample"]["name"]
        else:
            if sample is None:
                raise _err(422, "empty_sample", "choose an example or upload a sample file")
            while chunk := await sample.read(1024 * 1024):
                data += chunk
                if len(data) > MAX_SAMPLE:
                    raise _err(413, "too_large", "sample larger than 64 MiB")
            sample_name = sample.filename or "sample"
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
        name = Path(sample_name).name[:120]
        job = store.create_job(jspec, name, sha256_hex(bytes(data)))
        gateway.store_sample(job["id"], bytes(data))
        return job_summary(job)

    @app.get("/api/jobs/{job_id}")
    def job_detail(job_id: str):
        j = need_job(job_id)
        return {"summary": job_summary(j), "spec": j["spec"], "progress": store.progress(job_id),
                "totals": store.totals(job_id)}

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel(job_id: str):
        j = need_job(job_id)
        if j["status"] == "queued":
            return job_summary(store.update_job(job_id, status="cancelled", finished_at=j["created_at"]))
        if j["status"] == "running":
            return job_summary(store.update_job(job_id, cancel_requested=1))
        return job_summary(j)

    # ---- tree, queue, task -----------------------------------------------------------------------------
    def node(t: dict) -> dict:
        keys = ("id", "parent_id", "seq", "title", "kind", "origin", "status", "priority", "reason", "started_at",
                "finished_at", "duration_ms", "summary_en", "summary_de")
        return {**{k: t.get(k) for k in keys}, "children": []}

    @app.get("/api/jobs/{job_id}/tree")
    def tree(job_id: str):
        need_job(job_id)
        nodes = {t["id"]: node(t) for t in store.list_tasks(job_id)}
        roots = []
        for n in nodes.values():
            parent = nodes.get(n["parent_id"])
            (parent["children"] if parent else roots).append(n)
        return roots

    @app.get("/api/jobs/{job_id}/queue")
    def queue(job_id: str):
        need_job(job_id)
        return [{"task_id": t["id"], "title": t["title"], "origin": t["origin"], "status": t["status"],
                 "priority": t["priority"], "reason": t["reason"], "done_when": t["params"].get("done_when") or "",
                 "position": i + 1}
                for i, t in enumerate(store.queue(job_id))]

    @app.get("/api/jobs/{job_id}/tasks/{task_id}")
    def task_detail(job_id: str, task_id: str):
        need_job(job_id)
        t = store.get_task(task_id)
        if not t or t["job_id"] != job_id:
            raise _err(404, "not_found", "task not found")
        steps = store.list_steps(task_id)
        fids = [f["id"] for f in store.list_findings(job_id) if f["task_id"] == task_id]
        eids = [s["evidence_id"] for s in steps if s["evidence_id"]]
        return {"task": node(t), "prompt": {"id": t["prompt_id"], "version": t["prompt_version"],
                                            "sha256": t["prompt_sha256"], "text": t["prompt_text"]},
                "steps": steps, "finding_ids": fids, "evidence_ids": eids}

    # ---- results -----------------------------------------------------------------------------------------
    @app.get("/api/jobs/{job_id}/findings")
    def findings(job_id: str):
        need_job(job_id)
        return store.list_findings(job_id)

    @app.get("/api/jobs/{job_id}/answers")
    def answers(job_id: str):
        need_job(job_id)
        out = []
        for a in store.list_answers(job_id):
            a["match"] = None if a["match"] is None else bool(a["match"])
            out.append(a)
        return out

    @app.get("/api/jobs/{job_id}/evidence")
    def evidence(job_id: str):
        need_job(job_id)
        return store.list_evidence(job_id)

    @app.get("/api/jobs/{job_id}/evidence/{eid}")
    def evidence_one(job_id: str, eid: str):
        need_job(job_id)
        e = store.get_evidence(eid)
        if not e or e["job_id"] != job_id:
            raise _err(404, "not_found", "evidence not found")
        return e

    # ---- code viewer -------------------------------------------------------------------------------------
    @app.get("/api/jobs/{job_id}/files")
    def files(job_id: str):
        need_job(job_id)
        return gateway.list_files(job_id)

    @app.get("/api/jobs/{job_id}/files/content")
    def file_content(job_id: str, path: str, start: int = 1, end: int = 400):
        need_job(job_id)
        try:
            res = gateway.read_file_lines(job_id, path, max(start, 1), min(end, start + 399))
        except Exception as e:  # tool-level problems (jail, missing file) become a clean 400
            raise _err(400, "bad_path", str(e))
        res["annotations"] = [{"id": a["id"], "line_start": a["line_start"], "line_end": a["line_end"],
                               "text_en": a["text_en"], "text_de": a["text_de"], "finding_id": a["finding_id"],
                               "evidence_id": a["evidence_id"], "kind": a["kind"]}
                              for a in store.list_annotations(job_id, path)]
        return res


    # ---- live activity: what is the AI doing right now -------------------------------------------------
    @app.get("/api/jobs/{job_id}/activity")
    def activity(job_id: str):
        from datetime import datetime, timezone
        j = need_job(job_id)

        def elapsed(ts):
            try:
                return int((datetime.now(timezone.utc) - datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)).total_seconds() * 1000)
            except (TypeError, ValueError):
                return 0
        tasks = store.list_tasks(job_id)
        running = next((t for t in tasks if t["status"] == "running" and t["kind"] != "group"), None)
        step = None
        recent = []
        if running:
            steps = store.list_steps(running["id"])
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
        nxt = [{"task_id": t["id"], "title": t["title"]} for t in store.queue(job_id) if t["status"] == "pending"][:3]
        return {"state": state, "phase": phase,
                "task": ({"id": running["id"], "title": running["title"], "goal": running["goal"], "origin": running["origin"],
                          "started_at": running["started_at"], "elapsed_ms": elapsed(running["started_at"])} if running else None),
                "step": step, "model": {"name": report_model or llm.model}, "recent": recent,
                "queue_length": len(store.queue(job_id)), "next": nxt}

    # ---- log, timeline, guard, audit ---------------------------------------------------------------------
    @app.get("/api/jobs/{job_id}/log")
    def log(job_id: str, after: int = 0, level: str = "info"):
        need_job(job_id)
        ev = store.events_after(job_id, after, 500, level, ("log",))
        last = store.events_after(job_id, after, 5000, None)
        return {"events": [{"seq": e["seq"], "ts": e["ts"], "level": e["level"], "type": e["type"],
                            "message": e["message"], "data": e["data"]} for e in ev],
                "last_seq": last[-1]["seq"] if last else after}

    @app.get("/api/jobs/{job_id}/timeline")
    def timeline(job_id: str):
        need_job(job_id)
        return [{"task_id": t["id"], "title": t["title"], "status": t["status"], "started_at": t["started_at"],
                 "duration_ms": t["duration_ms"]} for t in store.list_tasks(job_id) if t["kind"] != "group"]

    @app.get("/api/jobs/{job_id}/guard")
    def guard(job_id: str):
        need_job(job_id)
        return store.list_guard_events(job_id)

    @app.get("/api/jobs/{job_id}/audit")
    def audit(job_id: str):
        need_job(job_id)
        v = verify_file(store.audit_path(job_id))
        return {"valid": v.valid, "entries": v.entries, "head_hash": v.head_hash, "broken_at": v.broken_at}

    # ---- live stream -------------------------------------------------------------------------------------
    @app.get("/api/jobs/{job_id}/stream")
    async def stream(job_id: str, request: Request, after: int = 0):
        need_job(job_id)
        last_id = request.headers.get("last-event-id")
        cursor = int(last_id) if last_id and last_id.isdigit() else after

        async def gen():
            nonlocal cursor
            idle = 0
            while not await request.is_disconnected():
                rows = store.events_after(job_id, cursor, 200)
                for e in rows:
                    cursor = e["seq"]
                    payload = json.dumps({"seq": e["seq"], "ts": e["ts"], "type": e["type"], "level": e["level"],
                                          "message": e["message"], "data": e["data"]}, ensure_ascii=False)
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
        j = need_job(job_id)
        if lang not in ("de", "en") or format not in ("md", "json"):
            raise _err(422, "bad_param", "lang is de|en, format is md|json")
        md = build_report(store, job_id, lang, report_model or llm.model)
        if format == "json":
            return {"live": j["status"] in ("queued", "running"), "lang": lang, "markdown": md}
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

    # ---- static frontend ---------------------------------------------------------------------------------
    # Static files at the root so that relative references in index.html (app.js, styles.css) resolve.
    # Mounted last: every /api route above takes precedence.
    if STATIC_DIR.is_dir():
        app.mount("/", _SpaFiles(directory=str(STATIC_DIR), html=True), name="static")

    return app
