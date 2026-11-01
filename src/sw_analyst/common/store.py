"""SQLite persistence for jobs, tasks, steps, evidence, findings, answers and events.

Every mutating method also writes an event row. The event table is the single source for
the live stream, the background log and the per-job audit chain (logs/<job>/audit.jsonl).
Thread-safe: one connection guarded by a re-entrant lock.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional

from sw_analyst.common.audit import AuditLog
from sw_analyst.common.models import JobSpec
from sw_analyst.common.util import preview, sha256_hex, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, title TEXT, description TEXT, context_info TEXT, focus TEXT, spec_json TEXT,
  sample_name TEXT, sample_sha256 TEXT, detected_type TEXT DEFAULT '', recipe TEXT DEFAULT '',
  status TEXT, created_at TEXT, started_at TEXT, finished_at TEXT, duration_ms INTEGER DEFAULT 0,
  cancel_requested INTEGER DEFAULT 0, summary_en TEXT DEFAULT '', summary_de TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY, seq INTEGER, job_id TEXT, parent_id TEXT, title TEXT, goal TEXT, kind TEXT,
  origin TEXT, status TEXT, priority INTEGER, reason TEXT DEFAULT '', prompt_id TEXT DEFAULT '',
  prompt_version TEXT DEFAULT '', prompt_sha256 TEXT DEFAULT '', prompt_text TEXT DEFAULT '',
  params_json TEXT DEFAULT '{}', attempts INTEGER DEFAULT 0, created_at TEXT, started_at TEXT,
  finished_at TEXT, duration_ms INTEGER DEFAULT 0, summary_en TEXT DEFAULT '', summary_de TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS ix_tasks_job ON tasks(job_id, status, priority, seq);
CREATE TABLE IF NOT EXISTS steps (
  id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, task_id TEXT, idx INTEGER, kind TEXT, what TEXT,
  how TEXT, why TEXT, status TEXT, started_at TEXT, duration_ms INTEGER DEFAULT 0, tool TEXT DEFAULT '',
  input_preview TEXT DEFAULT '', output_preview TEXT DEFAULT '', evidence_id TEXT);
CREATE INDEX IF NOT EXISTS ix_steps_task ON steps(task_id, idx);
CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY, job_id TEXT, task_id TEXT, tool TEXT, tool_version TEXT, params_json TEXT,
  result_sha256 TEXT, text TEXT, source_ref_json TEXT, injection_flags_json TEXT DEFAULT '[]', created_at TEXT);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, job_id TEXT, task_id TEXT, statement_en TEXT, statement_de TEXT DEFAULT '',
  status TEXT, reject_reason TEXT DEFAULT '', evidence_ids_json TEXT, quotes_json TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS annotations (
  id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, task_id TEXT, file TEXT, line_start INTEGER,
  line_end INTEGER, text_en TEXT, text_de TEXT DEFAULT '', finding_id TEXT, evidence_id TEXT, kind TEXT);
CREATE TABLE IF NOT EXISTS answers (
  job_id TEXT, question_id TEXT, text_orig TEXT, text_en TEXT, expected TEXT, answer_en TEXT DEFAULT '',
  answer_de TEXT DEFAULT '', status TEXT DEFAULT 'pending', finding_ids_json TEXT DEFAULT '[]',
  evaluation_en TEXT DEFAULT '', evaluation_de TEXT DEFAULT '', match INTEGER, PRIMARY KEY (job_id, question_id));
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, ts TEXT, level TEXT, type TEXT, message TEXT, data_json TEXT);
CREATE INDEX IF NOT EXISTS ix_events_job ON events(job_id, seq);
CREATE TABLE IF NOT EXISTS guard_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, task_id TEXT, ts TEXT, stage TEXT, rule TEXT,
  severity TEXT, action TEXT, snippet TEXT);
CREATE TABLE IF NOT EXISTS translations (
  direction TEXT, text_sha256 TEXT, translated TEXT, PRIMARY KEY (direction, text_sha256));
"""

# tables that hold the rows of one job (export/import); counters and translations are per installation
EXPORT_TABLES = ("jobs", "tasks", "steps", "evidence", "findings", "annotations", "answers", "events", "guard_events")

_JSON_COLS = {"spec_json", "params_json", "source_ref_json", "injection_flags_json",
              "evidence_ids_json", "quotes_json", "finding_ids_json", "data_json"}


def _row(row: sqlite3.Row | None) -> Optional[dict]:
    if row is None:
        return None
    d = dict(row)
    for k in list(d):
        if k in _JSON_COLS:
            d[k[:-5]] = json.loads(d.pop(k) or "null")
    return d


class Store:
    def __init__(self, db_path: str | Path, log_dir: str | Path | None = None):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_dir = Path(log_dir) if log_dir else self.db_path.parent / "logs"
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.db_path), check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(SCHEMA)
        self._audits: dict[str, AuditLog] = {}

    # ---- low level -------------------------------------------------------------------------
    def _q(self, sql: str, args: tuple = ()) -> list[dict]:
        with self._lock:
            return [_row(r) for r in self._db.execute(sql, args).fetchall()]

    def _one(self, sql: str, args: tuple = ()) -> Optional[dict]:
        rows = self._q(sql, args)
        return rows[0] if rows else None

    def _x(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            return self._db.execute(sql, args).lastrowid

    def _next(self, name: str) -> int:
        with self._lock:
            self._db.execute("INSERT INTO counters(name,value) VALUES(?,1) "
                             "ON CONFLICT(name) DO UPDATE SET value=value+1", (name,))
            return self._db.execute("SELECT value FROM counters WHERE name=?", (name,)).fetchone()[0]

    def audit_log(self, job_id: str) -> AuditLog:
        with self._lock:
            if job_id not in self._audits:
                self._audits[job_id] = AuditLog(self.log_dir / job_id / "audit.jsonl")
            return self._audits[job_id]

    def audit_path(self, job_id: str) -> Path:
        return self.log_dir / job_id / "audit.jsonl"

    def emit(self, job_id: str, type_: str, data: Any, *, level: str = "info", message: str = "") -> int:
        ts = utcnow()
        payload = json.dumps(data, ensure_ascii=False, default=str)
        seq = self._x("INSERT INTO events(job_id,ts,level,type,message,data_json) VALUES(?,?,?,?,?,?)",
                      (job_id, ts, level, type_, message, payload))
        try:
            self.audit_log(job_id).append({"seq": seq, "ts": ts, "level": level, "type": type_,
                                           "message": message, "data_sha256": sha256_hex(payload),
                                           "data": json.loads(payload) if len(payload) < 4000 else None})
        except OSError:
            pass  # the DB event is still stored; audit write problems must not kill the job
        return seq

    def log(self, job_id: str, message: str, level: str = "info", **data) -> None:
        self.emit(job_id, "log", data, level=level, message=message)

    # ---- jobs ------------------------------------------------------------------------------
    def create_job(self, spec: JobSpec, sample_name: str, sample_sha256: str, status: str = "queued") -> dict:
        """status 'uploading' keeps the worker away until the caller has stored the sample (F-10)."""
        n = self._next("job")
        job_id = f"J-{n:04d}"
        self._x("INSERT INTO jobs(id,title,description,context_info,focus,spec_json,sample_name,sample_sha256,"
                "status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (job_id, spec.title, spec.description, spec.context_info, spec.focus,
                 spec.model_dump_json(), sample_name, sample_sha256, status, utcnow()))
        for q in spec.target_questions:
            self._x("INSERT INTO answers(job_id,question_id,text_orig,text_en,expected) VALUES(?,?,?,?,?)",
                    (job_id, q.id, q.text_orig, q.text_en, q.expected))
        job = self.get_job(job_id)
        self.emit(job_id, "job", job, message="job created")
        return job

    def get_job(self, job_id: str) -> Optional[dict]:
        return self._one("SELECT * FROM jobs WHERE id=?", (job_id,))

    def list_jobs(self) -> list[dict]:
        return self._q("SELECT * FROM jobs ORDER BY created_at DESC, id DESC")

    def update_job(self, job_id: str, **fields) -> dict:
        if fields:
            cols = ",".join(f"{k}=?" for k in fields)
            self._x(f"UPDATE jobs SET {cols} WHERE id=?", (*fields.values(), job_id))
        job = self.get_job(job_id)
        self.emit(job_id, "job", job, message=f"job update: {', '.join(fields)}")
        return job

    def next_queued_job(self) -> Optional[dict]:
        return self._one("SELECT * FROM jobs WHERE status='queued' ORDER BY created_at, id LIMIT 1")

    def running_job(self) -> Optional[dict]:
        return self._one("SELECT * FROM jobs WHERE status='running' LIMIT 1")

    def update_spec(self, job_id: str, spec: JobSpec) -> None:
        self._x("UPDATE jobs SET spec_json=? WHERE id=?", (spec.model_dump_json(), job_id))
        for q in spec.target_questions:
            self._x("UPDATE answers SET text_en=? WHERE job_id=? AND question_id=?", (q.text_en, job_id, q.id))

    def set_question_text_en(self, job_id: str, qid: str, text_en: str) -> None:
        self._x("UPDATE answers SET text_en=? WHERE job_id=? AND question_id=?", (text_en, job_id, qid))
        spec = JobSpec.model_validate(self.get_job(job_id)["spec"])
        for q in spec.target_questions:
            if q.id == qid:
                q.text_en = text_en
        self._x("UPDATE jobs SET spec_json=? WHERE id=?", (spec.model_dump_json(), job_id))

    # ---- tasks -----------------------------------------------------------------------------
    def add_task(self, job_id: str, *, title: str, goal: str, kind: str, origin: str, priority: int,
                 parent_id: str | None = None, reason: str = "", params: dict | None = None) -> dict:
        n = self._next("task")
        tid = f"T-{n:06d}"
        seq = self._next(f"taskseq:{job_id}")
        self._x("INSERT INTO tasks(id,seq,job_id,parent_id,title,goal,kind,origin,status,priority,reason,"
                "params_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (tid, seq, job_id, parent_id, title, goal, kind, origin, "pending", priority, reason,
                 json.dumps(params or {}), utcnow()))
        t = self.get_task(tid)
        self.emit(job_id, "task", t, message=f"task added ({origin}): {title}")
        return t

    def get_task(self, task_id: str) -> Optional[dict]:
        return self._one("SELECT * FROM tasks WHERE id=?", (task_id,))

    def update_task(self, task_id: str, **fields) -> dict:
        if fields:
            cols = ",".join(f"{k}=?" for k in fields)
            self._x(f"UPDATE tasks SET {cols} WHERE id=?", (*fields.values(), task_id))
        t = self.get_task(task_id)
        self.emit(t["job_id"], "task", t, message=f"task {t['status']}: {t['title']}")
        return t

    def list_tasks(self, job_id: str) -> list[dict]:
        return self._q("SELECT * FROM tasks WHERE job_id=? ORDER BY seq", (job_id,))

    def next_pending_task(self, job_id: str) -> Optional[dict]:
        return self._one("SELECT * FROM tasks WHERE job_id=? AND status='pending' AND kind!='group' "
                         "ORDER BY priority, seq LIMIT 1", (job_id,))

    def queue(self, job_id: str) -> list[dict]:
        return self._q("SELECT * FROM tasks WHERE job_id=? AND kind!='group' AND status IN ('running','pending') "
                       "ORDER BY CASE status WHEN 'running' THEN 0 ELSE 1 END, priority, seq", (job_id,))

    def has_similar_task(self, job_id: str, norm_title: str) -> bool:
        for t in self.list_tasks(job_id):
            if " ".join(t["title"].lower().split()) == norm_title:
                return True
        return False

    # ---- steps -----------------------------------------------------------------------------
    def begin_step(self, job_id: str, task_id: str, kind: str, what: str, *, how: str = "", why: str = "",
                   tool: str = "", input_preview: str = "") -> int:
        idx = (self._one("SELECT COALESCE(MAX(idx),0)+1 AS n FROM steps WHERE task_id=?", (task_id,)) or {"n": 1})["n"]
        sid = self._x("INSERT INTO steps(job_id,task_id,idx,kind,what,how,why,status,started_at,tool,input_preview)"
                      " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                      (job_id, task_id, idx, kind, what, how, why, "running", utcnow(), tool,
                       preview(input_preview)))
        self.emit(job_id, "step", self.get_step(sid), message=f"step {kind}: {what}")
        return sid

    def finish_step(self, step_id: int, *, status: str, duration_ms: int, output_preview: str = "",
                    evidence_id: str | None = None, why: str | None = None, how: str | None = None) -> dict:
        sets = {"status": status, "duration_ms": duration_ms, "output_preview": preview(output_preview),
                "evidence_id": evidence_id}
        if why is not None:
            sets["why"] = why
        if how is not None:
            sets["how"] = how
        cols = ",".join(f"{k}=?" for k in sets)
        self._x(f"UPDATE steps SET {cols} WHERE id=?", (*sets.values(), step_id))
        s = self.get_step(step_id)
        self.emit(s["job_id"], "step", s, message=f"step {status}: {s['what']} ({duration_ms} ms)")
        return s

    def get_step(self, step_id: int) -> Optional[dict]:
        return self._one("SELECT * FROM steps WHERE id=?", (step_id,))

    def list_steps(self, task_id: str) -> list[dict]:
        return self._q("SELECT * FROM steps WHERE task_id=? ORDER BY idx", (task_id,))

    def count_steps(self, job_id: str) -> int:
        return self._one("SELECT COUNT(*) AS n FROM steps WHERE job_id=?", (job_id,))["n"]

    # ---- evidence --------------------------------------------------------------------------
    def add_evidence(self, job_id: str, task_id: str | None, tool: str, tool_version: str, params: dict,
                     text: str, source_ref: dict | None = None, injection_flags: list | None = None) -> dict:
        eid = f"EV-{self._next('evidence'):06d}"
        self._x("INSERT INTO evidence(id,job_id,task_id,tool,tool_version,params_json,result_sha256,text,"
                "source_ref_json,injection_flags_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (eid, job_id, task_id, tool, tool_version, json.dumps(params, default=str), sha256_hex(text), text,
                 json.dumps(source_ref or {}), json.dumps(injection_flags or []), utcnow()))
        ev = self.get_evidence(eid)
        self.emit(job_id, "log", {"evidence_id": eid, "tool": tool, "sha256": ev["result_sha256"]},
                  message=f"evidence {eid} from {tool}")
        return ev

    def get_evidence(self, eid: str) -> Optional[dict]:
        return self._one("SELECT * FROM evidence WHERE id=?", (eid,))

    def find_evidence(self, job_id: str, tool: str, params: dict) -> Optional[dict]:
        """Earlier successful result of the same deterministic call in this job, if any."""
        for ev in self._q("SELECT * FROM evidence WHERE job_id=? AND tool=? ORDER BY id", (job_id, tool)):
            if ev["params"] == params and not ev["text"].startswith("[tool error]"):
                return ev
        return None

    def evidence_index(self, job_id: str, limit: int = 12) -> list[dict]:
        """Newest evidence as id, tool, parameters, without the (untrusted) text."""
        rows = self._q("SELECT id,tool,params_json FROM evidence WHERE job_id=? ORDER BY id DESC LIMIT ?", (job_id, limit))
        return list(reversed(rows))

    def list_evidence(self, job_id: str) -> list[dict]:
        rows = self._q("SELECT id,task_id,tool,tool_version,params_json,result_sha256,LENGTH(text) AS size,"
                       "SUBSTR(text,1,240) AS preview,injection_flags_json,created_at "
                       "FROM evidence WHERE job_id=? ORDER BY id", (job_id,))
        return rows

    # ---- findings, annotations, answers ----------------------------------------------------
    def add_finding(self, job_id: str, task_id: str, statement_en: str, status: str, evidence_ids: list[str],
                    quotes: list[dict], reject_reason: str = "") -> dict:
        fid = f"F-{self._next('finding'):06d}"
        self._x("INSERT INTO findings(id,job_id,task_id,statement_en,status,reject_reason,evidence_ids_json,"
                "quotes_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (fid, job_id, task_id, statement_en, status, reject_reason, json.dumps(evidence_ids),
                 json.dumps(quotes), utcnow()))
        f = self.get_finding(fid)
        self.emit(job_id, "finding", f, message=f"finding {fid} [{status}]")
        return f

    def get_finding(self, fid: str) -> Optional[dict]:
        return self._one("SELECT * FROM findings WHERE id=?", (fid,))

    def list_findings(self, job_id: str, status: str | None = None) -> list[dict]:
        if status:
            return self._q("SELECT * FROM findings WHERE job_id=? AND status=? ORDER BY id", (job_id, status))
        return self._q("SELECT * FROM findings WHERE job_id=? ORDER BY id", (job_id,))

    def set_finding_de(self, fid: str, text_de: str) -> dict:
        self._x("UPDATE findings SET statement_de=? WHERE id=?", (text_de, fid))
        f = self.get_finding(fid)
        self.emit(f["job_id"], "finding", f, message=f"finding {fid} translated")
        return f

    def add_annotation(self, job_id: str, task_id: str, file: str, line_start: int, line_end: int, text_en: str,
                       kind: str = "note", finding_id: str | None = None, evidence_id: str | None = None) -> dict:
        aid = self._x("INSERT INTO annotations(job_id,task_id,file,line_start,line_end,text_en,finding_id,"
                      "evidence_id,kind) VALUES(?,?,?,?,?,?,?,?,?)",
                      (job_id, task_id, file, line_start, line_end, text_en, finding_id, evidence_id, kind))
        a = self._one("SELECT * FROM annotations WHERE id=?", (aid,))
        self.emit(job_id, "annotation", a, message=f"annotation {file}:{line_start}-{line_end}")
        return a

    def set_annotation_de(self, aid: int, text_de: str) -> None:
        self._x("UPDATE annotations SET text_de=? WHERE id=?", (text_de, aid))

    def list_annotations(self, job_id: str, file: str | None = None) -> list[dict]:
        if file:
            return self._q("SELECT * FROM annotations WHERE job_id=? AND file=? ORDER BY line_start", (job_id, file))
        return self._q("SELECT * FROM annotations WHERE job_id=? ORDER BY file, line_start", (job_id,))

    def get_answer(self, job_id: str, qid: str) -> Optional[dict]:
        return self._one("SELECT * FROM answers WHERE job_id=? AND question_id=?", (job_id, qid))

    def list_answers(self, job_id: str) -> list[dict]:
        return self._q("SELECT * FROM answers WHERE job_id=? ORDER BY question_id", (job_id,))

    def update_answer(self, job_id: str, qid: str, **fields) -> dict:
        if "finding_ids" in fields:
            fields["finding_ids_json"] = json.dumps(fields.pop("finding_ids"))
        cols = ",".join(f"{k}=?" for k in fields)
        self._x(f"UPDATE answers SET {cols} WHERE job_id=? AND question_id=?", (*fields.values(), job_id, qid))
        a = self.get_answer(job_id, qid)
        self.emit(job_id, "answer", a, message=f"answer {qid}: {a['status']}")
        return a

    # ---- guard, events, translations -------------------------------------------------------
    def add_guard_event(self, job_id: str, task_id: str | None, stage: str, rule: str, severity: str,
                        action: str, snippet: str) -> dict:
        gid = self._x("INSERT INTO guard_events(job_id,task_id,ts,stage,rule,severity,action,snippet) "
                      "VALUES(?,?,?,?,?,?,?,?)", (job_id, task_id, utcnow(), stage, rule, severity, action,
                                                  preview(snippet, 200)))
        g = self._one("SELECT * FROM guard_events WHERE id=?", (gid,))
        self.emit(job_id, "guard", g, level="warn", message=f"guard {action}: {rule} ({severity})")
        return g

    def list_guard_events(self, job_id: str) -> list[dict]:
        return self._q("SELECT * FROM guard_events WHERE job_id=? ORDER BY id", (job_id,))

    def events_after(self, job_id: str, after: int = 0, limit: int = 500, level: str | None = None,
                     types: tuple[str, ...] | None = None) -> list[dict]:
        sql, args = "SELECT * FROM events WHERE job_id=? AND seq>?", [job_id, after]
        if level and level != "debug":
            order = {"info": ("info", "warn", "error"), "warn": ("warn", "error"), "error": ("error",)}
            lv = order.get(level, ("info", "warn", "error"))
            sql += f" AND level IN ({','.join('?' * len(lv))})"
            args += list(lv)
        if types:
            sql += f" AND type IN ({','.join('?' * len(types))})"
            args += list(types)
        sql += " ORDER BY seq LIMIT ?"
        args.append(limit)
        return self._q(sql, tuple(args))

    # TranslationCache protocol (sw_analyst.translate.pipeline)
    def get(self, direction: str, text_sha256: str) -> Optional[str]:
        r = self._one("SELECT translated FROM translations WHERE direction=? AND text_sha256=?",
                      (direction, text_sha256))
        return r["translated"] if r else None

    def put(self, direction: str, text_sha256: str, translated: str) -> None:
        self._x("INSERT OR REPLACE INTO translations(direction,text_sha256,translated) VALUES(?,?,?)",
                (direction, text_sha256, translated))

    # ---- aggregates ------------------------------------------------------------------------
    def progress(self, job_id: str) -> dict:
        rows = self._q("SELECT status, COUNT(*) AS n FROM tasks WHERE job_id=? AND kind!='group' GROUP BY status",
                       (job_id,))
        c = {r["status"]: r["n"] for r in rows}
        total = sum(c.values())
        finished = c.get("done", 0) + c.get("failed", 0) + c.get("skipped", 0) + c.get("blocked", 0)
        return {"tasks_total": total, "done": c.get("done", 0), "pending": c.get("pending", 0),
                "running": c.get("running", 0), "failed": c.get("failed", 0), "blocked": c.get("blocked", 0),
                "percent": round(100 * finished / total) if total else 0}

    def step_counts(self, job_id: str) -> dict[str, int]:
        """Number of steps per kind for one job (dashboard: which phases have happened)."""
        return {r["kind"]: r["n"] for r in self._q("SELECT kind, COUNT(*) AS n FROM steps WHERE job_id=? GROUP BY kind",
                                                   (job_id,))}

    def totals(self, job_id: str) -> dict:
        r = self._one("SELECT COUNT(*) AS steps, "
                      "SUM(CASE WHEN kind='tool' THEN 1 ELSE 0 END) AS tools, "
                      "SUM(CASE WHEN kind='prompt' THEN 1 ELSE 0 END) AS llm, "
                      "COALESCE(SUM(duration_ms),0) AS ms FROM steps WHERE job_id=?", (job_id,))
        return {"steps": r["steps"], "tool_calls": r["tools"] or 0, "llm_calls": r["llm"] or 0,
                "duration_ms": r["ms"]}

    # ---- export / import of one job (sw_analyst.webui.bundle) --------------------------------
    def export_rows(self, job_id: str) -> dict[str, list[dict]]:
        """Raw rows of one job from every job table; JSON columns stay the stored strings. Read-only."""
        out: dict[str, list[dict]] = {}
        with self._lock:      # one consistent snapshot against writers of this store
            for table in EXPORT_TABLES:
                key = "id" if table == "jobs" else "job_id"
                cur = self._db.execute(f"SELECT * FROM {table} WHERE {key}=? ORDER BY rowid", (job_id,))
                out[table] = [dict(r) for r in cur.fetchall()]
        return out

    def import_rows(self, rows: dict[str, list[dict]]) -> None:
        """Insert rows from export_rows() into this separate store, unchanged and in one transaction.

        Table and column names come only from the schema (PRAGMA table_info), unknown names raise ValueError,
        values must be NULL, int, float or str. No events and no audit entries: the imported audit file is copied
        byte-exact and an emit here would extend it.
        """
        if not isinstance(rows, dict):
            raise ValueError("rows must map table names to row lists")
        with self._lock:
            allowed = {t: {c["name"] for c in self._db.execute(f"PRAGMA table_info({t})").fetchall()}
                       for t in EXPORT_TABLES}
            plan: list[tuple[str, tuple]] = []
            for table, items in rows.items():
                if table not in allowed:
                    raise ValueError(f"unknown table {str(table)[:40]!r}")
                if not isinstance(items, list):
                    raise ValueError(f"rows of {table} must be a list")
                for row in items:
                    if not isinstance(row, dict) or not row:
                        raise ValueError(f"a row of {table} is not a non-empty object")
                    for col, val in row.items():
                        if col not in allowed[table]:
                            raise ValueError(f"unknown column {table}.{str(col)[:40]!r}")
                        if val is not None and type(val) not in (int, float, str):
                            raise ValueError(f"unsupported value type in {table}.{col}")
                        if type(val) is int and not -2 ** 63 <= val < 2 ** 63:
                            raise ValueError(f"integer out of range in {table}.{col}")
                    cols = list(row)      # every name checked against the schema above
                    plan.append((f"INSERT INTO {table}({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                                 tuple(row[c] for c in cols)))
            self._db.execute("BEGIN")
            try:
                for sql, args in plan:
                    self._db.execute(sql, args)
                self._db.execute("COMMIT")
            except (sqlite3.Error, ValueError, OverflowError) as exc:   # ValueError: e.g. a lone surrogate in a str
                try:
                    self._db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass      # SQLite already rolled back
                raise ValueError(f"rows could not be inserted ({type(exc).__name__})") from None

    def delete_job(self, job_id: str) -> dict[str, int]:
        """Remove every row of one job from all per-job tables (one transaction); returns the row counts.

        Files (job directory, audit log) are not touched here; see ``webui.jobdelete``."""
        counts: dict[str, int] = {}
        with self._lock:
            self._db.execute("BEGIN")
            try:
                for t in reversed(EXPORT_TABLES):
                    col = "id" if t == "jobs" else "job_id"
                    counts[t] = self._db.execute(f"DELETE FROM {t} WHERE {col}=?", (job_id,)).rowcount
                self._db.execute("COMMIT")
            except sqlite3.Error:
                self._db.execute("ROLLBACK")
                raise
            self._audits.pop(job_id, None)
        return counts

    def make_read_only(self) -> None:
        """Refuse every later write on this connection (imported jobs): an emit fails before it touches the audit."""
        with self._lock:
            self._db.execute("PRAGMA query_only=ON")

    def close(self) -> None:
        with self._lock:
            self._db.close()
