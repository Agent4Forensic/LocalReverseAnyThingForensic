"""Example challenges for the dashboard: list sorted by difficulty, show where their code lives, start them as a job.

Source of truth stays example/ (challenge.json per folder, sample builders in example/samples.py). Samples are built
in memory and handed to the gateway like an upload, so they land in <data>/jobs/<job>/sample and nowhere else.
The expected flag is not passed to the job (see example/README.md); the dashboard only compares it afterwards.
"""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import threading
from pathlib import Path
from typing import Any, Optional

from sw_analyst.common.paths import PROJECT_ROOT

LEVELS = {"leicht": 1, "mittel": 2, "schwer": 3}
_ID_OK = set("abcdefghijklmnopqrstuvwxyz0123456789-")


class Examples:
    def __init__(self, example_dir: Path | None = None, registry_file: Path | None = None):
        self.dir = Path(example_dir) if example_dir else PROJECT_ROOT / "example"
        self.registry_file = registry_file      # <data>/examples.json: which job came from which example
        self._lock = threading.Lock()
        self._mod = None

    # ---- loading ----------------------------------------------------------------------------------------
    def _builders(self) -> dict:
        if self._mod is None:
            path = self.dir / "samples.py"
            spec = importlib.util.spec_from_file_location("sw_analyst_example_samples", path)
            if spec is None or spec.loader is None:
                raise FileNotFoundError(path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            self._mod = mod
        return self._mod.BUILDERS

    def available(self) -> bool:
        return (self.dir / "samples.py").is_file() and (self.dir / "challenges").is_dir()

    def _rel(self, p: Path) -> str:
        try:
            return p.resolve().relative_to(PROJECT_ROOT).as_posix()
        except ValueError:
            return p.as_posix()

    def _load(self) -> list[dict]:
        if not self.available():
            return []
        builders = self._builders()
        out = []
        for f in sorted((self.dir / "challenges").glob("*/challenge.json")):
            c = json.loads(f.read_text(encoding="utf-8"))
            cid = c.get("id", "")
            fn = builders.get(c.get("sample", {}).get("builder", ""))
            if cid != f.parent.name or not set(cid) <= _ID_OK or fn is None:
                continue        # same rule as example/run_eval.py: broken entries are skipped, not guessed
            data = fn()
            try:
                line = inspect.getsourcelines(fn)[1]
            except (OSError, TypeError):
                line = 0
            level = c.get("level", "")
            out.append({
                "id": cid, "title": c.get("title", cid), "level": level, "level_rank": LEVELS.get(level, 9),
                "description": c.get("description", ""), "goal": c.get("goal", ""), "tests": c.get("tests", ""),
                "job_description": c.get("job_description", ""), "questions": list(c.get("questions", [])),
                "flag": c.get("flag", ""),
                "sample": {"name": c["sample"]["name"], "builder": fn.__name__, "size": len(data),
                           "sha256": hashlib.sha256(data).hexdigest()},
                "paths": {"folder": self._rel(f.parent), "challenge": self._rel(f),
                          "builder_file": self._rel(self.dir / "samples.py"), "builder_line": line,
                          "runner": self._rel(self.dir / "start_eval.ps1"),
                          "stored_as": "data/jobs/<Auftrag>/sample",
                          # copy of the builder output in the repository (ADR-0009); the builder stays the source
                          "sample_file": self._rel(f.parent / "sample" / c["sample"]["name"]),
                          "sample_file_ok": self._same(f.parent / "sample" / c["sample"]["name"], data)},
            })
        out.sort(key=lambda e: (e["level_rank"], e["id"]))
        return out

    @staticmethod
    def _same(path: Path, data: bytes) -> Optional[bool]:
        """True: file equals the builder output, False: differs, None: no file in the repository."""
        try:
            return path.read_bytes() == data if path.is_file() else None
        except OSError:
            return False

    def list(self, store=None) -> list[dict]:
        items = self._load()
        runs = self._runs()
        for e in items:
            mine = [j for j, cid in runs.items() if cid == e["id"]]
            e["runs"] = []
            for jid in sorted(mine, reverse=True)[:5]:
                job = store.get_job(jid) if store else None
                if job:
                    e["runs"].append({"job_id": jid, "status": job["status"], "created_at": job["created_at"],
                                      "flag_found": self._flag_found(store, jid, e["flag"])})
        return items

    def get(self, cid: str) -> Optional[dict]:
        return next((e for e in self._load() if e["id"] == cid), None)

    def source(self, cid: str) -> Optional[dict]:
        e = self.get(cid)
        if not e:
            return None
        fn = self._builders()[e["sample"]["builder"]]
        try:
            code = inspect.getsource(fn)
        except (OSError, TypeError):
            code = ""
        challenge = (PROJECT_ROOT / e["paths"]["challenge"]).read_text(encoding="utf-8")
        return {"id": cid, "builder_source": code, "challenge_json": challenge}

    def build(self, cid: str) -> Optional[tuple[dict, bytes]]:
        e = self.get(cid)
        if not e:
            return None
        return e, self._builders()[e["sample"]["builder"]]()

    # ---- which job came from which example ----------------------------------------------------------------
    def _runs(self) -> dict[str, str]:
        if not self.registry_file or not self.registry_file.is_file():
            return {}
        try:
            data = json.loads(self.registry_file.read_text(encoding="utf-8"))
            return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def remember(self, job_id: str, cid: str) -> None:
        if not self.registry_file:
            return
        with self._lock:
            runs = self._runs()
            runs[job_id] = cid
            tmp = self.registry_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(runs, indent=1, sort_keys=True), encoding="utf-8")
            tmp.replace(self.registry_file)

    def example_of(self, job_id: str) -> Optional[str]:
        return self._runs().get(job_id)

    @staticmethod
    def _flag_found(store, job_id: str, flag: str) -> Optional[bool]:
        """Same rule as example/run_eval.py: an accepted answer must contain the flag. None while the job runs."""
        job = store.get_job(job_id)
        if not job or job["status"] in ("queued", "running"):
            return None
        return any(a["status"] == "answered" and flag and flag in (a["answer_en"] or "")
                   for a in store.list_answers(job_id))


def example_summary(e: dict[str, Any]) -> dict:
    """List entry without the flag: the dashboard reveals it only on request."""
    return {k: v for k, v in e.items() if k != "flag"}
