"""Single background worker: runs one job at a time from the queue (requirement: one job at a time)."""
from __future__ import annotations

import threading
from datetime import datetime

from sw_analyst.common.store import Store
from sw_analyst.common.util import utcnow
from sw_analyst.orchestrator.engine import JobEngine


def _ms_between(start: str | None, end: str | None) -> int:
    """Duration up to the last recorded activity; the time while the server was down does not count."""
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    try:
        return max(0, int((datetime.strptime(end, fmt) - datetime.strptime(start, fmt)).total_seconds() * 1000))
    except (TypeError, ValueError):
        return 0


class Worker:
    def __init__(self, store: Store, engine: JobEngine, poll_s: float = 0.5):
        self.store, self.engine, self.poll_s = store, engine, poll_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.current_job: str | None = None

    def start(self) -> None:
        self.recover()
        self._thread = threading.Thread(target=self._run, name="sw-analyst-worker", daemon=True)
        self._thread.start()

    def recover(self) -> list[str]:
        """A job left in 'running' by a stop or crash cannot be resumed safely: mark it failed and say why. Its
        running tasks and steps are closed too, otherwise the dashboard shows them as running forever. A job left
        in 'uploading' never got its sample."""
        done = []
        for job in self.store.list_jobs():
            if job["status"] not in ("running", "uploading"):
                continue
            reason = "job interrupted by restart" if job["status"] == "running" else "upload interrupted by restart"
            last = max([job["started_at"] or ""] + [t["finished_at"] or t["started_at"] or "" for t in
                                                     self.store.list_tasks(job["id"])])
            for t in self.store.list_tasks(job["id"]):
                for st in self.store.list_steps(t["id"]):
                    if st["status"] == "running":
                        self.store.finish_step(st["id"], status="error", duration_ms=st["duration_ms"] or 0,
                                               output_preview=reason)
                if t["status"] == "running":
                    self.store.update_task(t["id"], status="failed", finished_at=utcnow(), summary_en=reason)
            self.store.log(job["id"], reason, level="error")
            self.store.update_job(job["id"], status="failed", finished_at=utcnow(), summary_en=reason,
                                  duration_ms=_ms_between(job["started_at"], last))
            done.append(job["id"])
        return done

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def _run(self) -> None:
        while not self._stop.is_set():
            job = self.store.next_queued_job()
            if not job:
                self._stop.wait(self.poll_s)
                continue
            self.current_job = job["id"]
            try:
                self.engine.run_job(job["id"])
            except Exception as e:  # noqa: BLE001 - the worker must survive a broken job (F-09)
                try:
                    self.store.log(job["id"], f"worker caught an error: {type(e).__name__}: {e}", level="error")
                    if (self.store.get_job(job["id"]) or {}).get("status") in ("running", "queued"):
                        self.store.update_job(job["id"], status="failed", finished_at=utcnow())
                except Exception:  # noqa: BLE001 - storage itself is broken: keep the thread alive, try later
                    self._stop.wait(self.poll_s)
            finally:
                self.current_job = None

    @property
    def state(self) -> str:
        return "running" if self.current_job else "idle"
