"""Single background worker: runs one job at a time from the queue (requirement: one job at a time)."""
from __future__ import annotations

import threading

from sw_analyst.common.store import Store
from sw_analyst.orchestrator.engine import JobEngine


class Worker:
    def __init__(self, store: Store, engine: JobEngine, poll_s: float = 0.5):
        self.store, self.engine, self.poll_s = store, engine, poll_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.current_job: str | None = None

    def start(self) -> None:
        # A job left in 'running' by a crash cannot be resumed safely: mark it failed and say why.
        stale = self.store.running_job()
        if stale:
            self.store.log(stale["id"], "job interrupted by restart", level="error")
            self.store.update_job(stale["id"], status="failed")
        self._thread = threading.Thread(target=self._run, name="sw-analyst-worker", daemon=True)
        self._thread.start()

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
            finally:
                self.current_job = None

    @property
    def state(self) -> str:
        return "running" if self.current_job else "idle"
