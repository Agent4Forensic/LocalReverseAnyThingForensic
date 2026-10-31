"""Restart recovery and robustness of the worker (F-09, F-10)."""
from __future__ import annotations

from sw_analyst.common.models import JobSpec
from sw_analyst.common.store import Store
from sw_analyst.orchestrator.worker import Worker


class _Boom:
    def run_job(self, job_id):
        raise RuntimeError("engine broke")


def _job(store, status="queued"):
    return store.create_job(JobSpec(title="t"), "s.txt", "0" * 64, status=status)


def test_restart_closes_running_job_tasks_and_steps(tmp_path):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    j = _job(store)
    store.update_job(j["id"], status="running")
    t = store.add_task(j["id"], title="a", goal="g", kind="analysis", origin="recipe", priority=1)
    store.update_task(t["id"], status="running")
    sid = store.begin_step(j["id"], t["id"], "tool", "x")
    up = _job(store, status="uploading")
    assert sorted(Worker(store, _Boom()).recover()) == sorted([j["id"], up["id"]])
    job = store.get_job(j["id"])
    assert job["status"] == "failed" and job["finished_at"]
    assert store.get_task(t["id"])["status"] == "failed"
    assert store.get_step(sid)["status"] == "error"
    assert store.get_job(up["id"])["status"] == "failed"


def test_uploading_job_is_not_taken_by_the_worker(tmp_path):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    _job(store, status="uploading")
    assert store.next_queued_job() is None


def test_worker_survives_a_crashing_engine(tmp_path):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    w = Worker(store, _Boom(), poll_s=0.01)
    a, b = _job(store), _job(store)
    w.start()
    import time
    for _ in range(200):
        if all(store.get_job(x["id"])["status"] == "failed" for x in (a, b)):
            break
        time.sleep(0.01)
    w.stop()
    assert store.get_job(a["id"])["status"] == "failed" and store.get_job(b["id"])["status"] == "failed"
