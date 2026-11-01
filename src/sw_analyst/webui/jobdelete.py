"""Delete one job completely (DB rows, gateway job directory, audit log) after writing a proof line.

Only own jobs in a final state can be deleted. Imported analyses are read-only and are refused by the route.
Paths are rebuilt from the validated job id and must resolve below ``data_dir``; symlinks are never followed."""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
from pathlib import Path

from sw_analyst.common.util import utcnow

JOB_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
BUSY = ("queued", "running", "uploading")
PROOF_FILE = "deleted_jobs.jsonl"
REASON = "gelöscht über Dashboard"


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def _writable_then_retry(func, path, _exc):
    os.chmod(path, stat.S_IRWXU)
    func(path)


def _rmtree(path: Path, root: Path) -> bool:
    """Remove ``path`` if it is a real directory (no symlink) strictly below ``root``."""
    if path.is_symlink() or not path.exists():
        if path.is_symlink():
            path.unlink()      # remove the link itself, never its target
        return False
    if not path.is_dir() or path.resolve() == root.resolve() or not _inside(path, root):
        raise ValueError("path outside the data directory")
    shutil.rmtree(path, onerror=_writable_then_retry)
    return True


def delete_job(store, gateway, data_dir, job_id: str) -> dict:
    if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
        raise ValueError("invalid job id")
    job = store.get_job(job_id)
    if not job:
        raise KeyError(job_id)
    if job["status"] in BUSY:
        raise ValueError(f"job is {job['status']} and cannot be deleted")
    data_dir = Path(data_dir).resolve()

    job_dir = Path(gateway.sample_path(job_id)).parent
    if job_dir.name != job_id or job_dir.parent.name != "jobs" or not _inside(job_dir.parent, data_dir):
        raise ValueError("job directory is not below the data directory")
    audit_dir = Path(store.audit_path(job_id)).parent
    if audit_dir.name != job_id:
        raise ValueError("unexpected audit path")

    proof = {"time": utcnow(), "job_id": job_id, "title": job.get("title", ""),
             "sample_sha256": job.get("sample_sha256", ""), "reason": REASON}
    with (data_dir / PROOF_FILE).open("a", encoding="utf-8", newline="\n") as f:     # proof first
        f.write(json.dumps(proof, ensure_ascii=False, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())

    rows = store.delete_job(job_id)
    files = _rmtree(job_dir, data_dir)
    audit = _rmtree(audit_dir, data_dir) if _inside(audit_dir.parent, data_dir) else False
    return {"deleted": job_id, "rows": rows, "job_dir_removed": files, "audit_removed": audit}
