"""Delete one job from the dashboard (DB rows, sample and derived files) after writing a hash-chained proof line.

The audit log is never destroyed (CLAUDE.md rule 3, ADR-0011): it moves byte-identical into
``<data>/deleted/<job>-<time>/`` together with a JSON export of the job's database rows, so the chain of custody of
a deleted job stays verifiable. Only own jobs in a final state can be deleted; imported analyses are refused by the
route. Paths are rebuilt from the validated job id and must resolve below ``data_dir``; symlinks are never followed."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path

from sw_analyst.common.audit import verify_file
from sw_analyst.common.util import utcnow

JOB_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
BUSY = ("queued", "running", "uploading")
PROOF_FILE = "deleted_jobs.jsonl"
ARCHIVE_DIR = "deleted"
REASON = "gelöscht über Dashboard"


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def _writable_then_retry(func, path, _exc):
    """Make the parent directory writable and retry. A symlink itself is never chmodded (it would change the target);
    Windows refuses to delete a read-only file (samples are 0o444), so there a real file is made writable first."""
    os.chmod(os.path.dirname(path), stat.S_IRWXU)
    if os.name == "nt" and not os.path.islink(path):
        os.chmod(path, stat.S_IWRITE)
    func(path)


def _sha_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _last_proof_sha(proof: Path) -> str:
    """SHA-256 of the previous proof line: each deletion record names its predecessor (hash chain)."""
    try:
        lines = [ln for ln in proof.read_bytes().split(b"\n") if ln.strip()]
    except OSError:
        return ""
    return hashlib.sha256(lines[-1]).hexdigest() if lines else ""


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

    audit_file = Path(store.audit_path(job_id))
    av = verify_file(audit_file) if audit_file.is_file() and not audit_file.is_symlink() else None
    stamp = utcnow().replace(":", "").replace("-", "")
    archive = data_dir / ARCHIVE_DIR / f"{job_id}-{stamp}"
    proof_path = data_dir / PROOF_FILE
    proof = {"time": utcnow(), "job_id": job_id, "title": job.get("title", ""),
             "sample_sha256": job.get("sample_sha256", ""), "reason": REASON,
             "audit_sha256": _sha_file(audit_file) if audit_file.is_file() else "",
             "audit_head_hash": av.head_hash if av else "", "audit_entries": av.entries if av else 0,
             "audit_valid": bool(av.valid) if av else None,
             "archive": f"{ARCHIVE_DIR}/{archive.name}", "prev_sha256": _last_proof_sha(proof_path)}

    archive.mkdir(parents=True, exist_ok=False)
    rows_json = json.dumps(store.export_rows(job_id), ensure_ascii=False, sort_keys=True, default=str)
    (archive / "rows.json").write_text(rows_json, encoding="utf-8")
    proof["rows_sha256"] = hashlib.sha256(rows_json.encode("utf-8")).hexdigest()
    if audit_dir.is_dir() and not audit_dir.is_symlink():
        shutil.move(str(audit_dir), str(archive / "audit"))      # byte-identical, never deleted

    with proof_path.open("a", encoding="utf-8", newline="\n") as f:     # proof before the rows go
        f.write(json.dumps(proof, ensure_ascii=False, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())

    rows = store.delete_job(job_id)
    files = _rmtree(job_dir, data_dir)
    return {"deleted": job_id, "rows": rows, "job_dir_removed": files, "audit_archived": proof["archive"]}
