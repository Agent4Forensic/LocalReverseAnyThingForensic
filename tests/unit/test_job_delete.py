import json
import sqlite3

import pytest

from sw_analyst.common.models import JobSpec
from sw_analyst.common.store import EXPORT_TABLES, Store
from sw_analyst.common.util import sha256_hex
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.webui.jobdelete import delete_job


def _make(tmp_path, status="done"):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    gw = DevGateway(tmp_path)
    data = b"harmless sample"
    j = store.create_job(JobSpec(title="T"), "a.txt", sha256_hex(data))
    gw.store_sample(j["id"], data)
    store.update_job(j["id"], status=status)
    t = store.add_task(j["id"], title="x", goal="g", kind="k", origin="plan", priority=1)
    store.log(j["id"], "hello")
    store.audit_log(j["id"]).append({"a": 1})
    return store, gw, j["id"], t


def _count(tmp_path, job_id):
    db = sqlite3.connect(tmp_path / "t.db")
    n = 0
    for t in EXPORT_TABLES:
        col = "id" if t == "jobs" else "job_id"
        n += db.execute(f"SELECT COUNT(*) FROM {t} WHERE {col}=?", (job_id,)).fetchone()[0]
    return n


def test_delete_removes_rows_files_audit_and_writes_proof(tmp_path):
    store, gw, jid, _ = _make(tmp_path)
    other = store.create_job(JobSpec(title="keep"), "b.txt", "0" * 64)
    assert _count(tmp_path, jid) > 0 and (tmp_path / "jobs" / jid).is_dir() and store.audit_path(jid).exists()
    out = delete_job(store, gw, tmp_path, jid)
    assert out["deleted"] == jid
    assert _count(tmp_path, jid) == 0
    assert not (tmp_path / "jobs" / jid).exists() and not store.audit_path(jid).exists()
    assert store.get_job(other["id"]) is not None
    line = json.loads((tmp_path / "deleted_jobs.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert line["job_id"] == jid and line["title"] == "T" and line["sample_sha256"] == sha256_hex(b"harmless sample")
    assert line["reason"] == "gelöscht über Dashboard" and line["time"]


@pytest.mark.parametrize("status", ["queued", "running", "uploading"])
def test_busy_job_is_refused(tmp_path, status):
    store, gw, jid, _ = _make(tmp_path, status)
    with pytest.raises(ValueError):
        delete_job(store, gw, tmp_path, jid)
    assert store.get_job(jid) is not None and (tmp_path / "jobs" / jid).is_dir()
    assert not (tmp_path / "deleted_jobs.jsonl").exists()


@pytest.mark.parametrize("bad", ["../x", "..", "a/b", "a\\b", "", ".", "x" * 65, "a\x00b"])
def test_path_attack_is_impossible(tmp_path, bad):
    store, gw, jid, _ = _make(tmp_path)
    victim = tmp_path.parent / "x"
    victim.mkdir(exist_ok=True)
    with pytest.raises(ValueError):
        delete_job(store, gw, tmp_path, bad)
    assert victim.is_dir() and (tmp_path / "jobs" / jid).is_dir()


def test_unknown_job_is_keyerror(tmp_path):
    store, gw, _, _ = _make(tmp_path)
    with pytest.raises(KeyError):
        delete_job(store, gw, tmp_path, "J9999")


def test_symlinked_job_dir_target_is_not_followed(tmp_path):
    store, gw, jid, _ = _make(tmp_path)
    outside = tmp_path.parent / "outside_keep"
    outside.mkdir(exist_ok=True)
    (outside / "f").write_text("keep")
    import shutil
    (tmp_path / "jobs" / jid / "sample").chmod(0o644)      # read-only blocks the setup rmtree on Windows
    shutil.rmtree(tmp_path / "jobs" / jid)
    (tmp_path / "jobs" / jid).symlink_to(outside, target_is_directory=True)
    try:
        delete_job(store, gw, tmp_path, jid)
    except ValueError:
        pass
    assert (outside / "f").read_text() == "keep"
