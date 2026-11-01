"""Routes added for dashboard v3: lineage, dynamic plan, replay export, delete, walkthroughs, task nodes.
Harmless self-made data only; nothing is executed."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile
from pathlib import Path

from tests.unit.test_dashboard_api import ORIGIN, _app, _job  # noqa: F401

from sw_analyst.common.audit import verify_file


def _chain(store, gw, jid):
    inner = b"plain harmless inner text\n"
    r = gw.call(jid, "decode_layer", {"path": "sample", "method": "base64"})
    assert r.ok, r.error
    ev = store.add_evidence(jid, None, "decode_layer", r.tool_version, {"path": "sample", "method": "base64"}, r.text,
                            source_ref=r.meta)
    return inner, ev


def test_lineage_dynamic_and_replay_routes(tmp_path: Path):
    client, store, gw = _app(tmp_path)
    jid = _job(store, gw, base64.b64encode(b"plain harmless inner text\n"))
    _, ev = _chain(store, gw, jid)
    store.update_job(jid, status="done")
    lin = client.get(f"/api/jobs/{jid}/lineage").json()
    assert {n["path"] for n in lin["nodes"]} >= {"sample"} and lin["edges"] and lin["edges"][0]["evidence_id"] == ev["id"]
    dyn = client.get(f"/api/jobs/{jid}/dynamic").json()
    assert dyn["enabled"] is False
    r = client.get(f"/api/jobs/{jid}/replay", params={"include_sample": 1})
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert "replay.py" in names and any(n.startswith("sample/") for n in names)


def test_replay_refused_while_running(tmp_path: Path):
    client, store, gw = _app(tmp_path)
    jid = _job(store, gw, b"x")
    store.update_job(jid, status="running")
    assert client.get(f"/api/jobs/{jid}/replay").status_code == 409


def test_delete_route_needs_origin_and_finished_job(tmp_path: Path):
    client, store, gw = _app(tmp_path)
    jid = _job(store, gw, b"harmless")
    store.update_job(jid, status="running")
    assert client.delete(f"/api/jobs/{jid}").status_code == 403          # no Origin: refused by the middleware
    assert client.delete(f"/api/jobs/{jid}", headers=ORIGIN).status_code == 409
    store.update_job(jid, status="done")
    r = client.delete(f"/api/jobs/{jid}", headers=ORIGIN)
    assert r.status_code == 200 and r.json()["deleted"] == jid
    assert client.get(f"/api/jobs/{jid}").status_code == 404
    proof = [json.loads(ln) for ln in (tmp_path / "deleted_jobs.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(proof) == 1 and proof[0]["job_id"] == jid and proof[0]["audit_head_hash"]
    archived = tmp_path / proof[0]["archive"] / "audit" / "audit.jsonl"
    assert archived.is_file() and verify_file(archived).valid      # the chain of custody survives the delete


def test_deletion_records_are_hash_chained(tmp_path: Path):
    client, store, gw = _app(tmp_path)
    ids = [_job(store, gw, b"harmless %d" % i) for i in range(2)]
    for jid in ids:
        store.update_job(jid, status="done")
        assert client.delete(f"/api/jobs/{jid}", headers=ORIGIN).status_code == 200
    lines = (tmp_path / "deleted_jobs.jsonl").read_bytes().splitlines()
    assert json.loads(lines[1])["prev_sha256"] == hashlib.sha256(lines[0]).hexdigest()


def test_tree_nodes_carry_goal_and_done_when(tmp_path: Path):
    client, store, gw = _app(tmp_path)
    jid = _job(store, gw, b"harmless")
    store.add_task(jid, title="Read it", goal="read the file", kind="analyze", origin="recipe", priority=10,
                   params={"done_when": "the file is read"})
    node = client.get(f"/api/jobs/{jid}/tree").json()[0]
    assert node["goal"] == "read the file" and node["done_when"] == "the file is read"


def test_walkthroughs_without_function_is_empty(tmp_path: Path):
    client, store, gw = _app(tmp_path)
    jid = _job(store, gw, b"harmless")
    assert client.get(f"/api/jobs/{jid}/walkthroughs").json() == []
