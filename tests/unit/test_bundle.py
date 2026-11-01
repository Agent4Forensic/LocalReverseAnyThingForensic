"""Export and read-only import of one job (sw_analyst.webui.bundle). Harmless self-made samples only, nothing is run."""
from __future__ import annotations

import io
import json
import re
import sqlite3
import struct
import warnings
import zipfile

import pytest

import sw_analyst.webui.bundle as bundle
from sw_analyst.common.audit import verify_file
from sw_analyst.common.models import JobSpec, TargetQuestion
from sw_analyst.common.store import EXPORT_TABLES, Store
from sw_analyst.common.util import sha256_hex
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.llm.fake import ScriptedLLM
from sw_analyst.orchestrator.engine import JobEngine
from sw_analyst.webui.bundle import BundleError, ImportRegistry, export_bundle

SAMPLE = b"plain harmless text\nsecond line\n"
EVAL = json.dumps({"goal_reached": True, "assessment": "ok", "gaps": [], "followups": []})
NOTHING = json.dumps({"action": "finish", "summary": "nothing", "findings": []})


def _model(messages):
    t = "\n".join(m.content for m in messages)
    if "critical reviewer" in t:
        return EVAL
    if "orders the work queue" in t:
        return json.dumps({"changes": [], "new_tasks": []})
    if "Describe file structure" not in t:
        return NOTHING
    if "is stored as" not in t:
        return json.dumps({"action": "tool", "tool": "read_lines", "args": {"path": "sample"}, "why": "read"})
    ev = re.findall(r"is stored as (EV-\d{6})", t)[-1]
    return json.dumps({"action": "finish", "summary": "s", "findings": [
        {"statement": "The file holds text.", "status": "confirmed",
         "evidence": [{"id": ev, "quote": "plain harmless text"}]}]})


@pytest.fixture(scope="module")
def src(tmp_path_factory):
    d = tmp_path_factory.mktemp("src")
    store, gw = Store(d / "sw_analyst.db", d / "logs"), DevGateway(d)
    spec = JobSpec(title="t", description="test", target_questions=[TargetQuestion(id="Q1", text_orig="What is it?")])
    jid = store.create_job(spec, "s.txt", sha256_hex(SAMPLE))["id"]
    gw.store_sample(jid, SAMPLE)
    assert JobEngine(store, ScriptedLLM(_model), gw).run_job(jid) in ("done", "partial")
    task = store.list_tasks(jid)[-1]["id"]
    store.add_annotation(jid, task, "sample", 1, 1, "first line")
    store.add_guard_event(jid, task, "input", "test-rule", "low", "flag", "harmless snippet")
    root = d / "jobs" / jid
    (root / "derived" / "layer01.bin").write_bytes(b"derived harmless bytes")
    (root / "tool-cache").mkdir()
    (root / "tool-cache" / f"ghidra-{'a' * 64}-{'b' * 64}.json").write_text("{}", encoding="utf-8")
    yield store, gw, jid
    store.close()


def _export(src, files=False):
    store, gw, jid = src
    return export_bundle(store, gw, jid, model="test-model:1b", app_version="0.1.0", include_files=files)[0]


def _reg(tmp_path):
    return ImportRegistry(tmp_path / "dst", DevGateway)


def _entries(data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {i.filename: z.read(i) for i in z.infolist()}


def _rezip(data, change=None, fix=True, edit=None, add=()):
    """Rewrite a bundle: replace entries, optionally keep the manifest consistent, add raw entries."""
    entries = _entries(data)
    man = json.loads(entries["manifest.json"])
    for name, new in (change or {}).items():
        entries[name] = new
        if fix:
            man["files"][name] = {"sha256": sha256_hex(new), "size": len(new)}
    if edit:
        edit(man)
    entries["manifest.json"] = json.dumps(man).encode()
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")      # duplicate names on purpose
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for name, blob in [*entries.items(), *add]:
                z.writestr(name, blob)
    return buf.getvalue()


def _refused(reg, data, code):
    with pytest.raises(BundleError) as exc:
        reg.import_bundle(data)
    assert exc.value.code == code, exc.value.message
    assert exc.value.status == {"bad_bundle": 400, "too_large": 413}.get(code, 422)
    assert [p.name for p in (reg._root).iterdir()] == [], "a refused import must leave nothing behind"
    assert reg.list_jobs() == []
    return exc.value


# ---- export ----------------------------------------------------------------------------------------------------------

def test_export_layout_and_manifest(src):
    store, gw, jid = src
    data, name = export_bundle(store, gw, jid, model="test-model:1b", app_version="0.1.0", include_files=True)
    assert name == f"sw-analyst-{jid}-{sha256_hex(data)[:8]}.zip"
    entries = _entries(data)
    man = json.loads(entries["manifest.json"])
    assert man["format"] == "sw-analyst-export/1" and man["job_id"] == jid and man["include_files"] is True
    assert man["sample_sha256"] == sha256_hex(SAMPLE) and man["model"] == "test-model:1b"
    assert set(entries) - {"manifest.json"} == set(man["files"]) == {
        "job.json", "audit.jsonl", "report.de.md", "report.en.md", "files/sample", "files/derived/layer01.bin",
        f"files/tool-cache/ghidra-{'a' * 64}-{'b' * 64}.json"}
    for n, meta in man["files"].items():
        assert sha256_hex(entries[n]) == meta["sha256"] and len(entries[n]) == meta["size"]
    assert entries["audit.jsonl"] == store.audit_path(jid).read_bytes(), "audit must be copied byte-exact"
    v = verify_file(store.audit_path(jid))
    assert man["audit"] == {"entries": v.entries, "head_hash": v.head_hash}
    assert json.loads(entries["job.json"]) == store.export_rows(jid)
    assert set(_entries(_export(src))) == {"manifest.json", "job.json", "audit.jsonl", "report.de.md", "report.en.md"}


def test_export_refuses_active_and_unknown_jobs(tmp_path):
    store, gw = Store(tmp_path / "t.db", tmp_path / "logs"), DevGateway(tmp_path)
    jid = store.create_job(JobSpec(title="t"), "s.txt", sha256_hex(SAMPLE))["id"]
    for status in ("queued", "running"):
        store.update_job(jid, status=status)
        with pytest.raises(BundleError) as exc:
            export_bundle(store, gw, jid, model="m", app_version="1", include_files=False)
        assert (exc.value.status, exc.value.code) == (409, "job_active")
    for bad in ("J-9999", "../J-0001", 7):
        with pytest.raises(BundleError) as exc:
            export_bundle(store, gw, bad, model="m", app_version="1", include_files=False)
        assert exc.value.status == 404
    store.close()


def test_export_refuses_what_an_import_would_refuse(tmp_path):
    store, gw = Store(tmp_path / "t.db", tmp_path / "logs"), DevGateway(tmp_path)
    jid = store.create_job(JobSpec(title="t"), "s.txt", sha256_hex(SAMPLE))["id"]
    store.update_job(jid, status="done")

    def code(**kw):
        with pytest.raises(BundleError) as exc:
            export_bundle(store, gw, jid, **{"model": "m", "app_version": "1", "include_files": False, **kw})
        return exc.value.status, exc.value.code
    assert code(include_files=True) == (409, "files_missing")                  # no sample on disk
    assert code(model="m | <b>") == (400, "bad_request")
    path = store.audit_path(jid)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")           # last event lost its audit entry
    assert code() == (409, "audit_invalid")
    path.write_text("\n".join([lines[0].replace("job created", "forged"), *lines[1:]]) + "\n", encoding="utf-8")
    assert code() == (409, "audit_invalid")                                      # broken chain
    store.close()


# ---- round trip ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("files", [False, True])
def test_round_trip_keeps_rows_audit_and_ids(src, tmp_path, files):
    store, gw, jid = src
    data = _export(src, files)
    reg = _reg(tmp_path)
    res = reg.import_bundle(data)
    assert res["job_id"] == f"I0001-{jid}" and res["import_id"] == "I0001" and res["duplicate"] is False
    c = res["checks"]
    assert c["audit_valid"] and c["event_mismatches"] == 0 and c["events_checked"] > 0
    assert c["report_reproducible"] is True and c["sample_sha256_ok"] is (True if files else None)
    assert all(c["rows"][t] > 0 for t in EXPORT_TABLES)

    istore, igw, orig = reg.resolve(res["job_id"])
    assert orig == jid
    assert istore.export_rows(jid) == store.export_rows(jid), "original ids and raw values stay untouched"
    assert istore.audit_path(jid).read_bytes() == store.audit_path(jid).read_bytes()
    listed = reg.list_jobs()
    assert len(listed) == 1 and listed[0]["id"] == res["job_id"] and listed[0]["imported"] is True
    assert listed[0]["original_id"] == jid and listed[0]["import_id"] == "I0001"
    assert listed[0]["title"] == store.get_job(jid)["title"]
    info = reg.info(res["job_id"])
    assert info["bundle_sha256"] == sha256_hex(data) and info["imported_at"] and info["checks"] == c
    assert info["manifest"]["job_id"] == jid
    d = tmp_path / "dst" / "imports" / "I0001"
    assert json.loads((d / "import.json").read_text(encoding="utf-8"))["bundle_sha256"] == sha256_hex(data)
    assert (d / "bundle" / "report.de.md").read_bytes() == _entries(data)["report.de.md"]

    got = {f["path"]: f["sha256"] for f in igw.list_files(jid)}
    if files:
        assert got == {f["path"]: f["sha256"] for f in gw.list_files(jid)}
        assert got["sample"] == sha256_hex(SAMPLE)
        assert (d / "jobs" / jid / "tool-cache" / f"ghidra-{'a' * 64}-{'b' * 64}.json").is_file()
    else:
        assert got == {}
    assert reg.resolve(f"I0001-J-9999") is None and reg.resolve("I0002-" + jid) is None
    assert reg.resolve("../" + jid) is None and reg.info("nonsense") is None


def test_imported_store_is_read_only(src, tmp_path):
    jid = src[2]
    reg = _reg(tmp_path)
    istore, _, _ = reg.resolve(reg.import_bundle(_export(src))["job_id"])
    before = istore.audit_path(jid).read_bytes()
    with pytest.raises(sqlite3.OperationalError):
        istore.update_job(jid, status="queued")
    with pytest.raises(sqlite3.OperationalError):
        istore.log(jid, "must not land")
    assert istore.audit_path(jid).read_bytes() == before
    assert istore.get_job(jid)["status"] == src[0].get_job(jid)["status"]


def test_duplicate_and_second_bundle(src, tmp_path):
    reg = _reg(tmp_path)
    a, b = _export(src), _export(src, files=True)
    first = reg.import_bundle(a)
    again = reg.import_bundle(a)
    assert again["duplicate"] is True and again["job_id"] == first["job_id"] and again["import_id"] == "I0001"
    second = reg.import_bundle(b)
    assert second["import_id"] == "I0002" and second["job_id"] == f"I0002-{src[2]}" and not second["duplicate"]
    assert sorted(p.name for p in reg._root.iterdir()) == ["I0001", "I0002"]
    assert [j["id"] for j in reg.list_jobs()] == [second["job_id"], first["job_id"]]


def test_registry_reloads_imports_and_drops_stale_temp_dirs(src, tmp_path):
    reg, data = _reg(tmp_path), _export(src)
    res = reg.import_bundle(data)
    stale = reg._root / ".tmp-0123456789abcdef"
    (stale / "jobs").mkdir(parents=True)
    reg2 = _reg(tmp_path)
    assert not stale.exists()
    assert [j["id"] for j in reg2.list_jobs()] == [res["job_id"]]
    assert reg2.import_bundle(data)["duplicate"] is True


def test_changed_report_is_recorded_not_refused(src, tmp_path):
    data = _rezip(_export(src), {"report.en.md": b"# forged report\n"})
    res = _reg(tmp_path).import_bundle(data)
    assert res["checks"]["report_reproducible"] is False
    assert res["checks"]["reports_reproducible"] == {"de": True, "en": False}


# ---- hostile bundles ---------------------------------------------------------------------------------------------------

def test_tampered_entry_is_a_checksum_mismatch(src, tmp_path):
    data = _export(src, files=True)
    reg = _reg(tmp_path)
    rep = bytearray(_entries(data)["report.de.md"])
    rep[5] ^= 0x01                                                    # same size, other content
    _refused(reg, _rezip(data, {"report.de.md": bytes(rep)}, fix=False), "checksum_mismatch")
    _refused(reg, _rezip(data, {"files/sample": SAMPLE + b"x"}, fix=False), "checksum_mismatch")
    # consistent manifest, but the sample is no longer the one the job recorded
    _refused(reg, _rezip(data, {"files/sample": b"another harmless text\n"}), "checksum_mismatch")


def test_tampered_audit_is_refused(src, tmp_path):
    data = _export(src)
    reg = _reg(tmp_path)
    lines = _entries(data)["audit.jsonl"].decode().splitlines()
    obj = json.loads(lines[1])
    obj["message"] = "forged"
    edited = "\n".join([lines[0], json.dumps(obj), *lines[2:]]) + "\n"
    e = _refused(reg, _rezip(data, {"audit.jsonl": edited.encode()}), "audit_invalid")
    assert "entry 2" in e.message
    truncated = ("\n".join(lines[:-1]) + "\n").encode()
    _refused(reg, _rezip(data, {"audit.jsonl": truncated}), "audit_invalid")   # tail cut: manifest head differs
    v_lines = len(lines) - 1
    head = json.loads(lines[-2])["hash"]

    def fake_head(m):
        m["audit"] = {"entries": v_lines, "head_hash": head}
    e = _refused(reg, _rezip(data, {"audit.jsonl": truncated}, edit=fake_head), "audit_invalid")
    assert "1 event row" in e.message                                   # the last event has no audit entry now
    e = _refused(reg, _rezip(data, {"audit.jsonl": b"\xff\xfe not utf-8\n"}), "audit_invalid")
    assert "not a readable hash chain" in e.message
    _refused(reg, _rezip(data, {"audit.jsonl": b"[1, 2]\n"}), "audit_invalid")


def test_event_row_without_matching_audit_entry_is_refused(src, tmp_path):
    data = _export(src)
    rows = json.loads(_entries(data)["job.json"])
    rows["events"][0]["data_json"] = json.dumps({"forged": True})
    e = _refused(_reg(tmp_path), _rezip(data, {"job.json": json.dumps(rows).encode()}), "audit_invalid")
    assert e.message.startswith("1 event row")


@pytest.mark.parametrize("name", [
    "../evil.txt", "files/derived/../../../evil.txt", "/tmp/evil.txt", "files\\derived\\evil.txt", "files/derived/a/b",
    "C:/evil.txt", "files/derived/..", "files/other/evil.txt", "files/derived/con", "files/derived/x:ads",
    "files/derived/", "files/", "files/derived/.hidden", "manifest.json/x"])
def test_path_traversal_and_unknown_names_are_refused(src, tmp_path, name):
    blob = b"harmless"

    def listed(m):
        m["files"][name] = {"sha256": sha256_hex(blob), "size": len(blob)}
    _refused(_reg(tmp_path), _rezip(_export(src, files=True), edit=listed, add=[(name, blob)]), "bad_bundle")
    assert not list(tmp_path.rglob("evil*"))


def test_duplicate_entry_names_are_refused(src, tmp_path):
    data = _export(src)
    _refused(_reg(tmp_path), _rezip(data, add=[("report.de.md", b"second copy")]), "bad_bundle")


def test_zip_bomb_by_declared_size_is_refused_before_reading(src, tmp_path):
    data = bytearray(_export(src))
    target, pos = b"report.en.md", 0
    while True:                            # central directory record of report.en.md: uncompressed size at +24
        pos = data.index(b"PK\x01\x02", pos)
        nlen = struct.unpack_from("<H", data, pos + 28)[0]
        if bytes(data[pos + 46:pos + 46 + nlen]) == target:
            struct.pack_into("<I", data, pos + 24, 0x7FFF0000)
            break
        pos += 4
    _refused(_reg(tmp_path), bytes(data), "too_large")


def test_highly_compressed_entry_counts_against_the_unpacked_limit(src, tmp_path, monkeypatch):
    monkeypatch.setattr(bundle, "MAX_TOTAL_BYTES", 4 * 1024 * 1024)
    zeros = bytes(8 * 1024 * 1024)             # 8 MiB of zeros, a few KiB compressed
    data = _rezip(_export(src, files=True), {"files/derived/layer01.bin": zeros})
    assert len(data) < 200_000
    _refused(_reg(tmp_path), data, "too_large")


def test_size_and_entry_limits(src, tmp_path, monkeypatch):
    data = _export(src)
    reg = _reg(tmp_path)
    monkeypatch.setattr(bundle, "MAX_ENTRIES", 3)
    _refused(reg, data, "too_large")
    monkeypatch.setattr(bundle, "MAX_BUNDLE_BYTES", 100)
    _refused(reg, data, "too_large")


def test_manifest_size_lie_is_a_checksum_mismatch(src, tmp_path):
    data = _export(src)

    def lie(m):
        m["files"]["report.de.md"]["size"] += 1
    _refused(_reg(tmp_path), _rezip(data, edit=lie), "checksum_mismatch")


def test_wrong_format_and_garbage(src, tmp_path):
    reg = _reg(tmp_path)
    data = _export(src)
    _refused(reg, _rezip(data, edit=lambda m: m.update(format="other-tool/9")), "wrong_format")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("job.json", "{}")
    _refused(reg, buf.getvalue(), "wrong_format")
    _refused(reg, b"MZ this is not a zip at all", "bad_bundle")
    _refused(reg, data[: len(data) // 2], "bad_bundle")
    _refused(reg, b"PK\x03\x04" + b"\x00" * 64, "bad_bundle")


@pytest.mark.parametrize("field, value", [
    ("model", "x | <script>alert(1)</script>"), ("job_id", "../../J-0001"), ("include_files", "yes"),
    ("sample_sha256", "abc"), ("status", "running"), ("audit", {"entries": -1, "head_hash": "0" * 64})])
def test_invalid_manifest_fields_are_refused(src, tmp_path, field, value):
    _refused(_reg(tmp_path), _rezip(_export(src), edit=lambda m: m.update({field: value})), "bad_bundle")


def test_files_without_include_files_are_refused(src, tmp_path):
    _refused(_reg(tmp_path), _rezip(_export(src, files=True), edit=lambda m: m.update(include_files=False)),
             "bad_bundle")


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(counters=[{"name": "job", "value": 1}]),                 # unknown table
    lambda r: r["tasks"][0].update({"evil) VALUES(1);--": 1}),                   # unknown column
    lambda r: r["tasks"][0].update(job_id="J-9999"),                             # row of another job
    lambda r: r["jobs"].append(dict(r["jobs"][0])),                              # two job rows
    lambda r: r["tasks"][0].update(params_json="{not json"),                     # JSON column does not parse
    lambda r: r["tasks"][0].update(title={"nested": 1}),                          # unsupported value type
    lambda r: r["evidence"].append(dict(r["evidence"][0])),                       # duplicate primary key
    lambda r: r["jobs"][0].update(spec_json="[]"),                                # report cannot be rebuilt
    lambda r: r.pop("findings"),                                                  # table missing
    lambda r: r["tasks"][0].update(priority=2 ** 70),                             # integer SQLite cannot hold
    lambda r: r["tasks"][0].update(title="\ud800"),                              # lone surrogate
])
def test_hostile_rows_are_refused(src, tmp_path, mutate):
    data = _export(src)
    rows = json.loads(_entries(data)["job.json"])
    mutate(rows)
    _refused(_reg(tmp_path), _rezip(data, {"job.json": json.dumps(rows).encode()}), "bad_bundle")


# ---- store level -----------------------------------------------------------------------------------------------------

def test_import_rows_whitelist(tmp_path, src):
    s = Store(tmp_path / "x.db", tmp_path / "logs")
    with pytest.raises(ValueError, match="unknown table"):
        s.import_rows({"translations": [{"direction": "en", "text_sha256": "x", "translated": "y"}]})
    with pytest.raises(ValueError, match="unknown column"):
        s.import_rows({"jobs": [{"id": "J-0001", "id=1;DROP TABLE jobs;--": 1}]})
    with pytest.raises(ValueError):
        s.import_rows({"jobs": [{"id": "J-0001", "title": b"bytes"}]})
    with pytest.raises(ValueError):
        s.import_rows({"jobs": [{"id": "J-0001"}, {"id": "J-0001"}]})        # whole batch rolls back
    assert s.get_job("J-0001") is None
    rows = src[0].export_rows(src[2])
    s.import_rows(rows)
    assert s.export_rows(src[2]) == rows
    assert s.events_after(src[2], 0, limit=1)[0]["seq"] == rows["events"][0]["seq"]
    assert not s.audit_path(src[2]).exists(), "import_rows must not emit or write an audit entry"
    s.close()
