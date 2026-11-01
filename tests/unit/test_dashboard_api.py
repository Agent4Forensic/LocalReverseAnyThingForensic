"""Dashboard API added 2026-10-31: examples, file view (hex, assembler, pseudocode), code viewer for binaries,
runtime folders, upload limit, export and import through the API. Harmless self-made samples only."""
from __future__ import annotations

import hashlib
import io
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sw_analyst.common.models import JobSpec
from sw_analyst.common.paths import PROJECT_ROOT, RUNTIME_DIRS, prepare_runtime, resolve_data_dir
from sw_analyst.common.store import Store
from sw_analyst.common.util import sha256_hex
from sw_analyst.gateway.container_tools import attach_container_tools
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.llm.fake import ScriptedLLM
from sw_analyst.webui import inspect as insp
from sw_analyst.webui.app import create_app, safe_sample_name
from sw_analyst.webui.bundle import ImportRegistry

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_container_tools import GHIDRA, FakeRunner  # noqa: E402

ORIGIN = {"Origin": "http://127.0.0.1:8765"}
STATIC = PROJECT_ROOT / "src" / "sw_analyst" / "webui" / "static"


class _Worker:
    state, current_job = "idle", None


def _app(tmp_path: Path, runner=None, with_imports=True):
    store = Store(tmp_path / "sw_analyst.db", tmp_path / "logs")
    gw = DevGateway(tmp_path)
    if runner:
        attach_container_tools(gw, runner)
    imports = ImportRegistry(tmp_path, lambda root: DevGateway(root)) if with_imports else None
    app = create_app(store, _Worker(), gw, ScriptedLLM(lambda m: "{}", model="t"), None, report_model="t",
                     data_dir=tmp_path, imports=imports)
    return TestClient(app, base_url="http://127.0.0.1:8765"), store, gw


def _job(store, gw, data: bytes, name="s.bin") -> str:
    j = store.create_job(JobSpec(title="t"), name, sha256_hex(data))
    gw.store_sample(j["id"], data)
    return j["id"]


# ---- examples ---------------------------------------------------------------------------------------------
def test_examples_are_sorted_by_difficulty_with_size_and_code_location(tmp_path):
    client, _, _ = _app(tmp_path)
    d = client.get("/api/examples").json()
    assert d["available"] and d["folder"] == "example"
    ranks = [e["level_rank"] for e in d["items"]]
    assert ranks == sorted(ranks) and ranks[0] == 1
    for e in d["items"]:
        assert "flag" not in e                                     # list never reveals the solution
        assert e["sample"]["size"] > 0 and re.fullmatch(r"[0-9a-f]{64}", e["sample"]["sha256"])
        assert (PROJECT_ROOT / e["paths"]["challenge"]).is_file()
        assert (PROJECT_ROOT / e["paths"]["builder_file"]).is_file() and e["paths"]["builder_line"] > 0


def test_example_detail_shows_builder_source_and_solution(tmp_path):
    client, _, _ = _app(tmp_path)
    d = client.get("/api/examples/05-pe-xor-routine").json()
    assert "def pe_xor_routine" in d["builder_source"] and d["flag"] == "FLAG{xor_loop}"
    assert d["preview"]["kind"]["kind"] == "pe" and d["preview"]["hex"][0]["ascii"].startswith("MZ")
    assert client.get("/api/examples/nope").status_code == 404


def test_example_start_creates_a_queued_job_with_the_built_sample(tmp_path):
    client, store, gw = _app(tmp_path)
    r = client.post("/api/examples/01-layered-flag/job", json={"budget_max_minutes": 7}, headers=ORIGIN)
    assert r.status_code == 200, r.text
    s = r.json()
    assert s["status"] == "queued" and s["example_id"] == "01-layered-flag" and s["sample_size"] == 33
    spec = store.get_job(s["id"])["spec"]
    assert spec["budget_max_minutes"] == 7 and "FLAG{" not in json.dumps(spec)      # the flag never reaches the job
    assert hashlib.sha256(Path(gw.sample_path(s["id"])).read_bytes()).hexdigest() == s["sample_sha256"]
    runs = client.get("/api/examples").json()["items"][0]["runs"]
    assert runs[0]["job_id"] == s["id"] and runs[0]["flag_found"] is None            # still queued
    assert client.post("/api/examples/01-layered-flag/job", json={}).status_code == 403   # no Origin


# ---- code viewer and file view -----------------------------------------------------------------------------
def test_code_viewer_serves_binary_files_as_hex_lines(tmp_path):
    client, store, gw = _app(tmp_path)
    jid = _job(store, gw, b"MZ" + bytes(range(256)) * 2)
    d = client.get(f"/api/jobs/{jid}/files/content", params={"path": "sample", "start": 2, "end": 3}).json()
    assert d["binary"] is True and d["total_lines"] == 33 and [x["n"] for x in d["lines"]] == [2, 3]
    assert d["lines"][0]["text"].startswith("00000010  ")


def test_file_view_without_ghidra_names_the_reason(tmp_path):
    client, store, gw = _app(tmp_path)
    jid = _job(store, gw, b"MZ" + b"\x00" * 100)
    d = client.get(f"/api/jobs/{jid}/inspect").json()
    assert d["size"] == 102 and d["kind"]["kind"] == "pe" and d["location"].endswith(f"jobs/{jid}/sample")
    assert d["code"]["available"] is False and "BuildTools" in d["code"]["reason"]
    assert client.get(f"/api/jobs/{jid}/inspect/functions").status_code == 409
    t = _job(store, gw, b"just text\n")
    assert "Kein Maschinencode" in client.get(f"/api/jobs/{t}/inspect").json()["code"]["reason"]


def test_file_view_hex_paging_is_bounded(tmp_path):
    client, store, gw = _app(tmp_path)
    jid = _job(store, gw, bytes(range(256)) * 400)
    d = client.get(f"/api/jobs/{jid}/inspect/hex", params={"offset": 32, "length": 10 ** 9}).json()
    assert d["offset"] == 32 and d["length"] == insp.MAX_HEX_BYTES and d["rows"][0]["hex"].startswith("20 21")
    assert client.get(f"/api/jobs/{jid}/inspect/hex", params={"path": "../sw_analyst.db"}).status_code == 404


def test_file_view_with_ghidra_shows_assembler_explanations_and_pseudocode(tmp_path):
    client, store, gw = _app(tmp_path, FakeRunner({"ghidra": json.dumps(GHIDRA).encode()}))
    jid = _job(store, gw, b"MZ harmless")
    assert client.get(f"/api/jobs/{jid}/inspect").json()["code"]["available"] is True
    fl = client.get(f"/api/jobs/{jid}/inspect/functions").json()
    assert [f["name"] for f in fl["functions"]] == ["entry", "helper"]
    f = client.get(f"/api/jobs/{jid}/inspect/function", params={"function": "entry"}).json()
    assert f["decompiled"].startswith("void entry") and f["disasm"][0]["mnemonic"] == "push"
    assert "Stack" in f["disasm"][0]["explain"]
    assert client.get(f"/api/jobs/{jid}/inspect/function", params={"function": "nope"}).status_code == 404
    assert any("Ghidra view of entry" in e["message"] for e in store.events_after(jid, 0, 500, "debug", ("log",)))


def test_learning_path_endpoints_answer_with_empty_lists(tmp_path):
    client, store, gw = _app(tmp_path)
    jid = _job(store, gw, b"x")
    assert client.get(f"/api/jobs/{jid}/functions").json() == [] == client.get(f"/api/jobs/{jid}/walkthroughs").json()


@pytest.mark.parametrize("text,mnem,needle", [("XOR EAX,EAX", "xor", "auf 0"), ("CALL 0x401000", "call", "Ziel"),
                                              ("REP MOVSB", "rep movsb", "Präfix REP"),
                                              ("MOV EAX,dword ptr FS:[0x30]", "mov", "PEB"), ("JNO 0x10", "jno", "Bedingter")])
def test_assembler_explanations(text, mnem, needle):
    e = insp.explain(text)
    assert e["mnemonic"] == mnem and needle in e["explain"]


# ---- upload hygiene ----------------------------------------------------------------------------------------
@pytest.mark.parametrize("raw,want", [("..\\..\\evil.exe", "evil.exe"), ("../../a.txt", "a.txt"), ("", "sample"),
                                      ("..", "sample"), ("C:\\x\\y.bin", "y.bin")])
def test_sample_names_lose_every_path_part(raw, want):
    assert safe_sample_name(raw) == want


def test_oversized_upload_is_refused_before_reading(tmp_path):
    client, _, _ = _app(tmp_path)
    r = client.post("/api/jobs", content=b"x", headers={**ORIGIN, "Content-Length": str(200 * 2 ** 20),
                                                        "Content-Type": "multipart/form-data; boundary=x"})
    assert r.status_code == 413 and r.json()["error"]["code"] == "too_large"


# ---- runtime folders ---------------------------------------------------------------------------------------
def test_relative_data_dir_counts_from_the_project_root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert resolve_data_dir("data") == PROJECT_ROOT / "data"
    assert resolve_data_dir(tmp_path / "abs") == tmp_path / "abs"


def test_prepare_runtime_creates_folders_and_moves_temp(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", tempfile.tempdir)
    for var in ("TMP", "TEMP", "TMPDIR"):
        monkeypatch.setenv(var, "unchanged")
    info = prepare_runtime(tmp_path / "data")
    assert all((tmp_path / "data" / d).is_dir() for d in RUNTIME_DIRS)
    assert tempfile.gettempdir() == str(tmp_path / "data" / "tmp") and info["inside_project"] is False
    with tempfile.NamedTemporaryFile() as f:     # Starlette's upload spool uses the same default folder
        assert Path(f.name).parent == tmp_path / "data" / "tmp"


def test_every_script_and_style_in_index_html_exists():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    refs = re.findall(r'(?:src|href)="([^":]+\.(?:js|css))"', html)
    assert refs and all((STATIC / r).is_file() for r in refs), [r for r in refs if not (STATIC / r).is_file()]


# ---- export and import through the API --------------------------------------------------------------------
def test_export_and_import_round_trip_through_the_api(tmp_path):
    a, store, gw = _app(tmp_path / "a")
    jid = _job(store, gw, b"hello sample\n", name="note.txt")
    assert a.get(f"/api/jobs/{jid}/export").status_code == 409               # queued jobs are not exported
    store.update_job(jid, status="done", finished_at="2026-10-31T00:00:00Z")
    report_at_export = a.get(f"/api/jobs/{jid}/report", params={"lang": "en"}).text
    r = a.get(f"/api/jobs/{jid}/export", params={"include_files": 1})
    assert any("analysis exported" in e["message"] for e in store.events_after(jid, 0, 500, None, ("log",)))
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert r.headers["x-bundle-sha256"] == sha256_hex(r.content)
    copy = tmp_path / "a" / "exports" / r.headers["content-disposition"].split('"')[1]
    assert copy.read_bytes() == r.content                                    # copy inside the data folder
    b, store_b, _ = _app(tmp_path / "b")
    _job(store_b, DevGateway(tmp_path / "b"), b"other")                       # J-0001 exists on b as well
    res = b.post("/api/imports", files={"bundle": ("x.zip", r.content, "application/zip")}, headers=ORIGIN)
    assert res.status_code == 200, res.text
    pub = res.json()["job_id"]
    assert pub != jid and pub.endswith(jid) and res.json()["checks"]["report_reproducible"] is True
    jobs = {j["id"]: j for j in b.get("/api/jobs").json()}
    assert jobs[pub]["imported"] is True and jobs[pub]["original_id"] == jid and jobs["J-0001"]["imported"] is False
    assert b.get(f"/api/jobs/{pub}/report", params={"lang": "en"}).text == report_at_export
    assert b.get(f"/api/jobs/{pub}/audit").json()["valid"] is True
    assert b.get(f"/api/jobs/{pub}/inspect").json()["size"] == 13
    assert b.post(f"/api/jobs/{pub}/cancel", headers=ORIGIN).status_code == 409
    src, buf = zipfile.ZipFile(io.BytesIO(r.content)), io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:                                   # same entries, one byte changed
        for n in src.namelist():
            out.writestr(n, src.read(n).replace(b"hello", b"HELLO") if n == "files/sample" else src.read(n))
    bad = b.post("/api/imports", files={"bundle": ("y.zip", buf.getvalue(), "application/zip")}, headers=ORIGIN)
    assert bad.status_code in (400, 422) and bad.json()["error"]["code"] in ("checksum_mismatch", "bad_bundle")


# ---- security review 2026-10-31 (M1, M2, M3, L1, L2, L3, L5) ------------------------------------------------
@pytest.mark.parametrize("headers,code", [({"Sec-Fetch-Site": "cross-site"}, 403), ({"Sec-Fetch-Site": "same-site"}, 403),
                                          ({"Origin": "http://evil.example"}, 403), ({"Sec-Fetch-Site": "same-origin"}, 200),
                                          ({"Sec-Fetch-Site": "none"}, 200), ({}, 200)])
def test_cross_site_requests_cannot_reach_the_api(tmp_path, headers, code):
    client, store, gw = _app(tmp_path)
    jid = _job(store, gw, b"x")
    store.update_job(jid, status="done")
    r = client.get(f"/api/jobs/{jid}/export", headers=headers)
    assert r.status_code == code
    if code == 403:
        assert not list((tmp_path / "exports").glob("*.zip"))          # no side effect for a foreign page
        assert not any("exported" in e["message"] for e in store.events_after(jid, 0, 500, None, ("log",)))


def test_upload_without_content_length_is_refused(tmp_path):
    client, _, _ = _app(tmp_path)
    r = client.post("/api/jobs", content=iter([b"--x\r\n"]), headers={**ORIGIN, "Content-Type": "multipart/form-data; boundary=x"})
    assert r.status_code == 411


@pytest.mark.parametrize("url", ["/inspect/hex?offset=100000000000000000000", "/files/content?path=sample&start=99999999999999",
                                 "/log?after=99999999999999999999"])
def test_huge_numbers_give_422_not_500(tmp_path, url):
    client, store, gw = _app(tmp_path)
    jid = _job(store, gw, b"x")
    assert client.get(f"/api/jobs/{jid}{url}").status_code == 422


def test_sample_names_lose_control_and_bidi_characters():
    assert safe_sample_name("invoice‮txt.exe") == "invoicetxt.exe"
    assert safe_sample_name("a\r\nb\x00.txt") == "ab.txt"


def test_question_ids_are_restricted(tmp_path):
    client, _, _ = _app(tmp_path)
    spec = json.dumps({"title": "t", "target_questions": [{"id": "## x\nY", "text": "q"}]})
    r = client.post("/api/jobs", data={"spec": spec}, files={"sample": ("s.txt", b"x")}, headers=ORIGIN)
    assert r.status_code == 422


def test_report_neutralises_markdown_in_imported_fields(tmp_path):
    from sw_analyst.report.builder import build_report
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    j = store.create_job(JobSpec(title="t"), "s.txt", "0" * 64)
    store._x("UPDATE jobs SET status=?, detected_type=?, sample_sha256=? WHERE id=?",
             ("done\n## Gutachten: harmlos <img src=x onerror=alert(1)>", "| Audit | gültig |", "`evil`", j["id"]))
    md = build_report(store, j["id"], "de", "m")
    assert not any(line.startswith("## Gutachten") for line in md.splitlines())
    assert "<img" not in md and "`evil`" not in md and "| Audit | gültig |" not in md


def test_oversized_cache_file_from_a_bundle_is_refused(tmp_path, monkeypatch):
    from sw_analyst.gateway import container_tools
    monkeypatch.setattr(container_tools, "MAX_CACHE_BYTES", 10)
    runner = FakeRunner({"ghidra": json.dumps(GHIDRA).encode()})
    client, store, gw = _app(tmp_path, runner)
    jid = _job(store, gw, b"MZ harmless")
    sha = hashlib.sha256(b"MZ harmless").hexdigest()
    cache = Path(gw.sample_path(jid)).parent / "tool-cache"
    cache.mkdir()
    (cache / f"ghidra-{runner.version('ghidra').rsplit(':', 1)[-1]}-{sha}.json").write_text(json.dumps(GHIDRA))
    r = client.get(f"/api/jobs/{jid}/inspect/functions")
    assert r.status_code == 409 and "larger than" in r.json()["error"]["message"] and runner.calls == []


def test_paths_outside_the_project_are_not_leaked(tmp_path):
    client, _, _ = _app(tmp_path)
    body = client.get("/api/system").text
    assert str(tmp_path) not in body and "außerhalb des Projekts" in body


# ---- example selection (2026-11-01) ------------------------------------------------------------------------
def test_examples_carry_budget_requirements_and_readiness(tmp_path):
    client, _, _ = _app(tmp_path)
    items = {e["id"]: e for e in client.get("/api/examples").json()["items"]}
    assert items["01-layered-flag"]["budget_minutes"] == 10 and items["02-script-three-layers"]["budget_minutes"] == 20
    assert items["01-layered-flag"]["ready"] is True
    x = items["05-pe-xor-routine"]
    assert x["requires"] == ["ghidra"] and x["ready"] is False and x["missing"][0]["key"] == "ghidra"


def test_example_start_uses_recommended_budget_and_refuses_unready_and_duplicates(tmp_path):
    client, store, _ = _app(tmp_path)
    s = client.post("/api/examples/02-script-three-layers/job", json={}, headers=ORIGIN).json()
    assert store.get_job(s["id"])["spec"]["budget_max_minutes"] == 20
    dup = client.post("/api/examples/02-script-three-layers/job", json={}, headers=ORIGIN)
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "already_running" and s["id"] in dup.text
    assert client.get("/api/examples").json()["items"][1]["active_job"] == s["id"]
    no = client.post("/api/examples/05-pe-xor-routine/job", json={}, headers=ORIGIN)
    assert no.status_code == 409 and no.json()["error"]["code"] == "not_ready" and "Ghidra" in no.text
    forced = client.post("/api/examples/05-pe-xor-routine/job", json={"force": True}, headers=ORIGIN)
    assert forced.status_code == 200


def test_example_start_refused_while_the_model_is_offline(tmp_path):
    _, store, gw = _app(tmp_path)
    llm = ScriptedLLM(lambda m: "{}", model="t")
    llm.reachable = lambda: False
    app = create_app(store, _Worker(), gw, llm, None, report_model="t", data_dir=tmp_path)
    off = TestClient(app, base_url="http://127.0.0.1:8765")
    r = off.post("/api/examples/01-layered-flag/job", json={}, headers=ORIGIN)
    assert r.status_code == 409 and "Sprachmodell" in r.json()["error"]["message"]


def test_batch_starts_ready_examples_in_difficulty_order(tmp_path):
    client, store, _ = _app(tmp_path)
    r = client.post("/api/examples-batch", json={}, headers=ORIGIN).json()
    titles = [store.get_job(s["id"])["title"] for s in r["started"]]
    assert [t.split(":")[0] for t in titles] == ["Beispiel 01-layered-flag", "Beispiel 02-script-three-layers",
                                                  "Beispiel 03-pe-appended-config", "Beispiel 04-prompt-injection"]
    assert [x["id"] for x in r["skipped"]] == ["05-pe-xor-routine"]
    again = client.post("/api/examples-batch", json={}, headers=ORIGIN).json()
    assert again["started"] == [] and len(again["skipped"]) == 5          # all queued already or not ready


def test_job_detail_names_the_example_and_its_result(tmp_path):
    client, store, gw = _app(tmp_path)
    s = client.post("/api/examples/01-layered-flag/job", json={}, headers=ORIGIN).json()
    d = client.get(f"/api/jobs/{s['id']}").json()
    assert d["example"] == {"id": "01-layered-flag", "title": "Doppelt kodierte Flagge", "level": "leicht", "flag_found": None}
    store.update_job(s["id"], status="done")
    store.update_answer(s["id"], "Q1", status="answered", answer_en="The flag is FLAG{layered_ok}")
    assert client.get(f"/api/jobs/{s['id']}").json()["example"]["flag_found"] is True


# ---- process state and collected data (2026-11-01) --------------------------------------------------------
def test_activity_reports_each_phase_and_why_the_job_ended(tmp_path):
    a, store, gw = _app(tmp_path)
    jid = _job(store, gw, b"MZ harmless")
    store.update_job(jid, status="running", started_at="2026-11-01T00:00:00Z")
    tri = store.add_task(jid, title="Triage", goal="g", kind="triage", origin="triage", priority=1)
    store.update_task(tri["id"], status="done")
    work = store.add_task(jid, title="Strings", goal="g", kind="analyze", origin="recipe", priority=10)
    store.update_task(work["id"], status="running", started_at="2026-11-01T00:00:01Z")
    sid = store.begin_step(jid, work["id"], "evaluate", "self check")
    act = a.get(f"/api/jobs/{jid}/activity").json()
    ph = {p["id"]: p for p in act["phases"]}
    assert act["state"] == "working" and act["end"] is None
    assert ph["triage"]["state"] == "done" and ph["triage"]["total"] == 1
    assert ph["planning"]["state"] == "done" and ph["analysis"] == {"id": "analysis", "state": "open", "count": 0, "total": 1}
    assert ph["evaluation"]["state"] == "cur" and ph["finalizing"]["state"] == "open"
    store.finish_step(sid, status="ok", duration_ms=5)
    store.update_task(work["id"], status="done")
    store.log(jid, "stopping: time budget exhausted", level="warn")
    store.update_job(jid, status="partial", finished_at="2026-11-01T00:10:00Z", summary_de="1 von 1 Aufgaben erledigt")
    act = a.get(f"/api/jobs/{jid}/activity").json()
    ph = {p["id"]: p for p in act["phases"]}
    assert act["state"] == "finished" and ph["analysis"]["state"] == "done" and ph["finalizing"]["state"] == "done"
    assert ph["prioritization"]["state"] == "open"                         # never happened: shown as not reached
    assert act["end"]["status"] == "partial" and act["end"]["reason"] == "stopping: time budget exhausted"
    assert act["end"]["summary_de"] == "1 von 1 Aufgaben erledigt"


def test_evidence_list_shows_what_was_collected(tmp_path):
    a, store, gw = _app(tmp_path)
    jid = _job(store, gw, b"hello")
    store.add_evidence(jid, None, "strings", "1.0", {"path": "sample", "min_len": 4}, "hello\nworld\n" * 50,
                       injection_flags=["ignore-previous"])
    row = a.get(f"/api/jobs/{jid}/evidence").json()[0]
    assert row["params"] == {"path": "sample", "min_len": 4} and row["size"] == 600
    assert row["preview"].startswith("hello\nworld") and len(row["preview"]) == 240
    assert row["injection_flags"] == ["ignore-previous"] and "text" not in row
