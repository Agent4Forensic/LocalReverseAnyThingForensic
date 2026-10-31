"""The web app must build and answer. A missing runtime dependency (python-multipart for the upload route) once
made `python -m sw_analyst` crash at start while every other test stayed green."""
import json

from fastapi.testclient import TestClient

from sw_analyst.common.store import Store
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.llm.fake import ScriptedLLM
from sw_analyst.orchestrator.engine import JobEngine
from sw_analyst.orchestrator.worker import Worker
from sw_analyst.webui.app import create_app


ORIGIN = {"Origin": "http://127.0.0.1:8765"}


def _examples(tmp_path):
    d = tmp_path / "ex"
    (d / "challenges" / "01-x").mkdir(parents=True)
    (d / "samples.py").write_text("BUILDERS = {'mk': lambda: b'hello'}\n", encoding="utf-8")
    (d / "challenges" / "01-x" / "challenge.json").write_text(json.dumps({
        "id": "01-x", "title": "T", "level": "leicht", "description": "D", "goal": "G", "tests": "X",
        "sample": {"name": "ctf.txt", "builder": "mk"}, "job_description": "CTF: find the flag.",
        "questions": ["What is the flag?"], "flag": "FLAG{secret}"}), encoding="utf-8")
    return d


def _client(tmp_path, examples_dir=None):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    gw = DevGateway(tmp_path)
    llm = ScriptedLLM(lambda m: json.dumps({"action": "finish"}))
    worker = Worker(store, JobEngine(store, llm, gw, None))
    return TestClient(create_app(store, worker, gw, llm, None, report_model="t", examples_dir=examples_dir),
                      base_url="http://127.0.0.1:8765")


def test_app_builds_and_reports_system_state(tmp_path):
    r = _client(tmp_path).get("/api/system")
    assert r.status_code == 200 and r.json()["gateway"]["tools"] == 17


def test_static_dashboard_is_served(tmp_path):
    r = _client(tmp_path).get("/")
    assert r.status_code == 200 and "sw-analyst" in r.text


def test_post_without_origin_is_refused(tmp_path):
    assert _client(tmp_path).post("/api/jobs", data={"spec": "{}"}, files={"sample": ("a.txt", b"x")}).status_code == 403


def test_examples_hide_flag_goal_and_test_notes(tmp_path):
    r = _client(tmp_path, _examples(tmp_path)).get("/api/examples")
    assert r.status_code == 200 and [e["id"] for e in r.json()] == ["01-x"]
    assert "FLAG{secret}" not in r.text and "goal" not in r.json()[0] and "tests" not in r.json()[0]


def test_missing_examples_folder_means_empty_list(tmp_path):
    assert _client(tmp_path, tmp_path / "none").get("/api/examples").json() == []


def test_job_from_example_needs_no_upload_and_gets_the_largest_budget(tmp_path):
    c = _client(tmp_path, _examples(tmp_path))
    r = c.post("/api/jobs", data={"spec": json.dumps({"title": "T"}), "example": "01-x"}, headers=ORIGIN)
    assert r.status_code == 200 and r.json()["sample_name"] == "ctf.txt"
    spec = c.get(f"/api/jobs/{r.json()['id']}").json()["spec"]
    assert (spec["budget_max_tasks"], spec["budget_max_steps"], spec["budget_max_minutes"]) == (300, 5000, 1440)


def test_unknown_example_and_missing_sample_are_refused(tmp_path):
    c = _client(tmp_path, _examples(tmp_path))
    spec = json.dumps({"title": "T"})
    assert c.post("/api/jobs", data={"spec": spec, "example": "../x"}, headers=ORIGIN).json()["error"]["code"] == "unknown_example"
    assert c.post("/api/jobs", data={"spec": spec}, headers=ORIGIN).json()["error"]["code"] == "empty_sample"


def test_own_upload_still_works(tmp_path):
    r = _client(tmp_path).post("/api/jobs", data={"spec": json.dumps({"title": "T"})},
                               files={"sample": ("a.txt", b"x")}, headers=ORIGIN)
    assert r.status_code == 200 and r.json()["sample_name"] == "a.txt"


def test_clean_urls_serve_the_app_but_unknown_api_and_assets_stay_404(tmp_path):
    c = _client(tmp_path)
    assert "sw-analyst" in c.get("/job/job-0001/activity").text and 'src="/app.js"' in c.get("/new").text
    assert c.get("/api/nope").status_code == 404 and c.get("/missing.js").status_code == 404


def test_every_script_in_index_html_is_served(tmp_path):
    """index.html once loaded three scripts that did not exist (404), so whole tabs were missing."""
    import re
    c = _client(tmp_path)
    srcs = re.findall(r'<script src="(/[^"]+)"', c.get("/").text)
    assert srcs and all(c.get(s).status_code == 200 for s in srcs)
