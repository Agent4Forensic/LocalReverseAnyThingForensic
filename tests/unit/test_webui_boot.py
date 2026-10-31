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


def _client(tmp_path):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    gw = DevGateway(tmp_path)
    llm = ScriptedLLM(lambda m: json.dumps({"action": "finish"}))
    worker = Worker(store, JobEngine(store, llm, gw, None))
    return TestClient(create_app(store, worker, gw, llm, None, report_model="t"), base_url="http://127.0.0.1:8765")


def test_app_builds_and_reports_system_state(tmp_path):
    r = _client(tmp_path).get("/api/system")
    assert r.status_code == 200 and r.json()["gateway"]["tools"] == 13


def test_static_dashboard_is_served(tmp_path):
    r = _client(tmp_path).get("/")
    assert r.status_code == 200 and "sw-analyst" in r.text


def test_post_without_origin_is_refused(tmp_path):
    assert _client(tmp_path).post("/api/jobs", data={"spec": "{}"}, files={"sample": ("a.txt", b"x")}).status_code == 403
