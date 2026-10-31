"""Forensic test plan I6 (web API) and I7 (frontend assets), docs/testing/forensic-test-plan.md.

Covers Origin/Host checks, security headers, upload limits and file names, path traversal in the code viewer,
the error format, and a static scan of src/sw_analyst/webui/static. Only harmless, self-made sample bytes."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sw_analyst.common.store import Store
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.llm.fake import ScriptedLLM
from sw_analyst.orchestrator.engine import JobEngine
from sw_analyst.orchestrator.worker import Worker
from sw_analyst.webui.app import MAX_SAMPLE, STATIC_DIR, create_app

MIB = 1024 * 1024
SPEC = json.dumps({"title": "api-security"})


def _make(tmp_path, port=8765):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    gw = DevGateway(tmp_path)
    llm = ScriptedLLM(lambda m: json.dumps({"action": "finish"}))
    worker = Worker(store, JobEngine(store, llm, gw, None))
    app = create_app(store, worker, gw, llm, None, report_model="t", port=port)
    # raise_server_exceptions=False: a crash must surface as the HTTP 500 a client would see.
    client = TestClient(app, base_url=f"http://127.0.0.1:{port}", raise_server_exceptions=False)
    return client, store, gw


@pytest.fixture
def env(tmp_path):
    return _make(tmp_path)


def _origin(port=8765):
    return {"Origin": f"http://127.0.0.1:{port}"}


def _upload(client, name="a.txt", data=b"hello\nworld\n", headers=None, spec=SPEC):
    return client.post("/api/jobs", data={"spec": spec}, files={"sample": (name, data)},
                       headers=_origin() if headers is None else headers)


def _job(client, data=b"line one\nline two\nline three\n"):
    r = _upload(client, data=data)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _error_code(r):
    return r.json()["error"]["code"]


# ---- I6: Origin check (state-changing requests) ------------------------------------------------------------------

@pytest.mark.parametrize("origin", ["http://127.0.0.1:8765", "http://localhost:8765"])
def test_loopback_origin_is_accepted(env, origin):
    client, _, _ = env
    assert _upload(client, headers={"Origin": origin}).status_code == 200


@pytest.mark.parametrize("origin", [
    None,                              # no Origin at all (curl, script, some CSRF vectors)
    "null",                            # sandboxed iframe / file:// page
    "",
    "http://evil.example",
    "http://evil.example:8765",
    "http://127.0.0.1.evil.example:8765",
    "http://127.0.0.1:8765.evil.example",
    "http://localhost.evil.example:8765",
    "http://127.0.0.1:8766",           # right host, wrong port
    "https://127.0.0.1:8765",          # wrong scheme
    "http://[::1]:8765",
    "http://0.0.0.0:8765",
])
def test_foreign_origin_is_refused_on_post(env, origin):
    client, store, _ = env
    headers = {} if origin is None else {"Origin": origin}
    r = _upload(client, headers=headers)
    assert r.status_code == 403 and _error_code(r) == "forbidden_origin"
    assert store.list_jobs() == []     # refused before anything was stored


def test_cancel_requires_a_loopback_origin(env):
    client, _, _ = env
    jid = _job(client)
    assert client.post(f"/api/jobs/{jid}/cancel", headers={"Origin": "http://evil.example"}).status_code == 403
    assert client.post(f"/api/jobs/{jid}/cancel").status_code == 403
    assert client.get(f"/api/jobs/{jid}").json()["summary"]["status"] == "queued"
    assert client.post(f"/api/jobs/{jid}/cancel", headers=_origin()).json()["status"] == "cancelled"


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])
def test_other_state_changing_methods_need_origin(env, method):
    client, _, _ = env
    r = client.request(method, "/api/jobs/J-0001")
    assert r.status_code == 403


def test_origin_follows_the_configured_port_not_a_fixed_8765(tmp_path):
    client, _, _ = _make(tmp_path, port=9123)
    assert _upload(client, headers=_origin(9123)).status_code == 200
    r = _upload(client, headers=_origin(8765))
    assert r.status_code == 403 and _error_code(r) == "forbidden_origin"


# ---- I6: Host check (DNS rebinding), applies to every method -----------------------------------------------------

@pytest.mark.parametrize("host", ["127.0.0.1:8765", "localhost:8765", "127.0.0.1", "localhost"])
def test_loopback_host_is_accepted(env, host):
    client, _, _ = env
    assert client.get("/api/system", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize("host", [
    "evil.example", "evil.example:8765", "127.0.0.1.evil.example", "localhost.evil.example:8765",
    "evil.example:127.0.0.1", "192.168.1.5:8765", "0.0.0.0:8765", "",
])
def test_foreign_host_is_refused_on_get(env, host):
    client, _, _ = env
    for path in ("/api/system", "/api/jobs", "/"):
        r = client.get(path, headers={"Host": host})
        assert r.status_code == 400 and _error_code(r) == "bad_host", (path, host)


def test_foreign_host_is_refused_even_with_valid_origin(env):
    client, store, _ = env
    r = _upload(client, headers={**_origin(), "Host": "evil.example:8765"})
    assert r.status_code == 400 and _error_code(r) == "bad_host"
    assert store.list_jobs() == []


def test_host_check_follows_loopback_for_non_default_port(tmp_path):
    client, _, _ = _make(tmp_path, port=9123)
    assert client.get("/api/system", headers={"Host": "127.0.0.1:9123"}).status_code == 200
    assert client.get("/api/system", headers={"Host": "evil.example:9123"}).status_code == 400


# ---- I6: security headers --------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/", "/index.html", "/app.js", "/styles.css", "/api/system", "/api/jobs",
                                  "/api/prompts", "/does-not-exist", "/api/jobs/J-9999"])
def test_security_headers_on_every_response(env, path):
    client, _, _ = env
    h = client.get(path).headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "no-referrer"
    assert h["cache-control"] == "no-store"
    assert "content-security-policy" in h


def test_security_headers_on_report_and_event_stream_setup(env):
    client, _, _ = env
    jid = _job(client)
    r = client.get(f"/api/jobs/{jid}/report")
    assert r.status_code == 200 and "content-security-policy" in r.headers
    assert r.headers["x-content-type-options"] == "nosniff"


def test_csp_is_strict(env):
    client, _, _ = env
    csp = client.get("/").headers["content-security-policy"]
    directives = {d.split()[0]: d.split()[1:] for d in (x.strip() for x in csp.split(";")) if d}
    assert directives["default-src"] == ["'none'"]
    assert directives["script-src"] == ["'self'"]
    assert directives["style-src"] == ["'self'"]
    assert directives["frame-ancestors"] == ["'none'"]
    assert directives["base-uri"] == ["'none'"]
    assert directives["connect-src"] == ["'self'"]
    assert "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
    # no directive may name a foreign origin or a wildcard
    for sources in directives.values():
        assert not any(s == "*" or s.startswith(("http:", "https:", "ws:", "wss:")) for s in sources)


def test_no_cors_headers_are_ever_sent(env):
    client, _, _ = env
    r = client.get("/api/system", headers={"Origin": "http://evil.example"})
    assert not any(k.lower().startswith("access-control-") for k in r.headers)
    r = client.options("/api/jobs", headers={"Origin": "http://evil.example",
                                             "Access-Control-Request-Method": "POST"})
    assert not any(k.lower().startswith("access-control-") for k in r.headers)


def test_docs_and_openapi_are_not_exposed(env):
    client, _, _ = env
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


# ---- I6: upload ---------------------------------------------------------------------------------------------------

def test_upload_limit_is_64_mib():
    assert MAX_SAMPLE == 64 * MIB


def test_upload_over_limit_is_refused_and_leaves_nothing(env, tmp_path):
    client, store, _ = env
    r = _upload(client, data=b"\x00" * (MAX_SAMPLE + 1))
    assert r.status_code == 413 and _error_code(r) == "too_large"
    assert store.list_jobs() == []
    assert not (tmp_path / "jobs").exists() or not any((tmp_path / "jobs").iterdir())


def test_upload_exactly_at_limit_is_accepted(env):
    client, _, _ = env
    r = _upload(client, data=b"A" * MAX_SAMPLE)
    assert r.status_code == 200 and r.json()["sample_sha256"]


def test_empty_upload_is_refused(env):
    client, store, _ = env
    r = _upload(client, data=b"")
    assert r.status_code == 422 and _error_code(r) == "empty_sample"
    assert store.list_jobs() == []


def test_upload_without_sample_part_is_refused(env):
    client, store, _ = env
    r = client.post("/api/jobs", data={"spec": SPEC}, headers=_origin())
    assert r.status_code == 422 and store.list_jobs() == []


@pytest.mark.parametrize("spec", ["{}", "not json", '{"title":""}', '{"title":"' + "x" * 201 + '"}',
                                  '{"title":"t","budget_max_tasks":1}', '{"title":"t","target_questions":[' + ",".join(
                                      ['{"text":"q"}'] * 21) + ']}'])
def test_invalid_spec_is_refused(env, spec):
    client, store, _ = env
    r = _upload(client, spec=spec)
    assert r.status_code == 422 and _error_code(r) == "invalid_spec"
    assert store.list_jobs() == []


def test_emulation_opt_in_is_refused(env):
    client, store, _ = env
    r = _upload(client, spec=json.dumps({"title": "t", "emulation_opt_in": True}))
    assert r.status_code == 422 and _error_code(r) == "emulation_disabled" and store.list_jobs() == []


def test_duplicate_question_ids_are_refused(env):
    client, store, _ = env
    spec = json.dumps({"title": "t", "target_questions": [{"id": "Q1", "text": "a"}, {"id": "Q1", "text": "b"}]})
    r = _upload(client, spec=spec)
    assert r.status_code == 422 and _error_code(r) == "duplicate_question_id" and store.list_jobs() == []


HOSTILE_NAMES = [
    "../../../evil.exe", "..\\..\\evil.exe", "/etc/passwd", "C:\\Windows\\System32\\evil.exe", "C:evil.exe",
    "\\\\server\\share\\evil.exe", "a/../../b", "....//....//x", "%2e%2e%2fevil", "..", ".", "CON", "nul.txt",
    "evil\u202egpj.exe",           # right-to-left override: displays as evil...exe.jpg
    "\u2025\u2025/evil",           # TWO DOT LEADER look-alike for '..'
    "\uff0e\uff0e/evil",           # fullwidth full stop
    "evil\x00.txt", "evil\r\n.txt", "x" * 400 + ".exe", "<img src=x onerror=alert(1)>.exe",
]


@pytest.mark.parametrize("name", HOSTILE_NAMES, ids=[f"name{i}" for i in range(len(HOSTILE_NAMES))])
def test_hostile_file_name_never_reaches_the_file_system(env, tmp_path, name):
    client, store, gw = env
    r = _upload(client, name=name, data=b"harmless bytes\n")
    assert r.status_code == 200, r.text
    job = r.json()
    # The stored name is metadata only: no separators, bounded length, and the sample lives at a fixed path.
    assert "/" not in job["sample_name"] and "\\" not in job["sample_name"]
    assert len(job["sample_name"]) <= 120
    on_disk = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*")
                     if p.is_file() and p.suffix not in (".db", ".jsonl", ".log")
                     and not p.name.startswith("t.db") and "logs" not in p.parts)
    assert on_disk == [f"jobs/{job['id']}/sample"]
    assert not (tmp_path.parent / "evil.exe").exists() and not (tmp_path / "evil.exe").exists()
    # the file list never exposes the upload name as a path
    assert [f["path"] for f in client.get(f"/api/jobs/{job['id']}/files").json()] == ["sample"]


@pytest.mark.xfail(strict=True, reason="webui/app.py:125 keeps bidi/control characters in sample_name; the name is "
                                       "shown in UI and report and can spoof the file extension (low severity)")
def test_sample_name_has_no_bidi_or_control_characters(env):
    # httpx percent-encodes CR/LF/NUL in file names, so only the bidi override can reach the server.
    client, _, _ = env
    shown = _upload(client, name="evil‮gpj.exe").json()["sample_name"]
    assert not any(ord(c) < 32 or c in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" for c in shown)


# ---- I6: path traversal in code viewer / file endpoints ----------------------------------------------------------

TRAVERSAL_PATHS = [
    "..", "../sample", "../../t.db", "derived/../../../t.db", "derived/../../sample", "./../sample",
    "%2e%2e/sample", "%2e%2e%2f%2e%2e%2ft.db", "..%2fsample", "%252e%252e/sample",
    "/etc/passwd", "/sample", "C:\\Windows\\win.ini", "C:/Windows/win.ini", "C:win.ini", "c:\\sample",
    "\\\\server\\share\\x", "\\sample", "..\\sample", "derived\\..\\..\\t.db", "derived\\..\\sample",
    "sample\x00.txt", "sample/", "sample/.", "derived", "derived/", "", " ", "../" * 40 + "etc/passwd",
    "\u2025/sample", "\uff0e\uff0e/sample", "file:///etc/passwd", "~/x", "sample:stream", "CON",
]


@pytest.mark.parametrize("path", TRAVERSAL_PATHS, ids=[f"path{i}" for i in range(len(TRAVERSAL_PATHS))])
def test_code_viewer_refuses_traversal(env, tmp_path, path):
    client, _, _ = env
    jid = _job(client)
    # `params=` percent-encodes, so '%2e%2e' arrives as the literal text '%2e%2e' and as decoded dots below.
    for r in (client.get(f"/api/jobs/{jid}/files/content", params={"path": path}),
              client.get(f"/api/jobs/{jid}/files/content?path={path.replace(chr(0), '%00')}")):
        assert r.status_code in (400, 404, 422), (path, r.status_code)
        body = r.text
        assert "line one" not in body and "SQLite" not in body
        assert str(tmp_path) not in body and "Traceback" not in body
        if r.status_code == 400:
            assert _error_code(r) == "bad_path"


def test_code_viewer_still_serves_the_sample(env):
    client, _, _ = env
    jid = _job(client)
    r = client.get(f"/api/jobs/{jid}/files/content", params={"path": "sample"})
    assert r.status_code == 200 and [x["text"] for x in r.json()["lines"][:2]] == ["line one", "line two"]


def test_code_viewer_lines_follow_the_documented_contract(env):
    client, _, _ = env
    jid = _job(client)
    body = client.get(f"/api/jobs/{jid}/files/content", params={"path": "sample"}).json()
    assert body["lines"][0] == {"n": 1, "text": "line one"} and "binary" in body


@pytest.mark.parametrize("job_id", ["..", "%2e%2e", "J-0001/../..", "..\\..", "C:", "a" * 200,
                                    "J-0001%00", "J-9999"])
def test_job_id_in_path_cannot_escape(env, tmp_path, job_id):
    client, _, _ = env
    _job(client)
    for suffix in ("", "/files", "/files/content?path=sample", "/report", "/audit", "/log"):
        r = client.get(f"/api/jobs/{job_id}{suffix}")
        assert r.status_code in (404, 400, 422, 405), (job_id, suffix, r.status_code)
        assert str(tmp_path) not in r.text and "Traceback" not in r.text


def test_symlink_inside_job_workspace_is_denied(env, tmp_path):
    client, _, _ = env
    jid = _job(client)
    secret = tmp_path / "outside-secret.txt"
    secret.write_text("TOP-SECRET-OUTSIDE\n", encoding="utf-8")
    link = tmp_path / "jobs" / jid / "derived" / "link.txt"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted for this user")
    r = client.get(f"/api/jobs/{jid}/files/content", params={"path": "derived/link.txt"})
    assert r.status_code == 400 and "TOP-SECRET-OUTSIDE" not in r.text
    assert "link.txt" not in [f["path"] for f in client.get(f"/api/jobs/{jid}/files").json()]


@pytest.mark.parametrize("path", ["/..%2f..%2fapp.py", "/%2e%2e/app.py", "/%2e%2e%2fapp.py", "/..\\app.py",
                                  "/static/../app.py", "/../../../../etc/passwd", "/%2e%2e%5c%2e%2e%5capp.py",
                                  "/..%252fapp.py"])
def test_static_mount_refuses_traversal(env, path):
    client, _, _ = env
    r = client.get(path)
    assert "create_app" not in r.text and "root:" not in r.text and "[fonts]" not in r.text.lower()
    assert r.status_code in (400, 404)


def _status_without_leak(env, path):
    r = env[0].get(path)
    assert "root:" not in r.text and "[fonts]" not in r.text.lower()
    return r.status_code


@pytest.mark.xfail(strict=True, reason="webui/app.py:342 StaticFiles answers 500 (ValueError) for an embedded NUL "
                                       "byte in the path; no leak, but not a clean 404 (low)")
def test_static_mount_nul_byte_is_a_clean_404(env):
    assert _status_without_leak(env, "/index.html%00.js") == 404


@pytest.mark.skipif(os.name != "nt", reason="drive letters are a Windows concept")
@pytest.mark.xfail(strict=True, reason="webui/app.py:342 StaticFiles answers 500 (ValueError, different drive) for "
                                       "'/<other drive>:/...'; no leak, but not a clean 404 (low)")
def test_static_mount_foreign_drive_is_a_clean_404(env):
    other = "C:" if STATIC_DIR.drive.upper() != "C:" else "E:"
    assert _status_without_leak(env, f"/{other}/Windows/win.ini") == 404


def test_static_mount_same_drive_absolute_path_is_refused(env):
    assert _status_without_leak(env, f"/{STATIC_DIR.drive or 'D:'}/Windows/win.ini") in (400, 404)


def test_static_mount_does_not_serve_python_sources(env):
    client, _, _ = env
    assert client.get("/app.py").status_code == 404
    assert client.get("/__init__.py").status_code == 404


# ---- I6: error format -------------------------------------------------------------------------------------------

def test_unknown_job_uses_documented_error_format(env):
    client, _, _ = env
    r = client.get("/api/jobs/J-9999")
    assert r.status_code == 404 and r.json() == {"error": {"code": "not_found", "message": "job J-9999 does not exist"}}


def test_error_bodies_are_json_with_code_and_message(env):
    client, _, _ = env
    jid = _job(client)
    for r in (client.get("/api/jobs/J-9999/tree"), client.get(f"/api/jobs/{jid}/tasks/T-nope"),
              client.get(f"/api/jobs/{jid}/evidence/E-nope"), client.get("/api/prompts/nope"),
              client.get(f"/api/jobs/{jid}/report?lang=xx"), client.get(f"/api/jobs/{jid}/files/content?path=../x")):
        assert r.status_code >= 400
        err = r.json()["error"]
        assert set(err) == {"code", "message"} and err["code"] and isinstance(err["message"], str)


@pytest.mark.parametrize("path", ["/api/jobs/J-0001/files/content", "/api/jobs/J-0001/log?after=abc",
                                  "/api/jobs/J-0001/files/content?path=sample&start=x"])
def test_request_validation_errors_do_not_leak_details(env, tmp_path, path):
    client, _, _ = env
    _job(client)
    r = client.get(path)
    assert r.status_code == 422
    assert str(tmp_path) not in r.text and "Traceback" not in r.text and "site-packages" not in r.text


@pytest.mark.xfail(strict=True, reason="FastAPI's default RequestValidationError handler (webui/app.py, no handler "
                                       "registered) answers {'detail': [...]} instead of the documented "
                                       "{'error': {code, message}} (docs/architecture/api.md); contract deviation, low")
def test_request_validation_error_uses_documented_format(env):
    client, _, _ = env
    _job(client)
    r = client.get("/api/jobs/J-0001/files/content")      # required query parameter 'path' missing
    assert r.status_code == 422 and set(r.json()["error"]) == {"code", "message"}


def test_internal_failure_is_a_bare_500_without_stacktrace_or_paths(tmp_path, monkeypatch):
    client, store, _ = _make(tmp_path)
    secret_path = str(tmp_path / "very" / "secret" / "place.db")

    def boom():
        raise RuntimeError(f"cannot open {secret_path}")
    monkeypatch.setattr(store, "list_jobs", boom)
    r = client.get("/api/jobs")
    assert r.status_code == 500
    for needle in ("Traceback", "RuntimeError", secret_path, str(tmp_path), "secret", "File \""):
        assert needle not in r.text, needle


def test_gateway_failure_message_does_not_leak_local_paths(tmp_path):
    client, _, _ = _make(tmp_path)
    jid = _job(client)
    for p in ("nope", "derived/nope.bin", "derived", "/etc/passwd", "..\\x"):
        r = client.get(f"/api/jobs/{jid}/files/content", params={"path": p})
        assert r.status_code == 400
        assert str(tmp_path) not in r.text and str(tmp_path).replace("\\", "/") not in r.text
        assert re.search(r"[A-Za-z]:\\\\|/(home|Users|tmp)/", r.text) is None


@pytest.mark.xfail(strict=True, reason="webui/app.py:75 registers the error handler for fastapi.HTTPException only; "
                                       "Starlette's own 404 (unknown route, static mount) answers {'detail': ...} "
                                       "instead of the documented {'error': {code, message}} (low)")
def test_unknown_route_uses_documented_error_format(env):
    client, _, _ = env
    r = client.get("/api/nonexistent")
    assert r.status_code == 404 and set(r.json()["error"]) == {"code", "message"}


def test_method_not_allowed_and_unknown_api_route_are_clean(env, tmp_path):
    client, _, _ = env
    for r in (client.get("/api/jobs/J-0001/cancel"), client.get("/api/nonexistent"), client.post("/api/system",
                                                                                                   headers=_origin())):
        assert r.status_code in (404, 405)
        assert "Traceback" not in r.text and str(tmp_path) not in r.text


# ---- I7: frontend assets ------------------------------------------------------------------------------------------

ASSETS = sorted(p for p in STATIC_DIR.rglob("*") if p.is_file() and p.suffix in (".js", ".html", ".css"))
# Namespace identifiers, not network requests (createElementNS). Anything else must be loopback.
ALLOWED_URL = re.compile(r"^https?://(127\.0\.0\.1|localhost)(:\d+)?(/|$)|^http://www\.w3\.org/(2000/svg|1999/xhtml)$")
DANGEROUS_JS = re.compile(r"\.(innerHTML|outerHTML)\b|insertAdjacentHTML|document\.write|\beval\s*\(|new\s+Function\s*\(|"
                          r"setTimeout\s*\(\s*['\"`]|setInterval\s*\(\s*['\"`]|javascript:|createContextualFragment|"
                          r"DOMParser|\bimportScripts\b|\bimport\s*\(")


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"(?m)(^|[^:\\'\"`])//.*$", r"\1", src)


def test_static_assets_exist():
    names = {p.name for p in ASSETS}
    assert {"index.html", "app.js", "dom.js", "styles.css", "view_code.js"} <= names


@pytest.mark.parametrize("asset", [p for p in ASSETS if p.suffix == ".js"], ids=lambda p: p.name)
def test_js_has_no_html_sinks_or_dynamic_code(asset):
    hits = DANGEROUS_JS.findall(_strip_comments(asset.read_text(encoding="utf-8")))
    assert not hits, f"{asset.name}: {hits}"


def test_dom_helper_refuses_event_handler_style_and_src_attributes():
    src = (STATIC_DIR / "dom.js").read_text(encoding="utf-8")
    assert "/^on/i.test(key) || key === 'style' || key === 'src' || key === 'srcdoc'" in src


@pytest.mark.parametrize("asset", ASSETS, ids=lambda p: p.name)
def test_assets_reference_no_foreign_resources(asset):
    text = asset.read_text(encoding="utf-8")
    urls = re.findall(r"""(?:https?:)?//[^\s'"`)<>]+""", _strip_comments(text) if asset.suffix == ".js" else text)
    # protocol-relative URLs look like '//host'; skip JS division/regex noise by requiring a dotted or http host
    bad = [u for u in urls if u.startswith(("http:", "https:")) and not ALLOWED_URL.match(u)]
    bad += [u for u in urls if u.startswith("//") and re.match(r"//[\w-]+(\.[\w-]+)+", u)]
    assert not bad, f"{asset.name}: {bad}"
    assert not re.search(r"@import|url\(\s*['\"]?(https?:|//)", text) if asset.suffix == ".css" else True


def test_index_html_is_csp_clean_and_self_contained():
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", html), "inline script blocked by CSP / unsafe"
    assert not re.search(r"\son[a-z]+\s*=", html, re.I), "inline event handler"
    assert not re.search(r"\sstyle\s*=", html, re.I), "inline style attribute (style-src 'self')"
    assert not re.search(r"<style\b", html, re.I) and not re.search(r"<(iframe|object|embed|base|form)\b", html, re.I)
    for ref in re.findall(r"""\b(?:src|href)\s*=\s*["']([^"']+)["']""", html):
        assert ref == "data:," or not re.match(r"^(?:[a-z][a-z0-9+.-]*:|//)", ref, re.I) or ALLOWED_URL.match(ref), ref
        if not ref.startswith("#"):
            assert ".." not in ref and not ref.startswith("/api"), ref


def test_sample_derived_text_is_inserted_only_as_text():
    """The code viewer and job views are the places sample lines and strings are rendered."""
    for name in ("view_code.js", "view_job.js", "view_report.js", "markdown.js", "dom.js"):
        src = _strip_comments((STATIC_DIR / name).read_text(encoding="utf-8"))
        assert "innerHTML" not in src and "insertAdjacentHTML" not in src, name
    assert "textContent" in (STATIC_DIR / "dom.js").read_text(encoding="utf-8") or \
           "createTextNode" in (STATIC_DIR / "dom.js").read_text(encoding="utf-8")


def test_served_assets_are_identical_to_files_on_disk(env):
    client, _, _ = env
    for p in ASSETS:
        r = client.get("/" + p.relative_to(STATIC_DIR).as_posix())
        assert r.status_code == 200 and r.content == p.read_bytes(), p.name
        assert "content-security-policy" in r.headers
