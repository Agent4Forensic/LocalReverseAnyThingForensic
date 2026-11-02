"""ColibriClient against a fake `coli serve`, plus the checks of the model on its volume (ADR-0012)."""
import hashlib
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import sw_analyst.preflight as pf
from sw_analyst.llm.base import ChatMessage, LLMError
from sw_analyst.llm.colibri import ColibriClient

ROOT = Path(__file__).resolve().parents[2]
USER = [ChatMessage(role="user", content="hi")]


@pytest.fixture
def server():
    state = {"reply": {"model": "m", "choices": [{"message": {"content": "{}", "reasoning_content": "why"}, "finish_reason": "length"}],
                       "usage": {"prompt_tokens": 3, "completion_tokens": 4}},
             "status": 200, "seen": None, "headers": None, "health": 200, "location": "", "paths": []}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(state["health"] if self.path == "/health" else 404)
            self.end_headers()

        def do_POST(self):
            state["seen"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["headers"], state["path"] = dict(self.headers), self.path
            state["paths"].append(self.path)
            self.send_response(state["status"])
            if state["location"]:
                self.send_header("Location", state["location"])
            self.end_headers()
            self.wfile.write(json.dumps(state["reply"]).encode())

    s = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield state, ColibriClient("m", f"http://127.0.0.1:{s.server_port}", api_key="k")
    s.shutdown()


def test_refuses_non_local_endpoint():
    with pytest.raises(ValueError):
        ColibriClient("m", "http://10.0.0.1:11436")


def test_reply_maps_to_the_llm_response(server):
    state, c = server
    r = c.chat(USER)
    assert (r.text, r.thinking, r.prompt_tokens, r.completion_tokens, r.done_reason) == ("{}", "why", 3, 4, "length")
    assert state["path"] == "/v1/chat/completions" and state["headers"]["Authorization"] == "Bearer k"


def test_temperature_is_always_zero_and_no_seed_is_claimed(server):
    state, c = server
    c.chat(USER, temperature=0.7)
    assert state["seen"]["temperature"] == 0 and "seed" not in state["seen"]
    assert not hasattr(c, "seed")  # the runner logs getattr(llm, "seed", None): the engine has none, a report must not name one


def test_thinking_is_off_unless_allowed(server):
    state, c = server
    c.chat(USER, think=True)
    assert state["seen"]["enable_thinking"] is False
    c.allow_think = True
    c.chat(USER, think=True)
    assert state["seen"]["enable_thinking"] is True


def test_json_mode_adds_a_short_instruction_but_never_the_schema(server):
    state, c = server
    schema = {"type": "object", "required": ["action"], "description": "must not reach the prompt"}
    c.chat([ChatMessage(role="system", content="S"), *USER], json_mode=schema)
    sysmsg = state["seen"]["messages"][0]
    assert sysmsg["role"] == "system" and sysmsg["content"].startswith("S\n\n") and "exactly one JSON object" in sysmsg["content"]
    assert "must not reach the prompt" not in json.dumps(state["seen"]) and "response_format" not in state["seen"]
    c.chat(USER, json_mode=True)
    assert state["seen"]["messages"][0]["role"] == "system" and "exactly one JSON object" in state["seen"]["messages"][0]["content"]
    c.chat(USER)
    assert state["seen"]["messages"] == [{"role": "user", "content": "hi"}]


@pytest.mark.parametrize("status,reply", [(500, {"error": "x"}), (200, {"choices": []}), (200, {})])
def test_bad_replies_raise_llm_error(server, status, reply):
    state, c = server
    state["status"], state["reply"] = status, reply
    with pytest.raises(LLMError):
        c.chat(USER)


def test_a_proxy_setting_cannot_take_the_key_off_the_machine(server, monkeypatch):
    state, c = server
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")   # nothing listens there: going through it would fail
    monkeypatch.delenv("NO_PROXY", raising=False)
    assert c.chat(USER).text == "{}"


def test_a_redirect_is_never_followed(server):
    state, c = server
    state["status"], state["location"] = 307, c.base_url + "/elsewhere"
    with pytest.raises(LLMError):
        c.chat(USER)
    assert state["paths"] == ["/v1/chat/completions"]


def test_unreachable_raises_llm_error():
    with pytest.raises(LLMError):
        ColibriClient("m", "http://127.0.0.1:9", timeout_s=2).chat(USER)


def test_reachable_only_when_the_engine_has_loaded(server):
    state, c = server
    assert c.reachable() is True
    state["health"] = 503
    assert c.reachable() is False
    assert ColibriClient("m", "http://127.0.0.1:9").reachable() is False


# ---- preflight ------------------------------------------------------------------------------------------
def _manifest(tmp_path):
    exe = tmp_path / "engine" / "coli"
    exe.parent.mkdir(exist_ok=True)
    exe.write_text("x")
    return {"components": {"colibri": {"version": "2.1.0", "target": str(exe.parent), "exe": "coli"}},
            "models": {"colibri": {"id": "m", "revision": "a" * 40, "volume_label": "ki_data", "dir": "d"}}}


def _status(res, name):
    return next(r["status"] for r in res if r["name"] == name)


PINS = [{"file": "f.safetensors", "size": 3, "sha256": hashlib.sha256(b"abc").hexdigest(), "git_blob": ""}]


def _model(tmp_path, data=b"abc"):
    d = tmp_path / "d"
    d.mkdir(exist_ok=True)
    (d / "f.safetensors").write_bytes(data)
    return d


def test_preflight_ok_with_all_files(tmp_path, monkeypatch):
    monkeypatch.setattr(pf, "_volume_root", lambda label: tmp_path)
    _model(tmp_path)
    res = pf.check_colibri(_manifest(tmp_path), PINS)
    assert _status(res, "colibri:binary") == pf.OK and _status(res, "colibri:model") == pf.OK


def test_preflight_fails_without_the_volume(tmp_path, monkeypatch):
    monkeypatch.setattr(pf, "_volume_root", lambda label: None)
    assert _status(pf.check_colibri(_manifest(tmp_path), PINS), "colibri:volume") == pf.FEHLER


def test_preflight_fails_on_truncated_shard_missing_file_or_no_pins(tmp_path, monkeypatch):
    monkeypatch.setattr(pf, "_volume_root", lambda label: tmp_path)
    assert _status(pf.check_colibri(_manifest(tmp_path), PINS), "colibri:model") == pf.FEHLER
    _model(tmp_path, b"ab")
    assert _status(pf.check_colibri(_manifest(tmp_path), PINS), "colibri:model") == pf.FEHLER
    assert _status(pf.check_colibri(_manifest(tmp_path), []), "colibri:model") == pf.FEHLER


def _fetch_script():
    spec = importlib.util.spec_from_file_location("fetch_colibri_model", ROOT / "infra" / "fetch-colibri-model.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_verify_finds_a_changed_file_of_the_right_size(tmp_path):
    fetch = _fetch_script()
    d = _model(tmp_path)
    assert fetch.verify(d, PINS) == []
    _model(tmp_path, b"abX")
    assert fetch.verify(d, PINS) == ["f.safetensors"]
    (d / "f.safetensors").unlink()
    assert fetch.verify(d, PINS) == ["f.safetensors"]


def test_verify_uses_the_git_blob_id_for_small_files(tmp_path):
    fetch = _fetch_script()
    (tmp_path / "c.json").write_bytes(b"{}")
    blob = hashlib.sha1(b"blob 2\0{}").hexdigest()
    assert fetch.verify(tmp_path, [{"file": "c.json", "size": 2, "sha256": "", "git_blob": blob}]) == []
    assert fetch.verify(tmp_path, [{"file": "c.json", "size": 2, "sha256": "", "git_blob": "0" * 40}]) == ["c.json"]


# ---- manifest and scripts -------------------------------------------------------------------------------
def test_manifest_pins_engine_and_models():
    m = json.loads((ROOT / "infra" / "manifest.json").read_text(encoding="utf-8"))
    c = m["components"]["colibri"]
    assert c["url"].startswith("https://github.com/") and c["url_cuda"].startswith("https://github.com/")
    assert len(c["sha256"]) == 64 and len(c["sha256_cuda"]) == 64 and len(c["commit"]) == 40
    v = m["models"]["colibri"]
    assert len(v["revision"]) == 40 and v["volume_label"] == "ki_data" and not v["dir"][1:].startswith(":")
    pins = json.loads((ROOT / "infra" / "colibri-model.files.json").read_text(encoding="utf-8"))
    assert pins["revision"] == v["revision"] and pins["repo"] == v["repo"]
    assert len(pins["files"]) > 50 and all(f["sha256"] for f in pins["files"] if f["file"].endswith(".safetensors"))
    assert all("/" not in f["file"] and "\\" not in f["file"] and ".." not in f["file"] for f in pins["files"])


def test_start_runs_colibri_on_loopback_and_only_serve():
    txt = (ROOT / "scripts" / "start.ps1").read_text(encoding="ascii")
    assert "'--host', '127.0.0.1'" in txt and "COLI_API_KEY" in txt and "colibri_settings --json" in txt
    for forbidden in ("0.0.0.0", "START-HERE", "'setup'", "'web'", "'mcp'"):
        assert forbidden not in txt


def test_colibri_process_ownership_is_bound_to_the_tools_folder():
    for script in ("stop.ps1", "cleanup.ps1"):
        assert "[regex]::Escape($ToolsRoot)" in (ROOT / "scripts" / script).read_text(encoding="ascii")


def test_start_checks_the_model_hashes_and_scopes_the_key():
    txt = (ROOT / "scripts" / "start.ps1").read_text(encoding="ascii")
    assert "'--verify'" in txt and "Remove-Item Env:COLI_API_KEY" in txt and "Remove-Item Env:SW_COLIBRI_KEY" in txt
