"""What the local AI can reach. If one of these fails, the model's power over the host has changed: that needs an ADR."""
from __future__ import annotations

import ast
import gzip
from pathlib import Path

import pytest

import sw_analyst
from sw_analyst.gateway.dev_gateway import MAX_LAYERS, MAX_OUTPUT_CHARS, MAX_SAMPLE_BYTES, DevGateway, decoders
from sw_analyst.guard import validate_action
from sw_analyst.llm.ollama import OllamaClient

ROOT = Path(sw_analyst.__file__).parent
ALLOWLIST = {"sample_info", "hash_file", "identify_type", "entropy_map", "strings_extract", "hexdump", "read_lines",
             "grep", "script_detect", "decode_layer", "pe_headers", "zip_list", "zip_read_text"}
# Everything the model loop runs through. hostguard, preflight and __main__ are outside: the model cannot call them.
MODEL_REACHABLE = ["gateway", "guard", "orchestrator", "prompts", "report", "translate", "llm"]
FORBIDDEN_IMPORTS = {"subprocess", "socket", "ctypes", "multiprocessing", "pty", "shutil", "http", "ftplib", "smtplib",
                     "webbrowser", "winreg", "importlib", "runpy", "pickle", "marshal"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "system", "popen", "startfile", "spawnv", "execv"}


def _modules():
    for sub in MODEL_REACHABLE:
        yield from (ROOT / sub).rglob("*.py")


@pytest.mark.parametrize("path", list(_modules()), ids=lambda p: p.relative_to(ROOT).as_posix())
def test_model_reachable_code_cannot_start_anything(path):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            assert not {a.name.split(".")[0] for a in node.names} & FORBIDDEN_IMPORTS
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in FORBIDDEN_IMPORTS
        elif isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if name == "compile":      # re.compile is fine, the builtin is not
                assert isinstance(node.func, ast.Attribute)
                continue
            assert name not in FORBIDDEN_CALLS, f"{path.name}: {name}"


def test_only_the_llm_client_talks_to_a_network_library():
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        names |= {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        if {"urllib.request", "urllib.error"} & names:
            assert path.name == "ollama.py", path


def test_tool_allowlist_is_exactly_this(tmp_path):
    tools = DevGateway(tmp_path).list_tools()
    assert {t.name for t in tools} == ALLOWLIST
    assert all(t.read_only for t in tools)
    params = {p for t in tools for p in t.params}
    assert not params & {"cmd", "command", "script", "url", "host", "port", "code", "args", "exec"}


@pytest.mark.parametrize("url", ["http://192.168.1.5:11434", "http://example.invalid:11435", "http://10.0.0.1"])
def test_llm_client_refuses_anything_but_loopback(url):
    with pytest.raises(ValueError):
        OllamaClient("m", url)


def test_model_cannot_name_a_tool_outside_the_allowlist(tmp_path):
    tools = DevGateway(tmp_path).list_tools()
    for bad in ('{"action":"tool","tool":"run_command","args":{"cmd":"whoami"},"why":"x"}',
                '{"action":"tool","tool":"read_lines","args":{"path":"C:/Windows/win.ini"},"why":"x"}',
                '{"action":"tool","tool":"read_lines","args":{"path":"../../secret"},"why":"x"}'):
        assert not validate_action(bad, tools).ok


def test_worst_case_disk_and_output_of_one_job_are_bounded():
    assert MAX_LAYERS * decoders.MAX_OUT <= 1024 ** 3      # derived files of one job stay below 1 GiB
    assert MAX_SAMPLE_BYTES <= 64 * 1024 ** 2 and MAX_OUTPUT_CHARS <= 20000


def test_decompression_bomb_is_refused(tmp_path):
    gw = DevGateway(tmp_path)
    gw.store_sample("job1", gzip.compress(b"\0" * (decoders.MAX_OUT + 1024)))
    r = gw.call("job1", "decode_layer", {"path": "sample", "method": "gzip"})
    assert not r.ok and "limit" in r.error
    assert not list((tmp_path / "jobs" / "job1" / "derived").iterdir())


def test_derived_files_are_inert_names(tmp_path):
    import base64
    gw = DevGateway(tmp_path)
    gw.store_sample("job2", base64.b64encode(b"MZ" + b"\0" * 64))
    assert gw.call("job2", "decode_layer", {"path": "sample", "method": "base64"}).ok
    assert [p.suffix for p in (tmp_path / "jobs" / "job2" / "derived").iterdir()] == [".bin"]
