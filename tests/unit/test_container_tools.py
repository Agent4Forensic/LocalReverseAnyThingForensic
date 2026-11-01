"""Container tools on recorded tool output: no Docker needed. tests/integration/test_tool_images.py runs the real images."""
from __future__ import annotations

import io
import json
import tarfile
import zipfile

import pytest

from sw_analyst.gateway.container_runner import ContainerError, ContainerRunner
from sw_analyst.gateway.container_tools import attach_container_tools
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.orchestrator.engine import JobEngine

JOB = "job1"
GHIDRA = {"program": {"format": "PE", "language": "x86:LE:32:default", "compiler": "windows", "image_base": "0x400000"},
          "functions": [
              {"name": "entry", "entry": "0x401000", "start": "0x401000", "end": "0x401008", "size": 9, "thunk": False,
               "signature": "undefined entry(void)", "disasm": [["0x401000", "55", "PUSH EBP"], ["0x401001", "e802000000", "CALL 0x401008"]],
               "disasm_truncated": False, "blocks": [{"start": "0x401000", "end": "0x401008", "succ": [["0x401010", "CALL"]]}],
               "decompiled": "void entry(void) { helper(); }"},
              {"name": "helper", "entry": "0x401010", "start": "0x401010", "end": "0x401012", "size": 3, "thunk": True,
               "signature": "int helper(void)", "disasm": [["0x401010", "31c0", "XOR EAX,EAX"]], "disasm_truncated": False,
               "blocks": [], "decompiled": None}],
          "refs": [["0x401001", "0x401010", "UNCONDITIONAL_CALL"]], "truncated": False}
CAPA = {"rules": {"encode data using XOR": {"meta": {"namespace": "data-manipulation/encoding/xor",
                                                     "attack": [{"id": "T1027"}]},
                                            "matches": [[{"type": "absolute", "value": 4198400}, {}]]},
                  "helper rule": {"meta": {"lib": True}, "matches": []}}}
FLOSS = {"strings": {"decoded_strings": [{"string": "hidden config", "address": 4198416}],
                     "stack_strings": [{"string": "stack text", "function": 4198400}],
                     "tight_strings": [], "static_strings": [{"string": "plain", "offset": 16}]}}
YARA = {"version": "1.22.1", "matches": [{"rule": "crypto_aes_sbox", "file": "/job/sample", "meta": {"description": "AES"},
                                          "strings": [{"identifier": "$a", "offset": 1024, "match": "c|w"}]}]}


class FakeRunner(ContainerRunner):
    def __init__(self, outputs=None, fail=None):
        super().__init__({"ghidra": "sha256:" + "a" * 64, "triage": "sha256:" + "b" * 64, "jadx": "sha256:" + "c" * 64})
        self.outputs = outputs or {}
        self.fail = fail
        self.calls = []

    def run(self, op, data):
        self.calls.append(op)
        if self.fail:
            raise ContainerError(self.fail)
        return self.outputs[op]


def _setup(tmp_path, outputs=None, sample=b"MZ harmless", fail=None):
    gw = DevGateway(tmp_path)
    runner = FakeRunner(outputs or {"ghidra": json.dumps(GHIDRA).encode(), "capa": json.dumps(CAPA).encode(),
                                    "floss": json.dumps(FLOSS).encode(), "yara": json.dumps(YARA).encode()}, fail)
    attach_container_tools(gw, runner)
    gw.store_sample(JOB, sample)
    return gw, runner


def test_ghidra_runs_once_and_all_tools_read_the_cached_result(tmp_path):
    gw, runner = _setup(tmp_path)
    assert "entry" in gw.call(JOB, "list_functions", {}).text
    assert "void entry(void)" in gw.call(JOB, "decompile", {"function": "entry"}).text
    assert "CALL 0x401008" in gw.call(JOB, "disassemble", {"function": "0x401001"}).text
    assert "UNCONDITIONAL_CALL" in gw.call(JOB, "xrefs", {"target": "helper"}).text
    assert gw.call(JOB, "basic_blocks", {"function": "entry"}).meta["blocks"][0]["succ"] == [["0x401010", "CALL"]]
    assert runner.calls == ["ghidra"]
    gw2 = DevGateway(tmp_path)        # a restart keeps the cache
    r2 = FakeRunner({})
    attach_container_tools(gw2, r2)
    assert gw2.call(JOB, "list_functions", {}).ok and r2.calls == []


def test_cache_stays_out_of_the_artifact_recursion(tmp_path):
    gw, _ = _setup(tmp_path)
    gw.call(JOB, "list_functions", {})
    assert [f["path"] for f in gw.list_files(JOB)] == ["sample"]
    assert list((gw._jobs / JOB / "tool-cache").iterdir())


def test_result_names_tool_version_with_image_id(tmp_path):
    gw, _ = _setup(tmp_path)
    r = gw.call(JOB, "list_functions", {})
    assert r.tool_version == "ghidra-12.1.4@sha256:" + "a" * 12


def test_model_arguments_never_reach_the_container(tmp_path):
    gw, runner = _setup(tmp_path)
    evil = "$(whoami); rm -rf / --script=x.py"
    for tool, args in (("list_functions", {"name_contains": evil}), ("decompile", {"function": evil}),
                       ("xrefs", {"target": evil}), ("floss_decode", {"kind": evil})):
        gw.call(JOB, tool, args)
    assert set(runner.calls) <= {"ghidra", "floss"}      # fixed operations only


def test_function_lookup_errors_are_clean(tmp_path):
    gw, _ = _setup(tmp_path)
    assert "No function" in gw.call(JOB, "decompile", {"function": "missing"}).error
    assert "hexadecimal" in gw.call(JOB, "xrefs", {"target": "0xzz"}).error
    r = gw.call(JOB, "decompile", {"function": "helper"})
    assert not r.ok and "disassemble" in r.error


def test_list_functions_filter_and_paging(tmp_path):
    gw, _ = _setup(tmp_path)
    assert gw.call(JOB, "list_functions", {"name_contains": "HELP"}).meta["count"] == 1
    r = gw.call(JOB, "list_functions", {"limit": 1})
    assert r.truncated and "offset=1" in r.text


def test_capa_and_yara_are_hypotheses_and_skip_library_rules(tmp_path):
    gw, _ = _setup(tmp_path)
    c = gw.call(JOB, "capa_scan", {})
    assert c.meta["hypothesis"] and "hypotheses" in c.text and "T1027" in c.text and "0x401000" in c.text
    assert c.meta["rules"] == ["encode data using XOR"]
    y = gw.call(JOB, "yara_scan", {})
    assert y.meta["hypothesis"] and y.meta["rules"] == ["crypto_aes_sbox"] and "0x400" in y.text


def test_floss_kinds(tmp_path):
    gw, _ = _setup(tmp_path)
    r = gw.call(JOB, "floss_decode", {})
    assert "hidden config" in r.text and "stack text" in r.text and "plain" not in r.text
    assert "plain" in gw.call(JOB, "floss_decode", {"kind": "static"}).text
    assert not gw.call(JOB, "floss_decode", {"kind": "x"}).ok


def test_container_failure_is_a_tool_error_and_is_not_cached(tmp_path):
    gw, runner = _setup(tmp_path, fail="Tool 'ghidra' failed with exit code 1: no loader")
    r = gw.call(JOB, "list_functions", {})
    assert not r.ok and "no loader" in r.error
    assert not (gw._jobs / JOB / "tool-cache").exists()
    gw.call(JOB, "list_functions", {})
    assert runner.calls == ["ghidra", "ghidra"]


@pytest.mark.parametrize("raw", [b"not json", b"[1,2]", b'{"functions": 5}'])
def test_unreadable_ghidra_output_is_refused(tmp_path, raw):
    gw, _ = _setup(tmp_path, {"ghidra": raw})
    assert not gw.call(JOB, "list_functions", {}).ok


def _jadx_output():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        body = b"package com.example;\nclass Main {\n  String u = \"http://example.invalid\";\n}\n"
        info = tarfile.TarInfo("./com/example/Main.java")
        info.size = len(body)
        tar.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def _apk(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    return buf.getvalue()


def test_jadx_lists_searches_reads_and_picks_the_input_type(tmp_path):
    outputs = {"jadx-apk": _jadx_output(), "jadx-jar": _jadx_output(), "jadx-dex": _jadx_output()}
    gw, runner = _setup(tmp_path, outputs, _apk({"classes.dex": b"dex\n035\0"}))
    assert "com/example/Main.java" in gw.call(JOB, "jadx_decompile", {}).text
    assert runner.calls == ["jadx-apk"]
    assert "com/example/Main.java:3:" in gw.call(JOB, "jadx_decompile", {"search": "EXAMPLE.invalid"}).text
    assert "class Main" in gw.call(JOB, "jadx_decompile", {"class_file": "com/example/Main.java"}).text
    assert "No class file" in gw.call(JOB, "jadx_decompile", {"class_file": "../x.java"}).error
    assert runner.calls == ["jadx-apk"]
    gw.store_sample("jar", _apk({"A.class": b"\xca\xfe"}))
    gw.call("jar", "jadx_decompile", {})
    gw.store_sample("dex", b"dex\n035\0" + b"\0" * 32)
    gw.call("dex", "jadx_decompile", {})
    assert runner.calls == ["jadx-apk", "jadx-jar", "jadx-dex"]


def test_jadx_refuses_other_files_without_starting_a_container(tmp_path):
    gw, runner = _setup(tmp_path, sample=b"plain text")
    assert not gw.call(JOB, "jadx_decompile", {}).ok and runner.calls == []


def test_recipe_steps_with_missing_tools_are_not_planned(tmp_path):
    from sw_analyst.orchestrator.recipes import load_recipe
    plain = DevGateway(tmp_path / "a")
    full = DevGateway(tmp_path / "b")
    attach_container_tools(full, FakeRunner())
    for rid, code_step in (("exe", "ghidra_full"), ("exe", "capa_yara"), ("apk", "jadx_code")):
        recipe = load_recipe(rid)
        without = [s["id"] for s in JobEngine._usable_steps(type("E", (), {"gateway": plain})(), recipe)]
        with_tools = [s["id"] for s in JobEngine._usable_steps(type("E", (), {"gateway": full})(), recipe)]
        assert code_step not in without and code_step in with_tools


def test_every_tool_hint_in_every_recipe_exists(tmp_path):
    from sw_analyst.orchestrator.recipes import RECIPE_DIR, load_recipe
    full = DevGateway(tmp_path)
    attach_container_tools(full, FakeRunner())
    names = {t.name for t in full.list_tools()}
    for path in RECIPE_DIR.glob("*.yaml"):
        for step in load_recipe(path.stem)["steps"]:
            assert set(step.get("tools_hint", [])) <= names, step["id"]
            assert set(step.get("requires_tools", [])) <= names, step["id"]
