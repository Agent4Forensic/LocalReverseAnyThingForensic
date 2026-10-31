import json

import pytest

from sw_analyst.common.models import ToolSpec
from sw_analyst.guard import ActionResult, validate_action

TOOLS = [
    ToolSpec(name="strings_extract", description="strings", params={
        "min_len": {"type": "int", "required": False, "description": "min length"},
        "encoding": {"type": "str", "required": False, "description": "enc"},
        "unique": {"type": "bool", "required": False, "description": "dedupe"}}),
    ToolSpec(name="read_member", description="read", params={
        "path": {"type": "str", "required": True, "description": "p"},
        "member": {"type": "str", "required": False, "description": "m"},
        "offset": {"type": "int", "required": False, "description": "o"}}),
    ToolSpec(name="hash_file", description="hash", params={}),
    ToolSpec(name="read_file", description="read", params={
        "file": {"type": "str", "required": True, "description": "f"}}),
]


def tool(args=None, **kw):
    d = {"action": "tool", "tool": "strings_extract", "args": {"min_len": 6}, "why": "look for URLs"}
    d.update(kw)
    if args is not None:
        d["args"] = args
    return json.dumps(d)


def finish(**kw):
    d = {"action": "finish", "summary": "done", "findings": []}
    d.update(kw)
    return json.dumps(d)


def ok(raw, tools=TOOLS):
    r = validate_action(raw, tools)
    assert r.ok, r.error
    return r


def bad(raw, tools=TOOLS, contains=None):
    r = validate_action(raw, tools)
    assert not r.ok and r.action is None and r.kind is None and r.error
    if contains:
        assert contains in r.error, r.error
    return r


# ---------------------------------------------------------------- valid
def test_valid_tool_action_normalised():
    r = ok(tool())
    assert isinstance(r, ActionResult)
    assert r.kind == "tool"
    assert r.action == {"action": "tool", "tool": "strings_extract", "args": {"min_len": 6},
                        "why": "look for URLs"}


def test_valid_tool_without_args_key_and_no_params():
    r = ok(json.dumps({"action": "tool", "tool": "hash_file", "why": "hash"}))
    assert r.action["args"] == {}


def test_valid_all_types():
    r = ok(tool({"min_len": 4, "encoding": "utf-16", "unique": True}))
    assert r.action["args"] == {"min_len": 4, "encoding": "utf-16", "unique": True}


def test_json_fence_and_whitespace():
    ok("```json\n" + tool() + "\n```")
    ok("```\n" + tool() + "\n```")
    ok("  \n\n" + tool() + "\n\n  ")
    ok("```json\r\n" + tool() + "\r\n```\n")


def test_valid_finish_full():
    raw = finish(
        findings=[{"statement": "Contains URL", "status": "confirmed",
                   "evidence": [{"id": "EV-000012", "quote": "http://example.com"}]},
                  {"statement": "Maybe packed", "status": "hypothesis",
                   "evidence": [{"id": "EV-000003"}]}],
        annotations=[{"file": "sample", "line_start": 10, "line_end": 14, "text": "note",
                      "evidence_id": "EV-000012", "kind": "ioc"}],
        subtasks=[{"title": "t", "goal": "g", "reason": "r"}],
        answer={"text": "42"})
    r = ok(raw)
    assert r.kind == "finish"
    a = r.action
    assert a["findings"][1]["evidence"] == [{"id": "EV-000003", "quote": ""}]
    assert a["annotations"][0]["kind"] == "ioc" and a["subtasks"][0]["title"] == "t"
    assert a["answer"] == {"text": "42"}


def test_minimal_finish():
    r = ok(finish())
    assert r.action == {"action": "finish", "summary": "done", "findings": []}


# ---------------------------------------------------------------- invalid structure
@pytest.mark.parametrize("raw", [
    "", "   ", "no json at all", "[1,2,3]", '"string"', "42", "null",
    "Sure! " + tool(), tool() + " thanks", tool() + tool(), tool() + "\n" + finish(),
    "```json\n" + tool() + "\n``` and more", "```json\n" + tool(), tool()[:-1],
    '{"action":"tool",}', "{'action':'tool'}",
])
def test_malformed_or_foreign_text(raw):
    bad(raw)


def test_multiple_objects_rejected():
    bad(tool() + "\n" + tool(), contains="extra")


def test_duplicate_keys_rejected():
    bad('{"action":"tool","tool":"hash_file","tool":"read_file","why":"x"}', contains="duplicate")


def test_nan_and_infinity_rejected():
    bad('{"action":"tool","tool":"strings_extract","args":{"min_len":NaN},"why":"x"}')
    bad('{"action":"tool","tool":"strings_extract","args":{"min_len":Infinity},"why":"x"}')


def test_unknown_top_level_keys():
    bad(tool(extra="x"), contains="unknown")
    bad(finish(extra=1), contains="unknown")
    bad(finish(tool="strings_extract"), contains="unknown")


def test_unknown_action():
    bad(json.dumps({"action": "shell", "cmd": "id"}))
    bad(json.dumps({"tool": "hash_file", "why": "x"}))
    bad(json.dumps({"action": "TOOL", "tool": "hash_file", "why": "x"}))


# ---------------------------------------------------------------- tool rules
def test_tool_not_in_allowlist():
    bad(tool(tool="rm_rf"), contains="allowlist")
    bad(tool(tool=""), )
    bad(tool(tool=5))
    bad(tool(), tools=[])


def test_args_unknown_key():
    bad(tool({"min_len": 6, "cmd": "id"}), contains="unknown argument")


def test_args_types():
    bad(tool({"min_len": "6"}))
    bad(tool({"min_len": 6.0}))
    bad(tool({"min_len": True}))        # bool is not an int
    bad(tool({"unique": 1}))
    bad(tool({"unique": "true"}))
    bad(tool({"encoding": 5}))
    bad(tool({"min_len": None}))
    bad(tool({"min_len": [1]}))
    bad(tool(args=[1, 2]))
    bad(tool(args="min_len=6"))


def test_int_plausibility():
    ok(tool({"min_len": 10**9}))
    ok(tool({"min_len": -10**9}))
    bad(tool({"min_len": 10**9 + 1}))
    bad(tool({"min_len": -10**9 - 1}))
    bad(tool({"min_len": 10**30}))


def test_string_limits():
    ok(tool({"encoding": "a" * 4000}))
    bad(tool({"encoding": "a" * 4001}))


def test_required_arguments():
    bad(json.dumps({"action": "tool", "tool": "read_member", "args": {}, "why": "x"}), contains="required")
    ok(json.dumps({"action": "tool", "tool": "read_member", "args": {"path": "sample"}, "why": "x"}))


def test_why_required_and_limits():
    bad(json.dumps({"action": "tool", "tool": "hash_file"}), contains="why")
    bad(tool(why=""))
    bad(tool(why="   "))
    bad(tool(why=5))
    bad(tool(why=None))
    ok(tool(why="w" * 500))
    bad(tool(why="w" * 501))


@pytest.mark.parametrize("path", [
    "..", "../secret", "a/../../b", "a\\..\\b", "..\\..\\windows\\system32", "/etc/passwd", "\\windows\\x",
    "C:\\Windows\\System32\\cmd.exe", "c:/x", "D:rel", "\\\\server\\share\\x", "//server/share", "~/x", "~root/x",
    "a\x00b", "sample\x00.txt", "%APPDATA%\\x", "$HOME/x", "%2e%2e/x", "a/%2E%2E/b", "..%2fetc", "file.txt:stream",
    "a/./b", "...", "a/.../b", ".. ", "a/.. /b", "\uff0e\uff0e/x", "\uff0e\uff0e\uff0fx", "CON", "nul.txt", "a/COM1",
    "a<b", "a|b", "a?b", "a*b", "", "   ",
])
def test_path_tricks_rejected(path):
    bad(json.dumps({"action": "tool", "tool": "read_member", "args": {"path": path}, "why": "x"}))
    bad(json.dumps({"action": "tool", "tool": "read_member", "args": {"path": "sample", "member": path}, "why": "x"}))
    bad(json.dumps({"action": "tool", "tool": "read_file", "args": {"file": path}, "why": "x"}))


@pytest.mark.parametrize("path", ["sample", "classes.dex", "res/layout/main.xml", "dir\\sub\\file.txt",
                                  "lib/arm64-v8a/libfoo.so", ".hidden", "a b/c d.txt", "Caf\u00e9/x.txt"])
def test_logical_names_accepted(path):
    ok(json.dumps({"action": "tool", "tool": "read_member", "args": {"path": path}, "why": "x"}))


def test_non_path_params_not_path_checked():
    ok(tool({"encoding": "../not-a-path"}))


# ---------------------------------------------------------------- finish rules
def finding(**kw):
    d = {"statement": "s", "status": "confirmed", "evidence": [{"id": "EV-000001", "quote": "q"}]}
    d.update(kw)
    return d


def test_finish_required_fields():
    bad(json.dumps({"action": "finish", "findings": []}), contains="summary")
    bad(json.dumps({"action": "finish", "summary": "x"}), contains="findings")
    bad(finish(summary=5))
    bad(finish(findings="none"))
    bad(finish(findings={"a": 1}))


def test_finish_limits():
    ok(finish(summary="s" * 4000))
    bad(finish(summary="s" * 4001))
    ok(finish(findings=[finding()] * 30))
    bad(finish(findings=[finding()] * 31))
    ok(finish(findings=[finding(statement="x" * 1000)]))
    bad(finish(findings=[finding(statement="x" * 1001)]))
    ok(finish(findings=[finding(evidence=[{"id": "EV-000001", "quote": "q" * 1000}])]))
    bad(finish(findings=[finding(evidence=[{"id": "EV-000001", "quote": "q" * 1001}])]))
    ok(finish(findings=[finding(evidence=[{"id": "EV-%06d" % i, "quote": "q"} for i in range(10)])]))
    bad(finish(findings=[finding(evidence=[{"id": "EV-%06d" % i, "quote": "q"} for i in range(11)])]))


def test_finding_status_and_evidence():
    bad(finish(findings=[finding(status="rejected")]))
    bad(finish(findings=[finding(status="open")]))
    bad(finish(findings=[finding(status="Confirmed")]))
    bad(finish(findings=[finding(evidence=[])]))
    bad(finish(findings=[finding(evidence="EV-000001")]))
    bad(finish(findings=[finding(extra=1)]), contains="unknown")
    bad(finish(findings=[finding(evidence=[{"id": "EV-1", "quote": "q"}])]))
    bad(finish(findings=[finding(evidence=[{"id": "EV-0000012", "quote": "q"}])]))
    bad(finish(findings=[finding(evidence=[{"id": "ev-000001", "quote": "q"}])]))
    bad(finish(findings=[finding(evidence=[{"id": "EV-000001\n", "quote": "q"}])]))
    bad(finish(findings=[finding(evidence=[{"id": "EV-000001", "quote": "q", "x": 1}])]))
    bad(finish(findings=[finding(evidence=[{"id": "EV-000001"}])]))      # confirmed needs quote
    bad(finish(findings=[finding(evidence=[{"id": "EV-000001", "quote": ""}])]))
    ok(finish(findings=[finding(status="hypothesis", evidence=[{"id": "EV-000001"}])]))
    bad(finish(findings=[finding(statement="")]))
    bad(finish(findings=["text"]))


def test_annotations():
    good = {"file": "sample", "line_start": 1, "line_end": 1, "text": "t"}
    ok(finish(annotations=[good]))
    ok(finish(annotations=[good] * 50))
    bad(finish(annotations=[good] * 51))
    bad(finish(annotations=[dict(good, line_start=0)]))
    bad(finish(annotations=[dict(good, line_start=-3)]))
    bad(finish(annotations=[dict(good, line_start=5, line_end=4)]))
    bad(finish(annotations=[dict(good, line_end=10**9 + 1)]))
    bad(finish(annotations=[dict(good, line_start="1")]))
    bad(finish(annotations=[dict(good, line_start=True)]))
    bad(finish(annotations=[dict(good, text="t" * 501)]))
    bad(finish(annotations=[dict(good, file="../x")]))
    bad(finish(annotations=[dict(good, file="C:\\x")]))
    bad(finish(annotations=[dict(good, evidence_id="EV-12")]))
    bad(finish(annotations=[dict(good, kind="bogus")]))
    bad(finish(annotations=[dict(good, extra=1)]))
    ok(finish(annotations=[dict(good, kind=k) for k in ("finding", "note", "ioc", "warning")]))


def test_subtasks_and_answer():
    st = {"title": "t", "goal": "g", "reason": "r"}
    ok(finish(subtasks=[st] * 8))
    bad(finish(subtasks=[st] * 9))
    bad(finish(subtasks=[dict(st, title="t" * 121)]))
    bad(finish(subtasks=[dict(st, goal="g" * 501)]))
    bad(finish(subtasks=[dict(st, reason="r" * 501)]))
    bad(finish(subtasks=[{"title": "t", "goal": "g"}]))
    bad(finish(subtasks=[dict(st, extra=1)]))
    ok(finish(answer={"text": "a" * 4000}))
    bad(finish(answer={"text": "a" * 4001}))
    bad(finish(answer="text"))
    bad(finish(answer={"text": "a", "x": 1}))


def test_subtask_done_when():
    st = {"title": "t", "goal": "g", "reason": "r"}
    r = ok(finish(subtasks=[dict(st, done_when="value quoted")]))
    assert r.action["subtasks"][0]["done_when"] == "value quoted"
    ok(finish(subtasks=[dict(st, done_when="d" * 300)]))
    bad(finish(subtasks=[dict(st, done_when=5)]))
    bad(finish(subtasks=[dict(st, done_when="d" * 301)]))
    assert "done_when" not in ok(finish(subtasks=[st])).action["subtasks"][0]


# ---------------------------------------------------------------- resource limits
def test_size_limit_and_deep_nesting():
    big = finish(summary="s" * 4000, findings=[])
    ok(big)
    bad(tool(why="x") + " " * 70000)                                  # > 64 KiB
    bad('{"action":"finish","summary":"' + "a" * 70000 + '","findings":[]}')
    bad("{" + '"a":{' * 20000 + "1" + "}" * 20000 + "}")


def test_huge_int_literal_does_not_crash():
    bad('{"action":"tool","tool":"strings_extract","args":{"min_len":' + "9" * 5000 + '},"why":"x"}')


def test_never_raises_on_garbage():
    for raw in [None, 5, b"bytes", [], "\x00\x01", "{" * 100, "}" * 100, '{"action":', "\ud800"]:
        r = validate_action(raw, TOOLS)
        assert isinstance(r, ActionResult) and not r.ok


def test_control_chars_stripped_from_text_fields():
    r = ok(tool(why="a\x07b"))
    assert r.action["why"] == "ab"
