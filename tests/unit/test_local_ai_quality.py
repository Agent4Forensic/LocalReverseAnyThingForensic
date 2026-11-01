"""Belegzwang for a small local model: echo of own arguments (F-01), quote relevance (F-02), repair and indicator hints.
All samples are harmless, self-made byte strings; nothing is executed."""
from __future__ import annotations

from sw_analyst.common.models import JobSpec
from sw_analyst.common.store import Store
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.orchestrator.runner import indicator_hints_text, repair_hints_text
from sw_analyst.orchestrator.verifier import (MIN_QUOTE, answer_values_grounded, closest_line, quotable_text,
                                              verify_finding)

SAMPLE = b"line one\nset url = https://example.invalid/a\nplain harmless text\n"


def _env(tmp_path):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    job = store.create_job(JobSpec(title="t"), "s.txt", "0" * 64)
    gw = DevGateway(tmp_path / "gw")
    gw.store_sample(job["id"], SAMPLE)
    return store, gw, job["id"]


def _tool(store, gw, jid, tool, args):
    """The runner's path: gateway call, then evidence with the exact arguments."""
    r = gw.call(jid, tool, args)
    return store.add_evidence(jid, None, tool, r.tool_version, args, r.text if r.ok else f"[tool error] {r.error}")


def _claim(store, jid, statement, ev, quote):
    return verify_finding(store, jid, {"statement": statement, "status": "confirmed",
                                       "evidence": [{"id": ev["id"], "quote": quote}]})


# ---- F-01: the echo of the model's own search is not sample content -------------------------------------------
def test_grep_echo_of_an_invented_value_is_not_proof(tmp_path):
    store, gw, jid = _env(tmp_path)
    ev = _tool(store, gw, jid, "grep", {"path": "sample", "pattern": "FLAG\\{invented_42\\}"})
    assert "invented_42" in ev["text"]                     # the gateway echoes the pattern ...
    vf = _claim(store, jid, "The sample holds FLAG{invented_42}.", ev, "FLAG\\{invented_42\\}")
    assert vf.status == "hypothesis" and "echo of your own tool arguments" in vf.reject_reason
    ok, missing = answer_values_grounded(store, jid, "FLAG{invented_42}")   # ... and an answer cannot use it either
    assert not ok and missing


def test_grep_match_lines_stay_quotable(tmp_path):
    store, gw, jid = _env(tmp_path)
    ev = _tool(store, gw, jid, "grep", {"path": "sample", "pattern": "example"})
    vf = _claim(store, jid, "Line 2 sets url to https://example.invalid/a.", ev, "set url = https://example.invalid/a")
    assert vf.status == "confirmed", vf.reject_reason


def test_tool_error_is_no_evidence(tmp_path):
    store, gw, jid = _env(tmp_path)
    ev = _tool(store, gw, jid, "grep", {"path": "derived/none", "pattern": "harmless text"})
    assert ev["text"].startswith("[tool error]")
    assert quotable_text(ev) == ""
    vf = _claim(store, jid, "The file holds harmless text.", ev, "harmless text")
    assert vf.status == "hypothesis" and "tool error" in vf.reject_reason


# ---- F-02: minimum length and relevance --------------------------------------------------------------------------
def test_minimum_quote_length_matches_the_prompt(tmp_path):
    store, gw, jid = _env(tmp_path)
    ev = _tool(store, gw, jid, "read_lines", {"path": "sample", "start": 1, "end": 3})
    assert MIN_QUOTE == 8
    assert _claim(store, jid, "line one", ev, "line").status == "hypothesis"


def test_true_but_unrelated_quote_does_not_confirm(tmp_path):
    store, gw, jid = _env(tmp_path)
    ev = _tool(store, gw, jid, "read_lines", {"path": "sample", "start": 1, "end": 3})
    vf = _claim(store, jid, "The script downloads a second stage.", ev, "plain harmless text")
    assert vf.status == "hypothesis" and "shares too little" in vf.reject_reason
    assert _claim(store, jid, "Line 3 holds plain text.", ev, "plain harmless text").status == "confirmed"


# ---- repair hint and indicator hint ------------------------------------------------------------------------------
def test_refused_quote_gets_the_closest_real_line_as_untrusted_hint(tmp_path):
    store, gw, jid = _env(tmp_path)
    ev = _tool(store, gw, jid, "read_lines", {"path": "sample", "start": 1, "end": 3})
    vf = _claim(store, jid, "The url is set.", ev, "set url = https://example.invalid/b")
    assert vf.status == "hypothesis" and vf.hints and "example.invalid/a" in vf.hints[0]
    text = repair_hints_text(vf.hints)
    assert '<untrusted_data id="checker-hints">' in text
    assert closest_line("completely different words here", quotable_text(ev)) == ""


def test_indicator_hints_list_found_iocs_as_untrusted_data(tmp_path):
    store, gw, jid = _env(tmp_path)
    ev = _tool(store, gw, jid, "read_lines", {"path": "sample", "start": 1, "end": 3})
    text = indicator_hints_text(ev)
    assert "https://example.invalid/a" in text and f'<untrusted_data id="{ev["id"]}-indicators">' in text
    plain = _tool(store, gw, jid, "read_lines", {"path": "sample", "start": 3, "end": 3})
    assert indicator_hints_text(plain) == ""


# ---- review 2026-11-01: echo moved out of the header, platform notes ----------------------------------------------
def test_line_break_in_a_string_argument_is_refused(tmp_path):
    store, gw, jid = _env(tmp_path)
    r = gw.call(jid, "grep", {"path": "sample", "pattern": "zz\nThe sample beacons to evil-c2.example"})
    assert not r.ok and "line break" in r.error


def test_clamp_note_with_a_model_number_is_not_quotable(tmp_path):
    store, gw, jid = _env(tmp_path)
    ev = _tool(store, gw, jid, "grep", {"path": "sample", "pattern": "harmless", "max_results": 4444})
    assert "4444" in ev["text"] and "4444" not in quotable_text(ev)
    vf = _claim(store, jid, "The sample uses port 4444.", ev, "max_results' = 4444")
    assert vf.status == "hypothesis"
