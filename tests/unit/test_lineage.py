"""Lineage of derived files and the deterministic walkthrough of a Ghidra function (harmless synthetic data)."""
from __future__ import annotations

import base64

from sw_analyst.common.models import JobSpec
from sw_analyst.common.store import Store
from sw_analyst.common.util import sha256_hex
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.webui.learnpath import walkthrough
from sw_analyst.webui.lineage import lineage


def _setup(tmp_path):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    gw = DevGateway(tmp_path)
    inner = b"hello harmless inner text, nothing more\n" * 3
    data = base64.b64encode(base64.b64encode(inner))
    j = store.create_job(JobSpec(title="lineage"), "a.txt", sha256_hex(data))
    gw.store_sample(j["id"], data)
    return store, gw, j["id"], inner


def _decode(store, gw, rid, path):
    r = gw.call(rid, "decode_layer", {"path": path, "method": "base64"})
    assert r.ok, r.text
    ev = store.add_evidence(rid, None, "decode_layer", r.tool_version, {"path": path, "method": "base64"}, r.text,
                            source_ref=r.meta)
    return r.meta["derived"], ev["id"]


def test_lineage_chain(tmp_path):
    store, gw, rid, inner = _setup(tmp_path)
    l1, e1 = _decode(store, gw, rid, "sample")
    l2, e2 = _decode(store, gw, rid, l1)
    out = lineage(store, gw, rid)
    paths = {n["path"]: n for n in out["nodes"]}
    assert {"sample", l1, l2} <= set(paths)
    edges = {(e["from"], e["to"]): e for e in out["edges"]}
    assert edges[("sample", l1)]["evidence_id"] == e1 and edges[(l1, l2)]["evidence_id"] == e2
    assert edges[(l1, l2)]["tool"] == "decode_layer" and edges[(l1, l2)]["method"] == "base64"
    assert out["final"] == [l2]
    assert paths[l2]["preview"].startswith("hello harmless") and len(paths[l2]["preview"]) <= 400
    assert paths[l2]["sha256"] == sha256_hex(inner)


def test_lineage_cycle_is_safe(tmp_path):
    store, gw, rid, _ = _setup(tmp_path)
    l1, _e = _decode(store, gw, rid, "sample")
    store.add_evidence(rid, None, "decode_layer", "v", {"path": l1}, "x", source_ref={"derived": "sample"})
    out = lineage(store, gw, rid)
    assert {(e["from"], e["to"]) for e in out["edges"]} == {("sample", l1), (l1, "sample")}
    assert out["final"] == []


def test_walkthrough():
    fn = {"name": "decode", "entry": "0x401000", "path": "sample",
          "disasm": [["0x401000", "55", "PUSH EBP"], ["0x401001", "89e5", "MOV EBP,ESP"],
                     ["0x401003", "31c0", "XOR EAX,EAX"], ["0x401005", "40", "INC EAX"],
                     ["0x401006", "83f80a", "CMP EAX,0xa"], ["0x401009", "75fa", "JNZ 0x401005"],
                     ["0x40100b", "e800000000", "CALL 0x401010"], ["0x401010", "c3", "RET"]],
          "blocks": [{"start": "0x401000", "end": "0x401004", "succ": [["0x401005", "fall"]]},
                     {"start": "0x401005", "end": "0x40100a", "succ": [["0x401005", "jump"], ["0x40100b", "fall"]]}]}
    w = walkthrough(fn)
    kinds = [s["kind"] for s in w["steps"]]
    assert kinds[0] == "prolog" and {"block", "compare", "loop", "call", "return"} <= set(kinds)
    loop = next(s for s in w["steps"] if s["kind"] == "loop")
    assert (loop["line_start"], loop["line_end"]) == (4, 6)
    assert [s["n"] for s in w["steps"]] == list(range(1, len(w["steps"]) + 1))
    assert walkthrough({"name": "empty"})["steps"] == []
