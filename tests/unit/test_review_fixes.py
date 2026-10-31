"""Regressions from the security review of ADR-0006: resource limits on data the sample or a container controls."""
from __future__ import annotations

import dataclasses
import io
import json
import struct
import sys
import tarfile
import threading
import time

import pytest

from sw_analyst.gateway import container_runner as cr
from sw_analyst.gateway.container_runner import OPS, ContainerError, ContainerRunner
from sw_analyst.gateway.container_tools import ContainerTools, attach_container_tools
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.gateway.dev_tools import axml
from sw_analyst.gateway.dev_tools.axml import AxmlError, parse_axml
from sw_analyst.gateway.dev_tools.pe import MAX_RESOURCE_ENTRIES, MAX_RESOURCE_WARNINGS, parse_resources

IMAGE_IDS = {"ghidra": "sha256:" + "a" * 64, "triage": "sha256:" + "b" * 64, "jadx": "sha256:" + "c" * 64}


# ---- binary XML -----------------------------------------------------------------------------------------------
def _pool(strings_blob: bytes, offsets: list[int], utf8: bool = False) -> bytes:
    strings_at = 28 + 4 * len(offsets)
    size = strings_at + len(strings_blob)
    head = struct.pack("<HHIIIIII", 0x0001, 28, size, len(offsets), 0, 0x100 if utf8 else 0, strings_at, 0)
    return head + b"".join(struct.pack("<I", o) for o in offsets) + strings_blob


def _element(name: int, attrs: list[int]) -> bytes:
    body = struct.pack("<IIHHHHHH", 0xFFFFFFFF, name, 20, 20, len(attrs), 0, 0, 0)
    for a in attrs:
        body += struct.pack("<IIIHBBI", 0xFFFFFFFF, 1, a, 8, 0, 0x03, a)
    return struct.pack("<HHI", 0x0102, 16, 16 + len(body)) + b"\0" * 8 + body


def _doc(*chunks: bytes) -> bytes:
    body = b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def test_one_long_utf16_string_is_not_decoded_again_for_every_index():
    n = 2000
    blob = struct.pack("<H", 0x7FFF) + b"A\0" * 200_000
    t0 = time.monotonic()
    with pytest.raises(AxmlError):                  # refused or empty, but quick; no elements follow the pool
        parse_axml(_doc(_pool(blob, [0] * n)))
    assert time.monotonic() - t0 < 5


def test_overlapping_strings_cannot_decode_without_bound():
    blob = struct.pack("<H", 0x7FFF) + b"A\0" * 8192
    with pytest.raises(AxmlError, match="more than"):
        parse_axml(_doc(_pool(blob, [0] * 200_000)))


def test_output_stops_at_the_budget_and_says_so(monkeypatch):
    monkeypatch.setattr(axml, "MAX_XML_CHARS", 2000)
    name = "a" * 100
    blob = struct.pack("<H", len(name)) + name.encode("utf-16le") + b"\0\0" + struct.pack("<H", 1) + b"b\0\0\0"
    pool = _pool(blob, [0, 2 + 200 + 2])
    res = parse_axml(_doc(pool, *[_element(0, [])] * 500))
    assert res["truncated"] is True
    assert 2000 <= len(res["xml"]) < 2500
    assert res["elements"] < 500


# ---- PE resources --------------------------------------------------------------------------------------------
def _dir_blob(entries: list[tuple[int, int]]) -> bytes:
    return struct.pack("<IIHHHH", 0, 0, 0, 0, 0, len(entries)) + b"".join(struct.pack("<II", a, b) for a, b in entries)


def _info(size: int) -> dict:
    return {"dirs": [(0, 0), (0, 0), (0x1000, size)],
            "sections": [{"virtual_address": 0x1000, "virtual_size": size, "raw_offset": 0, "raw_size": size}]}


def _resources(data: bytes) -> dict:
    return parse_resources(data, _info(len(data)))


def test_tree_without_leaves_stops_at_the_entry_budget():
    # The root lists itself again and again: entries pile up without producing a single resource.
    t0 = time.monotonic()
    tree = _resources(_dir_blob([(1, 0x80000000)] * (MAX_RESOURCE_ENTRIES + 5000)))
    assert time.monotonic() - t0 < 5
    assert tree["resources"] == [] and len(tree["warnings"]) <= MAX_RESOURCE_WARNINGS
    assert any("directory entries" in w for w in tree["warnings"])


def test_warnings_stay_bounded_on_a_loop_of_many_directories():
    tree = _resources(_dir_blob([(1, 0x80000000 | (i * 16)) for i in range(5000)]))
    assert len(tree["warnings"]) <= MAX_RESOURCE_WARNINGS


def test_same_big_range_is_hashed_once_and_entropy_has_a_budget(monkeypatch):
    from sw_analyst.gateway.dev_tools import pe
    calls = []
    real = pe.shannon_entropy
    monkeypatch.setattr(pe, "shannon_entropy", lambda b: calls.append(len(b)) or real(b))
    n = 200
    leaf = n * 8 + 16             # every entry shares one data entry, so all name the same range
    data_entry = struct.pack("<IIII", 0x1000 + 0x1000, 0x1000, 0, 0)
    blob = _dir_blob([(i, leaf) for i in range(n)]) + data_entry
    blob += b"\0" * (0x1000 - len(blob)) + b"\xAB" * 0x2000
    tree = _resources(blob)
    assert len(tree["resources"]) == n and len(calls) == 1
    monkeypatch.setattr(pe, "MAX_ENTROPY_BYTES", 10)
    tree = _resources(blob)
    assert all(r["entropy"] is None for r in tree["resources"]) and any("entropy" in w for w in tree["warnings"])
    assert tree["resources"][0]["head"] == b"\xAB" * 4


# ---- tar from the container ----------------------------------------------------------------------------------
def _with_negative_size() -> bytes:
    info = tarfile.TarInfo("./A.java")
    info.size = 0
    block = bytearray(info.tobuf(format=tarfile.GNU_FORMAT))
    block[124:136] = b"\xff" * 12            # base-256 for -1
    block[148:156] = b" " * 8
    chk = sum(block[:512])
    block[148:156] = b"%06o\0 " % chk
    return bytes(block) + b"\0" * 1024


def test_negative_tar_size_is_refused_and_does_not_loop():
    box: list = []

    def work():
        try:
            box.append(ContainerTools.parse_jadx_tar(_with_negative_size()))
        except ValueError as exc:
            box.append(exc)
    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(10)
    assert not t.is_alive(), "tar parser loops forever"
    assert isinstance(box[0], ValueError)


def test_member_count_is_bounded(monkeypatch):
    from sw_analyst.gateway import container_tools
    monkeypatch.setattr(container_tools, "MAX_TAR_MEMBERS", 3)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for i in range(6):
            tar.addfile(tarfile.TarInfo(f"./{i}.txt"), io.BytesIO(b""))
    assert ContainerTools.parse_jadx_tar(buf.getvalue())["truncated"] is True


# ---- gateway and runner --------------------------------------------------------------------------------------
class _Fake(ContainerRunner):
    def __init__(self, outputs=None, fail=None):
        super().__init__(IMAGE_IDS)
        self.outputs, self.fail, self.calls = outputs or {}, fail, []

    def run(self, op, data):
        self.calls.append(op)
        if self.fail:
            raise self.fail
        return self.outputs[op]


def _gw(tmp_path, runner):
    gw = DevGateway(tmp_path)
    attach_container_tools(gw, runner)
    gw.store_sample("j", b"MZ harmless")
    return gw


def test_lone_surrogate_from_a_container_does_not_break_evidence(tmp_path):
    raw = b'{"functions": [{"name": "f\\ud800", "entry": "0x1", "start": "0x1", "end": "0x2", "size": 1, "signature": ""}]}'
    gw = _gw(tmp_path, _Fake({"ghidra": raw}))
    r = gw.call("j", "list_functions", {})
    assert r.ok
    r.text.encode("utf-8")      # add_evidence hashes and stores this


@pytest.mark.parametrize("final, runs", [(True, 1), (False, 2)])
def test_only_final_failures_are_remembered(tmp_path, final, runs):
    runner = _Fake(fail=ContainerError("stopped", final=final))
    gw = _gw(tmp_path, runner)
    for _ in range(2):
        assert "stopped" in gw.call("j", "list_functions", {}).error
    assert len(runner.calls) == runs


def test_unreadable_output_is_not_produced_twice(tmp_path):
    runner = _Fake({"ghidra": b"not json"})
    gw = _gw(tmp_path, runner)
    for _ in range(2):
        assert not gw.call("j", "list_functions", {}).ok
    assert runner.calls == ["ghidra"]


def test_block_limit_of_the_export_reaches_the_model(tmp_path):
    fn = {"name": "f", "entry": "0x1", "start": "0x1", "end": "0x2", "size": 1, "signature": "", "disasm": [],
          "blocks": [], "blocks_truncated": True, "decompiled": None}
    gw = _gw(tmp_path, _Fake({"ghidra": json.dumps({"functions": [fn]}).encode()}))
    r = gw.call("j", "basic_blocks", {"function": "f"})
    assert r.truncated and "incomplete" in r.text


def _run_script(monkeypatch, code: str, **spec) -> bytes:
    """The real run() with a Python child in place of docker: pipes, limits and kill path are the ones in production."""
    monkeypatch.setattr(cr, "build_argv", lambda op, image, name: [sys.executable, "-c", code])
    monkeypatch.setattr(cr, "_docker", lambda *a, **k: None)
    monkeypatch.setitem(OPS, "capa", dataclasses.replace(OPS["capa"], **spec))
    return ContainerRunner(IMAGE_IDS).run("capa", b"data")


def test_timeout_is_final(monkeypatch):
    monkeypatch.setattr(cr, "TIMEOUT_S", 1)
    with pytest.raises(ContainerError) as e:
        _run_script(monkeypatch, "import time; time.sleep(30)")
    assert e.value.final


def test_output_limit_is_final(monkeypatch):
    with pytest.raises(ContainerError, match="output limit") as e:
        _run_script(monkeypatch, "import sys\nwhile True: sys.stdout.buffer.write(bytes(1 << 20))", max_output=4 << 20)
    assert e.value.final


@pytest.mark.parametrize("code, final", [(124, True), (137, True), (1, False)])
def test_exit_codes_for_limits_are_final(monkeypatch, code, final):
    with pytest.raises(ContainerError) as e:
        _run_script(monkeypatch, f"import sys; sys.exit({code})")
    assert e.value.final is final


def test_json_tools_have_the_lower_output_limit():
    assert OPS["ghidra"].max_output == cr.MAX_JSON_OUTPUT < OPS["jadx-apk"].max_output == cr.MAX_TAR_OUTPUT
