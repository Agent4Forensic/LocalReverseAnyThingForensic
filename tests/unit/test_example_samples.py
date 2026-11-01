"""Committed example samples (ADR-0009) are exact copies of the builder output and listed in the manifest."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_committed_samples_match_builders_and_manifest():
    r = subprocess.run([sys.executable, "-I", str(ROOT / "example" / "build_samples.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_manifest_lists_every_challenge_and_only_sample_paths():
    files = json.loads((ROOT / "example" / "samples.manifest.json").read_text(encoding="utf-8"))["files"]
    ids = {p.parent.name for p in (ROOT / "example" / "challenges").glob("*/challenge.json")}
    assert {v["challenge"] for v in files.values()} == ids
    for rel, v in files.items():
        assert rel.startswith("example/challenges/") and "/sample/" in rel and ".." not in rel
        assert hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() == v["sha256"]


def test_examples_api_points_to_the_committed_file():
    from sw_analyst.webui.examples import Examples
    for e in Examples().list():
        assert e["paths"]["sample_file"].endswith("/sample/" + e["sample"]["name"]) and e["paths"]["sample_file_ok"] is True


# ---------------------------------------------------------------- hard challenges 06-09: replay the solution path
# Each test only uses DevGateway tools (the platform's static tools) and the evidence found in the sample itself.
import re  # noqa: E402

import pytest  # noqa: E402

from sw_analyst.gateway.dev_gateway import DevGateway  # noqa: E402

sys.path.insert(0, str(ROOT / "example"))
from samples import BUILDERS  # noqa: E402

JOB = "job1"


def _challenge(cid: str) -> dict:
    return json.loads((ROOT / "example" / "challenges" / cid / "challenge.json").read_text(encoding="utf-8"))


def _gw(tmp_path: Path, cid: str):
    c = _challenge(cid)
    gw = DevGateway(tmp_path)
    data = (ROOT / "example" / "challenges" / cid / "sample" / c["sample"]["name"]).read_bytes()
    assert data == BUILDERS[c["sample"]["builder"]]()
    gw.store_sample(JOB, data)
    return gw, c, data


def _call(gw, name, **args):
    r = gw.call(JOB, name, args)
    assert r.ok, r.text
    return r


def _layer(gw, path: str) -> bytes:
    return (gw._jobs / JOB / path).read_bytes()


def _dec(gw, path, method, **kw):
    return _call(gw, "decode_layer", path=path, method=method, **kw).meta["derived"]


def test_hard_challenges_are_registered_and_evaluable():
    for cid in ("06-polyglot-zip-xor", "07-pe-rsrc-xor-config", "08-script-mini-vm", "09-matroschka-seven"):
        c = _challenge(cid)
        assert c["id"] == cid and c["sample"]["builder"] in BUILDERS and c["flag"] and c["questions"]
        assert not c["sample"]["name"].endswith(".exe") and c["requires"] == []
        data = BUILDERS[c["sample"]["builder"]]()
        assert c["flag"].encode() not in data        # never in clear text
        assert b"http://" not in data and b"https://" not in data


def test_06_polyglot_chain(tmp_path):
    gw, c, data = _gw(tmp_path, "06-polyglot-zip-xor")
    assert "unknown" in _call(gw, "identify_type", path="sample").text.lower()   # no magic at offset 0: polyglot
    assert "NOTES/readme.txt" in _call(gw, "zip_list", path="sample").text
    readme = _call(gw, "zip_read_text", member="NOTES/readme.txt", path="sample").text
    part_b = re.search(r"part B: ([0-9a-f]+)", readme).group(1)
    strs = _call(gw, "strings_extract", path="sample", min_len=6, encoding="ascii", max_results=500).text
    part_a = re.search(r"key-part-A: ([0-9a-f]+)", strs).group(1)
    part_c = re.search(r"part-C: ([0-9a-f]+)", strs).group(1)
    layer = _call(gw, "zip_extract", member="payload.dat", path="sample").meta["derived"]
    layer = _dec(gw, layer, "xor_key", key_hex=part_a + part_b + part_c)
    layer = _dec(gw, layer, "base64")
    layer = _dec(gw, layer, "gzip")
    assert c["flag"].encode() in _layer(gw, layer)
    # wrong key order does not reach the flag
    bad = _call(gw, "zip_extract", member="payload.dat", path="sample").meta["derived"]
    bad = _dec(gw, bad, "xor_key", key_hex=part_b + part_a + part_c)
    assert c["flag"].encode() not in _layer(gw, bad)


def test_07_pe_rsrc_chain(tmp_path):
    gw, c, data = _gw(tmp_path, "07-pe-rsrc-xor-config")
    assert "overlay" in _call(gw, "pe_headers", path="sample").text.lower()
    res = _call(gw, "pe_resources", path="sample").meta["resources"]
    assert len(res) == 2
    r101 = next(r for r in res if "101" in r["path"])
    ov = data.find(b"CFGK")
    dump = _call(gw, "hexdump", path="sample", offset=ov, length=32).text
    key_hex = data[ov + 8:ov + 16].hex()        # header: CFGK, u16 version, u16 key length (8), key
    assert " ".join(key_hex[i:i + 2] for i in range(0, 16, 2)) in dump
    layer = _call(gw, "extract_range", offset=r101["file_offset"], length=r101["size"], path="sample").meta["derived"]
    text = _layer(gw, _dec(gw, layer, "xor_key", key_hex=key_hex)).decode()
    fields = dict(re.findall(r"^(\w+)=(.*)$", text, re.M))
    assert f"SWBENCH{{{fields['campaign']}_{fields['build_tag']}}}" == c["flag"]
    r102 = next(r for r in res if "102" in r["path"])
    d = _call(gw, "extract_range", offset=r102["file_offset"], length=r102["size"], path="sample").meta["derived"]
    assert b"decoy" not in _layer(gw, _dec(gw, d, "xor_key", key_hex=key_hex))


def test_08_mini_vm_chain(tmp_path):
    gw, c, data = _gw(tmp_path, "08-script-mini-vm")
    txt = data.decode()
    table = bytes.fromhex(re.search(r'TABLE = bytes.fromhex\("([0-9a-f]+)"\)', txt).group(1))
    prog = bytes.fromhex(re.search(r'^PROG = bytes.fromhex\("([0-9a-f]+)"\)', txt, re.M).group(1))
    assert "PROG" in _call(gw, "grep", pattern=r"^PROG = ", path="sample").text
    # hand-run of the byte code: collect the order of operations and the keys
    pc, ops, keys = 0, [], []
    while prog[pc] != 0xFF:
        op = prog[pc]
        if op == 0x02:
            n = prog[pc + 1]
            keys.append(bytes(table[i & 15] for i in prog[pc + 2:pc + 2 + n]))
            ops.append("xor"); pc += 2 + n
        else:
            ops.append({1: "hex", 3: "base64", 4: "gzip", 0x0A: "nop"}[op]); pc += 1
    assert [o for o in ops if o != "nop"] == ["hex", "xor", "base64", "xor", "gzip"]
    off = data.find(b'DATA = "') + len('DATA = "')
    length = data.index(b'"', off) - off
    layer = _dec(gw, "sample", "hex", offset=off, length=length)
    layer = _dec(gw, layer, "xor_key", key_hex=keys[0].hex())
    layer = _dec(gw, layer, "base64")
    layer = _dec(gw, layer, "xor_key", key_hex=keys[1].hex())
    layer = _dec(gw, layer, "gzip")
    assert c["flag"].encode() in _layer(gw, layer)
    assert b"FLAG{debug_path_is_a_decoy}" not in _layer(gw, layer)


def test_09_matroschka_chain(tmp_path):
    gw, c, data = _gw(tmp_path, "09-matroschka-seven")
    assert "blob=" in _call(gw, "grep", pattern="^blob=", path="sample").text
    off = data.find(b"blob=") + 5
    length = data.index(b"\n", off) - off
    layer = _dec(gw, "sample", "base64", offset=off, length=length)
    for m in ("gzip", "url", "base64", "rot13", "hex", "zlib"):
        layer = _dec(gw, layer, m)
    final = _layer(gw, layer)
    assert c["flag"].encode() in final
    assert re.search(rb"final_token = (SWBENCH\{[^}]+\})", final).group(1).decode() == c["flag"]
