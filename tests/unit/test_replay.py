"""Replay export: real chain through the DevGateway, ZIP built, script run in a temp dir. All data is harmless."""
from __future__ import annotations

import base64
import gzip
import importlib.util
import io
import json
import subprocess
import sys
import zipfile

import pytest

from sw_analyst.common.models import JobSpec, TargetQuestion
from sw_analyst.common.store import Store
from sw_analyst.common.util import sha256_hex
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.gateway.dev_tools import decoders
from sw_analyst.report import replay

PLAIN = b"Hello analyst. The harmless answer is flag{replay_ok} and nothing else.\n" * 3
KEY = 0x5A


def _setup(tmp_path, sample: bytes, calls: list[tuple[str, dict]]):
    gw = DevGateway(tmp_path / "data")
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    spec = JobSpec(title="t", description="d", target_questions=[TargetQuestion(id="Q1", text_orig="Flagge?", text_en="Flag?")])
    job = store.create_job(spec, "evil name/..\\x.txt", sha256_hex(sample))
    jid = job["id"]
    gw.store_sample(jid, sample)
    t = store.add_task(jid, title="T", goal="g", kind="question", origin="question", priority=1,
                       params={"question_id": "Q1"})
    evs = []
    for tool, args in calls:
        r = gw.call(jid, tool, args)
        assert r.ok, r.error
        evs.append(store.add_evidence(jid, t["id"], tool, r.tool_version, args, r.text, source_ref=r.meta))
    return store, gw, jid, t, evs


def _chain(tmp_path):
    sample = base64.b64encode(gzip.compress(decoders.xor_with(PLAIN, KEY)))
    calls = [("decode_layer", {"method": "base64"}),
             ("decode_layer", {"method": "gzip", "path": "derived/layer01.bin"}),
             ("decode_layer", {"method": "auto", "path": "derived/layer02.bin"})]
    store, gw, jid, t, evs = _setup(tmp_path, sample, calls[:2] + [("decode_layer", {"method": "xor_single_byte", "key": KEY, "path": "derived/layer02.bin"})])
    f = store.add_finding(jid, t["id"], "Flag found.", "confirmed", [evs[-1]["id"]],
                          [{"evidence_id": evs[-1]["id"], "quote": "flag{replay_ok}"},
                           {"evidence_id": evs[-1]["id"], "quote": "not in bytes zzz"}])
    store.update_answer(jid, "Q1", status="answered", answer_en="The flag is flag{replay_ok}.",
                        answer_de="Die Flagge ist flag{replay_ok}.", finding_ids=[f["id"]])
    return store, gw, jid, sample


def _unpack(zbytes: bytes, d):
    with zipfile.ZipFile(io.BytesIO(zbytes)) as zf:
        zf.extractall(d)
        return zf.namelist()


def _run(d, *args):
    return subprocess.run([sys.executable, "-I", "replay.py", "--no-pause", *args], cwd=str(d), capture_output=True,
                          text=True, timeout=60, stdin=subprocess.DEVNULL)


def test_replay_chain_ok(tmp_path):
    store, gw, jid, sample = _chain(tmp_path)
    z = replay.build_replay_zip(store, gw, jid, include_sample=False)
    d = tmp_path / "x"
    names = _unpack(z, d)
    assert {"replay.py", "run_replay.cmd", "run_replay.sh", "README.txt", "steps.json"} <= set(names)
    assert not any(n.startswith("sample/") for n in names)
    steps = json.loads((d / "steps.json").read_text("utf-8"))["steps"]
    assert [s["method"] for s in steps] == ["base64", "gzip", "xor_single_byte"] and steps[2]["xor_key"] == KEY
    sp = tmp_path / "orig.bin"
    sp.write_bytes(sample)
    r = _run(d, "--sample", str(sp), "--out", str(tmp_path / "out"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.count("OK (gleich") == 3 and "ABWEICHUNG" not in r.stdout
    assert "Die Flagge ist flag{replay_ok}." in r.stdout
    assert "im reproduzierten Inhalt gefunden: derived/layer03.bin" in r.stdout
    assert "nicht in den reproduzierten Bytes" in r.stdout
    assert (tmp_path / "out" / "layer03.bin").read_bytes() == PLAIN


def test_replay_with_sample_and_wrong_file(tmp_path):
    store, gw, jid, sample = _chain(tmp_path)
    z = replay.build_replay_zip(store, gw, jid, include_sample=True)
    d = tmp_path / "x"
    names = _unpack(z, d)
    sample_names = [n for n in names if n.startswith("sample/")]
    assert len(sample_names) == 1 and ".." not in sample_names[0] and "\\" not in sample_names[0]
    r = _run(d)                                   # sample found beside the script
    assert r.returncode == 0 and "OK (gleich" in r.stdout
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"other")
    r = _run(d, "--sample", str(bad))
    assert r.returncode == 2 and "ABBRUCH" in r.stdout and "Schritt 1" not in r.stdout
    r = _run(tmp_path / "x", "--sample", str(tmp_path / "missing"))
    assert r.returncode == 2 and "ABBRUCH" in r.stdout


def test_replay_zip_extract_range_and_unknown(tmp_path):
    inner = b"member payload: harmless text 12345"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a/b.txt", inner)
    sample = b"PAD" + buf.getvalue()
    store, gw, jid, t, evs = _setup(tmp_path, sample, [
        ("extract_range", {"offset": 3, "length": len(sample) - 3}),
        ("zip_extract", {"member": "a/b.txt", "path": "derived/layer01.bin"}),
        ("hash_file", {})])
    store.add_evidence(jid, t["id"], "yara_scan", "1", {}, "x", source_ref={"derived": "derived/layer77.bin", "sha256": "0" * 64})
    z = replay.build_replay_zip(store, gw, jid, include_sample=False)
    d = tmp_path / "x"
    _unpack(z, d)
    steps = json.loads((d / "steps.json").read_text("utf-8"))["steps"]
    assert [s["tool"] for s in steps] == ["extract_range", "zip_extract", "yara_scan"]
    sp = tmp_path / "o.bin"
    sp.write_bytes(sample)
    r = _run(d, "--sample", str(sp))
    assert r.stdout.count("OK (gleich") == 2, r.stdout
    assert "nicht nachvollziehbar, siehe Beleg" in r.stdout.lower() or "Nicht nachvollziehbar, siehe Beleg" in r.stdout
    assert "member payload" in r.stdout and r.returncode == 1


def test_replay_detects_deviation_and_sanitises(tmp_path):
    store, gw, jid, sample = _chain(tmp_path)
    z = replay.build_replay_zip(store, gw, jid, include_sample=False)
    d = tmp_path / "x"
    _unpack(z, d)
    meta = json.loads((d / "steps.json").read_text("utf-8"))
    meta["steps"][0]["output_sha256"] = "1" * 64
    meta["questions"][0]["answer"] = "evil \x1b[31m red \x07 bell"
    (d / "steps.json").write_text(json.dumps(meta), "utf-8")
    sp = tmp_path / "o.bin"
    sp.write_bytes(sample)
    r = _run(d, "--sample", str(sp))
    assert "ABWEICHUNG" in r.stdout and r.returncode == 1
    assert "\x1b" not in r.stdout and "\x07" not in r.stdout


def test_script_decoders_match_platform(tmp_path):
    p = tmp_path / "replay_mod.py"
    p.write_text(replay.SCRIPT, "utf-8")
    sp = importlib.util.spec_from_file_location("replay_mod", p)
    mod = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(mod)
    data = {"base64": base64.b64encode(PLAIN), "base32": base64.b32encode(PLAIN), "base85": base64.b85encode(PLAIN),
            "hex": PLAIN.hex().encode(), "url": b"a%20b%41", "rot13": b"Hello World abc",
            "charcode": b"72,101,0x6c", "gzip": gzip.compress(PLAIN), "zlib": __import__("zlib").compress(PLAIN)}
    for m, chunk in data.items():
        assert mod.SIMPLE[m](chunk) == decoders.SIMPLE[m](chunk), m
    assert mod.xor_key(PLAIN, b"\x01\x02\x03") == decoders.xor_key(PLAIN, b"\x01\x02\x03")
    assert mod.rc4(PLAIN, b"key") == decoders.rc4(PLAIN, b"key")
    assert not any(w in replay.SCRIPT for w in ("subprocess", "eval(", "exec(", "socket", "urlopen", "shell=True"))


def test_unknown_job(tmp_path):
    store = Store(tmp_path / "t.db", tmp_path / "logs")
    with pytest.raises(KeyError):
        replay.build_replay_zip(store, DevGateway(tmp_path / "d"), "nope", False)
