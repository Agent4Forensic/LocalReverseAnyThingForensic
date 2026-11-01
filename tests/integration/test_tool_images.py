"""The real tool images on harmless samples built here. Skipped without Docker or images; building them: infra/tools/build-images.ps1."""
from __future__ import annotations

import base64
import shutil
import struct
import subprocess
import uuid

import pytest

from sw_analyst.gateway.container_runner import IMAGES, ContainerRunner
from sw_analyst.gateway.container_tools import attach_container_tools
from sw_analyst.gateway.dev_gateway import DevGateway

RUNNER = ContainerRunner.detect()
pytestmark = pytest.mark.skipif(set(RUNNER.image_ids) != set(IMAGES), reason="tool images not built or Docker not running")

AES_SBOX_HEAD = bytes.fromhex("637C777BF26B6FC53001672BFED7AB76")


def harmless_pe() -> bytes:
    """A PE32 that does nothing useful: entry calls a helper that XORs 16 bytes in place and returns a constant.

    Carries one AES S-box row as plain data. The XOR loop is there so that a capa rule has something to match.
    """
    code = bytes.fromhex("5589E5E8050000005DC3909090"
                         "B910000000" "8A040E" "3455" "88040E" "E2F6" "B82A000000" "C3")
    buf = bytearray(0x600)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x14C, 2, 0x5F000000, 0, 0, 0xE0, 0x0102)
    o = 0x98
    struct.pack_into("<H", buf, o, 0x10B)
    struct.pack_into("<I", buf, o + 4, 0x200)
    struct.pack_into("<I", buf, o + 16, 0x1000)       # entry
    struct.pack_into("<I", buf, o + 20, 0x1000)       # base of code
    struct.pack_into("<I", buf, o + 28, 0x400000)     # image base
    struct.pack_into("<II", buf, o + 32, 0x1000, 0x200)
    struct.pack_into("<HH", buf, o + 40, 4, 0)        # OS version
    struct.pack_into("<HH", buf, o + 48, 4, 0)        # subsystem version
    struct.pack_into("<II", buf, o + 56, 0x3000, 0x200)
    struct.pack_into("<H", buf, o + 68, 3)
    struct.pack_into("<I", buf, o + 92, 16)
    sec = o + 0xE0
    struct.pack_into("<8sIIIIIIHHI", buf, sec, b".text", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<8sIIIIIIHHI", buf, sec + 40, b".data", 0x200, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0xC0000040)
    buf[0x200:0x200 + len(code)] = code
    buf[0x400:0x400 + 16] = AES_SBOX_HEAD
    return bytes(buf)


@pytest.fixture(scope="module")
def pe_gw(tmp_path_factory):
    gw = DevGateway(tmp_path_factory.mktemp("data"))
    assert len(attach_container_tools(gw, RUNNER)) == 10
    gw.store_sample("pe", harmless_pe())
    return gw


def test_ghidra_finds_decompiles_and_links_the_functions(pe_gw):
    r = pe_gw.call("pe", "list_functions", {})
    assert r.ok, r.error
    assert r.meta["count"] >= 2 and "0x401000" in r.text
    assert r.tool_version.startswith("ghidra-12.1.4@sha256:")
    dec = pe_gw.call("pe", "decompile", {"function": "0x401000"})
    assert dec.ok, dec.error
    assert "(" in dec.text
    assert "PUSH" in pe_gw.call("pe", "disassemble", {"function": "0x401000"}).text
    assert pe_gw.call("pe", "xrefs", {"target": "0x40100d"}).meta["to"] >= 1
    assert pe_gw.call("pe", "basic_blocks", {"function": "0x401000"}).meta["blocks"]


def test_yara_hits_the_own_rule(pe_gw):
    r = pe_gw.call("pe", "yara_scan", {})
    assert r.ok, r.error
    assert r.meta["rules"] == ["crypto_aes_sbox"] and r.meta["hypothesis"] and "0x400" in r.text


def test_capa_and_floss_run_offline(pe_gw):
    c = pe_gw.call("pe", "capa_scan", {})
    assert c.ok and c.meta["hypothesis"], c.error
    assert "encode data using XOR" in c.meta["rules"] and "0x401012" in c.text, c.text
    f = pe_gw.call("pe", "floss_decode", {})
    assert f.ok, f.error


def test_jadx_decompiles_a_harmless_jar(tmp_path):
    javac, jar = shutil.which("javac"), shutil.which("jar")
    if not javac or not jar:
        pytest.skip("host JDK missing")
    (tmp_path / "Hello.java").write_text('public class Hello { static String u = "http://example.invalid"; }', encoding="utf-8")
    subprocess.run([javac, "--release", "11", "Hello.java"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run([jar, "cf", "h.zip", "Hello.class"], cwd=tmp_path, check=True, capture_output=True)
    gw = DevGateway(tmp_path / "data")
    attach_container_tools(gw, RUNNER)
    gw.store_sample("jar", (tmp_path / "h.zip").read_bytes())
    r = gw.call("jar", "jadx_decompile", {})
    assert r.ok and r.meta["count"] >= 1, r.error
    assert "Hello.java" in r.text
    assert "example.invalid" in gw.call("jar", "jadx_decompile", {"search": "example"}).text


def _probe(op: str, script_free_payload: bytes = b"x") -> subprocess.CompletedProcess:
    """Starts the hardened argv but swaps the entrypoint, to look at the sandbox from inside."""
    from sw_analyst.gateway.container_runner import OPS, build_argv
    return build_argv(op, RUNNER.image_ids[OPS[op].image], f"sw-analyst-probe-{uuid.uuid4().hex}")


@pytest.mark.parametrize("op", ["capa", "ghidra", "jadx-jar", "emulate"])
def test_sandbox_from_inside_no_network_read_only_noexec_not_root(op):
    argv = _probe(op)
    image, _ = argv[-2], argv[-1]
    check = ("id -u; "
             "touch /opt/x 2>/dev/null && echo ROOTFS_WRITABLE; "
             "cat > /job/s; chmod 0755 /job/s; /job/s 2>/dev/null && echo JOB_EXEC; "
             "grep -v lo: /proc/net/dev | tail -n +3 | grep . && echo HAS_NIC; "
             "echo done")
    run = argv[:-2] + ["--entrypoint", "/bin/sh", image, "-c", check]
    r = subprocess.run(run, input=b"#!/bin/sh\necho hi\n", capture_output=True, timeout=120, check=False)
    out = r.stdout.decode()
    assert out.startswith("10001"), out + r.stderr.decode()
    assert "done" in out
    for marker in ("ROOTFS_WRITABLE", "JOB_EXEC", "HAS_NIC"):
        assert marker not in out, out


def test_garbage_input_is_a_clean_tool_error(tmp_path):
    gw = DevGateway(tmp_path)
    attach_container_tools(gw, RUNNER)
    gw.store_sample("junk", base64.b64encode(b"not a program at all") * 4)
    r = gw.call("junk", "capa_scan", {})
    assert not r.ok and "exit code" in r.error


# ---- emulate_function (ADR-0005 stage 2): a simulated CPU, the file is never started -------------------------------------
XOR_X86 = bytes.fromhex("8B742404" "8B4C2408" "807C0EFF00".replace("7C", "74").replace("FF00", "FF55") + "E2F9" "B82A000000" "C3")
SECRET = b"hidden-config"


def _emu_gw(tmp_path, sample):
    gw = DevGateway(tmp_path)
    attach_container_tools(gw, RUNNER)
    gw.dynamic_enabled = lambda: True
    gw.dynamic_allowed = lambda _job: True
    gw.store_sample("emu", sample)
    return gw


def test_emulator_decrypts_a_blob_and_saves_the_result(tmp_path):
    blob = bytes(c ^ 0x55 for c in SECRET)
    gw = _emu_gw(tmp_path, XOR_X86.ljust(0x40, b"\x90") + blob)
    r = gw.call("emu", "emulate_function", {"start": "0x10000", "arch": "x86", "call_args": "input,input_len",
                                            "input_offset": 0x40, "input_length": len(blob)})
    assert r.ok, r.error
    assert "Stopped: returned" in r.text and "Return register: 0x2a" in r.text and "hypothesis" in r.text
    assert r.meta["emulated"] is True and SECRET.decode() in r.text
    saved = gw.read_bytes("emu", r.meta["derived"], 0, 4096)["data"]
    assert saved.startswith(SECRET)


def test_emulator_stops_at_budget_fault_and_imports(tmp_path):
    gw = _emu_gw(tmp_path, bytes.fromhex("EBFE") + bytes.fromhex("A100000000"))    # endless loop; read of address 0
    loop = gw.call("emu", "emulate_function", {"start": "0x10000", "arch": "x86", "max_instructions": 1000})
    assert "Stopped: budget" in loop.text
    fault = gw.call("emu", "emulate_function", {"start": "0x10002", "arch": "x86"})
    assert "Stopped: fault" in fault.text and "Fault:" in fault.text
    outside = gw.call("emu", "emulate_function", {"start": "0x7000000", "arch": "x86"})
    assert not outside.ok and "outside the mapped file" in outside.error


def test_emulator_names_the_import_instead_of_calling_it(tmp_path):
    pe = bytearray(harmless_pe())
    pe[0x200:0x206] = bytes.fromhex("FF1560204000")                # call [0x402060]
    struct.pack_into("<II", pe, 0x98 + 96 + 8, 0x2000, 40)         # import directory
    struct.pack_into("<IIIII", pe, 0x400, 0x2040, 0, 0, 0x2080, 0x2060)
    struct.pack_into("<I", pe, 0x440, 0x20A0)                      # lookup table: one name
    struct.pack_into("<I", pe, 0x460, 0x20A0)                      # import address table
    pe[0x480:0x48D] = b"kernel32.dll\0"
    pe[0x4A2:0x4A8] = b"Sleep\0"
    gw = _emu_gw(tmp_path, bytes(pe))
    r = gw.call("emu", "emulate_function", {"start": "0x401000"})
    assert r.ok, r.error
    assert "Stopped: api_call" in r.text and "kernel32.dll!Sleep" in r.text


def test_emulator_refuses_garbage_cleanly(tmp_path):
    gw = _emu_gw(tmp_path, b"no headers here")
    r = gw.call("emu", "emulate_function", {"start": "0x10000"})
    assert not r.ok and "not a PE or ELF" in r.error
    bad = gw.call("emu", "emulate_function", {"start": "0x10000", "arch": "x86", "call_args": "rm -rf /"})
    assert not bad.ok and "call_args" in bad.error
