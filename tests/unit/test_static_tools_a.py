"""ADR-0006 package A: own stdlib tools. All samples are harmless, synthetic data built in the tests."""
from __future__ import annotations

import base64
import io
import random
import struct
import zipfile

import pytest

from sw_analyst.gateway.dev_gateway import MAX_KEYS_PER_JOB, DevGateway, decoders
from sw_analyst.gateway.dev_tools.axml import AxmlError, parse_axml
from sw_analyst.gateway.dev_tools.pe import parse_pe, parse_resources

JOB = "job1"


@pytest.fixture()
def gw(tmp_path):
    return DevGateway(tmp_path)


def _derived(gw, logical):
    return (gw._jobs / JOB / logical).read_bytes()


# ---------------------------------------------------------------- binary XML built by hand
def _pool(strings, utf8=False):
    body, offs = bytearray(), []
    for s in strings:
        offs.append(len(body))
        if utf8:
            raw = s.encode()
            body += bytes([len(s), len(raw)]) + raw + b"\0"
        else:
            body += struct.pack("<H", len(s)) + s.encode("utf-16le") + b"\0\0"
    body += b"\0" * (-len(body) % 4)
    start = 28 + 4 * len(strings)
    head = struct.pack("<HHIIIIII", 1, 28, start + len(body), len(strings), 0, 256 if utf8 else 0, start, 0)
    return head + b"".join(struct.pack("<I", o) for o in offs) + bytes(body)


def _attr(ns, name, kind, data, raw=0xFFFFFFFF):
    return struct.pack("<IIIHBBI", ns, name, raw, 8, 0, kind, data)


def _start(name, attrs):
    body = struct.pack("<IIHHHHHH", 0xFFFFFFFF, name, 20, 20, len(attrs), 0, 0, 0) + b"".join(attrs)
    return struct.pack("<HHIII", 0x102, 16, 16 + len(body), 1, 0xFFFFFFFF) + body


def _end(name):
    return struct.pack("<HHIIIII", 0x103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, name)


def build_axml(utf8=False):
    s = ["android", "http://schemas.android.com/apk/res/android", "manifest", "package", "uses-permission", "name",
         "com.example.harmless", "android.permission.INTERNET", "application", "activity", ".Main", "exported"]
    res_map = struct.pack("<HHI", 0x180, 8, 8)
    ns = struct.pack("<HHIIIII", 0x100, 16, 24, 1, 0xFFFFFFFF, 0, 1)
    body = (_pool(s, utf8) + res_map + ns
            + _start(2, [_attr(0xFFFFFFFF, 3, 3, 6, 6)])
            + _start(4, [_attr(1, 5, 3, 7, 7)]) + _end(4)
            + _start(8, [])
            + _start(9, [_attr(1, 5, 3, 10, 10), _attr(1, 11, 0x12, 0xFFFFFFFF)]) + _end(9)
            + _end(8) + _end(2))
    return struct.pack("<HHI", 3, 8, 8 + len(body)) + body


def _zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    return buf.getvalue()


@pytest.mark.parametrize("utf8", [False, True])
def test_axml_reads_package_permissions_components(utf8):
    m = parse_axml(build_axml(utf8))
    assert m["package"] == "com.example.harmless"
    assert m["permissions"] == ["android.permission.INTERNET"]
    assert m["components"] == [{"kind": "activity", "name": ".Main", "exported": "true"}]
    assert 'android:name=".Main"' in m["xml"] and "</manifest>" in m["xml"]


def test_axml_escapes_markup_from_the_sample():
    s = ["manifest", "package", 'x"><evil>']
    body = _pool(s) + _start(0, [_attr(0xFFFFFFFF, 1, 3, 2, 2)]) + _end(0)
    xml = parse_axml(struct.pack("<HHI", 3, 8, 8 + len(body)) + body)["xml"]
    assert "<evil>" not in xml and "&lt;evil&gt;" in xml


@pytest.mark.parametrize("seed", range(40))
def test_axml_fuzz_only_raises_axml_error(seed):
    rnd = random.Random(seed)
    good = bytearray(build_axml(seed % 2 == 0))
    for _ in range(rnd.randint(1, 40)):
        good[rnd.randrange(len(good))] = rnd.randrange(256)
    data = bytes(good[:rnd.randint(0, len(good))]) if seed % 3 == 0 else bytes(good)
    try:
        parse_axml(data)
    except AxmlError:
        pass


def test_axml_random_bytes_and_big_counts_are_refused():
    with pytest.raises(AxmlError):
        parse_axml(b"\x03\x00\x08\x00" + b"\xff" * 64)
    with pytest.raises(AxmlError):
        parse_axml(b"not xml at all")


def test_apk_manifest_tool_on_apk_and_on_derived_file(gw):
    gw.store_sample(JOB, _zip({"AndroidManifest.xml": build_axml(), "classes.dex": b"dex\n035\0"}))
    r = gw.call(JOB, "apk_manifest", {})
    assert r.ok and "android.permission.INTERNET" in r.text and r.meta["package"] == "com.example.harmless"
    assert r.meta["source_ref"]["member"] == "AndroidManifest.xml"
    x = gw.call(JOB, "zip_extract", {"member": "AndroidManifest.xml"})
    assert x.ok and gw.call(JOB, "apk_manifest", {"path": x.meta["derived"]}).ok


def test_apk_manifest_without_manifest_is_a_clean_error(gw):
    gw.store_sample(JOB, _zip({"a.txt": b"x"}))
    r = gw.call(JOB, "apk_manifest", {})
    assert not r.ok and "not found" in r.error


# ---------------------------------------------------------------- extract_range / zip_extract
def test_extract_range_writes_inert_layer_with_hash(gw):
    gw.store_sample(JOB, b"AAAA" + b"MZ" + b"\0" * 62 + b"BBBB")
    r = gw.call(JOB, "extract_range", {"offset": 4, "length": 64})
    assert r.ok and r.meta["derived"] == "derived/layer01.bin" and r.meta["magic"] == "pe/mz"
    assert _derived(gw, r.meta["derived"]) == b"MZ" + b"\0" * 62
    assert r.meta["source_ref"] == {"file": "sample", "offset": 4, "length": 64}


def test_extract_range_bounds(gw):
    gw.store_sample(JOB, b"12345")
    assert "beyond end" in gw.call(JOB, "extract_range", {"offset": 5, "length": 1}).error
    assert not gw.call(JOB, "extract_range", {"offset": 0}).ok
    r = gw.call(JOB, "extract_range", {"offset": 0, "length": 10 ** 9})
    assert r.ok and r.meta["size"] == 5 and "clamped" in r.text


def test_zip_extract_name_comes_from_the_gateway(gw):
    gw.store_sample(JOB, _zip({"assets/config.json": b'{"a":1}'}))
    r = gw.call(JOB, "zip_extract", {"member": "assets/config.json"})
    assert r.ok and r.meta["derived"] == "derived/layer01.bin"
    assert _derived(gw, r.meta["derived"]) == b'{"a":1}'


@pytest.mark.parametrize("member", ["../evil", "/abs", "C:/x", "a\\b"])
def test_zip_extract_refuses_unsafe_names(gw, member):
    gw.store_sample(JOB, _zip({"a": b"x"}))
    r = gw.call(JOB, "zip_extract", {"member": member})
    assert not r.ok and "rejected" in r.error
    assert not list((gw._jobs / JOB / "derived").iterdir())


def test_zip_extract_bomb_is_refused(gw):
    gw.store_sample(JOB, _zip({"bomb": b"\0" * (decoders.MAX_OUT + 1)}))
    r = gw.call(JOB, "zip_extract", {"member": "bomb"})
    assert not r.ok and "limit" in r.error
    assert not list((gw._jobs / JOB / "derived").iterdir())


# ---------------------------------------------------------------- decode_layer methods
def test_new_decoders_round_trip(gw):
    plain = b"hello harmless world"
    cases = {"base32": base64.b32encode(plain), "base85": base64.b85encode(plain),
             "charcode": ",".join(str(c) for c in plain).encode()}
    for i, (method, enc) in enumerate(cases.items()):
        job = f"j{i}"
        gw.store_sample(job, enc)
        r = gw.call(job, "decode_layer", {"method": method})
        assert r.ok, r.error
        assert (gw._jobs / job / r.meta["derived"]).read_bytes() == plain


def test_ascii85_and_charcode_hex():
    assert decoders.d_base85(b"<~" + base64.a85encode(b"abc") + b"~>") == b"abc"
    assert decoders.d_charcode(b"[0x41, 66;67]") == b"ABC"
    for bad in (b"1,x,3", b"99999999", b"55296"):
        with pytest.raises(decoders.DecodeError):
            decoders.d_charcode(bad)


def test_rc4_known_vector_and_xor_key():
    assert decoders.rc4(b"Plaintext", b"Key").hex().upper() == "BBF316E8D940AF0AD3"
    assert decoders.xor_key(b"\x00\x00\x00", bytes.fromhex("0102")) == b"\x01\x02\x01"
    assert decoders.xor_key(decoders.xor_key(b"abcde", b"k1"), b"k1") == b"abcde"


def test_keyed_methods_need_a_valid_key(gw):
    gw.store_sample(JOB, b"data")
    for key in ("", "abc", "zz", "00" * 65):
        assert "key_hex" in gw.call(JOB, "decode_layer", {"method": "rc4", "key_hex": key}).error


def test_key_guessing_is_limited_per_job_but_reuse_is_free(gw):
    gw.store_sample(JOB, b"payload bytes")
    for k in range(MAX_KEYS_PER_JOB):
        assert gw.call(JOB, "decode_layer", {"method": "xor_key", "key_hex": f"{k + 1:02x}"}).ok
    r = gw.call(JOB, "decode_layer", {"method": "xor_key", "key_hex": "7f"})
    assert not r.ok and "Limit" in r.error
    assert gw.call(JOB, "decode_layer", {"method": "rc4", "key_hex": "01"}).ok


def test_auto_never_tries_keyed_methods(gw):
    gw.store_sample(JOB, base64.b64encode(b"hello harmless world"))
    r = gw.call(JOB, "decode_layer", {"method": "auto"})
    assert r.ok and not {c["method"] for c in r.meta["candidates"]} & {"xor_key", "rc4"}


# ---------------------------------------------------------------- pe_resources
def build_pe_with_resources(loop=False):
    buf = bytearray(0x600)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    o = 0x98
    struct.pack_into("<H", buf, o, 0x10B)
    struct.pack_into("<I", buf, o + 60, 0x200)
    struct.pack_into("<I", buf, o + 92, 16)
    struct.pack_into("<II", buf, o + 96 + 8 * 2, 0x1000, 0x100)
    struct.pack_into("<8sIIIIIIHHI", buf, o + 0xE0, b".rsrc", 0x400, 0x1000, 0x400, 0x200, 0, 0, 0, 0, 0x40000040)
    root = 0x200

    def directory(off, target, is_id):
        struct.pack_into("<H", buf, root + off + 14, 1)
        struct.pack_into("<II", buf, root + off + 16, is_id, target)
    directory(0x00, 0x80000020, 10)                       # RT_RCDATA
    directory(0x20, 0x80000040 if not loop else 0x80000000, 101)
    directory(0x40, 0x60, 1033)
    struct.pack_into("<II", buf, root + 0x60, 0x1100, 8)
    buf[root + 0x100:root + 0x108] = b"PAYLOAD!"
    return bytes(buf)


def test_pe_resources_lists_offset_size_and_extract_range_reads_it(gw):
    gw.store_sample(JOB, build_pe_with_resources())
    r = gw.call(JOB, "pe_resources", {})
    assert r.ok and r.meta["count"] == 1
    row = r.meta["resources"][0]
    assert row["path"] == "RCDATA/101/1033" and row["size"] == 8 and row["file_offset"] == 0x300
    x = gw.call(JOB, "extract_range", {"offset": row["file_offset"], "length": row["size"]})
    assert _derived(gw, x.meta["derived"]) == b"PAYLOAD!"


def test_pe_resources_survives_a_loop_and_non_pe(gw):
    data = build_pe_with_resources(loop=True)
    tree = parse_resources(data, parse_pe(data))
    assert tree["resources"] == [] and any("loop" in w for w in tree["warnings"])
    gw.store_sample(JOB, b"no pe here")
    assert not gw.call(JOB, "pe_resources", {}).ok


@pytest.mark.parametrize("seed", range(30))
def test_pe_resources_fuzz_never_raises(seed):
    rnd = random.Random(seed)
    data = bytearray(build_pe_with_resources())
    for _ in range(rnd.randint(1, 60)):
        data[rnd.randrange(0x98, len(data))] = rnd.randrange(256)
    info = parse_pe(bytes(data))
    if info.get("is_pe"):
        assert isinstance(parse_resources(bytes(data), info)["resources"], list)
