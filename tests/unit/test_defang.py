import hashlib
import re

import pytest

from sw_analyst.report.defang import (
    defang_ioc, defang_text, find_iocs, is_defanged, redact_payloads,
)


@pytest.mark.parametrize("src,expected", [
    ("evil.example.com", "evil[.]example[.]com"),
    ("10.0.0.5", "10[.]0[.]0[.]5"),
    ("http://x.y/z", "hxxp://x[.]y/z"),
    ("https://evil.com/a/b.php?q=1.2", "hxxps://evil[.]com/a/b.php?q=1.2"),
    ("ftp://files.evil.org/pub", "fxp://files[.]evil[.]org/pub"),
    ("http://1.2.3.4:8080/x", "hxxp://1[.]2[.]3[.]4:8080/x"),
    ("bob@evil.com", "bob[at]evil[.]com"),
    ("john.doe@mail.evil.co", "john.doe[at]mail[.]evil[.]co"),
    ("Contact: bob@evil.com.", "Contact: bob[at]evil[.]com."),
    ("See (http://evil.com/x).", "See (hxxp://evil[.]com/x)."),
    ("Connects to evil.example.com on 10.0.0.5, then https://c2.bad.ru/a.",
     "Connects to evil[.]example[.]com on 10[.]0[.]0[.]5, then hxxps://c2[.]bad[.]ru/a."),
])
def test_defang_positive(src, expected):
    assert defang_text(src) == expected


@pytest.mark.parametrize("src", [
    "e.g. this", "i.e. that", "v1.2.3", "version 2.0.1", "file.txt", "setup.py", "cmd.exe",
    "kernel32.dll", "malware.exe dropped payload.bin", "3.14159", "1.2.3.4.5",
    r"C:\Windows\System32\evil.com", "/var/www/evil.com/index.php", r"HKLM\Software\x.example.com",
    "d41d8cd98f00b204e9800998ecf8427e",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "Dr. Smith went home.", "see Fig. 3.", "libssl.so.1.1", "Foo::bar() calls baz()",
    "user@localhost", "image@2x.png",
])
def test_defang_false_positives_untouched(src):
    assert defang_text(src) == src


def test_defang_idempotent():
    text = ("Visit http://evil.com/a, https://x.y/z?q=a.b, ftp://1.2.3.4/f and mail bob@evil.com; "
            "host evil.example.com, ip 10.0.0.5. Also hxxp://already[.]done/x and a[.]b[.]com.")
    once = defang_text(text)
    assert defang_text(once) == once
    assert defang_text(defang_text(once)) == once
    assert "http://" not in once and "evil.com" not in once and "10.0.0.5" not in once
    assert is_defanged(once)
    assert not is_defanged(text)


def test_defang_half_defanged_is_normalised():
    assert defang_text("hxxp://x[.]y.com/p") == "hxxp://x[.]y[.]com/p"
    assert defang_text("hxxp://x[.]y[.]com/p") == "hxxp://x[.]y[.]com/p"


def test_bracket_scheme_option_idempotent():
    out = defang_text("http://evil.com/x", bracket_scheme=True)
    assert out == "hxxp[://]evil[.]com/x"
    assert defang_text(out, bracket_scheme=True) == out
    assert defang_text(out) == out


def test_path_part_of_url_keeps_dots():
    assert defang_text("http://a.com/p/file.name.php") == "hxxp://a[.]com/p/file.name.php"


def test_defang_ioc_with_kind():
    assert defang_ioc("http://evil.com/x") == "hxxp://evil[.]com/x"
    assert defang_ioc("evil.example.com", "domain") == "evil[.]example[.]com"
    assert defang_ioc("evil[.]example.com", "domain") == "evil[.]example[.]com"
    assert defang_ioc("10.0.0.5", "ip") == "10[.]0[.]0[.]5"
    assert defang_ioc("bob@evil.com", "email") == "bob[at]evil[.]com"
    assert defang_ioc("bob[at]evil[.]com", "email") == "bob[at]evil[.]com"
    assert defang_ioc("https://a.b/c", "url") == "hxxps://a[.]b/c"
    assert defang_ioc("a.b/c", "url") == "a[.]b/c"
    h = "d41d8cd98f00b204e9800998ecf8427e"
    assert defang_ioc(h, "hash") == h
    assert defang_ioc("C:\\x\\a.exe", "path") == "C:\\x\\a.exe"
    assert defang_ioc("evil.com") == "evil[.]com"
    assert defang_ioc("nofile.txt") == "nofile.txt"
    for v, k in [("http://evil.com", "url"), ("evil.com", "domain"), ("1.2.3.4", "ip"), ("a@b.com", "email")]:
        once = defang_ioc(v, k)
        assert defang_ioc(once, k) == once


def test_find_iocs():
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    text = (f"Beacon to http://evil.com/a.php, resolves evil.example.com -> 10.0.0.5. "
            f"Mail bob@evil.com. Also hxxps://c2[.]bad[.]ru/x and 8[.]8[.]8[.]8. {sha} {md5} "
            "Not an IOC: file.txt, v1.2.3, e.g.")
    iocs = find_iocs(text)
    got = {(i["kind"], i["value"]) for i in iocs}
    assert ("url", "http://evil.com/a.php") in got
    assert ("domain", "evil.example.com") in got
    assert ("ip", "10.0.0.5") in got
    assert ("email", "bob@evil.com") in got
    assert ("url", "hxxps://c2[.]bad[.]ru/x") in got
    assert ("ip", "8[.]8[.]8[.]8") in got
    assert ("hash", sha) in got and ("hash", md5) in got
    # no domain reported twice from inside the URL / mail
    assert ("domain", "evil.com") not in got
    assert not any(v in ("file.txt", "v1.2.3") for _, v in got)
    assert all(set(i) == {"kind", "value"} for i in iocs)
    assert len(iocs) == len(got)


def test_redact_base64_and_hex():
    b64 = "TVqQAAMAAAAEAAAA" * 20            # 320 chars, valid base64 alphabet, mixed case/digits
    hexb = "4d5a9000" * 40                    # 320 hex chars
    text = f"blob: {b64} and hex {hexb} end"
    out = redact_payloads(text)
    assert b64 not in out and hexb not in out
    assert f"[PAYLOAD-REDACTED sha256={hashlib.sha256(b64.encode()).hexdigest()} len={len(b64)}]" in out
    assert f"[PAYLOAD-REDACTED sha256={hashlib.sha256(hexb.encode()).hexdigest()} len={len(hexb)}]" in out
    assert out.startswith("blob: ") and out.endswith(" end")
    assert redact_payloads(out) == out        # idempotent


def test_redact_thresholds():
    assert redact_payloads("G1" * 99) == "G1" * 99                 # 198 chars < 200
    assert redact_payloads("g1" * 100) != "g1" * 100               # 200 chars
    short_hex = "ab" * 63                                          # 126 < 128
    assert redact_payloads(short_hex) == short_hex
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert redact_payloads(sha256) == sha256                       # hashes stay
    assert redact_payloads("x" * 300) == "x" * 300                 # plain word, not base64
    assert re.fullmatch(r"\[PAYLOAD-REDACTED sha256=[0-9a-f]{64} len=128\]", redact_payloads("ab" * 64))


def test_defang_text_redact_option():
    blob = "Zm9vYmFy0123" * 30
    out = defang_text(f"see http://evil.com {blob}", redact=True)
    assert "hxxp://evil[.]com" in out and "PAYLOAD-REDACTED" in out and blob not in out
