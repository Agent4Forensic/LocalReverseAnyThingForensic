"""Placeholder protection for the translation pipeline.

``protect`` replaces everything that must never be translated (code, IDs, hashes, URLs,
paths, ...) with placeholders of the form ``<<P0>>``, ``<<P1>>``, ...; ``restore`` puts the
originals back and verifies that the model kept every placeholder exactly once.

Categories, in priority order (a character belongs to at most one match):

1. ``literal``   - text that would collide with the machinery: existing ``<<Pn>>`` and ``<text>`` tags
2. ``code``      - fenced code blocks and backtick spans
3. ``flag``      - ``WORD{...}`` flags (before the rest, because a flag may contain URLs etc.)
4. ``id``        - EV-/F-/T-/J- identifiers
5. ``hash``      - 32+ hex digits (MD5/SHA-1/SHA-256/...)
6. ``url``       - URLs incl. defanged ones (hxxp://, [.], [://])
7. ``ip``        - IPv4 (incl. ``[.]``, port, CIDR) and IPv6
8. ``email``     - before domains, otherwise the domain would eat the address
9. ``registry``  - HKLM\\... paths
10. ``winpath``  - drive, UNC and %ENV% paths
11. ``unixpath`` - /etc/passwd, ~/x, ./x
12. ``domain``   - dotted names with a known TLD (also ``evil[.]com``)
13. ``file``     - file names with a known extension
14. ``func``     - ``Name()`` / ``Class::Name()``
15. ``hexbytes`` - ``4D 5A 90 00`` byte runs
16. ``number``   - ``0x401000`` and numbers with units (``12 KB``, ``50%``, ``3.5ms``)
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Callable

from sw_analyst.report.defang import DOMAIN_TLDS

__all__ = ["protect", "restore", "PLACEHOLDER_RE", "CATEGORIES"]

PLACEHOLDER_RE = re.compile(r"<<P(\d+)>>")

_TRAIL = ".,;:!?'\""


def _trim(s: str) -> int:
    """Length of ``s`` without trailing sentence punctuation / unbalanced closers."""
    end = len(s)
    while end > 0:
        ch = s[end - 1]
        core = s[:end]
        if ch in _TRAIL:
            end -= 1
        elif ch == ")" and core.count("(") < core.count(")"):
            end -= 1
        elif ch == "]" and core.count("[") < core.count("]"):
            end -= 1
        else:
            break
    return end


def _valid_ipv6(s: str) -> bool:
    import ipaddress
    if len(s) < 3:
        return False
    try:
        ipaddress.IPv6Address(s)
    except ValueError:
        return False
    return True


_SEP = r"(?:\[\.\]|\.)"
_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_TLD_ALT = "|".join(sorted(DOMAIN_TLDS, key=lambda t: (-len(t), t)))
_PSEG = r"[\w.@+~%=,$#-]+"
# One path segment of a Windows/registry path. Spaces are only allowed inside segments made of
# capitalised words ("Program Files", "Windows NT", "Documents and Settings"), so that running
# text after a path is not swallowed.
_WCH = r"[\w.$@#+(){}~%&-]"
_WSEG = (rf"(?:{_WCH}+|[A-Z0-9]{_WCH}*(?: (?:and |of )?[A-Z0-9]{_WCH}*)+)")

_FILE_EXTS = """
exe dll sys drv bat cmd ps1 psm1 vbs vbe js jse wsf hta lnk scr msi msp jar class apk dex ko elf bin dat
tmp log txt ini cfg conf json xml yaml yml csv db sqlite sqlite3 zip rar 7z gz tgz tar bz2 xz cab iso img
pdf doc docx docm xls xlsx xlsm ppt pptx pptm rtf py pyc pyd rb sh php asp aspx jsp html htm css cpp hpp cs
java go rs lua pl md key pem crt cer pfx reg sct inf pif cpl ocx tlb pdb map asm lst idb i64 gdb bndb out
obj lib sln vcxproj ps2 xsl xslt wasm so dylib plist bak old pcap pcapng evtx etl dmp mem raw vmem
""".split()
_EXT_ALT = "|".join(sorted(set(_FILE_EXTS), key=lambda t: (-len(t), t)))

_UNITS_SPACED = (r"(?:KiB|MiB|GiB|TiB|KB|MB|GB|TB|kB|kb|Mb|Gb|Bytes?|bytes?|bits?|ms|µs|us|ns|sec|secs|min|"
                 r"mins|kHz|MHz|GHz|Hz|px|dpi|fps|rpm)")
_UNITS_TIGHT = r"(?:s|h|B|b|d|m|k|K|M|G)"


def _spans(rx: re.Pattern, text: str, trim: bool = False) -> list[tuple[int, int]]:
    out = []
    for m in rx.finditer(text):
        s, e = m.start(), m.end()
        if trim:
            e = s + _trim(m.group(0))
        if e > s:
            out.append((s, e))
    return out


def _ipv6_spans(text: str) -> list[tuple[int, int]]:
    rx = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:])")
    return [(m.start(), m.end()) for m in rx.finditer(text) if _valid_ipv6(m.group(0))]


_RX = {
    "literal": re.compile(r"<<P\d+>>|</?text\s*>", re.IGNORECASE),
    "code": re.compile(r"```.*?(?:```|\Z)|``[^`\n]+``|`[^`\n]+`", re.DOTALL),
    "flag": re.compile(r"(?<![\w])[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}\n]{1,200}\}"),
    "id": re.compile(r"(?<![\w-])(?:EV|F|T|J)-(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)*(?![\w-])"),
    "hash": re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{32,}(?![0-9A-Za-z])"),
    "url": re.compile(r"(?<![\w])(?:https?|ftps?|sftp|hxxps?|fxps?|sfxp)"
                      r"(?:://|\[://\]|\[:\]//|:\[//\])[^\s<>\"'`]+", re.IGNORECASE),
    "ipv4": re.compile(rf"(?<![\w.])(?:{_OCT}{_SEP}){{3}}{_OCT}(?!\w)(?!{_SEP}[A-Za-z0-9])"
                       r"(?::\d{1,5})?(?:/\d{1,2})?"),
    "email": re.compile(rf"(?<![\w.%+-])[A-Za-z0-9][A-Za-z0-9._%+-]*(?:@|\[at\]|\(at\))"
                        rf"(?:{_LABEL}{_SEP})+[A-Za-z]{{2,24}}(?![\w-])"),
    "registry": re.compile(r"(?<![\w])(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)"
                           rf"(?:\\{_WSEG}(?=\\))*(?:\\{_WCH}*)?"),
    "winpath": re.compile(rf"(?<![\w/\\])(?:[A-Za-z]:[\\/](?:{_WSEG}[\\/])*[^\\/:*?\"<>|\s`]*"
                          r"|\\\\[\w.$-]+(?:\\[^\\/:*?\"<>|\s`]+)+"
                          r"|%[A-Za-z_][A-Za-z0-9_]*%(?:[\\/][^\\/:*?\"<>|\s`]*)*)"),
    "unixpath": re.compile(rf"(?<![\w/.:~\\-])(?:(?:~|\.\.?)(?:/{_PSEG})+/?|(?:/{_PSEG}){{2,}}/?"
                           r"|/(?:etc|tmp|bin|usr|var|dev|proc|sys|opt|home|root|lib|lib64|sbin|mnt|boot|srv)(?![\w/]))"),
    "domain": re.compile(rf"(?<![\w@./\\-])(?:{_LABEL}{_SEP})+(?:{_TLD_ALT})(?![\w-])(?!{_SEP}[A-Za-z0-9])",
                         re.IGNORECASE),
    "file": re.compile(rf"(?<![\w.\\/-])\w[\w.-]*\.(?:{_EXT_ALT})(?![\w-])", re.IGNORECASE),
    "func": re.compile(r"(?<![\w])[A-Za-z_][A-Za-z0-9_]*(?:(?:::|\.|->)[A-Za-z_][A-Za-z0-9_]*)*\(\)"),
    "hexbytes": re.compile(r"(?<![\w])(?:[0-9A-F]{2} ){3,}[0-9A-F]{2}(?![\w])"),
    "hexnum": re.compile(r"(?<![\w])0[xX][0-9A-Fa-f]+(?![\w])"),
    "number": re.compile(rf"(?<![\w.])\d+(?:[.,]\d+)*(?:\s?{_UNITS_SPACED}|{_UNITS_TIGHT}|\s?%)(?![\w])"),
}

# (category, span finder) in priority order
_FINDERS: list[tuple[str, Callable[[str], list[tuple[int, int]]]]] = [
    ("literal", lambda t: _spans(_RX["literal"], t)),
    ("code", lambda t: _spans(_RX["code"], t)),
    ("flag", lambda t: _spans(_RX["flag"], t)),
    ("id", lambda t: _spans(_RX["id"], t)),
    ("hash", lambda t: _spans(_RX["hash"], t)),
    ("url", lambda t: _spans(_RX["url"], t, trim=True)),
    ("ip", lambda t: _spans(_RX["ipv4"], t) + _ipv6_spans(t)),
    ("email", lambda t: _spans(_RX["email"], t)),
    ("registry", lambda t: _spans(_RX["registry"], t, trim=True)),
    ("winpath", lambda t: _spans(_RX["winpath"], t, trim=True)),
    ("unixpath", lambda t: _spans(_RX["unixpath"], t, trim=True)),
    ("domain", lambda t: _spans(_RX["domain"], t)),
    ("file", lambda t: _spans(_RX["file"], t)),
    ("func", lambda t: _spans(_RX["func"], t)),
    ("hexbytes", lambda t: _spans(_RX["hexbytes"], t)),
    ("number", lambda t: _spans(_RX["hexnum"], t) + _spans(_RX["number"], t)),
]

CATEGORIES: tuple[str, ...] = tuple(name for name, _ in _FINDERS)


def protect(text: str) -> tuple[str, dict[str, str]]:
    """Mask protected spans. Returns ``(masked_text, {placeholder: original})``.

    Every occurrence gets its own placeholder (``<<P0>>``, ``<<P1>>``, ... in order of appearance),
    so that "each placeholder exactly once" is a valid check after translation.
    """
    taken = bytearray(len(text))
    chosen: list[tuple[int, int]] = []
    for _, finder in _FINDERS:
        for s, e in sorted(finder(text)):
            if e <= s or any(taken[s:e]):
                continue
            taken[s:e] = b"\x01" * (e - s)
            chosen.append((s, e))
    chosen.sort()
    mapping: dict[str, str] = {}
    parts: list[str] = []
    pos = 0
    for i, (s, e) in enumerate(chosen):
        key = f"<<P{i}>>"
        mapping[key] = text[s:e]
        parts.append(text[pos:s])
        parts.append(key)
        pos = e
    parts.append(text[pos:])
    return "".join(parts), mapping


def restore(masked: str, mapping: dict[str, str]) -> tuple[str, bool, list[str]]:
    """Put the originals back. Returns ``(text, ok, problems)``.

    ``ok`` is False if a placeholder is missing, occurs more than once, or an unknown one
    appeared. The text is still restored on a best-effort basis (unknown ones stay as they are).
    """
    counts = Counter(m.group(0) for m in PLACEHOLDER_RE.finditer(masked))
    problems: list[str] = []
    for key in mapping:
        c = counts.get(key, 0)
        if c == 0:
            problems.append(f"missing placeholder {key}")
        elif c > 1:
            problems.append(f"duplicated placeholder {key} ({c}x)")
    for key in counts:
        if key not in mapping:
            problems.append(f"unknown placeholder {key}")
    text = PLACEHOLDER_RE.sub(lambda m: mapping.get(m.group(0), m.group(0)), masked)
    return text, not problems, problems
