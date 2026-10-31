"""Defanging of IOCs for reports, plus redaction of executable payload blobs.

Everything here is pure string processing (standard library only).

Rules
-----
* ``http`` -> ``hxxp``, ``https`` -> ``hxxps``, ``ftp`` -> ``fxp`` (``ftps`` -> ``fxps``,
  ``sftp`` -> ``sfxp``); optionally ``://`` -> ``[://]``.
* Dots in domains, IPv4 addresses and URL hosts -> ``[.]``; ``@`` in e-mails -> ``[at]``.
* Idempotent: ``defang_text(defang_text(x)) == defang_text(x)``. Already defanged
  (or half defanged) forms are normalised, never double-escaped.
* Left untouched: file names (``file.txt``), versions (``v1.2.3``), abbreviations
  (``e.g.``), hashes, Windows/Unix/registry paths.  A bare domain is only recognised
  when its last label is a known TLD (:data:`DOMAIN_TLDS`); extension-like TLDs
  (``.py``, ``.sh``, ``.zip`` ...) are deliberately not in the list.
* IPv6 addresses are neither defanged nor reported (colons are not clickable).
"""
from __future__ import annotations

import hashlib
import re

__all__ = [
    "DOMAIN_TLDS",
    "defang_text",
    "defang_ioc",
    "is_defanged",
    "find_iocs",
    "redact_payloads",
]

# Last labels that make a dotted word a domain.  Ambiguous with file extensions or
# common English words on purpose left out: py sh pl rs md so zip mov ps cc pm ai
# is it in at to no am as be by do go my on or we he hi id.
DOMAIN_TLDS: frozenset[str] = frozenset("""
com net org edu gov mil int info biz name pro xyz top site online store shop app dev
cloud tech club live icu vip work click link page space fun website zone today news
world life network systems digital solutions center agency press email host download
xxx tv fm io co me ly us ca eu ru su cn de uk fr nl jp kr br ir pk ua cz ch se fi dk
es au nz za mx ar cl tr il sa ae vn th sg hk tw ph gr pt ie hu ro bg sk si hr lt lv ee
kz ge li lu bz gg im je cx gl mn tk ml ga cf gq pw ws onion i2p local lan internal corp
home
""".split())

_TLD_ALT = "|".join(sorted(DOMAIN_TLDS, key=lambda t: (-len(t), t)))

_SEP = r"(?:\[\.\]|\.)"
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DOMAIN_CORE = (rf"(?:{_LABEL}{_SEP})+(?:{_TLD_ALT})(?![\w-])(?!{_SEP}[A-Za-z0-9])")
_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_SCHEMES = r"(?:https?|ftps?|sftp|hxxps?|fxps?|sfxp)"

_IOC_RE = re.compile(
    rf"(?P<url>(?<![\w])(?P<scheme>{_SCHEMES})(?P<sep>://|\[://\]|\[:\]//|:\[//\])"
    rf"(?P<rest>[^\s<>\"'`]+))"
    rf"|(?P<email>(?<![\w.%+-])(?P<local>[A-Za-z0-9][A-Za-z0-9._%+-]*)"
    rf"(?P<at>@|\[at\]|\(at\))(?P<edom>{_DOMAIN_CORE}))"
    rf"|(?P<ip>(?<![\w.])(?:{_OCT}{_SEP}){{3}}{_OCT}(?!\w)(?!{_SEP}[A-Za-z0-9]))"
    rf"|(?P<domain>(?<![\w@./\\-]){_DOMAIN_CORE})",
    re.IGNORECASE,
)

_HASH_RE = re.compile(
    r"(?<![0-9A-Za-z])(?:[0-9a-fA-F]{128}|[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})"
    r"(?![0-9A-Za-z])"
)

_SCHEME_MAP = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps", "sftp": "sfxp"}
_TRAIL = ".,;:!?'\""


def _dots(s: str) -> str:
    """Normalise to ``[.]`` (idempotent)."""
    return s.replace("[.]", ".").replace(".", "[.]")


def _trim_tail(s: str) -> tuple[str, str]:
    """Split trailing sentence punctuation / unbalanced brackets off a URL."""
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
    return s[:end], s[end:]


_IPV6_LITERAL = re.compile(r"\[[0-9A-Fa-f:.]+\]")


def _defang_rest(rest: str) -> str:
    """Defang ``authority/path`` of a URL: only the host gets its dots escaped."""
    m = re.match(r"([^/?#]*)(.*)", rest, re.DOTALL)
    authority, tail = m.group(1), m.group(2)
    prefix = ""
    if "@" in authority:
        userinfo, authority = authority.rsplit("@", 1)
        prefix = userinfo + "@"
    pm = re.match(r"(.*?)(:\d+)?$", authority, re.DOTALL)
    host, port = pm.group(1), pm.group(2) or ""
    if not _IPV6_LITERAL.fullmatch(host):
        host = _dots(host)
    return prefix + host + port + tail


def _defang_url(scheme: str, sep: str, rest: str, bracket_scheme: bool) -> str:
    core, tail = _trim_tail(rest)
    new_scheme = _SCHEME_MAP.get(scheme.lower(), scheme)
    if bracket_scheme:
        sep = "[://]"
    return new_scheme + sep + _defang_rest(core) + tail


def defang_text(text: str, *, bracket_scheme: bool = False, redact: bool = False) -> str:
    """Defang every URL, domain, IPv4 address and e-mail address in ``text``.

    ``bracket_scheme=True`` additionally writes ``[://]`` instead of ``://``.
    ``redact=True`` also applies :func:`redact_payloads` first.
    """
    if redact:
        text = redact_payloads(text)

    def repl(m: re.Match) -> str:
        if m.group("url"):
            return _defang_url(m.group("scheme"), m.group("sep"), m.group("rest"), bracket_scheme)
        if m.group("email"):
            return m.group("local") + "[at]" + _dots(m.group("edom"))
        return _dots(m.group(0))

    return _IOC_RE.sub(repl, text)


def defang_ioc(value: str, kind: str | None = None) -> str:
    """Defang a single IOC value.

    ``kind`` (``url|domain|ip|email|hash|...``) forces the treatment; without it the value is
    treated like running text.  Non-network kinds (hash, file, path, registry, ...) and IPv6
    addresses are returned unchanged.
    """
    k = (kind or "").strip().lower()
    if not k:
        return defang_text(value)
    if k == "url":
        stripped = value.strip()
        m = re.fullmatch(rf"({_SCHEMES})(://|\[://\]|\[:\]//|:\[//\])(.*)", stripped,
                         re.IGNORECASE | re.DOTALL)
        if m:
            return _defang_url(m.group(1), m.group(2), m.group(3), False)
        return _defang_rest(stripped)
    if k in ("domain", "hostname", "host", "fqdn", "ip", "ipv4", "ip_address", "ip-address"):
        return _dots(value)
    if k in ("email", "e-mail", "mail"):
        local, at, domain = re.split(r"(@|\[at\]|\(at\))", value, maxsplit=1) \
            if re.search(r"@|\[at\]|\(at\)", value) else (value, "", "")
        if not at:
            return value
        return local + "[at]" + _dots(domain)
    return value


def is_defanged(text: str) -> bool:
    """True if no live (clickable/resolvable) URL, domain, IPv4 or e-mail remains."""
    return defang_text(text) == text


def find_iocs(text: str) -> list[dict[str, str]]:
    """Find IOCs (live or defanged form). Kinds: url, domain, ip, email, hash.

    Domains inside URLs/e-mails are not reported twice.  Result is in text order and
    de-duplicated; ``value`` is exactly as written in the text (URL: trailing punctuation removed).
    """
    found: list[tuple[int, str, str]] = []
    for m in _IOC_RE.finditer(text):
        if m.group("url"):
            kind = "url"
            value = m.group("scheme") + m.group("sep") + _trim_tail(m.group("rest"))[0]
        elif m.group("email"):
            kind, value = "email", m.group("email")
        elif m.group("ip"):
            kind, value = "ip", m.group("ip")
        else:
            kind, value = "domain", m.group("domain")
        found.append((m.start(), kind, value))
    for m in _HASH_RE.finditer(text):
        found.append((m.start(), "hash", m.group(0)))
    found.sort(key=lambda t: t[0])
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for _, kind, value in found:
        key = (kind, value)
        if key not in seen:
            seen.add(key)
            out.append({"kind": kind, "value": value})
    return out


# --- payload redaction -----------------------------------------------------------------

_HEX_BLOB = re.compile(r"(?<![0-9A-Za-z])(?:0x)?[0-9a-fA-F]{128,}(?![0-9A-Za-z])")
_B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{200,}={0,2}(?![A-Za-z0-9+/=_-])")


def _redaction(blob: str) -> str:
    digest = hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()
    return f"[PAYLOAD-REDACTED sha256={digest} len={len(blob)}]"


def _looks_like_base64(blob: str) -> bool:
    classes = sum([any(c.islower() for c in blob), any(c.isupper() for c in blob),
                   any(c.isdigit() for c in blob), any(c in "+/" for c in blob)])
    return classes >= 2


def redact_payloads(text: str) -> str:
    """Replace long Base64 (>= 200 chars) and hex (>= 128 chars) blobs by a marker.

    Marker: ``[PAYLOAD-REDACTED sha256=<hash of the blob> len=<chars>]``.  Idempotent.
    Note: a bare 128-char hex string (SHA-512) is also redacted, as specified.
    """
    text = _HEX_BLOB.sub(lambda m: _redaction(m.group(0)), text)
    return _B64_BLOB.sub(
        lambda m: _redaction(m.group(0)) if _looks_like_base64(m.group(0)) else m.group(0), text)
