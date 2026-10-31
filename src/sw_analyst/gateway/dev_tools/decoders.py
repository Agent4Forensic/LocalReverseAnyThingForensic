"""Pure data decoders for decode_layer. They only transform bytes; nothing is ever executed."""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
import zlib

from .util import alnum_space_ratio, looks_utf16le, printable_ratio

MAX_OUT = 8 * 1024 * 1024
XOR_SCORE_WINDOW = 65536

_B64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_B64_URL = b"-_"
_HEX_ALPHABET = b"0123456789abcdefABCDEF"
_ROT13 = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


class DecodeError(Exception):
    """Decoding failed; message is safe to show to the model."""


def _text_bytes(data: bytes) -> bytes:
    """Text decoders also accept UTF-16LE text (common for PowerShell files)."""
    if data.startswith(b"\xff\xfe") or looks_utf16le(data):
        body = data[2:] if data.startswith(b"\xff\xfe") else data
        return body.decode("utf-16le", errors="replace").encode("ascii", errors="replace")
    return data


def d_base64(data: bytes) -> bytes:
    s = b"".join(_text_bytes(data).split()).strip(b"\"'")
    if not s:
        raise DecodeError("input is empty")
    if b"+" not in s and b"/" not in s:
        s = s.replace(b"-", b"+").replace(b"_", b"/")
    bad = s.translate(None, _B64_ALPHABET)
    if bad:
        raise DecodeError(f"input contains characters outside the base64 alphabet (e.g. 0x{bad[0]:02x})")
    s = s.rstrip(b"=")
    if len(s) % 4 == 1:
        raise DecodeError("invalid base64 length")
    try:
        return base64.b64decode(s + b"=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(f"invalid base64: {exc}") from None


def d_hex(data: bytes) -> bytes:
    s = _text_bytes(data)
    s = re.sub(rb"(?i)0x|\\x|[\s,:;]", b"", s)
    if not s:
        raise DecodeError("input is empty")
    if s.translate(None, _HEX_ALPHABET):
        raise DecodeError("input contains non-hex characters")
    if len(s) % 2:
        raise DecodeError("odd number of hex digits")
    return binascii.unhexlify(s)


def d_url(data: bytes) -> bytes:
    s = _text_bytes(data)
    if b"%" not in s:
        raise DecodeError("no percent-escapes found")
    return urllib.parse.unquote_to_bytes(s.decode("latin-1"))


def d_rot13(data: bytes) -> bytes:
    return _text_bytes(data).translate(_ROT13)


def _inflate(data: bytes, wbits: int) -> bytes:
    d = zlib.decompressobj(wbits)
    try:
        out = d.decompress(data, MAX_OUT + 1)
    except zlib.error as exc:
        raise DecodeError(f"not valid compressed data ({exc})") from None
    if len(out) > MAX_OUT:
        raise DecodeError(f"decompressed data exceeds the {MAX_OUT // (1024 * 1024)} MiB limit "
                          "(possible decompression bomb)")
    if not out:
        raise DecodeError("decompression produced no data")
    return out


def d_gzip(data: bytes) -> bytes:
    if data[:2] != b"\x1f\x8b":
        raise DecodeError("missing gzip magic 1f 8b")
    return _inflate(data, 31)


def d_zlib(data: bytes) -> bytes:
    try:
        return _inflate(data, 15)
    except DecodeError as first:
        if "bomb" in str(first):
            raise
        try:
            return _inflate(data, -15)  # raw deflate
        except DecodeError:
            raise first from None


def xor_with(data: bytes, key: int) -> bytes:
    return data.translate(bytes(i ^ key for i in range(256)))


def xor_rank(data: bytes, top: int = 5) -> list[tuple[int, float, float]]:
    """Rank single-byte XOR keys 1..255. Returns [(key, rank_score, printable_ratio)], best first."""
    window = data[:XOR_SCORE_WINDOW]
    rows = []
    for key in range(1, 256):
        out = xor_with(window, key)
        pr = printable_ratio(out)
        rows.append((key, 0.5 * pr + 0.5 * alnum_space_ratio(out), pr))
    rows.sort(key=lambda r: (-r[1], r[0]))
    return rows[:top]


def d_base32(data: bytes) -> bytes:
    s = b"".join(_text_bytes(data).split()).strip(b"\"'").upper().rstrip(b"=")
    if not s:
        raise DecodeError("input is empty")
    try:
        return base64.b32decode(s + b"=" * (-len(s) % 8))
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(f"invalid base32: {exc}") from None


def d_base85(data: bytes) -> bytes:
    """RFC 1924 base85, or Ascii85 when wrapped in <~ ~>."""
    s = b"".join(_text_bytes(data).split()).strip(b"\"'")
    if not s:
        raise DecodeError("input is empty")
    try:
        if s.startswith(b"<~") and s.endswith(b"~>"):
            return base64.a85decode(s, adobe=True)
        return base64.b85decode(s)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(f"invalid base85: {exc}") from None


_CHARCODE_SEP = re.compile(rb"[\s,;]+")
_CHARCODE_ITEM = re.compile(rb"(?i)(?:0x[0-9a-f]{1,6}|[0-9]{1,7})")


def d_charcode(data: bytes) -> bytes:
    """A list of character codes such as '72,101,0x6c' (fromCharCode, [char] arrays). Result is UTF-8."""
    items = [i for i in _CHARCODE_SEP.split(_text_bytes(data).strip(b" \t\r\n\"'()[]{}")) if i]
    if not items:
        raise DecodeError("input is empty")
    out = bytearray()
    for item in items:
        if not _CHARCODE_ITEM.fullmatch(item):
            raise DecodeError("input is not a list of decimal or 0x-hex character codes")
        code = int(item, 0) if item[:2].lower() == b"0x" else int(item)
        if code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
            raise DecodeError(f"character code {code} is out of range")
        out += chr(code).encode("utf-8")
    return bytes(out)


def parse_key_hex(key_hex: str) -> bytes:
    s = key_hex.strip().lower().removeprefix("0x")
    if not s or len(s) % 2 or not re.fullmatch(r"[0-9a-f]+", s):
        raise DecodeError("key_hex must be an even number of hex digits")
    key = bytes.fromhex(s)
    if len(key) > 64:
        raise DecodeError("key_hex is too long (max 64 bytes)")
    return key


def xor_key(data: bytes, key: bytes) -> bytes:
    if len(key) == 1:
        return xor_with(data, key[0])
    stream = (key * (len(data) // len(key) + 1))[:len(data)]
    return (int.from_bytes(data, "little") ^ int.from_bytes(stream, "little")).to_bytes(len(data), "little")


def rc4(data: bytes, key: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = b ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


SIMPLE = {
    "base64": d_base64, "hex": d_hex, "url": d_url, "rot13": d_rot13,
    "gzip": d_gzip, "zlib": d_zlib, "base32": d_base32, "base85": d_base85, "charcode": d_charcode,
}
KEYED = {"xor_key": xor_key, "rc4": rc4}
