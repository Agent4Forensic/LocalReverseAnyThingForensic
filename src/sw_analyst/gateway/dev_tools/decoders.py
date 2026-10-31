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


SIMPLE = {
    "base64": d_base64, "hex": d_hex, "url": d_url, "rot13": d_rot13,
    "gzip": d_gzip, "zlib": d_zlib,
}
