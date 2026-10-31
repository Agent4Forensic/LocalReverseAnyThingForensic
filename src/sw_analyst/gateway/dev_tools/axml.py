"""Own parser for Android binary XML (AndroidManifest.xml). Only reads bytes, resolves nothing, never loads a resource.

Raises AxmlError for anything it cannot read; a fuzz test keeps that promise (ADR-0006).
"""
from __future__ import annotations

import html
import struct

MAGIC = b"\x03\x00\x08\x00"
MAX_INPUT = 8 * 1024 * 1024
MAX_STRINGS = 200_000
MAX_ELEMENTS = 20_000
MAX_ATTRS = 256
MAX_DEPTH = 64
MAX_STRING_CHARS = 4096

_POOL, _XML, _RES_MAP = 0x0001, 0x0003, 0x0180
_START_NS, _END_NS, _START_EL, _END_EL, _CDATA = 0x0100, 0x0101, 0x0102, 0x0103, 0x0104
_UTF8_FLAG = 1 << 8
ANDROID_NS = "http://schemas.android.com/apk/res/android"
# Stripped manifests keep only the resource id of an attribute.
_ATTR_BY_ID = {0x01010001: "label", 0x01010002: "icon", 0x01010003: "name", 0x01010006: "permission",
               0x01010010: "exported", 0x0101020C: "minSdkVersion", 0x0101021B: "versionCode",
               0x0101021C: "versionName", 0x01010270: "targetSdkVersion"}


class AxmlError(Exception):
    """The data is not readable binary XML; the message is safe to show to the model."""


def _u16(d: bytes, o: int) -> int:
    return struct.unpack_from("<H", d, o)[0]


def _u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


def _printable(s: str) -> str:
    return "".join(c if c.isprintable() or c in "\t\n" else "?" for c in s)[:MAX_STRING_CHARS]


def _length(d: bytes, o: int, utf8: bool) -> tuple[int, int]:
    """Length prefix of a pool string: (value, bytes used)."""
    if utf8:
        first = d[o]
        return ((first & 0x7F) << 8 | d[o + 1], 2) if first & 0x80 else (first, 1)
    first = _u16(d, o)
    return ((first & 0x7FFF) << 16 | _u16(d, o + 2), 4) if first & 0x8000 else (first, 2)


def _pool(d: bytes, start: int, size: int) -> list[str]:
    count, _styles, flags, strings_at = struct.unpack_from("<IIII", d, start + 8)
    if count > MAX_STRINGS or start + 28 + 4 * count > start + size:
        raise AxmlError("string pool is larger than its chunk")
    utf8 = bool(flags & _UTF8_FLAG)
    base, end = start + strings_at, start + size
    out = []
    for i in range(count):
        o = base + _u32(d, start + 28 + 4 * i)
        if not base <= o < end:
            out.append("")
            continue
        try:
            if utf8:
                _, n1 = _length(d, o, True)
                blen, n2 = _length(d, o + n1, True)
                raw = d[o + n1 + n2:min(o + n1 + n2 + blen, end)]
                out.append(_printable(raw.decode("utf-8", "replace")))
            else:
                clen, n1 = _length(d, o, False)
                raw = d[o + n1:min(o + n1 + 2 * clen, end)]
                out.append(_printable(raw.decode("utf-16le", "replace")))
        except (IndexError, struct.error):
            out.append("")
    return out


def _value(kind: int, data: int, raw: int, strings: list[str]) -> str:
    if raw != 0xFFFFFFFF and raw < len(strings):
        return strings[raw]
    if kind == 0x03:
        return strings[data] if data < len(strings) else ""
    if kind == 0x01:
        return f"@0x{data:08x}"
    if kind == 0x02:
        return f"?0x{data:08x}"
    if kind == 0x10:
        return str(data - (1 << 32) if data >= 1 << 31 else data)
    if kind == 0x12:
        return "true" if data else "false"
    return f"0x{data:x}"


def parse_axml(d: bytes) -> dict:
    """Returns {xml, package, permissions, components, elements}. Raises only AxmlError."""
    try:
        return _parse(d)
    except AxmlError:
        raise
    except (struct.error, IndexError, ValueError, OverflowError) as exc:
        raise AxmlError(f"corrupt binary XML ({type(exc).__name__})") from None


def _parse(d: bytes) -> dict:
    if len(d) > MAX_INPUT:
        raise AxmlError(f"binary XML exceeds the {MAX_INPUT // (1024 * 1024)} MiB limit")
    if len(d) < 8 or d[:2] != MAGIC[:2]:
        raise AxmlError("not binary XML (missing 03 00 magic)")
    strings: list[str] = []
    res_ids: list[int] = []
    namespaces: dict[int, str] = {}
    lines: list[str] = []
    res = {"package": None, "permissions": [], "components": [], "elements": 0}
    depth = 0
    pos = _u16(d, 2)                 # first chunk after the file header
    end = min(_u32(d, 4), len(d))
    while pos + 8 <= end:
        ctype, header, size = _u16(d, pos), _u16(d, pos + 2), _u32(d, pos + 4)
        if size < 8 or header < 8 or pos + size > end:
            raise AxmlError(f"invalid chunk size at offset 0x{pos:x}")
        if ctype == _POOL:
            strings = _pool(d, pos, size)
        elif ctype == _RES_MAP:
            res_ids = [_u32(d, pos + 8 + 4 * i) for i in range(min((size - 8) // 4, MAX_STRINGS))]
        elif ctype == _START_NS:
            prefix, uri = _u32(d, pos + 16), _u32(d, pos + 20)
            if uri < len(strings) and prefix < len(strings):
                namespaces[uri] = strings[prefix]
        elif ctype == _START_EL:
            res["elements"] += 1
            if res["elements"] > MAX_ELEMENTS:
                raise AxmlError(f"more than {MAX_ELEMENTS} elements")
            if depth >= MAX_DEPTH:
                raise AxmlError(f"elements nested deeper than {MAX_DEPTH}")
            lines.append(_start_element(d, pos + header, pos + size, strings, res_ids, namespaces, depth, res))
            depth += 1
        elif ctype == _END_EL:
            depth = max(0, depth - 1)
            name = _u32(d, pos + 20)
            lines.append("  " * depth + f"</{html.escape(strings[name]) if name < len(strings) else '?'}>")
        pos += size
    if not lines:
        raise AxmlError("no XML elements found")
    res["xml"] = "\n".join(lines)
    return res


def _start_element(d, body, limit, strings, res_ids, namespaces, depth, res) -> str:
    name_i, attr_start, attr_size, attr_count = _u32(d, body + 4), _u16(d, body + 8), _u16(d, body + 10), _u16(d, body + 12)
    name = strings[name_i] if name_i < len(strings) else "?"
    if attr_count > MAX_ATTRS or attr_size < 20:
        attr_count = min(attr_count, MAX_ATTRS) if attr_size >= 20 else 0
    attrs: list[tuple[str, str]] = []
    for i in range(attr_count):
        o = body + attr_start + i * attr_size
        if o + 20 > limit:
            raise AxmlError("attribute lies outside its chunk")
        ns_i, an_i, raw = _u32(d, o), _u32(d, o + 4), _u32(d, o + 8)
        kind, data = d[o + 15], _u32(d, o + 16)
        aname = strings[an_i] if an_i < len(strings) else ""
        if an_i < len(res_ids) and res_ids[an_i] in _ATTR_BY_ID:
            aname = _ATTR_BY_ID[res_ids[an_i]]     # the id is authoritative: a stripped pool may lie
        prefix = namespaces.get(ns_i, "")
        attrs.append((f"{prefix}:{aname}" if prefix else aname or "?", _value(kind, data, raw, strings)))
    amap = dict(attrs)
    if name == "manifest" and res["package"] is None:
        res["package"] = amap.get("package")
    aname = amap.get("android:name") or amap.get("name") or ""
    if name in ("uses-permission", "uses-permission-sdk-23", "permission"):
        res["permissions"].append(aname)
    elif name in ("activity", "activity-alias", "service", "receiver", "provider"):
        exported = amap.get("android:exported") or amap.get("exported")
        res["components"].append({"kind": name, "name": aname, "exported": exported})
    body_attrs = "".join(f' {html.escape(k)}="{html.escape(v, quote=True)}"' for k, v in attrs)
    return "  " * depth + f"<{html.escape(name)}{body_attrs}>"
