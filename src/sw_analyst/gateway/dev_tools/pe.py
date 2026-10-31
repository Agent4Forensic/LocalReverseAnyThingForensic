"""Own struct-based PE parser. Static, tolerant against broken headers, never raises."""
from __future__ import annotations

import datetime as _dt
import struct
from typing import Any, Optional

from .util import shannon_entropy

MAX_IMPORT_FUNCS = 300
MAX_EXPORTS = 300
MAX_SECTIONS = 96
MAX_DESCRIPTORS = 512

MACHINES = {
    0x0: "UNKNOWN", 0x14C: "I386", 0x166: "MIPS R4000", 0x1C0: "ARM", 0x1C4: "ARMNT",
    0x200: "IA64", 0x5032: "RISCV32", 0x5064: "RISCV64", 0x8664: "AMD64", 0xAA64: "ARM64",
    0xEBC: "EBC",
}
SUBSYSTEMS = {
    0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 5: "OS2_CUI", 7: "POSIX_CUI",
    9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM", 14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION",
}
DIR_NAMES = [
    "export", "import", "resource", "exception", "security", "basereloc", "debug", "architecture",
    "globalptr", "tls", "load_config", "bound_import", "iat", "delay_import", "clr_runtime",
    "reserved",
]


class _Reader:
    def __init__(self, data: bytes):
        self.d = data

    def u16(self, off: int) -> int:
        return struct.unpack_from("<H", self.d, off)[0]

    def u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.d, off)[0]

    def u64(self, off: int) -> int:
        return struct.unpack_from("<Q", self.d, off)[0]

    def cstr(self, off: int, maxlen: int = 256) -> Optional[str]:
        if off < 0 or off >= len(self.d):
            return None
        chunk = self.d[off:off + maxlen]
        end = chunk.find(b"\x00")
        if end < 0:
            return None
        raw = chunk[:end]
        if not raw or any(b < 0x20 or b > 0x7E for b in raw):
            return None
        return raw.decode("ascii")


def _safe_name(raw: bytes) -> str:
    raw = raw.split(b"\x00", 1)[0]
    return "".join(chr(b) if 0x20 <= b < 0x7F else "?" for b in raw)


def _section_flags(ch: int) -> tuple[str, list[str]]:
    rwx = ("R" if ch & 0x40000000 else "-") + ("W" if ch & 0x80000000 else "-") + (
        "X" if ch & 0x20000000 else "-")
    names = []
    if ch & 0x20:
        names.append("CODE")
    if ch & 0x40:
        names.append("INIT_DATA")
    if ch & 0x80:
        names.append("UNINIT_DATA")
    if ch & 0x02000000:
        names.append("DISCARDABLE")
    return rwx, names


def parse_pe(data: bytes) -> dict[str, Any]:
    """Parse a PE image. Returns a dict; key 'is_pe' tells whether the core headers are valid."""
    info: dict[str, Any] = {"is_pe": False, "warnings": [], "error": ""}
    try:
        _parse_headers(data, info)
    except Exception as exc:  # noqa: BLE001 - parser must never raise
        info["is_pe"] = info.get("is_pe", False)
        info["error"] = info["error"] or f"header parsing failed ({type(exc).__name__})"
        return info
    if not info["is_pe"]:
        return info
    for step in (_parse_sections, _parse_imports, _parse_exports):
        try:
            step(data, info)
        except Exception as exc:  # noqa: BLE001
            info["warnings"].append(f"{step.__name__.lstrip('_')} aborted: {type(exc).__name__}")
    return info


def _parse_headers(data: bytes, info: dict) -> None:
    r = _Reader(data)
    if len(data) < 0x40 or data[:2] != b"MZ":
        info["error"] = "missing DOS signature 'MZ' at offset 0"
        return
    lfanew = r.u32(0x3C)
    info["e_lfanew"] = lfanew
    if lfanew < 4 or lfanew + 24 > len(data):
        info["error"] = f"e_lfanew 0x{lfanew:x} points outside the file"
        return
    if data[lfanew:lfanew + 4] != b"PE\x00\x00":
        info["error"] = f"no 'PE\\0\\0' signature at e_lfanew (0x{lfanew:x})"
        return
    info["is_pe"] = True
    c = lfanew + 4
    machine = r.u16(c)
    nsec = r.u16(c + 2)
    ts = r.u32(c + 4)
    optsize = r.u16(c + 16)
    chars = r.u16(c + 18)
    info.update(
        machine=machine, machine_name=MACHINES.get(machine, f"0x{machine:04x}"),
        number_of_sections=nsec, timestamp=ts, characteristics=chars,
        is_dll=bool(chars & 0x2000), is_exe=bool(chars & 0x2), size_of_optional_header=optsize,
        coff_offset=c,
    )
    try:
        info["timestamp_utc"] = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        info["timestamp_utc"] = "invalid"
    opt = c + 20
    info["optional_offset"] = opt
    info["section_table_offset"] = opt + optsize
    info["dirs"] = []
    info["dotnet"] = False
    if optsize < 2 or opt + 2 > len(data):
        info["warnings"].append("optional header missing or truncated")
        return
    magic = r.u16(opt)
    info["optional_magic"] = magic
    if magic not in (0x10B, 0x20B):
        info["warnings"].append(f"unknown optional header magic 0x{magic:x}")
        return
    plus = magic == 0x20B
    info["pe32plus"] = plus
    need = 112 if plus else 96
    if optsize < need or opt + need > len(data):
        info["warnings"].append("optional header truncated")
        return
    info["entry_rva"] = r.u32(opt + 16)
    info["image_base"] = r.u64(opt + 24) if plus else r.u32(opt + 28)
    info["section_alignment"] = r.u32(opt + 32)
    info["file_alignment"] = r.u32(opt + 36)
    info["size_of_image"] = r.u32(opt + 56)
    info["size_of_headers"] = r.u32(opt + 60)
    sub = r.u16(opt + 68)
    info["subsystem"] = sub
    info["subsystem_name"] = SUBSYSTEMS.get(sub, f"0x{sub:x}")
    info["dll_characteristics"] = r.u16(opt + 70)
    nrva = r.u32(opt + (108 if plus else 92))
    dir_off = opt + need
    dirs = []
    for i in range(min(nrva, 16)):
        o = dir_off + 8 * i
        if o + 8 > len(data) or 8 * (i + 1) + need > optsize:
            break
        dirs.append((r.u32(o), r.u32(o + 4)))
    info["dirs"] = dirs
    info["dotnet"] = len(dirs) > 14 and dirs[14][0] != 0


def _parse_sections(data: bytes, info: dict) -> None:
    r = _Reader(data)
    nsec = info["number_of_sections"]
    if nsec > MAX_SECTIONS:
        info["warnings"].append(f"section count {nsec} exceeds {MAX_SECTIONS}; only first {MAX_SECTIONS} parsed")
        nsec = MAX_SECTIONS
    off = info["section_table_offset"]
    sections = []
    for i in range(nsec):
        o = off + 40 * i
        if o + 40 > len(data):
            info["warnings"].append(f"section table truncated after {i} entries")
            break
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, o + 8)
        ch = r.u32(o + 36)
        raw = data[rptr:rptr + rsize] if rptr < len(data) else b""
        rwx, fnames = _section_flags(ch)
        sections.append({
            "index": i, "name": _safe_name(data[o:o + 8]), "virtual_size": vsize,
            "virtual_address": va, "raw_size": rsize, "raw_offset": rptr, "flags": ch,
            "rwx": rwx, "flag_names": fnames,
            "entropy": round(shannon_entropy(raw), 3) if raw else 0.0,
            "raw_truncated": rptr + rsize > len(data),
        })
    info["sections"] = sections
    ends = [s["raw_offset"] + s["raw_size"] for s in sections if s["raw_size"] > 0]
    info["overlay_offset"] = None
    info["overlay_size"] = 0
    if ends:
        end = max(ends)
        if end < len(data):
            info["overlay_offset"] = end
            info["overlay_size"] = len(data) - end
    for s in sections:
        if s["rwx"][1] == "W" and s["rwx"][2] == "X":
            info["warnings"].append(f"section {s['name']!r} is writable and executable")
        if s["raw_truncated"]:
            info["warnings"].append(f"section {s['name']!r} raw data extends beyond end of file")


def _rva_to_off(info: dict, rva: int, data_len: int) -> Optional[int]:
    soh = info.get("size_of_headers", 0)
    if rva < soh and rva < data_len:
        return rva
    for s in info.get("sections", []):
        span = max(s["virtual_size"], s["raw_size"])
        if s["virtual_address"] <= rva < s["virtual_address"] + span:
            delta = rva - s["virtual_address"]
            if delta >= s["raw_size"]:
                return None
            off = s["raw_offset"] + delta
            return off if off < data_len else None
    return None


RT_TYPES = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR", 8: "FONT",
            9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION",
            17: "DLGINCLUDE", 19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST"}
MAX_RESOURCES = 2000
MAX_RESOURCE_DEPTH = 8


def parse_resources(data: bytes, info: dict) -> dict[str, Any]:
    """Walk the resource tree of a parsed PE. Returns {resources, warnings}; never raises.

    The tree comes from the sample: offsets can loop or point anywhere, so visited directories, depth and count are bounded.
    """
    found: list[dict] = []
    warnings: list[str] = []
    dirs = info.get("dirs") or []
    root_rva = dirs[2][0] if len(dirs) > 2 else 0
    root = _rva_to_off(info, root_rva, len(data)) if root_rva else None
    if root is None:
        return {"resources": found, "warnings": warnings}
    r = _Reader(data)
    visited: set[int] = set()

    def name_of(entry_name: int, depth: int) -> str:
        if entry_name & 0x80000000:
            o = root + (entry_name & 0x7FFFFFFF)
            n = r.u16(o)
            return _safe_name(data[o + 2:o + 2 + 2 * min(n, 128)].decode("utf-16le", "replace").encode("ascii", "replace"))
        return RT_TYPES.get(entry_name, str(entry_name)) if depth == 0 else str(entry_name)

    def walk(offset: int, path: list[str], depth: int) -> None:
        if offset in visited or depth > MAX_RESOURCE_DEPTH:
            warnings.append(f"resource directory at 0x{offset:x} skipped (loop or too deep)")
            return
        visited.add(offset)
        count = r.u16(offset + 12) + r.u16(offset + 14)
        for i in range(count):
            if len(found) >= MAX_RESOURCES:
                warnings.append(f"listing limited to {MAX_RESOURCES} resources")
                return
            e = offset + 16 + 8 * i
            nm, target = r.u32(e), r.u32(e + 4)
            sub = path + [name_of(nm, depth)]
            if target & 0x80000000:
                walk(root + (target & 0x7FFFFFFF), sub, depth + 1)
                continue
            rva, size = r.u32(root + target), r.u32(root + target + 4)
            off = _rva_to_off(info, rva, len(data))
            raw = data[off:off + size] if off is not None else b""
            found.append({"path": "/".join(sub), "rva": rva, "file_offset": off, "size": size,
                          "entropy": round(shannon_entropy(raw), 3) if raw else 0.0,
                          "truncated": off is None or off + size > len(data), "head": raw[:4]})

    try:
        walk(root, [], 0)
    except (struct.error, IndexError, RecursionError) as exc:
        warnings.append(f"resource tree is corrupt ({type(exc).__name__}); listing is partial")
    return {"resources": found, "warnings": warnings}


def _parse_imports(data: bytes, info: dict) -> None:
    info["imports"] = []
    info["imports_truncated"] = False
    dirs = info.get("dirs", [])
    if len(dirs) < 2 or dirs[1][0] == 0:
        return
    r = _Reader(data)
    plus = info.get("pe32plus", False)
    tsize = 8 if plus else 4
    base = _rva_to_off(info, dirs[1][0], len(data))
    if base is None:
        info["warnings"].append("import directory RVA does not map into the file")
        return
    total = 0
    for i in range(MAX_DESCRIPTORS):
        o = base + 20 * i
        if o + 20 > len(data):
            info["warnings"].append("import directory truncated")
            break
        oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", data, o)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        name_off = _rva_to_off(info, name_rva, len(data))
        dll = r.cstr(name_off) if name_off is not None else None
        if dll is None:
            info["warnings"].append(f"import descriptor {i} has an invalid DLL name; stopped")
            break
        funcs: list[str] = []
        thunk_rva = oft or ft
        toff = _rva_to_off(info, thunk_rva, len(data)) if thunk_rva else None
        if toff is not None:
            for j in range(4096):
                p = toff + j * tsize
                if p + tsize > len(data):
                    break
                val = r.u64(p) if plus else r.u32(p)
                if val == 0:
                    break
                if total >= MAX_IMPORT_FUNCS:
                    info["imports_truncated"] = True
                    break
                ordinal_flag = (1 << 63) if plus else (1 << 31)
                if val & ordinal_flag:
                    funcs.append(f"ord#{val & 0xFFFF}")
                else:
                    ho = _rva_to_off(info, val & 0x7FFFFFFF, len(data))
                    fn = r.cstr(ho + 2, 128) if ho is not None else None
                    funcs.append(fn if fn else "<unreadable>")
                total += 1
        info["imports"].append({"dll": dll, "functions": funcs})
        if info["imports_truncated"]:
            break


def _parse_exports(data: bytes, info: dict) -> None:
    info["exports"] = None
    dirs = info.get("dirs", [])
    if not dirs or dirs[0][0] == 0:
        return
    r = _Reader(data)
    erva, esize = dirs[0]
    off = _rva_to_off(info, erva, len(data))
    if off is None or off + 40 > len(data):
        info["warnings"].append("export directory does not map into the file")
        return
    name_rva = r.u32(off + 12)
    base = r.u32(off + 16)
    nfuncs = r.u32(off + 20)
    nnames = r.u32(off + 24)
    aof, aon, aono = r.u32(off + 28), r.u32(off + 32), r.u32(off + 36)
    nm_off = _rva_to_off(info, name_rva, len(data))
    dll = r.cstr(nm_off) if nm_off is not None else None
    names_off = _rva_to_off(info, aon, len(data))
    ords_off = _rva_to_off(info, aono, len(data))
    funcs_off = _rva_to_off(info, aof, len(data))
    entries = []
    if names_off is not None and ords_off is not None:
        for i in range(min(nnames, MAX_EXPORTS)):
            if names_off + 4 * i + 4 > len(data) or ords_off + 2 * i + 2 > len(data):
                break
            n_off = _rva_to_off(info, r.u32(names_off + 4 * i), len(data))
            nm = r.cstr(n_off) if n_off is not None else None
            idx = r.u16(ords_off + 2 * i)
            frva = None
            if funcs_off is not None and funcs_off + 4 * idx + 4 <= len(data) and idx < nfuncs:
                frva = r.u32(funcs_off + 4 * idx)
            entries.append({"name": nm or "<unreadable>", "ordinal": base + idx, "rva": frva})
    info["exports"] = {
        "dll_name": dll, "ordinal_base": base, "number_of_functions": nfuncs,
        "number_of_names": nnames, "entries": entries,
        "truncated": nnames > MAX_EXPORTS,
    }


def format_pe(info: dict, file_size: int) -> str:
    L: list[str] = []
    kind = "DLL" if info.get("is_dll") else ("EXE" if info.get("is_exe") else "image")
    bits = "PE32+" if info.get("pe32plus") else ("PE32" if info.get("optional_magic") else "PE (no optional header)")
    L.append(f"PE file: {bits} {kind}, machine {info.get('machine_name')}")
    L.append(f"DOS header: 'MZ' at 0x0, e_lfanew = 0x{info['e_lfanew']:x} (PE signature at 0x{info['e_lfanew']:x})")
    L.append(f"Timestamp: {info['timestamp_utc']} (0x{info['timestamp']:08x}; may be forged)")
    L.append(f"Characteristics: 0x{info['characteristics']:04x}")
    if "entry_rva" in info:
        L.append(f"Subsystem: {info['subsystem_name']}")
        L.append(f"EntryPoint RVA: 0x{info['entry_rva']:x}")
        L.append(f"ImageBase: 0x{info['image_base']:x}")
        L.append(f"SizeOfImage: 0x{info['size_of_image']:x}   SizeOfHeaders: 0x{info['size_of_headers']:x}")
        L.append(f".NET (CLR header present): {'yes' if info.get('dotnet') else 'no'}")
        present = [DIR_NAMES[i] for i, (rva, sz) in enumerate(info["dirs"]) if rva or sz]
        L.append("Data directories present: " + (", ".join(present) if present else "none"))
    secs = info.get("sections", [])
    L.append("")
    L.append(f"Sections ({len(secs)}):")
    L.append("  #  name      vsize     vaddr     rawsize   rawoff    flags  entropy")
    for s in secs:
        L.append(
            f"  {s['index']:<2} {s['name']:<9} 0x{s['virtual_size']:<7x} 0x{s['virtual_address']:<7x} "
            f"0x{s['raw_size']:<7x} 0x{s['raw_offset']:<7x} {s['rwx']}    {s['entropy']:.3f}"
            + (f"  [{','.join(s['flag_names'])}]" if s["flag_names"] else ""))
    if info.get("overlay_offset") is not None:
        L.append(f"Overlay: offset 0x{info['overlay_offset']:x}, size {info['overlay_size']} bytes "
                 f"(file size {file_size})")
    else:
        L.append("Overlay: none")
    L.append("")
    imps = info.get("imports", [])
    nfun = sum(len(i["functions"]) for i in imps)
    L.append(f"Imports: {len(imps)} DLL(s), {nfun} function(s)" + (
        f" (limited to {MAX_IMPORT_FUNCS})" if info.get("imports_truncated") else ""))
    for imp in imps:
        L.append(f"  {imp['dll']}")
        for fn in imp["functions"]:
            L.append(f"    {fn}")
    exp = info.get("exports")
    L.append("")
    if exp:
        L.append(f"Exports: DLL name {exp['dll_name']!r}, {exp['number_of_functions']} function(s), "
                 f"{exp['number_of_names']} name(s)" + (f" (listing limited to {MAX_EXPORTS})" if exp["truncated"] else ""))
        for e in exp["entries"]:
            rva = f"0x{e['rva']:x}" if e["rva"] is not None else "?"
            L.append(f"  {e['name']} (ordinal {e['ordinal']}, rva {rva})")
    else:
        L.append("Exports: none")
    if info["warnings"]:
        L.append("")
        L.append("Warnings:")
        for w in info["warnings"]:
            L.append(f"  - {w}")
    return "\n".join(L)
