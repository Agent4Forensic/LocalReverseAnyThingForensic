"""Magic-byte based file type identification with reasons (static)."""
from __future__ import annotations

import io
import struct
import zipfile
from typing import Any, Optional

from .pe import parse_pe
from .scripts import detect_language
from .util import decode_text_bytes, hex_bytes, printable_ratio, shannon_entropy

_ELF_MACHINES = {3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}
_ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared object/PIE", 4: "core dump"}


def _res(type_: str, confidence: str, reasons: list[str], details: Optional[list[str]] = None) -> dict[str, Any]:
    return {"type": type_, "confidence": confidence, "reasons": reasons, "details": details or []}


def sniff_magic(data: bytes) -> Optional[tuple[str, str]]:
    """Cheap check used for decoded layers: (type, reason) or None. No archive inspection."""
    h = data[:16]
    if h[:2] == b"MZ":
        return "pe/mz", "starts with 'MZ'"
    if h[:4] == b"\x7fELF":
        return "elf", "starts with 0x7f 'ELF'"
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip", "starts with 'PK'"
    if h[:3] == b"\x1f\x8b\x08":
        return "gzip", "starts with 1f 8b 08"
    if h[:5] == b"%PDF-":
        return "pdf", "starts with '%PDF-'"
    if h[:4] == b"dex\n":
        return "dex", "starts with 'dex\\n'"
    if h[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z", "starts with 7z signature"
    if h[:6] == b"Rar!\x1a\x07":
        return "rar", "starts with 'Rar!'"
    if h[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole2", "starts with OLE2 signature"
    if h[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho", "Mach-O magic"
    return None


def identify(data: bytes) -> dict[str, Any]:
    n = len(data)
    if n == 0:
        return _res("unknown", "low", ["file is empty"])
    h = data[:64]
    first = hex_bytes(h, 8)

    if h[:2] == b"MZ":
        return _identify_mz(data, first)
    if h[:4] == b"\x7fELF":
        return _identify_elf(data)
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return _identify_zip(data, first)
    if h[:4] == b"dex\n" and len(data) >= 8 and data[7:8] == b"\x00":
        return _res("dex", "high", [f"bytes 0-7 = {data[:8]!r} (DEX header 'dex\\n<version>\\0')"],
                    [f"DEX version: {data[4:7].decode('ascii', 'replace')}"])
    if h[:5] == b"%PDF-" or b"%PDF-" in data[:1024]:
        off = 0 if h[:5] == b"%PDF-" else data.find(b"%PDF-")
        return _res("pdf", "high" if off == 0 else "medium",
                    [f"'%PDF-' found at offset {off} ({data[off:off + 8]!r})"])
    if h[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        bits = 64 if h[3:4] in (b"\xcf",) or h[:1] == b"\xcf" else 32
        endian = "big-endian" if h[0] == 0xFE else "little-endian"
        return _res("macho", "high", [f"bytes 0-3 = {hex_bytes(h[:4])} (Mach-O magic)"],
                    [f"{bits}-bit, {endian}"])
    if h[:4] == b"\xca\xfe\xba\xbe":
        v = struct.unpack(">I", data[4:8])[0] if n >= 8 else 0
        if v < 45:
            return _res("macho", "medium", [f"bytes 0-7 = {hex_bytes(h[:8])}: 'CAFEBABE' followed by "
                                            f"{v} (< 45) = universal (fat) Mach-O architecture count"])
        return _res("java_class", "medium", [f"bytes 0-7 = {hex_bytes(h[:8])}: 'CAFEBABE' followed by "
                                             f"class version field 0x{v:08x}"])
    if h[:3] == b"\x1f\x8b\x08":
        return _res("gzip", "high", [f"bytes 0-2 = {hex_bytes(h[:3])} (gzip magic 1f 8b 08)"])
    if h[:6] == b"7z\xbc\xaf\x27\x1c":
        return _res("7z", "high", [f"bytes 0-5 = {hex_bytes(h[:6])} (7-Zip signature)"])
    if h[:6] == b"Rar!\x1a\x07":
        return _res("rar", "high", [f"bytes 0-5 = {hex_bytes(h[:6])} ('Rar!' signature)"])
    if h[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return _res("ole2", "high", [f"bytes 0-7 = {hex_bytes(h[:8])} (OLE2/Compound File, e.g. legacy "
                                     "Office documents)"])
    return _identify_text_or_unknown(data, first)


def _identify_mz(data: bytes, first: str) -> dict[str, Any]:
    reasons = [f"bytes 0-1 = 'MZ' (4d 5a), DOS header magic"]
    info = parse_pe(data)
    if not info.get("is_pe"):
        reasons.append("no valid PE signature: " + (info.get("error") or "unknown"))
        return _res("pe", "low", reasons, ["treated as DOS MZ executable (not a valid PE)"])
    reasons.append(f"'PE\\0\\0' signature at offset 0x{info['e_lfanew']:x}")
    kind = "DLL" if info.get("is_dll") else "EXE"
    details = [f"{kind}, machine {info['machine_name']}"]
    if "subsystem_name" in info:
        details.append(f"subsystem {info['subsystem_name']}, {'PE32+' if info.get('pe32plus') else 'PE32'}")
    if info.get("dotnet"):
        details.append(".NET assembly (CLR runtime header present)")
    return _res("pe", "high", reasons, details)


def _identify_elf(data: bytes) -> dict[str, Any]:
    reasons = ["bytes 0-3 = 7f 45 4c 46 (0x7f 'ELF')"]
    details = []
    if len(data) >= 20:
        cls = {1: "32-bit", 2: "64-bit"}.get(data[4], f"class {data[4]}")
        order = {1: "little-endian", 2: "big-endian"}.get(data[5], f"data {data[5]}")
        fmt = "<" if data[5] == 1 else ">"
        etype, machine = struct.unpack_from(fmt + "HH", data, 16)
        details.append(f"{cls}, {order}")
        details.append(f"type {_ELF_TYPES.get(etype, etype)}, machine {_ELF_MACHINES.get(machine, machine)}")
        reasons.append(f"EI_CLASS byte 4 = {data[4]}, EI_DATA byte 5 = {data[5]}")
    return _res("elf", "high", reasons, details)


def _identify_zip(data: bytes, first: str) -> dict[str, Any]:
    reasons = [f"bytes 0-3 = {data[:4]!r} (ZIP 'PK' signature)"]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError, EOFError) as exc:
        reasons.append(f"central directory unreadable ({type(exc).__name__})")
        return _res("zip", "medium", reasons)
    nameset = set(names)
    details = [f"{len(names)} entries; first: " + ", ".join(names[:5])]
    if "AndroidManifest.xml" in nameset and "classes.dex" in nameset:
        reasons.append("archive contains AndroidManifest.xml and classes.dex")
        return _res("apk", "high", reasons, details)
    if "META-INF/MANIFEST.MF" in nameset or any(nm.endswith(".class") for nm in names):
        reasons.append("archive contains META-INF/MANIFEST.MF or .class files")
        if "AndroidManifest.xml" in nameset or "classes.dex" in nameset:
            details.append("has only one of AndroidManifest.xml/classes.dex, so not classified as APK")
        return _res("jar", "high", reasons, details)
    extra = []
    if "[Content_Types].xml" in nameset:
        extra.append("OOXML container ([Content_Types].xml), e.g. docx/xlsx/pptx")
    if "AndroidManifest.xml" in nameset or "classes.dex" in nameset:
        extra.append("has only one of AndroidManifest.xml/classes.dex, so not classified as APK")
    return _res("zip", "high", reasons, details + extra)


def _identify_text_or_unknown(data: bytes, first: str) -> dict[str, Any]:
    head = data[:262144]
    reasons = [f"no known magic number (first bytes: {first})"]
    dec = decode_text_bytes(head)
    if dec is None:
        ent = shannon_entropy(data[:65536])
        reasons.append(f"content is binary ({100 * (1 - printable_ratio(head)):.0f}% non-printable bytes in head)")
        details = []
        if ent > 7.2:
            details.append(f"high entropy {ent:.2f} in first 64 KiB (compressed, encrypted or packed?)")
        return _res("unknown", "low", reasons, details)
    text, enc = dec
    reasons.append(f"content decodes as {enc} text")
    lang, score, why = detect_language(text)
    if lang == "text":
        return _res("text", "medium", reasons + why)
    conf = "high" if score >= 6 else "medium"
    return _res(lang, conf, reasons + why, [f"language score {score}"])
