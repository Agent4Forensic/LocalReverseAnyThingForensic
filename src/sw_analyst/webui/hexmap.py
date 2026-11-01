"""Annotations for the hex view: what a byte range of a file means, without running the file and without the model.

Two sources, kept apart in the result:
- structure: fixed parsers for PE, ELF, ZIP/APK and gzip headers. They say what a range IS by format, with a German
  explanation from a fixed table. A wrong value in a hostile file shows as a parser note, never as an exception.
- analysis: where the evidence and the quotes of the job's findings lie in this file. Evidence carries the byte range
  the tool reported (source_ref); a finding quote is located by searching its exact bytes (ASCII and UTF-16LE).
  This shows the knowledge of the analysis in the code itself, with status and evidence id.

All names taken from the file (section names, ZIP member names) are sample text: the dashboard inserts them as text.
"""
from __future__ import annotations

import struct
from typing import Callable

from sw_analyst.gateway.dev_tools.pe import DIR_NAMES, SUBSYSTEMS, parse_pe

HEAD_BYTES = 64 * 1024
MAX_REGIONS = 3000
MAX_ZIP_ENTRIES = 400
MAX_ZIP_CD_BYTES = 1024 * 1024
SEARCH_LIMIT = 16 * 1024 * 1024     # quotes are searched in the first 16 MiB; beyond that only evidence ranges count
MAX_HITS_PER_QUOTE = 3
MAX_QUOTES = 200                    # distinct quotes searched per request (cost cap)

Reader = Callable[[int, int], bytes]   # (offset, length) -> bytes, at most 64 KiB per call

_SECTION_HINT = {
    ".text": "Ausführbarer Maschinencode des Programms.",
    "code": "Ausführbarer Maschinencode.",
    ".data": "Initialisierte globale Variablen (beschreibbar).",
    ".rdata": "Nur lesbare Daten: Konstanten, Zeichenketten, oft Import- und Debug-Verzeichnis.",
    ".bss": "Nicht initialisierte Daten (belegt in der Datei meist keinen Platz).",
    ".idata": "Import-Tabelle: welche DLL-Funktionen das Programm nutzt.",
    ".edata": "Export-Tabelle: Funktionen, die diese Datei anderen anbietet.",
    ".rsrc": "Ressourcen: Symbole, Dialoge, Versionsinfo, manchmal eingebettete Dateien.",
    ".reloc": "Relokationen: Korrekturen, falls das Programm an eine andere Adresse geladen wird.",
    ".pdata": "Ausnahmebehandlung (x64): Tabelle der Funktionsbereiche.",
    ".tls": "Thread-Local Storage; TLS-Callbacks laufen noch vor dem Einstiegspunkt.",
    "upx0": "UPX-Packer: leerer Platz für den entpackten Code (Hinweis auf Packen).",
    "upx1": "UPX-Packer: gepackter Code und Entpacker-Routine (Hinweis auf Packen).",
    ".ndata": "Typisch für NSIS-Installer.",
}

_DIR_HINT = {
    "export": "Export-Verzeichnis", "import": "Import-Verzeichnis (genutzte DLL-Funktionen)",
    "resource": "Ressourcen-Verzeichnis", "exception": "Ausnahme-Tabelle", "security": "Authenticode-Signatur",
    "basereloc": "Relokationen", "debug": "Debug-Verzeichnis (oft PDB-Pfad)", "tls": "TLS-Verzeichnis",
    "load_config": "Load-Config (Sicherheitsfunktionen wie CFG)", "iat": "Import-Adresstabelle",
    "delay_import": "Verzögerte Importe", "clr_runtime": ".NET-Kopf (verwaltetes Programm)",
}


def _r(offset: int, length: int, label: str, explain: str, group: str, level: int = 0, tone: str = "struct") -> dict:
    return {"offset": int(offset), "length": max(1, int(length)), "label": label, "explain": explain,
            "group": group, "level": level, "source": "structure", "tone": tone}


# ---- PE ------------------------------------------------------------------------------------------------------
def _pe(head: bytes, size: int) -> tuple[list[dict], list[str]]:
    info = parse_pe(head)
    out: list[dict] = [_r(0, 0x40, "DOS-Kopf (MZ)", "Pflichtkopf jeder Windows-EXE/DLL. Die Bytes 'MZ' am Anfang "
                          "kennzeichnen das Format; bei 0x3C steht der Zeiger auf den eigentlichen PE-Kopf.", "PE"),
                       _r(0, 2, "Signatur 'MZ'", "Kennung des DOS/PE-Formats (Mark Zbikowski).", "PE", 1)]
    notes = list(info.get("warnings") or [])
    if info.get("error"):
        notes.append(info["error"])
    lfanew = info.get("e_lfanew")
    if lfanew is None:
        return out, notes
    out.append(_r(0x3C, 4, "e_lfanew", f"Zeiger auf den PE-Kopf: 0x{lfanew:x}.", "PE", 1))
    if not info.get("is_pe"):
        return out, notes
    if lfanew > 0x40:
        out.append(_r(0x40, lfanew - 0x40, "DOS-Stub", "Kleines DOS-Programm ('This program cannot be run in DOS "
                      "mode'). Bei Windows ohne Funktion; dahinter steht oft der Rich-Header des Microsoft-Linkers, "
                      "ein Hinweis auf die Build-Werkzeuge.", "PE"))
    out.append(_r(lfanew, 4, "PE-Signatur", "'PE\\0\\0': hier beginnt der eigentliche Windows-Kopf.", "PE"))
    c = info["coff_offset"]
    kind = "DLL" if info.get("is_dll") else "EXE" if info.get("is_exe") else "Objekt"
    out.append(_r(c, 20, "COFF-Kopf", f"Maschine {info.get('machine_name')}, {info.get('number_of_sections')} "
                  f"Sektionen, Typ {kind}, Zeitstempel {info.get('timestamp_utc')} (vom Linker gesetzt, "
                  "kann gefälscht sein).", "PE"))
    out.append(_r(c + 4, 4, "TimeDateStamp", f"Build-Zeit laut Linker: {info.get('timestamp_utc')}. Kein Beweis, "
                  "lässt sich frei setzen.", "PE", 1))
    opt, optsize = info["optional_offset"], info.get("size_of_optional_header", 0)
    if optsize:
        ep = info.get("entry_rva")
        sub = SUBSYSTEMS.get(info.get("subsystem", -1), str(info.get("subsystem_name", "")))
        out.append(_r(opt, optsize, "Optional Header", f"{'PE32+ (64 Bit)' if info.get('pe32plus') else 'PE32 (32 Bit)'}; "
                      f"Einstiegspunkt RVA 0x{(ep or 0):x}, Image-Basis 0x{(info.get('image_base') or 0):x}, "
                      f"Subsystem {sub}. Steuert, wie Windows die Datei lädt.", "PE"))
        if ep is not None:
            out.append(_r(opt + 16, 4, "AddressOfEntryPoint", f"Einstiegspunkt RVA 0x{ep:x}: hier beginnt die "
                          "Ausführung (nach TLS-Callbacks).", "PE", 1))
    for i, (rva, sz) in enumerate(info.get("dirs") or []):
        if not rva or not sz:
            continue
        name = DIR_NAMES[i] if i < len(DIR_NAMES) else str(i)
        if name == "security" and rva < size:     # the only directory that holds a file offset, not an RVA
            out.append(_r(rva, min(sz, size - rva), "Authenticode-Signatur", "Digitale Signatur (PKCS#7) am Dateiende. "
                          "Ob sie gültig ist, prüft diese Ansicht nicht.", "PE", 0, "note"))
    st = info["section_table_offset"]
    secs = info.get("sections") or []
    if secs:
        out.append(_r(st, 40 * len(secs), "Sektionstabelle", "Je Sektion 40 Byte: Name, Größe und Lage in Datei "
                      "und Speicher, Rechte (lesen/schreiben/ausführen).", "PE"))
    ep = info.get("entry_rva")
    for s in secs:
        if s["raw_size"] <= 0 or s["raw_offset"] >= size:
            continue
        name = s["name"]
        hint = _SECTION_HINT.get(name.lower(), "Sektion ohne Standardnamen; Zweck aus Rechten und Inhalt ableiten.")
        rights = s["rwx"]
        extra = []
        if rights[1] == "W" and rights[2] == "X":
            extra.append("Schreibbar UND ausführbar: typisch für Packer oder selbstmodifizierenden Code.")
        if ep is not None and s["virtual_address"] <= ep < s["virtual_address"] + max(s["virtual_size"], s["raw_size"]):
            extra.append(f"Enthält den Einstiegspunkt (Dateioffset 0x{s['raw_offset'] + ep - s['virtual_address']:x}).")
        out.append(_r(s["raw_offset"], min(s["raw_size"], size - s["raw_offset"]), f"Sektion {name}",
                      f"{hint} Rechte {rights}. " + " ".join(extra), "Sektionen", 0,
                      "warn" if extra and "UND" in extra[0] else "struct"))
        if ep is not None and s["virtual_address"] <= ep < s["virtual_address"] + s["raw_size"]:
            out.append(_r(s["raw_offset"] + ep - s["virtual_address"], 16, "Einstiegspunkt",
                          "Erste Befehle des Programms. Assembler dazu unten (Ghidra), falls verfügbar.",
                          "Sektionen", 1, "note"))
    for i, (rva, sz) in enumerate(info.get("dirs") or []):
        name = DIR_NAMES[i] if i < len(DIR_NAMES) else ""
        if not rva or not sz or name == "security" or name not in _DIR_HINT:
            continue
        for s in secs:       # an RVA lies in the file only where a section maps it
            if s["virtual_address"] <= rva < s["virtual_address"] + s["raw_size"]:
                off = s["raw_offset"] + rva - s["virtual_address"]
                if off < size:
                    out.append(_r(off, min(sz, size - off), _DIR_HINT[name], f"Datenverzeichnis {i} ({name}), "
                                  f"RVA 0x{rva:x}, {sz} Byte, liegt in Sektion {s['name']}.", "Verzeichnisse", 1, "note"))
                break
    ends = [s["raw_offset"] + s["raw_size"] for s in secs if s["raw_size"] > 0]
    if ends and max(ends) < size:
        o = max(ends)
        out.append(_r(o, size - o, "Overlay", "Daten hinter der letzten Sektion. Der Windows-Lader lädt sie nicht. "
                      "Häufig: Installer-Archiv, Signatur oder angehängte Nutzlast.", "PE", 0, "warn"))
    return out, notes


# ---- ELF -----------------------------------------------------------------------------------------------------
_ELF_TYPE = {1: "relocatable (Objekt)", 2: "ausführbar", 3: "Shared Object / PIE", 4: "Core-Dump"}
_ELF_MACH = {3: "x86", 8: "MIPS", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}


def _elf(head: bytes, size: int) -> tuple[list[dict], list[str]]:
    if len(head) < 52:
        return [], ["ELF header truncated"]
    is64, le = head[4] == 2, head[5] == 1
    e = "<" if le else ">"
    hsz = 64 if is64 else 52
    try:
        etype, mach = struct.unpack_from(e + "HH", head, 16)
        if is64:
            entry, phoff, shoff = struct.unpack_from(e + "QQQ", head, 24)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", head, 54)
        else:
            entry, phoff, shoff = struct.unpack_from(e + "III", head, 24)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", head, 42)
    except struct.error:
        return [], ["ELF header truncated"]
    out = [_r(0, hsz, "ELF-Kopf", f"{'64' if is64 else '32'} Bit, {'Little' if le else 'Big'} Endian, "
              f"{_ELF_TYPE.get(etype, etype)}, Maschine {_ELF_MACH.get(mach, mach)}, Einstieg 0x{entry:x}.", "ELF"),
           _r(0, 4, "Signatur 0x7f 'ELF'", "Kennung des ELF-Formats (Linux, Android-Bibliotheken).", "ELF", 1)]
    if phoff and phnum and phoff < size:
        out.append(_r(phoff, min(phentsize * phnum, size - phoff), "Program Header", f"{phnum} Segmente: was der "
                      "Lader in den Speicher bringt und mit welchen Rechten.", "ELF"))
    if shoff and shnum and shoff < size:
        out.append(_r(shoff, min(shentsize * shnum, size - shoff), "Section Header", f"{shnum} Sektionen "
                      "(Code, Daten, Symbole). Für das Laden nicht nötig; fehlt oft bei gestrippten Dateien.", "ELF"))
    return out, []


# ---- ZIP / APK -----------------------------------------------------------------------------------------------
_ZIP_HINT = {"androidmanifest.xml": "Android-Manifest (binäres XML): Paketname, Rechte, Komponenten.",
             "classes.dex": "Dalvik-Bytecode: der eigentliche App-Code.",
             "resources.arsc": "Kompilierte App-Ressourcen.", "meta-inf/manifest.mf": "Manifest mit Prüfsummen.",
             }


def _zip(read: Reader, size: int) -> tuple[list[dict], list[str]]:
    tail_off = max(0, size - HEAD_BYTES)
    tail = read(tail_off, size - tail_off)
    i = tail.rfind(b"PK\x05\x06")
    if i < 0 or i + 22 > len(tail):
        return [], ["no end-of-central-directory record found (archive truncated or appended data)"]
    eocd = tail_off + i
    n_total, cd_size, cd_off = struct.unpack_from("<HII", tail, i + 10)
    out = [_r(eocd, 22, "Ende des Zentralverzeichnisses", f"{n_total} Einträge; Zentralverzeichnis bei 0x{cd_off:x}.",
              "ZIP")]
    notes: list[str] = []
    if cd_off >= size or cd_off + cd_size > size:
        return out, ["central directory points outside the file"]
    out.append(_r(cd_off, cd_size, "Zentralverzeichnis", "Inhaltsverzeichnis des Archivs mit Name, Größe und Lage "
                  "jedes Eintrags.", "ZIP"))
    cd = b""
    pos = cd_off
    want = min(cd_size, MAX_ZIP_CD_BYTES)
    while len(cd) < want:
        chunk = read(pos, min(HEAD_BYTES, want - len(cd)))
        if not chunk:
            break
        cd += chunk
        pos += len(chunk)
    p = 0
    count = 0
    while p + 46 <= len(cd) and cd[p:p + 4] == b"PK\x01\x02" and count < MAX_ZIP_ENTRIES:
        method, = struct.unpack_from("<H", cd, p + 10)
        csize, usize = struct.unpack_from("<II", cd, p + 20)
        nlen, xlen, clen = struct.unpack_from("<HHH", cd, p + 28)
        loff, = struct.unpack_from("<I", cd, p + 42)
        name = cd[p + 46:p + 46 + nlen].decode("utf-8", "replace")[:200]
        p += 46 + nlen + xlen + clen
        count += 1
        if loff + 30 > size:
            notes.append(f"entry {name!r}: local header outside the file")
            continue
        lh = read(loff, 30)
        if len(lh) < 30 or lh[:4] != b"PK\x03\x04":
            notes.append(f"entry {name!r}: no local header at 0x{loff:x}")
            continue
        ln, lx = struct.unpack_from("<HH", lh, 26)
        data_off = loff + 30 + ln + lx
        how = {0: "unkomprimiert", 8: "Deflate-komprimiert"}.get(method, f"Methode {method}")
        hint = _ZIP_HINT.get(name.lower(), "")
        out.append(_r(loff, 30 + ln + lx, f"Lokaler Kopf: {name}", "Eintragskopf mit Name und Größen.", "Einträge", 1))
        if csize and data_off < size:
            out.append(_r(data_off, min(csize, size - data_off), f"Daten: {name}",
                          f"{how}, {csize} Byte gespeichert, {usize} Byte entpackt. {hint}".strip(), "Einträge", 0,
                          "note" if hint else "struct"))
    if count < n_total:
        notes.append(f"{n_total - count} entries not shown (limit {MAX_ZIP_ENTRIES} or truncated directory)")
    return out, notes


def _gzip(head: bytes, size: int) -> tuple[list[dict], list[str]]:
    return [_r(0, 10, "gzip-Kopf", "Kennung 1f 8b, Methode 8 (Deflate), Flags, Zeitstempel. Danach folgt der "
               "komprimierte Datenstrom.", "gzip"),
            _r(max(10, size - 8), min(8, size), "gzip-Ende", "CRC-32 und Größe der entpackten Daten.", "gzip")], []


def structure(kind: str, read: Reader, size: int) -> tuple[list[dict], list[str]]:
    head = read(0, min(HEAD_BYTES, size))
    try:
        if kind == "pe":
            return _pe(head, size)
        if kind == "elf":
            return _elf(head, size)
        if kind == "zip":
            return _zip(read, size)
        if kind == "gzip":
            return _gzip(head, size)
    except Exception as exc:  # noqa: BLE001 - a hostile file must never break the view
        return [], [f"structure parser aborted ({type(exc).__name__})"]
    return [], []


# ---- analysis: evidence ranges and finding quotes -------------------------------------------------------------
_STATUS_DE = {"confirmed": "bestätigt", "hypothesis": "Hypothese", "open": "offener Punkt", "rejected": "verworfen"}


def analysis_regions(path: str, evidence: list[dict], findings: list[dict], read: Reader, size: int) -> tuple[list[dict], int]:
    """Byte ranges the analysis talks about. Returns (regions, bytes searched for quotes)."""
    cited: dict[str, list[dict]] = {}
    for f in findings:
        for eid in f.get("evidence_ids") or []:
            cited.setdefault(eid, []).append(f)
    out: list[dict] = []
    for ev in evidence:
        ref = ev.get("source_ref") or {}
        ref = ref.get("source_ref", ref) if isinstance(ref, dict) else {}
        if not isinstance(ref, dict) or ref.get("file") != path or "offset" not in ref:
            continue
        try:
            off, ln = int(ref["offset"]), int(ref.get("length") or 0)
        except (TypeError, ValueError):
            continue
        if off < 0 or off >= size or ln <= 0:
            continue
        fs = cited.get(ev["id"], [])
        best = next((s for s in ("confirmed", "hypothesis", "open") if any(f["status"] == s for f in fs)), "")
        out.append({"offset": off, "length": min(ln, size - off), "label": f"Beleg {ev['id']} ({ev['tool']})",
                    "explain": f"Bereich, den das Werkzeug {ev['tool']} gelesen hat"
                               + (f"; zitiert von {len(fs)} Befund(en)." if fs else "; von keinem Befund zitiert."),
                    "group": "Belege", "level": 0, "source": "evidence", "tone": "evidence",
                    "evidence_id": ev["id"], "finding_ids": [f["id"] for f in fs][:20], "status": best})
    searched = min(size, SEARCH_LIMIT)
    # Only quotes whose evidence read THIS file: a quote from a decoded layer or another member says nothing about
    # where it stands here, and a short quote would match arbitrary places.
    reads_here = {ev["id"] for ev in evidence if (ev.get("params") or {}).get("path", "sample") == path}
    quotes: dict[str, tuple[dict, dict]] = {}
    for f in findings:
        if f["status"] == "rejected":
            continue
        for q in f.get("quotes") or []:
            text = q.get("quote") or ""
            if len(text) >= 8 and q.get("evidence_id") in reads_here and text not in quotes and len(quotes) < MAX_QUOTES:
                quotes[text] = (f, q)
    if quotes and searched:
        buf = bytearray()
        pos = 0
        while pos < searched:
            chunk = read(pos, min(HEAD_BYTES, searched - pos))
            if not chunk:
                break
            buf += chunk
            pos += len(chunk)
        data = bytes(buf)
        for text, (f, q) in quotes.items():
            for enc, label in (("utf-8", ""), ("utf-16-le", ", UTF-16")):
                try:
                    needle = text.encode(enc)
                except UnicodeEncodeError:
                    continue
                start, hits = 0, 0
                while hits < MAX_HITS_PER_QUOTE:
                    i = data.find(needle, start)
                    if i < 0:
                        break
                    out.append({"offset": i, "length": len(needle),
                                "label": f"{f['id']} {_STATUS_DE.get(f['status'], f['status'])} (Zitat-Fundstelle{label})",
                                "explain": "Das Zitat dieses Befunds steht hier wörtlich in der Datei (Textsuche; "
                                           "bei mehreren Treffern ist nicht jeder die zitierte Stelle). Aussage: "
                                           + (f.get("statement_de") or f["statement_en"]),
                                "group": "Befunde", "level": 1, "source": "finding", "tone": f["status"],
                                "finding_id": f["id"], "evidence_id": q.get("evidence_id"), "status": f["status"]})
                    hits += 1
                    start = i + 1
    return out, searched


def build(kind: str, path: str, read: Reader, size: int, evidence: list[dict], findings: list[dict]) -> dict:
    regions, notes = structure(kind, read, size)
    found, searched = analysis_regions(path, evidence, findings, read, size)
    allr = []
    for r in regions + found:      # hostile headers may point past the end: clamp, drop what starts outside
        if 0 <= r["offset"] < size:
            r["length"] = max(1, min(r["length"], size - r["offset"]))
            allr.append(r)
    allr.sort(key=lambda r: (r["offset"], -r["length"]))
    if len(allr) > MAX_REGIONS:
        notes.append(f"{len(allr) - MAX_REGIONS} regions not shown (limit {MAX_REGIONS})")
        allr = allr[:MAX_REGIONS]
    for i, r in enumerate(allr):
        r["id"] = i
    return {"path": path, "size": size, "kind": kind, "regions": allr, "notes": notes[:20],
            "quote_search_bytes": searched}
