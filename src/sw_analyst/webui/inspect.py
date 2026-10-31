"""File inspector for the dashboard: size, hex rows, kind, and fixed German explanations of assembler instructions.

Nothing here runs the sample or asks the model. The explanations come from a fixed table (what an instruction
does in general), so they cannot be wrong about this sample in a way the model could be. What a function does in
this sample stays with the findings of the analysis, which carry evidence.
"""
from __future__ import annotations

import re

HEX_ROW = 16
MAX_HEX_BYTES = 64 * 1024        # per request; the viewer pages with offset

# file kind from magic bytes: (kind, label, has machine code that Ghidra can read)
_MAGIC = [
    (b"MZ", "pe", "Windows-PE (EXE/DLL)", True),
    (b"\x7fELF", "elf", "ELF (Linux/Android nativ)", True),
    (b"\xcf\xfa\xed\xfe", "macho", "Mach-O (macOS)", True),
    (b"\xfe\xed\xfa\xcf", "macho", "Mach-O (macOS)", True),
    (b"dex\n", "dex", "Android DEX (Dalvik-Bytecode)", False),
    (b"PK\x03\x04", "zip", "ZIP-Container (APK, JAR, Office …)", False),
    (b"\x1f\x8b", "gzip", "gzip-komprimiert", False),
]


def file_kind(head: bytes) -> dict:
    for magic, kind, label, code in _MAGIC:
        if head.startswith(magic):
            return {"kind": kind, "label": label, "machine_code": code}
    sample = head[:4096]
    if sample and sum(32 <= b < 127 or b in (9, 10, 13) for b in sample) / len(sample) > 0.9:
        return {"kind": "text", "label": "Text (Skript, Konfiguration oder kodierte Daten)", "machine_code": False}
    return {"kind": "binary", "label": "Binärdaten ohne bekanntes Format", "machine_code": False}


def hex_rows(data: bytes, base: int = 0) -> list[dict]:
    rows = []
    for i in range(0, len(data), HEX_ROW):
        chunk = data[i:i + HEX_ROW]
        rows.append({"offset": base + i, "hex": " ".join(f"{b:02x}" for b in chunk),
                     "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)})
    return rows


# ---- assembler explanations (x86/x64, Ghidra syntax) ---------------------------------------------------------
_EXPLAIN = {
    "mov": "Kopiert den rechten Wert in das linke Ziel (Register oder Speicher).",
    "movzx": "Kopiert einen kleineren Wert und füllt die oberen Bits mit Nullen auf.",
    "movsx": "Kopiert einen kleineren Wert mit Vorzeichen-Erweiterung.",
    "movsxd": "Erweitert einen 32-Bit-Wert mit Vorzeichen auf 64 Bit.",
    "movabs": "Lädt einen 64-Bit-Wert direkt in ein Register.",
    "lea": "Berechnet eine Adresse und legt sie ab, ohne Speicher zu lesen (oft auch für Rechnungen genutzt).",
    "push": "Legt einen Wert auf den Stack (Stapelspeicher), z. B. ein Argument vor einem Aufruf.",
    "pop": "Holt den obersten Wert vom Stack in ein Register.",
    "call": "Ruft eine Funktion auf; die Rücksprungadresse kommt auf den Stack.",
    "ret": "Kehrt aus der Funktion zum Aufrufer zurück.",
    "jmp": "Springt bedingungslos an eine andere Adresse.",
    "je": "Springt, wenn der letzte Vergleich Gleichheit ergab (Zero-Flag gesetzt).",
    "jz": "Springt, wenn das Ergebnis null war (Zero-Flag gesetzt).",
    "jne": "Springt, wenn der letzte Vergleich Ungleichheit ergab.",
    "jnz": "Springt, wenn das Ergebnis nicht null war.",
    "jg": "Springt, wenn größer (mit Vorzeichen).",
    "jge": "Springt, wenn größer oder gleich (mit Vorzeichen).",
    "jl": "Springt, wenn kleiner (mit Vorzeichen).",
    "jle": "Springt, wenn kleiner oder gleich (mit Vorzeichen).",
    "ja": "Springt, wenn größer (ohne Vorzeichen).",
    "jae": "Springt, wenn größer oder gleich (ohne Vorzeichen).",
    "jb": "Springt, wenn kleiner (ohne Vorzeichen, Carry-Flag gesetzt).",
    "jbe": "Springt, wenn kleiner oder gleich (ohne Vorzeichen).",
    "js": "Springt, wenn das Ergebnis negativ war.",
    "jns": "Springt, wenn das Ergebnis nicht negativ war.",
    "cmp": "Vergleicht zwei Werte (rechnet links minus rechts, setzt nur die Flags).",
    "test": "Prüft Bits (UND-Verknüpfung, setzt nur die Flags); oft: ist ein Register null?",
    "add": "Addiert den rechten Wert zum linken.",
    "sub": "Subtrahiert den rechten Wert vom linken.",
    "inc": "Erhöht um 1.",
    "dec": "Verringert um 1.",
    "imul": "Multipliziert mit Vorzeichen.",
    "mul": "Multipliziert ohne Vorzeichen.",
    "idiv": "Dividiert mit Vorzeichen.",
    "div": "Dividiert ohne Vorzeichen.",
    "neg": "Kehrt das Vorzeichen um.",
    "and": "Bitweises UND; oft zum Ausblenden von Bits.",
    "or": "Bitweises ODER; oft zum Setzen von Bits.",
    "xor": "Bitweises Exklusiv-ODER; mit sich selbst ergibt es 0, sonst typisch für einfache Verschlüsselung.",
    "not": "Kehrt alle Bits um.",
    "shl": "Schiebt Bits nach links (mal 2 je Stelle).",
    "sal": "Schiebt Bits nach links (mal 2 je Stelle).",
    "shr": "Schiebt Bits nach rechts (geteilt durch 2 je Stelle, ohne Vorzeichen).",
    "sar": "Schiebt Bits nach rechts mit Vorzeichen.",
    "rol": "Rotiert Bits nach links; häufig in Prüfsummen und Verschlüsselung.",
    "ror": "Rotiert Bits nach rechts; häufig in Prüfsummen und API-Hashing.",
    "nop": "Tut nichts (Platzhalter, Ausrichtung oder Füllung).",
    "int3": "Haltepunkt für Debugger; oft als Füllbyte zwischen Funktionen.",
    "int": "Löst einen Software-Interrupt aus (z. B. Systemaufruf).",
    "syscall": "Ruft direkt den Betriebssystemkern auf.",
    "sysenter": "Ruft direkt den Betriebssystemkern auf (ältere Variante).",
    "hlt": "Hält den Prozessor an (nur im Kernel erlaubt).",
    "leave": "Baut den Stack-Rahmen der Funktion ab (Gegenstück zum Prolog).",
    "enter": "Baut einen Stack-Rahmen für die Funktion auf.",
    "cdq": "Erweitert EAX mit Vorzeichen nach EDX:EAX (Vorbereitung einer Division).",
    "cqo": "Erweitert RAX mit Vorzeichen nach RDX:RAX (Vorbereitung einer Division).",
    "cmovz": "Kopiert nur, wenn das Ergebnis null war.",
    "cmovnz": "Kopiert nur, wenn das Ergebnis nicht null war.",
    "sete": "Setzt ein Byte auf 1 bei Gleichheit, sonst 0.",
    "setne": "Setzt ein Byte auf 1 bei Ungleichheit, sonst 0.",
    "xchg": "Tauscht zwei Werte.",
    "cpuid": "Fragt Prozessor-Informationen ab; auch zur Erkennung virtueller Maschinen genutzt.",
    "rdtsc": "Liest den Zeitstempelzähler; auch zur Erkennung von Debuggern über Zeitmessung genutzt.",
    "stosb": "Schreibt AL an die Adresse in EDI/RDI (mit REP: Speicher füllen).",
    "stosd": "Schreibt EAX an die Adresse in EDI/RDI (mit REP: Speicher füllen).",
    "movsb": "Kopiert ein Byte von ESI/RSI nach EDI/RDI (mit REP: Speicherblock kopieren).",
    "movsd": "Kopiert 4 Byte von ESI/RSI nach EDI/RDI (mit REP: Speicherblock kopieren).",
    "lodsb": "Lädt ein Byte von ESI/RSI nach AL.",
    "scasb": "Vergleicht AL mit dem Byte an EDI/RDI (mit REPNE: Zeichen suchen, z. B. Stringlänge).",
    "pushad": "Sichert alle allgemeinen Register auf dem Stack (typisch für Packer-Einstiege).",
    "popad": "Stellt alle allgemeinen Register vom Stack wieder her (typisch vor dem Sprung in entpackten Code).",
    "pushfd": "Sichert das Flag-Register auf dem Stack.",
    "popfd": "Stellt das Flag-Register vom Stack wieder her.",
    "loop": "Verringert ECX und springt, solange ECX nicht null ist.",
    "bswap": "Dreht die Byte-Reihenfolge um (Little/Big Endian).",
    "pxor": "Exklusiv-ODER auf 128-Bit-Registern (SSE); mit sich selbst: Register auf 0 setzen.",
    "movdqa": "Kopiert 16 Byte (SSE-Register, ausgerichtet).",
    "movdqu": "Kopiert 16 Byte (SSE-Register, nicht ausgerichtet).",
    "movaps": "Kopiert 16 Byte (SSE-Register).",
    "movups": "Kopiert 16 Byte (SSE-Register, nicht ausgerichtet).",
    "aesenc": "Eine AES-Verschlüsselungsrunde in Hardware.",
    "aesdec": "Eine AES-Entschlüsselungsrunde in Hardware.",
}
_PREFIXES = ("rep", "repe", "repz", "repne", "repnz", "lock")
_SELF_ZERO = re.compile(r"^(xor|sub|pxor)\s+([a-z0-9]+)\s*,\s*\2$")


def explain(text: str) -> dict:
    """{'mnemonic', 'explain'} for one Ghidra instruction text such as 'MOV EAX,dword ptr [EBP + 0x8]'."""
    t = " ".join(str(text).lower().split())
    words = t.split(" ", 1)
    prefix = ""
    if words and words[0] in _PREFIXES and len(words) > 1:
        prefix, t = words[0], words[1]
        words = t.split(" ", 1)
    mnem = words[0] if words else ""
    ops = words[1] if len(words) > 1 else ""
    if _SELF_ZERO.match(f"{mnem} {ops.replace(' ', '')}"):
        reg = ops.split(",")[0].strip().upper()
        return {"mnemonic": mnem, "explain": f"Setzt {reg} auf 0 (übliche Kurzform)."}
    base = _EXPLAIN.get(mnem)
    if base is None and mnem.startswith("j"):
        base = "Bedingter Sprung: springt nur, wenn die Bedingung aus dem letzten Vergleich zutrifft."
    if base is None and mnem.startswith("cmov"):
        base = "Bedingtes Kopieren: kopiert nur, wenn die Bedingung aus dem letzten Vergleich zutrifft."
    if base is None and mnem.startswith("set"):
        base = "Setzt ein Byte auf 1, wenn die Bedingung zutrifft, sonst auf 0."
    if base is None:
        base = ""
    extra = []
    if mnem == "call" and ops:
        extra.append(f"Ziel: {ops}.")
    if mnem == "push" and ops in ("ebp", "rbp"):
        extra.append("Beginn des Funktionsprologs: alter Rahmenzeiger wird gesichert.")
    if mnem == "mov" and ops.replace(" ", "") in ("ebp,esp", "rbp,rsp"):
        extra.append("Funktionsprolog: neuer Stack-Rahmen beginnt hier.")
    if "fs:" in ops or "gs:" in ops:
        extra.append("Zugriff über FS/GS: unter Windows der Thread-/Prozessblock (TEB/PEB), oft für Debugger-Erkennung "
                     "oder das Finden geladener DLLs.")
    if prefix:
        extra.insert(0, f"Präfix {prefix.upper()}: wiederholt den Befehl, solange ECX/RCX nicht null ist."
                     if prefix.startswith("rep") else "Präfix LOCK: atomarer Zugriff (mehrere Threads).")
    return {"mnemonic": (prefix + " " if prefix else "") + mnem, "explain": " ".join([base] + extra).strip()}
