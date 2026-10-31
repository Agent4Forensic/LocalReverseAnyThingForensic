"""Fixed term translations (EN -> DE) for forensics and reverse engineering.

The glossary is injected into the translation prompt so the local model uses the same German
term every time.  Bump ``GLOSSARY_VERSION`` whenever an entry changes: it is part of the
translation cache key.
"""
from __future__ import annotations

import re

__all__ = ["GLOSSARY_EN_DE", "GLOSSARY_VERSION", "glossary_prompt_block", "normalize_direction"]

GLOSSARY_VERSION = "1"

GLOSSARY_EN_DE: dict[str, str] = {
    # analysis workflow / report
    "finding": "Befund",
    "evidence": "Beleg",
    "hypothesis": "Hypothese",
    "confirmed": "bestätigt",
    "rejected": "verworfen",
    "unresolved": "ungeklärt",
    "quote": "Zitat",
    "confidence": "Konfidenz",
    "severity": "Schweregrad",
    "coverage": "Abdeckung",
    "report": "Bericht",
    "task": "Aufgabe",
    "job": "Auftrag",
    "triage": "Triage",
    "timeline": "Zeitleiste",
    "artifact": "Artefakt",
    "chain of custody": "Beweiskette",
    "forensic": "forensisch",
    "attribution": "Zuordnung",
    "threat actor": "Angreifer",
    "campaign": "Kampagne",
    # malware classes and behaviour
    "malware": "Schadsoftware",
    "ransomware": "Ransomware",
    "trojan": "Trojaner",
    "backdoor": "Backdoor",
    "worm": "Wurm",
    "rootkit": "Rootkit",
    "keylogger": "Keylogger",
    "botnet": "Botnetz",
    "dropper": "Dropper",
    "downloader": "Downloader",
    "loader": "Loader",
    "payload": "Nutzlast",
    "shellcode": "Shellcode",
    "exploit": "Exploit",
    "vulnerability": "Schwachstelle",
    "phishing": "Phishing",
    "c2": "C2",
    "command and control": "Command-and-Control",
    "beacon": "Beacon",
    "persistence": "Persistenz",
    "privilege escalation": "Rechteausweitung",
    "lateral movement": "laterale Bewegung",
    "exfiltration": "Exfiltration",
    "process injection": "Prozessinjektion",
    "code injection": "Code-Injektion",
    "evasion": "Umgehung",
    "anti-debugging": "Anti-Debugging",
    "anti-analysis": "Anti-Analyse",
    "sandbox": "Sandbox",
    "mutex": "Mutex",
    "scheduled task": "geplante Aufgabe",
    "service": "Dienst",
    "autorun": "Autostart",
    "network traffic": "Netzwerkverkehr",
    "indicator of compromise": "Kompromittierungsindikator",
    "ioc": "IOC",
    # reverse engineering
    "sample": "Sample",
    "reverse engineering": "Reverse Engineering",
    "static analysis": "statische Analyse",
    "dynamic analysis": "dynamische Analyse",
    "decompiler": "Dekompilierer",
    "decompilation": "Dekompilierung",
    "disassembler": "Disassembler",
    "disassembly": "Disassemblierung",
    "debugger": "Debugger",
    "breakpoint": "Haltepunkt",
    "obfuscation": "Obfuskation",
    "obfuscated": "obfuskiert",
    "deobfuscation": "Deobfuskation",
    "packer": "Packer",
    "packed": "gepackt",
    "unpacking": "Entpacken",
    "entropy": "Entropie",
    "import table": "Importtabelle",
    "export table": "Exporttabelle",
    "string": "Zeichenkette",
    "function": "Funktion",
    "call graph": "Aufrufgraph",
    "control flow": "Kontrollfluss",
    "entry point": "Einstiegspunkt",
    "section": "Sektion",
    "resource": "Ressource",
    "overlay": "Overlay",
    "header": "Header",
    "offset": "Offset",
    "stack": "Stack",
    "heap": "Heap",
    "register": "Register",
    "registry": "Registry",
    "library": "Bibliothek",
    "dependency": "Abhängigkeit",
    "compiler": "Compiler",
    "script": "Skript",
    "macro": "Makro",
    "archive": "Archiv",
    "metadata": "Metadaten",
    "timestamp": "Zeitstempel",
    "certificate": "Zertifikat",
    "digital signature": "digitale Signatur",
    "signature": "Signatur",
    "heuristic": "Heuristik",
    "false positive": "Fehlalarm",
    "checksum": "Prüfsumme",
    "hash": "Hash",
    "key": "Schlüssel",
    "encryption": "Verschlüsselung",
    "decryption": "Entschlüsselung",
    "mitigation": "Gegenmaßnahme",
    "remediation": "Bereinigung",
    "quarantine": "Quarantäne",
}


def normalize_direction(direction: str) -> str:
    """Map many spellings to ``'en-de'`` or ``'de-en'``; raise ValueError otherwise."""
    d = direction.strip().lower().replace("->", "-").replace("2", "-")
    d = re.sub(r"[\s_]+", "-", d).replace("-to-", "-")
    table = {"en-de": "en-de", "de-en": "de-en", "to-de": "en-de", "to-en": "de-en"}
    if d in table:
        return table[d]
    raise ValueError(f"unknown translation direction: {direction!r}")


def _term_regex(term: str) -> re.Pattern:
    return re.compile(r"(?<!\w)" + re.escape(term) + r"\w{0,4}", re.IGNORECASE)


def glossary_prompt_block(direction: str, text: str | None = None) -> str:
    """Prompt block listing the mandatory term translations.

    ``direction``: ``'en-de'`` (also ``'to_de'``) or ``'de-en'`` (``'to_en'``).
    With ``text`` only entries whose source term (or an inflection of it) occurs in ``text``
    are listed - keeps the prompt short for small models.
    """
    d = normalize_direction(direction)
    if d == "en-de":
        pairs = list(GLOSSARY_EN_DE.items())
    else:
        seen: dict[str, str] = {}
        for en, de in GLOSSARY_EN_DE.items():
            seen.setdefault(de, en)
        pairs = list(seen.items())
    if text is not None:
        pairs = [(s, t) for s, t in pairs if _term_regex(s).search(text)]
    if not pairs:
        return ""
    src, tgt = ("English", "German") if d == "en-de" else ("German", "English")
    lines = [f"Glossary ({src} -> {tgt}). Always use exactly these translations:"]
    lines += [f"- {s} => {t}" for s, t in pairs]
    return "\n".join(lines)
