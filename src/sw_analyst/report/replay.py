"""Replay export: a ZIP with a stdlib-only script that re-does the decoding steps of an analysis in a terminal.

The script only transforms bytes (base64, hex, gzip, XOR, byte ranges, ZIP members). It never runs the sample,
has no eval/exec/subprocess/network and treats every string from the analysis as data (steps.json).
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from typing import Any

from sw_analyst.common.util import sha256_hex
from sw_analyst.report.derivation import _TOOLS

REPLAY_TOOLS = ("decode_layer", "extract_range", "zip_extract")
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,100}")
_LOGICAL = re.compile(r"sample|derived/[A-Za-z0-9_.-]{1,100}")
_METHODS = ("base64", "base32", "base85", "hex", "url", "rot13", "charcode", "xor_single_byte", "xor_key", "rc4",
            "gzip", "zlib")
_METHOD_DE = {
    "base64": "Base64-Dekodierung", "base32": "Base32-Dekodierung", "base85": "Base85-Dekodierung",
    "hex": "Hex-Dekodierung", "url": "URL-Dekodierung (%XX)", "rot13": "ROT13", "charcode": "Zeichencode-Liste",
    "xor_single_byte": "XOR mit Einzelbyte-Schlüssel", "xor_key": "XOR mit Schlüssel", "rc4": "RC4 mit Schlüssel",
    "gzip": "gzip-Entpackung", "zlib": "zlib/deflate-Entpackung",
}
_FIXED_TIME = (2020, 1, 1, 0, 0, 0)


def _int(v: Any, default: int) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) else default


def _method_of(ev: dict, sr: dict) -> str:
    m = sr.get("method")
    if not m:
        mm = re.match(r"decode_layer: ([a-z0-9_]+)", ev.get("text") or "")
        m = mm.group(1) if mm else ""
    return str(m)


def _make_step(ev: dict) -> dict | None:
    sr = ev.get("source_ref") or {}
    params = ev.get("params") or {}
    out, sha = sr.get("derived"), sr.get("sha256")
    if not (isinstance(out, str) and isinstance(sha, str) and _LOGICAL.fullmatch(out) and out != "sample"):
        return None
    src = params.get("path") if isinstance(params.get("path"), str) else "sample"
    tool = ev["tool"]
    step: dict[str, Any] = {"evidence_id": ev["id"], "tool": tool, "tool_version": ev.get("tool_version") or "",
                            "input": src if _LOGICAL.fullmatch(src) else "sample", "output": out,
                            "output_sha256": sha, "output_size": _int(sr.get("size"), -1), "supported": False,
                            "explanation": _TOOLS.get(tool, ("", "Statisches Analysewerkzeug; siehe Beleg."))[1]}
    inner = sr.get("source_ref") if isinstance(sr.get("source_ref"), dict) else {}
    if tool == "decode_layer":
        method = _method_of(ev, sr)
        if method not in _METHODS:
            step["note"] = f"Methode '{method[:40]}' nicht nachvollziehbar, siehe Beleg {ev['id']}"
            return step
        step.update(method=method, offset=_int(inner.get("offset"), _int(params.get("offset"), 0)),
                    length=_int(inner.get("length"), -1))
        if method == "xor_single_byte":
            k = sr.get("xor_key")
            if not isinstance(k, int):
                step["note"] = f"XOR-Schlüssel fehlt im Beleg {ev['id']}"
                return step
            step["xor_key"] = k
        if method in ("xor_key", "rc4"):
            if not isinstance(sr.get("key_hex"), str):
                step["note"] = f"Schlüssel fehlt im Beleg {ev['id']}"
                return step
            step["key_hex"] = sr["key_hex"]
        extra = ""
        if "xor_key" in step:
            extra = f", Schlüssel 0x{step['xor_key']:02x}"
        elif "key_hex" in step:
            extra = f", Schlüssel (hex) {step['key_hex'][:128]}"
        step["explanation"] = (f"Schicht dekodieren: {_METHOD_DE[method]}{extra}, Eingabeausschnitt ab Offset "
                               f"{step['offset']}. Nichts wird ausgeführt.")
        step["supported"] = True
    elif tool == "extract_range":
        off, ln = _int(inner.get("offset"), _int(params.get("offset"), -1)), _int(inner.get("length"), -1)
        if off < 0 or ln < 0:
            step["note"] = f"Bereich fehlt im Beleg {ev['id']}"
            return step
        step.update(offset=off, length=ln, supported=True,
                    explanation=f"Bytebereich ausschneiden: Offset {off}, Länge {ln}.")
    elif tool == "zip_extract":
        member = sr.get("member") if isinstance(sr.get("member"), str) else params.get("member")
        if not isinstance(member, str) or not member:
            step["note"] = f"Archivelement fehlt im Beleg {ev['id']}"
            return step
        step.update(member=member[:300], supported=True,
                    explanation="ZIP-Element entpacken (nur lesen, nichts wird ausgeführt).")
    else:
        step["note"] = f"Werkzeug '{tool[:40]}' ist nicht nachvollziehbar, siehe Beleg {ev['id']}"
    return step


def collect_steps(store, rid: str) -> list[dict]:
    steps: list[dict] = []
    made: set[str] = set()
    for row in store.list_evidence(rid):
        ev = store.get_evidence(row["id"])
        if not ev or (ev.get("text") or "").startswith("[tool error]"):
            continue
        st = _make_step(ev)
        if st is None or st["output"] in made:
            continue            # identical content re-used an existing layer: first producer is enough
        made.add(st["output"])
        steps.append(st)
    # order by dependency: a step comes after the producer of its input (evidence order already ensures it)
    order: list[dict] = []
    done = {"sample"}
    pending = list(steps)
    while pending:
        nxt = next((s for s in pending if s["input"] in done or s["input"] not in made), None) or pending[0]
        pending.remove(nxt)
        done.add(nxt["output"])
        order.append(nxt)
    for n, s in enumerate(order, 1):
        s["n"] = n
    return order


def _questions(store, rid: str) -> list[dict]:
    out = []
    for a in store.list_answers(rid):
        fs = []
        for fid in a.get("finding_ids") or []:
            f = store.get_finding(fid)
            if f:
                fs.append({"id": f["id"], "status": f["status"], "statement": f.get("statement_de") or f["statement_en"],
                           "quotes": [{"evidence_id": str(q.get("evidence_id", "")), "quote": str(q.get("quote", ""))[:2000]}
                                      for q in (f.get("quotes") or []) if isinstance(q, dict)]})
        out.append({"id": a["question_id"], "text": a["text_orig"], "expected": a.get("expected") or "",
                    "status": a["status"], "answer": a.get("answer_de") or a.get("answer_en") or
                    a.get("evaluation_de") or a.get("evaluation_en") or "", "findings": fs})
    return out


def _safe_name(name: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "_", (name or "").replace("\\", "/").rsplit("/", 1)[-1])[:80].lstrip(".")
    return base or "sample.bin"


README = """REPLAY - Nachvollzug der Analyse Schritt für Schritt
=====================================================

Auftrag: {title}
Probe:   {sample_name}
SHA-256: {sha}

Was das Skript tut
------------------
Das Skript replay.py wiederholt auf Ihrem Rechner die Dekodier-Schritte der Analyse
(Base64, Hex, gzip, XOR, Bytebereiche, ZIP-Elemente). Nach jedem Schritt zeigt es
Eingabe, Ausgabe, Größe, SHA-256 und eine Vorschau und vergleicht den Hash mit dem
Hash der Analyse (OK / ABWEICHUNG). Am Ende nennt es die Fragen mit Antworten und
prüft, ob die zitierten Textstellen in den reproduzierten Bytes vorkommen.

Was das Skript NICHT tut
------------------------
Die Probe wird nie ausgeführt, geöffnet oder interpretiert. Es gibt kein eval/exec,
keinen Programmstart und keinen Netzwerkzugriff. Es werden nur Python-Standardmodule
benutzt (Python 3.9 oder neuer). Dateien werden nur mit --out <Ordner> geschrieben.

Starten
-------
Windows: Doppelklick auf run_replay.cmd (öffnet eine Konsole).
Linux/macOS: sh run_replay.sh
Oder direkt: python replay.py [--no-pause] [--sample <Pfad>] [--out <Ordner>]

{sample_hint}
Weicht der SHA-256 der Datei vom Auftrag ab, bricht das Skript ab.

Hinweis: Vorsicht beim Umgang mit der Probe selbst; sie kann schädlich sein.
Dieses Paket enthält Schritte und Hashes, die Aussagen der KI sind vom Menschen zu prüfen.
"""

CMD = ('@echo off\r\ncd /d "%~dp0"\r\nwhere py >nul 2>nul\r\nif %errorlevel%==0 (\r\n  py -3 replay.py %*\r\n) else (\r\n'
       '  python replay.py %*\r\n)\r\npause\r\n')
SH = ('#!/bin/sh\ncd "$(dirname "$0")" || exit 1\nif command -v python3 >/dev/null 2>&1; then\n'
      '  python3 replay.py "$@"\nelse\n  python replay.py "$@"\nfi\n')


def build_replay_zip(store, gateway, rid: str, include_sample: bool) -> bytes:
    job = store.get_job(rid)
    if not job:
        raise KeyError(rid)
    sname = _safe_name(job["sample_name"])
    sample_bytes = None
    if include_sample:
        try:
            with open(gateway.sample_path(rid), "rb") as f:
                data = f.read()
            if sha256_hex(data) == job["sample_sha256"]:
                sample_bytes = data
        except (OSError, Exception):  # noqa: BLE001 - no sample in the package, the script then asks for a path
            sample_bytes = None
    steps = collect_steps(store, rid)
    meta = {"version": 1, "job": {"id": job["id"], "title": job["title"], "sample_name": job["sample_name"],
                                  "sample_file": sname if sample_bytes is not None else "",
                                  "sample_sha256": job["sample_sha256"]},
            "steps": steps, "questions": _questions(store, rid)}
    hint = (f"Die Probe liegt bei: sample/{sname}" if sample_bytes is not None else
            "Die Probe liegt NICHT bei. Das Skript fragt nach dem Pfad (oder --sample <Pfad>).")
    readme = README.format(title=" ".join(str(job["title"]).split())[:200], sample_name=sname,
                           sha=job["sample_sha256"], sample_hint=hint)
    files: list[tuple[str, bytes, int]] = [
        ("README.txt", readme.replace("\n", "\r\n").encode("utf-8"), 0o644),
        ("replay.py", SCRIPT.encode("utf-8"), 0o644),
        ("run_replay.cmd", CMD.encode("ascii"), 0o644),
        ("run_replay.sh", SH.encode("ascii"), 0o755),
        ("steps.json", json.dumps(meta, ensure_ascii=False, indent=1).encode("utf-8"), 0o644),
    ]
    if sample_bytes is not None:
        files.append((f"sample/{sname}", sample_bytes, 0o644))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body, mode in files:
            zi = zipfile.ZipInfo(name, _FIXED_TIME)
            zi.external_attr = (0o100000 | mode) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, body)
    return buf.getvalue()


SCRIPT = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Replay der Analyse: wiederholt die Dekodier-Schritte (nur Python-Standardbibliothek, Python >= 3.9).

Die Probe wird nie ausgefuehrt. Keine Code-Auswertung, keine Prozesse, kein Netzwerk. Texte aus steps.json sind reine Daten.
Optionen: --sample PFAD  --no-pause  --out ORDNER
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
import re
import sys
import unicodedata
import urllib.parse
import zipfile
import zlib

MAX_OUT = 8 * 1024 * 1024
MAX_SAMPLE = 64 * 1024 * 1024
LOGICAL = re.compile(r"sample|derived/[A-Za-z0-9_.-]{1,100}")


class DecodeError(Exception):
    pass


# ---------------------------------------------------------------- decoders (same behaviour as the platform)
_B64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_HEXA = b"0123456789abcdefABCDEF"
_ROT13 = bytes.maketrans(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                         b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")


def looks_utf16le(data):
    head = data[:4096]
    if len(head) < 4:
        return False
    pairs = len(head) // 2
    odd_nul = head[1:2 * pairs:2].count(0)
    even_nul = head[0:2 * pairs:2].count(0)
    return odd_nul >= 0.4 * pairs and even_nul <= 0.05 * pairs


def _text_bytes(data):
    if data.startswith(b"\xff\xfe") or looks_utf16le(data):
        body = data[2:] if data.startswith(b"\xff\xfe") else data
        return body.decode("utf-16le", errors="replace").encode("ascii", errors="replace")
    return data


def d_base64(data):
    s = b"".join(_text_bytes(data).split()).strip(b"\"'")
    if not s:
        raise DecodeError("Eingabe leer")
    if b"+" not in s and b"/" not in s:
        s = s.replace(b"-", b"+").replace(b"_", b"/")
    if s.translate(None, _B64):
        raise DecodeError("Zeichen ausserhalb des Base64-Alphabets")
    s = s.rstrip(b"=")
    if len(s) % 4 == 1:
        raise DecodeError("ungueltige Base64-Laenge")
    try:
        return base64.b64decode(s + b"=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("ungueltiges Base64: %s" % exc)


def d_hex(data):
    s = _text_bytes(data)
    s = re.sub(rb"(?i)0x|\\x|[\s,:;]", b"", s)
    if not s:
        raise DecodeError("Eingabe leer")
    if s.translate(None, _HEXA):
        raise DecodeError("kein Hex")
    if len(s) % 2:
        raise DecodeError("ungerade Hex-Ziffern")
    return binascii.unhexlify(s)


def d_url(data):
    s = _text_bytes(data)
    if b"%" not in s:
        raise DecodeError("keine %-Escapes")
    return urllib.parse.unquote_to_bytes(s.decode("latin-1"))


def d_rot13(data):
    return _text_bytes(data).translate(_ROT13)


def _inflate(data, wbits):
    d = zlib.decompressobj(wbits)
    try:
        out = d.decompress(data, MAX_OUT + 1)
    except zlib.error as exc:
        raise DecodeError("keine gueltigen komprimierten Daten (%s)" % exc)
    if len(out) > MAX_OUT:
        raise DecodeError("Ausgabe zu gross (Dekompressionsbombe?)")
    if not out:
        raise DecodeError("Dekompression ohne Daten")
    return out


def d_gzip(data):
    if data[:2] != b"\x1f\x8b":
        raise DecodeError("gzip-Magic fehlt")
    return _inflate(data, 31)


def d_zlib(data):
    try:
        return _inflate(data, 15)
    except DecodeError as first:
        if "Bombe" in str(first):
            raise
        try:
            return _inflate(data, -15)
        except DecodeError:
            raise first


def xor_with(data, key):
    return data.translate(bytes(i ^ key for i in range(256)))


def d_base32(data):
    s = b"".join(_text_bytes(data).split()).strip(b"\"'").upper().rstrip(b"=")
    if not s:
        raise DecodeError("Eingabe leer")
    try:
        return base64.b32decode(s + b"=" * (-len(s) % 8))
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("ungueltiges Base32: %s" % exc)


def d_base85(data):
    s = b"".join(_text_bytes(data).split()).strip(b"\"'")
    if not s:
        raise DecodeError("Eingabe leer")
    try:
        if s.startswith(b"<~") and s.endswith(b"~>"):
            return base64.a85decode(s, adobe=True)
        return base64.b85decode(s)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("ungueltiges Base85: %s" % exc)


_SEP = re.compile(rb"[\s,;]+")
_ITEM = re.compile(rb"(?i)(?:0x[0-9a-f]{1,6}|[0-9]{1,7})")


def d_charcode(data):
    items = [i for i in _SEP.split(_text_bytes(data).strip(b" \t\r\n\"'()[]{}")) if i]
    if not items:
        raise DecodeError("Eingabe leer")
    out = bytearray()
    for item in items:
        if not _ITEM.fullmatch(item):
            raise DecodeError("keine Zeichencode-Liste")
        code = int(item, 0) if item[:2].lower() == b"0x" else int(item)
        if code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
            raise DecodeError("Zeichencode ausserhalb des Bereichs")
        out += chr(code).encode("utf-8")
    return bytes(out)


def xor_key(data, key):
    if len(key) == 1:
        return xor_with(data, key[0])
    stream = (key * (len(data) // len(key) + 1))[:len(data)]
    return (int.from_bytes(data, "little") ^ int.from_bytes(stream, "little")).to_bytes(len(data), "little")


def rc4(data, key):
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


SIMPLE = {"base64": d_base64, "hex": d_hex, "url": d_url, "rot13": d_rot13, "gzip": d_gzip, "zlib": d_zlib,
          "base32": d_base32, "base85": d_base85, "charcode": d_charcode}


def parse_key_hex(h):
    s = str(h).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if not s or len(s) % 2 or not re.fullmatch(r"[0-9a-f]+", s) or len(s) > 128:
        raise DecodeError("ungueltiger Schluessel")
    return bytes.fromhex(s)


def read_member(data, member):
    if (member.startswith("/") or member.startswith("\\") or "\\" in member or ":" in member
            or ".." in member.split("/")):
        raise DecodeError("Elementname abgelehnt")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        with zf:
            info = zf.getinfo(member)
            if info.is_dir() or info.flag_bits & 1:
                raise DecodeError("Element ist Ordner oder verschluesselt")
            with zf.open(info) as f:
                raw = f.read(MAX_OUT + 1)
    except KeyError:
        raise DecodeError("Element nicht im Archiv")
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError, EOFError, ValueError, zlib.error):
        raise DecodeError("Archiv nicht lesbar")
    if len(raw) > MAX_OUT:
        raise DecodeError("Element zu gross")
    if not raw:
        raise DecodeError("Element leer")
    return raw


def run_step(step, data):
    """Pure byte transformation of one step. Returns the output bytes."""
    tool = step["tool"]
    if tool == "extract_range":
        return data[step["offset"]:step["offset"] + step["length"]]
    if tool == "zip_extract":
        return read_member(data, step["member"])
    if tool != "decode_layer":
        raise DecodeError("Werkzeug nicht nachvollziehbar")
    off, ln = step.get("offset", 0), step.get("length", -1)
    chunk = data[off:off + ln] if ln >= 0 else data[off:]
    if not chunk:
        raise DecodeError("keine Eingabebytes")
    m = step["method"]
    if m == "xor_single_byte":
        out = xor_with(chunk, int(step["xor_key"]))
    elif m == "xor_key":
        out = xor_key(chunk, parse_key_hex(step["key_hex"]))
    elif m == "rc4":
        out = rc4(chunk, parse_key_hex(step["key_hex"]))
    elif m in SIMPLE:
        out = SIMPLE[m](chunk)
    else:
        raise DecodeError("Methode nicht nachvollziehbar")
    if not out:
        raise DecodeError("Ergebnis leer")
    if len(out) > MAX_OUT:
        raise DecodeError("Ergebnis zu gross")
    return out


# ---------------------------------------------------------------- output helpers
def clean(text, limit=None):
    """Neutralise control and format characters before anything from the sample is printed."""
    out = []
    for ch in text:
        cat = unicodedata.category(ch)
        if ch in "\r\n\t":
            out.append(" ")
        elif cat in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            out.append(".")
        else:
            out.append(ch)
    s = "".join(out)
    return s if limit is None or len(s) <= limit else s[:limit] + "..."


def preview(data, limit=200):
    head = data[:max(limit * 4, 1024)]
    if head.startswith(b"\xff\xfe") or looks_utf16le(head):
        text = head[2:].decode("utf-16le", errors="replace") if head.startswith(b"\xff\xfe") else head.decode("utf-16le", errors="replace")
    else:
        text = head.decode("utf-8", errors="replace")
    shown = sum(1 for c in text[:limit] if c.isprintable() or c in "\r\n\t")
    if text and shown / max(1, len(text[:limit])) >= 0.85 and "\x00" not in text[:limit]:
        return "Text: " + clean(text, limit)
    hx = " ".join("%02x" % b for b in data[:32])
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:32])
    return "Binaer: %s%s | %s" % (hx, " ..." if len(data) > 32 else "", asc)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def say(text=""):
    sys.stdout.write(text + "\n")


def pause(enabled):
    if not enabled:
        return
    try:
        input("[Enter = weiter] ")
    except EOFError:
        pass


def safe_out_name(logical):
    return logical.split("/", 1)[-1] if logical != "sample" else "sample.bin"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Replay der Analyse (fuehrt die Probe nie aus).")
    ap.add_argument("--sample", help="Pfad zur Originaldatei")
    ap.add_argument("--no-pause", action="store_true", help="nicht auf Enter warten")
    ap.add_argument("--out", help="Ordner, in den die Zwischenstufen geschrieben werden")
    ns = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "steps.json"), encoding="utf-8") as f:
        meta = json.load(f)
    job = meta["job"]
    say("=" * 70)
    say("REPLAY: " + clean(str(job.get("title", "")), 200))
    say("Probe : " + clean(str(job.get("sample_name", "")), 200))
    say("SHA-256 laut Auftrag: " + clean(str(job["sample_sha256"]), 64))
    say("Es werden nur Bytes umgewandelt; die Probe wird nie ausgefuehrt.")
    say("=" * 70)

    path = ns.sample
    if not path and job.get("sample_file") and re.fullmatch(r"[A-Za-z0-9._-]{1,100}", job["sample_file"]):
        cand = os.path.join(here, "sample", job["sample_file"])
        if os.path.isfile(cand):
            path = cand
    if not path:
        try:
            path = input("Pfad zur Originaldatei (%s): " % clean(str(job.get("sample_name", "")), 80)).strip().strip('"')
        except EOFError:
            path = ""
    if not path or not os.path.isfile(path):
        say("ABBRUCH: Originaldatei nicht gefunden.")
        return 2
    if os.path.getsize(path) > MAX_SAMPLE:
        say("ABBRUCH: Datei zu gross.")
        return 2
    with open(path, "rb") as f:
        sample = f.read()
    digest = sha(sample)
    if digest != job["sample_sha256"]:
        say("ABBRUCH: SHA-256 der Datei weicht vom Auftrag ab.")
        say("  Datei  : " + digest)
        say("  Auftrag: " + clean(str(job["sample_sha256"]), 64))
        return 2
    say("Originaldatei: %d Bytes, SHA-256 %s  OK" % (len(sample), digest))
    store = {"sample": sample}
    bad = 0
    steps = meta.get("steps", [])
    say("")
    pause(not ns.no_pause)
    for st in steps:
        say("-" * 70)
        say("Schritt %s/%d: %s (%s)" % (st["n"], len(steps), clean(st["tool"], 40), clean(st["evidence_id"], 20)))
        say("Erklaerung : " + clean(str(st.get("explanation", "")), 400))
        inp, outn = st["input"], st["output"]
        if not LOGICAL.fullmatch(inp) or not LOGICAL.fullmatch(outn):
            say("Nicht nachvollziehbar (ungueltiger Name), siehe Beleg.")
            bad += 1
            pause(not ns.no_pause)
            continue
        say("Eingabe    : %s -> Ausgabe: %s" % (inp, outn))
        if not st.get("supported"):
            say("Nicht nachvollziehbar, siehe Beleg: " + clean(str(st.get("note", "")), 300))
            bad += 1
            pause(not ns.no_pause)
            continue
        if inp not in store:
            say("Eingabe nicht verfuegbar (vorheriger Schritt fehlt).")
            bad += 1
            pause(not ns.no_pause)
            continue
        try:
            out = run_step(st, store[inp])
        except DecodeError as exc:
            say("FEHLER: " + clean(str(exc), 200))
            bad += 1
            pause(not ns.no_pause)
            continue
        h = sha(out)
        store[outn] = out
        ok = h == st["output_sha256"]
        bad += 0 if ok else 1
        say("Groesse    : %d Bytes" % len(out))
        say("SHA-256    : %s" % h)
        say("Pruefung   : %s" % ("OK (gleich wie in der Analyse)" if ok else
                                 "ABWEICHUNG (Analyse: %s)" % clean(str(st["output_sha256"]), 64)))
        say("Vorschau   : " + preview(out))
        if ns.out:
            os.makedirs(ns.out, exist_ok=True)
            with open(os.path.join(ns.out, safe_out_name(outn)), "wb") as f:
                f.write(out)
        pause(not ns.no_pause)

    say("=" * 70)
    say("ERGEBNIS: %d Schritt(e), %d ohne Bestaetigung" % (len(steps), bad))
    for q in meta.get("questions", []):
        say("")
        say("Frage %s: %s" % (clean(str(q["id"]), 40), clean(str(q["text"]), 400)))
        say("  Status : " + clean(str(q["status"]), 40))
        say("  Antwort: " + clean(str(q["answer"]), 1000))
        if q.get("expected"):
            say("  Sollwert: " + clean(str(q["expected"]), 300))
        for fd in q.get("findings", []):
            say("  Befund %s (%s): %s" % (clean(str(fd["id"]), 20), clean(str(fd["status"]), 20),
                                           clean(str(fd["statement"]), 500)))
            for qu in fd.get("quotes", []):
                needle = str(qu["quote"])
                where = []
                if needle:
                    for name in store:
                        blob = store[name]
                        if needle.encode("utf-8", "replace") in blob or needle.encode("utf-16le", "replace") in blob:
                            where.append(name)
                verdict = ("im reproduzierten Inhalt gefunden: " + ", ".join(where)) if where else \
                    "nicht in den reproduzierten Bytes (Beleg stammt aus Werkzeugausgabe)"
                say("    Zitat (%s): %s" % (clean(str(qu["evidence_id"]), 20), clean(needle, 200)))
                say("      -> " + verdict)
    say("")
    say("Fertig." if not bad else "Fertig mit Abweichungen oder nicht nachvollziehbaren Schritten.")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
'''
