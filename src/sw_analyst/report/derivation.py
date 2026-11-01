"""R5a derivation section: per target question, how the answer was reached from the input data (stored data only).

Tool explanations come from a fixed table, never from the model. Every text from sample, model or store passes the
builder helpers (_cell/_tok/_para/_hex), so defanging and Markdown protection apply as everywhere else in the report.
"""
from __future__ import annotations

_TOOLS = {
    "sample_info": ("Reads size, timestamps and the file header of the sample without changing it.",
                    "Liest Größe, Zeitstempel und Dateikopf der Probe, ohne sie zu verändern."),
    "hash_file": ("Computes cryptographic hashes over the exact bytes of the file; the hash identifies the file uniquely.",
                  "Berechnet kryptografische Hashes über die exakten Bytes der Datei; der Hash identifiziert die Datei eindeutig."),
    "identify_type": ("Determines the file type from magic bytes and structure, independent of the file name.",
                      "Bestimmt den Dateityp aus Magic Bytes und Struktur, unabhängig vom Dateinamen."),
    "entropy_map": ("Computes the Shannon entropy per block; high values indicate packed, encrypted or compressed regions.",
                    "Berechnet die Shannon-Entropie je Block; hohe Werte deuten auf gepackte, verschlüsselte oder komprimierte Bereiche."),
    "strings_extract": ("Extracts printable ASCII and UTF-16 character runs of a minimum length from the bytes.",
                        "Extrahiert druckbare ASCII- und UTF-16-Zeichenfolgen ab einer Mindestlänge aus den Bytes."),
    "hexdump": ("Shows the raw bytes of a range as hexadecimal values with an ASCII column.",
                "Zeigt die Rohbytes eines Bereichs als Hexadezimalwerte mit ASCII-Spalte."),
    "read_lines": ("Reads a line range of a text file verbatim.",
                   "Liest einen Zeilenbereich einer Textdatei unverändert."),
    "grep": ("Searches the content for a pattern and returns the matching lines with their position.",
             "Durchsucht den Inhalt nach einem Muster und liefert die Trefferzeilen mit Position."),
    "script_detect": ("Recognises the script language and typical obfuscation markers by static pattern matching.",
                      "Erkennt die Skriptsprache und typische Verschleierungsmerkmale durch statische Mustersuche."),
    "decode_layer": ("Decodes one encoding layer (for example Base64 or hex) and stores the result as a derived file; nothing is executed.",
                     "Dekodiert eine Kodierungsschicht (etwa Base64 oder Hex) und legt das Ergebnis als abgeleitete Datei ab; nichts wird ausgeführt."),
    "extract_range": ("Cuts a byte range out of a file and stores it as a derived file with its own hash.",
                      "Schneidet einen Bytebereich aus einer Datei und legt ihn als abgeleitete Datei mit eigenem Hash ab."),
    "zip_extract": ("Unpacks one archive member into a derived file without executing it.",
                    "Entpackt ein Archivelement in eine abgeleitete Datei, ohne es auszuführen."),
    "pe_resources": ("Parses the resource directory of a PE file and lists embedded resources such as icons, manifests or blobs.",
                     "Parst das Ressourcenverzeichnis einer PE-Datei und listet eingebettete Ressourcen wie Symbole, Manifeste oder Blobs."),
    "apk_manifest": ("Reads the Android manifest: package name, permissions, components and entry points.",
                     "Liest das Android-Manifest: Paketname, Berechtigungen, Komponenten und Einstiegspunkte."),
    "pe_headers": ("Parses the PE headers: architecture, sections, imports, exports and compile timestamp.",
                   "Parst die PE-Header: Architektur, Sektionen, Importe, Exporte und Kompilierzeitstempel."),
    "zip_list": ("Lists the members of a ZIP-based archive with names and sizes without unpacking.",
                 "Listet die Elemente eines ZIP-basierten Archivs mit Namen und Größen, ohne zu entpacken."),
    "zip_read_text": ("Reads a text member of an archive directly, without extracting it to disk.",
                      "Liest ein Textelement eines Archivs direkt, ohne es auf die Platte zu entpacken."),
    "list_functions": ("Lists the functions found by static disassembly with address and size.",
                       "Listet die per statischer Disassemblierung gefundenen Funktionen mit Adresse und Größe."),
    "disassemble": ("Translates machine code at an address into assembly instructions; the code is not run.",
                    "Übersetzt Maschinencode an einer Adresse in Assembler-Anweisungen; der Code wird nicht ausgeführt."),
    "decompile": ("Reconstructs pseudo source code of a function from the machine code; the result is an approximation.",
                  "Rekonstruiert Pseudo-Quelltext einer Funktion aus dem Maschinencode; das Ergebnis ist eine Näherung."),
    "xrefs": ("Finds the places that reference an address, function or string (cross references).",
              "Findet die Stellen, die auf eine Adresse, Funktion oder Zeichenfolge verweisen (Querverweise)."),
    "basic_blocks": ("Splits a function into basic blocks and shows the control flow between them.",
                     "Zerlegt eine Funktion in Basisblöcke und zeigt den Kontrollfluss zwischen ihnen."),
    "capa_scan": ("Matches the program against capability rules (capa) and reports behaviours such as network or file access.",
                  "Gleicht das Programm mit Fähigkeitsregeln (capa) ab und meldet Verhalten wie Netzwerk- oder Dateizugriff."),
    "floss_decode": ("Finds and statically decodes obfuscated strings (FLOSS) without running the program.",
                     "Findet und dekodiert verschleierte Zeichenfolgen (FLOSS) statisch, ohne das Programm auszuführen."),
    "yara_scan": ("Matches the bytes against YARA rules and reports which rules hit and where.",
                  "Gleicht die Bytes mit YARA-Regeln ab und meldet, welche Regeln wo treffen."),
    "jadx_decompile": ("Decompiles Android bytecode to Java source (jadx); the code is not run.",
                       "Dekompiliert Android-Bytecode zu Java-Quelltext (jadx); der Code wird nicht ausgeführt."),
}
_FALLBACK = ("Static analysis tool of the platform; its exact output is stored under the evidence ID.",
             "Statisches Analysewerkzeug der Plattform; die genaue Ausgabe liegt unter der Beleg-ID.")

_X = {
    "de": {"intro": "Für jede Zielfrage: von den Eingangsdaten über die angewandten Werkzeuge bis zur Antwort. Jeder Schritt nennt Werkzeug, Version, Eingabe, Parameter und Beleg; die Werkzeugerklärungen stammen aus einer festen Tabelle, nicht vom Modell.",
           "h1": "1. Ausgangsdaten", "h2": "2. Technischer Weg", "h3": "3. Erkenntnisse aus den Belegen",
           "h4": "4. Bedeutung für die Fragestellung", "h5": "5. Darstellung des Modells (ungeprüft)",
           "sample": "Probe", "type": "Typ/Rezept", "question": "Frage", "expected": "Sollwert", "on": "auf",
           "nocalls": "keine Werkzeugaufrufe", "tech": "Technik", "task": "Aufgabe", "made": "Erzeugt",
           "quote": "Zitat aus", "nofind": "keine Befunde", "answer": "Antwort", "limits": "Grenzen",
           "bound": "Belegt ist nur, was die Zitate zeigen; die Deutung stammt vom Modell und ist an die Zitate gebunden."},
    "en": {"intro": "For each target question: from the input data through the applied tools to the answer. Each step names tool, version, input, parameters and evidence; the tool explanations come from a fixed table, not from the model.",
           "h1": "1. Input data", "h2": "2. Technical path", "h3": "3. Findings from the evidence",
           "h4": "4. Meaning for the question", "h5": "5. Model's account (unverified)",
           "sample": "Sample", "type": "Type/recipe", "question": "Question", "expected": "Expected value", "on": "on",
           "nocalls": "no tool calls", "tech": "Technique", "task": "Task", "made": "Produced",
           "quote": "Quote from", "nofind": "no findings", "answer": "Answer", "limits": "Limits",
           "bound": "Only what the quotes show is proven; the interpretation comes from the model and is bound to the quotes."},
}


def _bt(b, s) -> str:
    return b._cell(s).replace("`", "'")


def derivation_lines(store, job_id: str, lang: str, t: dict, txt) -> list[str]:
    from sw_analyst.report import builder as b   # lazy: avoids a circular import with builder
    x = _X["de" if lang == "de" else "en"]
    idx = 1 if lang == "de" else 0
    job = store.get_job(job_id)
    tasks = {k["id"]: k for k in store.list_tasks(job_id)}
    ev_rows = store.list_evidence(job_id)
    ev_cache: dict = {}

    def ev(eid):
        if eid not in ev_cache:
            ev_cache[eid] = store.get_evidence(eid)
        return ev_cache[eid]

    producers: dict[str, list[str]] = {}
    for row in ev_rows:
        e = ev(row["id"])
        d = (e.get("source_ref") or {}).get("derived") if e else None
        if d:
            producers.setdefault(str(d), []).append(e["id"])

    def closure(seed: list[str]) -> list[str]:
        seen: set[str] = set()
        todo = list(seed)
        while todo:
            eid = todo.pop()
            if eid in seen or not ev(eid):
                continue
            seen.add(eid)
            path = (ev(eid).get("params") or {}).get("path")
            if isinstance(path, str) and path.startswith("derived/"):
                todo += [p for p in producers.get(path, []) if p not in seen]
        return sorted(seen)

    stat = {"confirmed": t["confirmed"], "hypothesis": t["hypothesis"], "open": t["open_s"], "rejected": t["rejected"]}

    def st(s):
        return stat.get(s) or b._tok(s)

    out = ["", f"## {t['derive']}", "", x["intro"], ""]
    for a in store.list_answers(job_id):
        qid = a["question_id"]
        qtask = next((k for k in tasks.values() if k["kind"] == "question"
                      and (k.get("params") or {}).get("question_id") == qid), None)
        findings = [f for f in (store.get_finding(i) for i in a["finding_ids"]) if f]
        seed = [e for f in findings for e in f["evidence_ids"]]
        if not findings and qtask:
            seed = [r["id"] for r in ev_rows if r["task_id"] == qtask["id"]]
        eids = closure(seed)
        out += [f"### {b._tok(qid)}: {b._cell(a['text_orig'])}", ""]

        out += [f"**{x['h1']}**", "",
                f"- {x['sample']}: {b._cell(job['sample_name'])}, SHA-256 `{b._hex(job['sample_sha256'])}`",
                f"- {x['type']}: {b._tok(job['detected_type']) or '-'} / {b._tok(job['recipe']) or '-'}",
                f"- {x['question']}: {b._cell(a['text_orig'])}"]
        if a["expected"]:
            out.append(f"- {x['expected']}: `{_bt(b, a['expected'])}`")
        out += ["", f"**{x['h2']}**", ""]
        if not eids:
            out.append(f"- {x['nocalls']}")
        for n, eid in enumerate(eids, 1):
            e = ev(eid)
            params = dict(e.get("params") or {})
            path = params.pop("path", None)
            rest = ", ".join(f"{k}={v}" for k, v in params.items())[:120]
            line = f"{n}. {b._tok(e['tool'])} ({b._tok(e['tool_version'])})"
            if path is not None:
                line += f" {x['on']} `{_bt(b, path)}`"
            if rest:
                line += f" {_bt(b, rest)}"
            line += f" → {b._tok(eid)}, SHA-256 `{b._hex((e['result_sha256'] or '')[:16])}…`"
            out.append(line)
            out.append(f"   - {x['tech']}: {_TOOLS.get(e['tool'], _FALLBACK)[idx]}")
            tk = tasks.get(e.get("task_id"))
            if tk:
                why = f": {b._cell(tk['reason'])}" if tk.get("reason") else ""
                out.append(f"   - {x['task']}: {b._tok(tk['id'])} {b._cell(tk['title'])} ({b._tok(tk['origin'])}{why})")
            sr = e.get("source_ref") or {}
            if sr.get("derived"):
                out.append(f"   - {x['made']}: `{_bt(b, sr['derived'])}` (SHA-256 `{b._hex(str(sr.get('sha256', ''))[:16])}…`)")

        out += ["", f"**{x['h3']}**", ""]
        for f in findings:
            line = f"- {b._tok(f['id'])} ({st(f['status'])}): {b._cell(txt(f['statement_en'], f['statement_de']))}"
            for q in f["quotes"]:
                line += f" — {x['quote']} {b._tok(q.get('evidence_id'))}: `{_bt(b, q.get('quote'))[:240]}`"
            out.append(line)
        if not findings:
            out.append(f"- {x['nofind']}")

        out += ["", f"**{x['h4']}**", ""]
        if a["status"] == "answered":
            out.append(f"- {x['answer']}: {b._cell(txt(a['answer_en'], a['answer_de']))}")
        else:
            label = t["unresolved"] if a["status"] == "unresolved" else b._tok(a["status"])
            out.append(f"- {label}: {b._cell(txt(a['evaluation_en'], a['evaluation_de']))}")
        if a["expected"]:
            m = {1: t["yes"], 0: t["no"], None: t["na"]}.get(a["match"], t["na"])
            out.append(f"- {t['expected']}: `{_bt(b, a['expected'])}` - {t['match']}: {m}")
        involved = {i for i in [qtask["id"] if qtask else None, *[ev(i).get("task_id") for i in eids],
                                *[f["task_id"] for f in findings]] if i}
        limits = [f for f in store.list_findings(job_id) if f["status"] in ("hypothesis", "open") and f["task_id"] in involved]
        if limits:
            out.append(f"- {x['limits']}:")
            out += [f"  - {b._tok(f['id'])} ({st(f['status'])}): {b._cell(txt(f['statement_en'], f['statement_de']))}" for f in limits]
        out.append(f"- {x['bound']}")

        summ = ""
        if qtask and (qtask.get("summary_en") or qtask.get("summary_de")):
            summ = txt(qtask.get("summary_en") or "", qtask.get("summary_de") or "")
        if summ:
            out += ["", f"**{x['h5']}**", "", b._para(summ)]
        out.append("")
    return out
