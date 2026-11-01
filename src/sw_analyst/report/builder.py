"""Report builder: assembles the forensic report from stored data (docs/blueprint/13-report-writing.md).

Sections follow the R-ids of the blueprint: R2 custody, R3 detection log, R4 findings with proof, R5 answers to the
target questions, plus IOCs, open questions, method/timeline and an evidence appendix. The same builder produces the
live report of a running job. Free text is defanged; payload-like blobs are redacted.
"""
from __future__ import annotations

import re

from sw_analyst.common.audit import verify_file
from sw_analyst.common.store import Store
from sw_analyst.prompts.registry import PROMPT_PACK_VERSION, list_prompts
from sw_analyst.report.defang import defang_text, find_iocs, redact_payloads

T = {
    "de": {
        "title": "Forensischer Analysebericht", "live": "LIVE-STAND (Analyse läuft noch)", "summary": "Zusammenfassung",
        "custody": "R2 Übergabe und Chain of Custody", "detect": "R3 Erkennungsprotokoll je Schritt der Toolkette",
        "findings": "R4 Befunde mit Nachweis", "answers": "R5 Beantwortung der Zielfragen", "iocs": "Indikatoren (entschärft)",
        "open": "Offene Fragen und Hypothesen", "method": "Methodik, Werkzeuge und Zeitverlauf", "appendix": "Anhang: Belegtabelle",
        "job": "Auftrag", "description": "Beschreibung", "context": "Weitere Informationen", "focus": "Fokus",
        "sample": "Probe", "type": "Erkannter Typ", "recipe": "Rezept", "status": "Status", "started": "Beginn (UTC)",
        "finished": "Ende (UTC)", "duration": "Dauer", "audit": "Audit-Kette", "valid": "gültig", "broken": "UNGÜLTIG ab Eintrag",
        "model": "Modell", "prompts": "Prompt-Version", "guard": "Prompt-Schutz-Ereignisse", "task": "Aufgabe", "tool": "Werkzeug",
        "result": "Ergebnis", "evidence": "Beleg", "time": "Zeit", "statement": "Aussage", "quote": "Zitat", "none": "keine",
        "question": "Frage", "answer": "Antwort", "expected": "Erwartet", "match": "Abgleich", "yes": "übereinstimmend",
        "no": "abweichend", "na": "kein Sollwert", "unresolved": "NICHT KLÄRBAR", "answered": "beantwortet",
        "confirmed": "bestätigt", "hypothesis": "Hypothese", "open_s": "offen", "rejected": "verworfen",
        "self_eval": "Ziel (Selbstbewertung des Modells)", "reached": "erreicht", "not_reached": "nicht erreicht", "not_rated": "nicht bewertet", "done_when": "Abnahmekriterium", "origin": "Herkunft", "reason": "Begründung",
        "refuted": "widerlegt", "closed": "Geschlossen", "code": "R6 Code-Auszüge (Ghidra)",
        "no_disasm": "Keine Disassembly erhoben: Das Ghidra-Image fehlte oder der Lauf war älter als dieser Schritt.",
        "cut": "gekürzt, vollständig im Beleg",
        "untranslated": "[EN]", "limits": "Grenzen: rein statische Analyse, offline, lokales Modell. Aussagen ohne Beleg wurden verworfen oder als Hypothese geführt; offene Punkte sind keine Aussagen und haben keinen Beleg.",
        "derived": "Abgeleitete Dateien (Herkunft, Hash)", "file": "Datei", "from": "aus",
        "rejected_h": "Anhang: verworfene Aussagen des Modells",
        "rejected_note": "Diese Aussagen bestanden die Belegprüfung nicht und sind keine Ergebnisse dieses Berichts. Sie stehen hier, damit nachvollziehbar bleibt, was das Modell behauptet hat und warum es verworfen wurde.",
    },
    "en": {
        "title": "Forensic Analysis Report", "live": "LIVE STATE (analysis still running)", "summary": "Summary",
        "custody": "R2 Hand-over and chain of custody", "detect": "R3 Detection log per toolchain step",
        "findings": "R4 Findings with proof", "answers": "R5 Answers to the target questions", "iocs": "Indicators (defanged)",
        "open": "Open questions and hypotheses", "method": "Method, tools and timeline", "appendix": "Appendix: evidence table",
        "job": "Job", "description": "Description", "context": "Further information", "focus": "Focus",
        "sample": "Sample", "type": "Detected type", "recipe": "Recipe", "status": "Status", "started": "Started (UTC)",
        "finished": "Finished (UTC)", "duration": "Duration", "audit": "Audit chain", "valid": "valid", "broken": "INVALID from entry",
        "model": "Model", "prompts": "Prompt version", "guard": "Prompt-guard events", "task": "Task", "tool": "Tool",
        "result": "Result", "evidence": "Evidence", "time": "Time", "statement": "Statement", "quote": "Quote", "none": "none",
        "question": "Question", "answer": "Answer", "expected": "Expected", "match": "Comparison", "yes": "matches",
        "no": "differs", "na": "no expected value", "unresolved": "NOT DETERMINABLE", "answered": "answered",
        "confirmed": "confirmed", "hypothesis": "hypothesis", "open_s": "open", "rejected": "rejected",
        "self_eval": "Goal (model's self-assessment)", "reached": "reached", "not_reached": "not reached", "not_rated": "not rated", "done_when": "Acceptance criterion", "origin": "origin", "reason": "reason",
        "refuted": "refuted", "closed": "Closed", "code": "R6 Code excerpts (Ghidra)",
        "no_disasm": "No disassembly collected: the Ghidra image was missing or the run predates this step.",
        "cut": "cut, complete in the evidence",
        "untranslated": "", "limits": "Limits: static analysis only, offline, local model. Statements without evidence were rejected or kept as hypotheses; open points are not statements and have no evidence.",
        "derived": "Derived files (origin, hash)", "file": "File", "from": "from",
        "rejected_h": "Appendix: rejected statements of the model",
        "rejected_note": "These statements failed the evidence check and are not results of this report. They are listed so that what the model claimed, and why it was rejected, stays on record.",
    },
}


def _cell(s) -> str:
    text = re.sub(r"[\r\n]", " ", defang_text(redact_payloads(str(s if s is not None else ""))))
    text = re.sub(r"(\\*)\|", lambda m: m.group(1) * 2 + "\\|", text)   # backslashes before a pipe must not cancel its escape
    # shortcut: "<x" reads "< x" in the report (exact text stays in the evidence), until reports get a real Markdown sanitizer.
    # The space stops raw HTML in foreign viewers; "&lt;" would show literally in the dashboard.
    return re.sub(r"<(?=[A-Za-z/!?])", "< ", text)


_TOKEN = re.compile(r"[A-Za-z0-9_.:@+/-]{0,80}")
_BLOCK_START = re.compile(r"^(\s*)([#>|*+=`~-]|\d+[.)])")


def _tok(s) -> str:
    """IDs, status words, tool names, timestamps: unchanged when they look like one, otherwise through _cell.
    Rows of an imported analysis are foreign input; a status such as '## Gutachten' must not become a heading."""
    text = "" if s is None else str(s)
    return text if _TOKEN.fullmatch(text) else _cell(text)


def _hex(s) -> str:
    text = "" if s is None else str(s)
    return text if re.fullmatch(r"[0-9a-fA-F]{0,128}", text) else "-"


def _para(s) -> str:
    """A cell value that stands at the start of a line: a leading Markdown block marker is escaped."""
    return _BLOCK_START.sub(lambda m: m.group(1) + "\\" + m.group(2), _cell(s))


_CODE_TOOLS = {"list_functions": "text", "disassemble": "asm", "decompile": "c"}
_CODE_LINES = 200
_CODE_BLOCKS = 12
_CODE_LINE = 500
_CODE_WARNINGS = 5
_DECODED_FIELD = re.compile(r"(field )(\S+=\S+)")


def _tool_warnings(text: str) -> list[str]:
    """Lines read by hand: tool output holds sample text, a regex over it could backtrack for long."""
    found = (line.partition("WARNING:")[2].strip().removesuffix("*/").strip()[:200] for line in text.splitlines() if "WARNING:" in line)
    return list(dict.fromkeys(w for w in found if w))[:_CODE_WARNINGS]


def _code_section(evidence: list[dict], t: dict) -> list[str]:
    """Tool output as code blocks: same defanging as every other text, no fence can be closed from inside."""
    rows = [e for e in evidence if e["tool"] in _CODE_TOOLS and not e["text"].startswith("[tool error]")]
    if not rows:
        return []
    out = ["", f"## {t['code']}", ""]
    if not any(e["tool"] == "disassemble" for e in rows):
        out += [f"> [!NOTE] {t['no_disasm']}", ""]
    for e in rows[:_CODE_BLOCKS]:
        lines = defang_text(redact_payloads(e["text"])).replace("`", "'").splitlines()
        version = re.sub(r"\s+", "_", _tok(e["tool_version"]))
        out += [f"```{_CODE_TOOLS[e['tool']]} ev={_tok(e['id'])} tool={_tok(e['tool'])} version={version} sha256={_hex(e['result_sha256'])}"]
        out += [line[:_CODE_LINE] for line in lines[:_CODE_LINES]]
        if len(lines) > _CODE_LINES:
            out.append(f"[... {len(lines) - _CODE_LINES} {t['cut']}]")
        out += ["```", ""]
        warnings = _tool_warnings(e["text"])
        out += [f"> [!WARNING] {_tok(e['id'])}: {_cell(w)}" for w in warnings] + ([""] if warnings else [])
    return out


def _dur(ms: int) -> str:
    s = (ms or 0) / 1000
    return f"{s:.1f} s" if s < 120 else f"{s / 60:.1f} min"


def build_report(store: Store, job_id: str, lang: str = "de", model_name: str = "") -> str:
    t = T["de" if lang == "de" else "en"]
    de = lang == "de"
    job = store.get_job(job_id)
    if not job:
        raise KeyError(job_id)
    spec = job["spec"]
    live = job["status"] in ("queued", "running")
    tasks = [x for x in store.list_tasks(job_id) if x["kind"] != "group"]
    findings = store.list_findings(job_id)
    answers = store.list_answers(job_id)
    evidence = [store.get_evidence(e["id"]) for e in store.list_evidence(job_id)]
    audit = verify_file(store.audit_path(job_id))

    def txt(en: str, de_txt: str) -> str:
        if not de:
            return en
        return de_txt if de_txt else f"{t['untranslated']} {en}"

    out: list[str] = [f"# {t['title']} {_tok(job['id'])}: {_cell(spec.get('title'))}"]
    if live:
        out += ["", f"> **{t['live']}**"]
    out += ["", f"## {t['summary']}", "", _para(txt(job["summary_en"], job["summary_de"])) or "-", "", t["limits"]]

    out += ["", f"## {t['job']}", ""]
    for label, key in (("description", "description"), ("context", "context_info"), ("focus", "focus")):
        if spec.get(key):
            out.append(f"- **{t[label]}:** {_cell(spec[key])}")
    for q in spec["target_questions"]:
        out.append(f"- **{_tok(q['id'])}:** {_cell(q['text_orig'])}")

    out += ["", f"## {t['custody']}", "",
            f"| | |", "|---|---|",
            f"| {t['sample']} | {_cell(job['sample_name'])} |",
            f"| SHA-256 | `{_hex(job['sample_sha256'])}` |",
            f"| {t['type']} / {t['recipe']} | {_tok(job['detected_type']) or '-'} / {_tok(job['recipe']) or '-'} |",
            f"| {t['status']} | {_tok(job['status'])} |",
            f"| {t['started']} / {t['finished']} | {_tok(job['started_at']) or '-'} / {_tok(job['finished_at']) or '-'} |",
            f"| {t['duration']} | {_dur(job['duration_ms'])} |",
            f"| {t['model']} | {_tok(model_name) or '-'} |",
            f"| {t['prompts']} | {PROMPT_PACK_VERSION} ({', '.join(p['id'] + ':' + p['sha256'][:8] for p in list_prompts())}) |",
            f"| {t['audit']} | {t['valid'] if audit.valid else t['broken'] + ' ' + str(audit.broken_at)}; {audit.entries} entries; head `{_hex(audit.head_hash[:16])}` |"]
    hashes = [e for e in evidence if e["tool"] in ("hash_file", "decode_layer", "sample_info")]
    if hashes:
        out += ["", f"| {t['evidence']} | {t['tool']} | SHA-256 |", "|---|---|---|"]
        out += [f"| {_tok(e['id'])} | {_tok(e['tool'])} | `{_hex(e['result_sha256'])}` |" for e in hashes]
    derived = [e for e in evidence if (e["source_ref"] or {}).get("derived") and (e["source_ref"] or {}).get("sha256")]
    if derived:
        out += ["", f"**{t['derived']}**", "", f"| {t['file']} | {t['from']} | {t['tool']} | bytes | SHA-256 | {t['evidence']} |",
                "|---|---|---|---|---|---|"]
        for e in derived:
            m, src = e["source_ref"], (e["source_ref"].get("source_ref") or {})
            how = _tok(e["tool"]) + (f" {_tok(m['method'])}" if m.get("method") else "")
            origin = f"{_cell(src.get('file', '-'))} @{_tok(src.get('offset', '-'))}+{_tok(src.get('length', '-'))}"
            out.append(f"| {_cell(m['derived'])} | {origin} | {how} | {_tok(m.get('size', '-'))} | `{_hex(m['sha256'])}` | {_tok(e['id'])} |")

    out += ["", f"## {t['detect']}", "", f"| # | {t['task']} | {t['tool']} | {t['result']} | {t['evidence']} | {t['time']} |",
            "|---|---|---|---|---|---|"]
    for tk in tasks:
        for s in store.list_steps(tk["id"]):
            if s["kind"] == "tool":
                out.append(f"| {_tok(tk['id'])}.{_tok(s['idx'])} | {_cell(tk['title'])} | {_tok(s['tool'])} | {_cell((s['output_preview'] or '').splitlines()[0] if s['output_preview'] else '')[:120]} | {_tok(s['evidence_id'])} | {_dur(s['duration_ms'])} |")

    out += ["", f"## {t['findings']}", ""]
    stat_name = {"confirmed": t["confirmed"], "hypothesis": t["hypothesis"], "open": t["open_s"], "rejected": t["rejected"]}
    for status in ("confirmed", "hypothesis"):   # open points have no proof, they stay in the section of their own
        rows = [f for f in findings if f["status"] == status]
        if not rows:
            continue
        out += [f"### {stat_name[status]}", ""]
        for f in rows:
            statement = _cell(txt(f["statement_en"], f["statement_de"]))
            out.append(f"- **{_tok(f['id'])}** ({', '.join(_tok(x) for x in f['evidence_ids']) or t['none']}): "
                       + (_DECODED_FIELD.sub(r"\1==\2==", statement) if f["statement_en"].startswith("Decoded configuration") else statement))
            for q in f["quotes"]:
                out.append(f"  - {_tok(q.get('evidence_id'))}: `{_cell(q.get('quote')).replace('`', chr(39))[:240]}`")
            if f["reject_reason"]:
                out.append(f"  - _{_cell(f['reject_reason'])}_")
        out.append("")
    refuted = [f for f in findings if f["status"] == "rejected" and f["reject_reason"].startswith("refuted")]
    if refuted:
        out += [f"### {t['refuted']}", ""]
        out += [f"- **{_tok(f['id'])}**: {_cell(txt(f['statement_en'], f['statement_de']))}\n  - _{_cell(f['reject_reason'])}_" for f in refuted]
        out.append("")

    out += [f"## {t['answers']}", ""]
    for a in answers:
        out += [f"### {_tok(a['question_id'])}: {_cell(a['text_orig'])}", ""]
        if a["status"] == "answered":
            out.append(f"**{t['answer']}:** {_cell(txt(a['answer_en'], a['answer_de']))}")
            out.append(f"- {t['evidence']}: {', '.join(_tok(x) for x in a['finding_ids']) or t['none']}")
        else:
            out.append(f"**{t['unresolved'] if a['status'] == 'unresolved' else _tok(a['status'])}** - {_cell(txt(a['evaluation_en'], a['evaluation_de']))}")
        if a["expected"]:
            m = {1: t["yes"], 0: t["no"], None: t["na"]}.get(a["match"], t["na"])
            out.append(f"- {t['expected']}: `{_cell(a['expected']).replace('`', chr(39))}` - {t['match']}: {m}")
        out.append("")

    iocs: dict[tuple, None] = {}
    for f in findings:
        if f["status"] == "confirmed":
            for i in find_iocs(f["statement_en"]):
                iocs[(i["kind"], defang_text(i["value"]))] = None
    out += [f"## {t['iocs']}", ""]
    out += [f"- {k}: `{v}`" for k, v in iocs] or [f"- {t['none']}"]

    out += ["", f"## {t['open']}", ""]
    ops = [f for f in findings if f["status"] in ("hypothesis", "open")]
    out += [f"- {_tok(f['id'])}: {_cell(txt(f['statement_en'], f['statement_de']))}" for f in ops] or [f"- {t['none']}"]
    closed = [f for f in findings if f["status"] == "closed"]
    if closed:
        out += ["", f"### {t['closed']}", ""]
        out += [f"- {_tok(f['id'])}: {_cell(txt(f['statement_en'], f['statement_de']))} (_{_cell(f['reject_reason'])}_)" for f in closed]

    out += _code_section(evidence, t)

    out += ["", f"## {t['method']}", "", f"| {t['task']} | {t['status']} | {t['origin']} | {t['self_eval']} | {t['duration']} | {t['reason']} | {t['done_when']} |", "|---|---|---|---|---|---|---|"]
    out += [f"| {_tok(x['id'])} {_cell(x['title'])} | {_tok(x['status'])} | {_tok(x['origin'])} | {({True: t['reached'], False: t['not_reached']}.get(x['params'].get('goal_reached'), t['not_rated']))} | {_dur(x['duration_ms'])} | {_cell(x['reason'])[:100]} | {_cell(x['params'].get('done_when'))[:100]} |" for x in tasks]
    guard = store.list_guard_events(job_id)
    out += ["", f"**{t['guard']}:** {len(guard)}"]
    out += [f"- {_tok(g['stage'])}/{_tok(g['rule'])} ({_tok(g['severity'])}, {_tok(g['action'])}): `{_cell(g['snippet']).replace('`', chr(39))[:100]}`" for g in guard[:20]]

    out += ["", f"## {t['appendix']}", "", f"| ID | {t['tool']} | version | SHA-256 | bytes |", "|---|---|---|---|---|"]
    out += [f"| {_tok(e['id'])} | {_tok(e['tool'])} | {_tok(e['tool_version'])} | `{_hex(e['result_sha256'][:16])}...` | {len(e['text'])} |" for e in evidence]
    rejected = [f for f in findings if f["status"] == "rejected" and not f["reject_reason"].startswith("refuted")]
    if rejected:   # what the model claimed and could not prove: no statement of the report, but part of the record
        out += ["", f"## {t['rejected_h']}", "", t["rejected_note"], ""]
        out += [f"- {_tok(f['id'])} ({_tok(f['task_id'])}): {_cell(txt(f['statement_en'], f['statement_de']))}\n  - _{_cell(f['reject_reason'])}_"
                for f in rejected]
    return "\n".join(out) + "\n"
