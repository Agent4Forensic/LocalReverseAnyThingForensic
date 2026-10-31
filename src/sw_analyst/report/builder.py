"""Report builder: assembles the forensic report from stored data (docs/blueprint/13-report-writing.md).

Sections follow the R-ids of the blueprint: R2 custody, R3 detection log, R4 findings with proof, R5 answers to the
target questions, plus IOCs, open questions, method/timeline and an evidence appendix. The same builder produces the
live report of a running job. Free text is defanged; payload-like blobs are redacted.
"""
from __future__ import annotations

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
        "self_eval": "Ziel (Selbstbewertung des Modells)", "reached": "erreicht", "not_reached": "nicht erreicht", "not_rated": "nicht bewertet",
        "untranslated": "[EN]", "limits": "Grenzen: rein statische Analyse, offline, lokales Modell. Aussagen ohne Beleg wurden verworfen oder als Hypothese geführt; offene Punkte sind keine Aussagen und haben keinen Beleg.",
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
        "self_eval": "Goal (model's self-assessment)", "reached": "reached", "not_reached": "not reached", "not_rated": "not rated",
        "untranslated": "", "limits": "Limits: static analysis only, offline, local model. Statements without evidence were rejected or kept as hypotheses; open points are not statements and have no evidence.",
    },
}


def _cell(s) -> str:
    return defang_text(redact_payloads(str(s if s is not None else ""))).replace("|", "\\|").replace("\n", " ")


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

    out: list[str] = [f"# {t['title']} {job['id']}: {_cell(spec.get('title') if not de else spec.get('title'))}"]
    if live:
        out += ["", f"> **{t['live']}**"]
    out += ["", f"## {t['summary']}", "", _cell(txt(job["summary_en"], job["summary_de"])) or "-", "", t["limits"]]

    out += ["", f"## {t['job']}", ""]
    for label, key in (("description", "description"), ("context", "context_info"), ("focus", "focus")):
        if spec.get(key):
            out.append(f"- **{t[label]}:** {_cell(spec[key])}")
    for q in spec["target_questions"]:
        out.append(f"- **{q['id']}:** {_cell(q['text_orig'])}")

    out += ["", f"## {t['custody']}", "",
            f"| | |", "|---|---|",
            f"| {t['sample']} | {_cell(job['sample_name'])} |",
            f"| SHA-256 | `{job['sample_sha256']}` |",
            f"| {t['type']} / {t['recipe']} | {job['detected_type'] or '-'} / {job['recipe'] or '-'} |",
            f"| {t['status']} | {job['status']} |",
            f"| {t['started']} / {t['finished']} | {job['started_at'] or '-'} / {job['finished_at'] or '-'} |",
            f"| {t['duration']} | {_dur(job['duration_ms'])} |",
            f"| {t['model']} | {model_name or '-'} |",
            f"| {t['prompts']} | {PROMPT_PACK_VERSION} ({', '.join(p['id'] + ':' + p['sha256'][:8] for p in list_prompts())}) |",
            f"| {t['audit']} | {t['valid'] if audit.valid else t['broken'] + ' ' + str(audit.broken_at)}; {audit.entries} entries; head `{audit.head_hash[:16]}` |"]
    hashes = [e for e in evidence if e["tool"] in ("hash_file", "decode_layer", "sample_info")]
    if hashes:
        out += ["", f"| {t['evidence']} | {t['tool']} | SHA-256 |", "|---|---|---|"]
        out += [f"| {e['id']} | {e['tool']} | `{e['result_sha256']}` |" for e in hashes]

    out += ["", f"## {t['detect']}", "", f"| # | {t['task']} | {t['tool']} | {t['result']} | {t['evidence']} | {t['time']} |",
            "|---|---|---|---|---|---|"]
    for tk in tasks:
        for s in store.list_steps(tk["id"]):
            if s["kind"] == "tool":
                out.append(f"| {tk['id']}.{s['idx']} | {_cell(tk['title'])} | {s['tool']} | {_cell((s['output_preview'] or '').splitlines()[0] if s['output_preview'] else '')[:120]} | {s['evidence_id'] or ''} | {_dur(s['duration_ms'])} |")

    out += ["", f"## {t['findings']}", ""]
    stat_name = {"confirmed": t["confirmed"], "hypothesis": t["hypothesis"], "open": t["open_s"], "rejected": t["rejected"]}
    for status in ("confirmed", "hypothesis"):   # open points have no proof, they stay in the section of their own
        rows = [f for f in findings if f["status"] == status]
        if not rows:
            continue
        out += [f"### {stat_name[status]}", ""]
        for f in rows:
            out.append(f"- **{f['id']}** ({', '.join(f['evidence_ids']) or t['none']}): {_cell(txt(f['statement_en'], f['statement_de']))}")
            for q in f["quotes"]:
                out.append(f"  - {q['evidence_id']}: `{_cell(q['quote'])[:240]}`")
            if f["reject_reason"]:
                out.append(f"  - _{_cell(f['reject_reason'])}_")
        out.append("")

    out += [f"## {t['answers']}", ""]
    for a in answers:
        out += [f"### {a['question_id']}: {_cell(a['text_orig'])}", ""]
        if a["status"] == "answered":
            out.append(f"**{t['answer']}:** {_cell(txt(a['answer_en'], a['answer_de']))}")
            out.append(f"- {t['evidence']}: {', '.join(a['finding_ids']) or t['none']}")
        else:
            out.append(f"**{t['unresolved'] if a['status'] == 'unresolved' else a['status']}** - {_cell(txt(a['evaluation_en'], a['evaluation_de']))}")
        if a["expected"]:
            m = {1: t["yes"], 0: t["no"], None: t["na"]}[a["match"]]
            out.append(f"- {t['expected']}: `{_cell(a['expected'])}` - {t['match']}: {m}")
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
    out += [f"- {f['id']}: {_cell(txt(f['statement_en'], f['statement_de']))}" for f in ops] or [f"- {t['none']}"]

    out += ["", f"## {t['method']}", "", f"| {t['task']} | {t['status']} | origin | {t['self_eval']} | {t['duration']} | reason |", "|---|---|---|---|---|---|"]
    out += [f"| {x['id']} {_cell(x['title'])} | {x['status']} | {x['origin']} | {({True: t['reached'], False: t['not_reached']}.get(x['params'].get('goal_reached'), t['not_rated']))} | {_dur(x['duration_ms'])} | {_cell(x['reason'])[:100]} |" for x in tasks]
    guard = store.list_guard_events(job_id)
    out += ["", f"**{t['guard']}:** {len(guard)}"]
    out += [f"- {g['stage']}/{g['rule']} ({g['severity']}, {g['action']}): `{_cell(g['snippet'])[:100]}`" for g in guard[:20]]

    out += ["", f"## {t['appendix']}", "", f"| ID | {t['tool']} | version | SHA-256 | bytes |", "|---|---|---|---|---|"]
    out += [f"| {e['id']} | {e['tool']} | {e['tool_version']} | `{e['result_sha256'][:16]}...` | {len(e['text'])} |" for e in evidence]
    return "\n".join(out) + "\n"
