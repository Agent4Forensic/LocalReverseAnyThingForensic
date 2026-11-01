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
from sw_analyst.report.derivation import derivation_lines
from sw_analyst.report.defang import defang_text, find_iocs, redact_payloads

T = {
    "de": {
        "title": "Forensischer Analysebericht", "live": "LIVE-STAND (Analyse läuft noch)", "summary": "Zusammenfassung",
        "custody": "R2 Übergabe und Chain of Custody", "detect": "R3 Erkennungsprotokoll je Schritt der Toolkette",
        "findings": "R4 Befunde mit Nachweis", "answers": "R5 Beantwortung der Zielfragen", "derive": "R5a Herleitung der Antworten", "iocs": "Indikatoren (entschärft)",
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
        "abstract": "Kurzfassung", "qa": "Fragestellungen und Kurzantworten", "mandate": "R6 Auftrag und Probe", "approach": "R7 Vorgehen und Methodik",
        "results": "R4 Ergebnisse je Thema", "limits_h": "Grenzen und offene Punkte", "appx": "Anhang", "terms": "Begriffe in diesem Bericht",
        "dynamic": "Dynamische Analyse", "tasks_h": "Aufgaben und Zeitverlauf", "tools_h": "Eingesetzte Werkzeuge", "calls": "Aufrufe", "purpose": "Zweck",
        "belegtab": "Belegtabelle", "guard_h": "Prompt-Schutz", "gap_what": "Offen", "gap_close": "Würde geklärt durch", "gap_q": "Frage", "gap_in": "Eingabe",
        "no_findings": "Zu diesem Thema liegen keine Befunde vor.", "no_questions": "Es wurden keine Zielfragen gestellt; die Analyse folgte dem Rezept.",
        "untranslated": "[EN]", "limits": "Grenzen: rein statische Analyse, offline, lokales Modell. Aussagen ohne Beleg wurden verworfen oder als Hypothese geführt; offene Punkte sind keine Aussagen und haben keinen Beleg.",
    },
    "en": {
        "title": "Forensic Analysis Report", "live": "LIVE STATE (analysis still running)", "summary": "Summary",
        "custody": "R2 Hand-over and chain of custody", "detect": "R3 Detection log per toolchain step",
        "findings": "R4 Findings with proof", "answers": "R5 Answers to the target questions", "derive": "R5a How each answer was derived", "iocs": "Indicators (defanged)",
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
        "abstract": "Abstract", "qa": "Questions and short answers", "mandate": "R6 Mandate and sample", "approach": "R7 Approach and methodology",
        "results": "R4 Results by topic", "limits_h": "Open questions and limits", "appx": "Appendix", "terms": "Terms used in this report",
        "dynamic": "Dynamic analysis", "tasks_h": "Tasks and timeline", "tools_h": "Tools used", "calls": "Calls", "purpose": "Purpose",
        "belegtab": "Evidence table", "guard_h": "Prompt guard", "gap_what": "Open", "gap_close": "Would be closed by", "gap_q": "Question", "gap_in": "Input",
        "no_findings": "There are no findings for this topic.", "no_questions": "No target questions were asked; the analysis followed the recipe.",
        "untranslated": "", "limits": "Limits: static analysis only, offline, local model. Statements without evidence were rejected or kept as hypotheses; open points are not statements and have no evidence.",
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


def _dur(ms: int) -> str:
    s = (ms or 0) / 1000
    return f"{s:.1f} s" if s < 120 else f"{s / 60:.1f} min"


def _glossary(de: bool) -> list[str]:
    if de:
        return ["- **Beleg (EV-…):** die gespeicherte, mit Hash versehene Ausgabe eines Werkzeugaufrufs. Nur was ein Beleg zeigt, gilt als belegt.",
                "- **Befund (F-…):** eine Aussage des Modells über die Probe, an Belege und wörtliche Zitate gebunden.",
                "- **bestätigt / Hypothese / offen:** bestätigt = durch Zitat aus einem Beleg gestützt; Hypothese = plausibel, aber nicht bewiesen; offen = ungeklärter Punkt ohne Beleg. Antworten stützen sich nur auf bestätigte Befunde.",
                "- **Audit-Kette:** Protokoll aller Schritte, in dem jeder Eintrag den Hash seines Vorgängers enthält; nachträgliche Änderungen fallen bei der Prüfung auf.",
                "- **Entschärft (defanged):** Adressen und Dateipfade sind so geschrieben, dass sie nicht versehentlich aufgerufen werden (zum Beispiel `hxxp`)."]
    return ["- **Evidence (EV-…):** the stored, hashed output of one tool call. Only what an evidence item shows counts as proven.",
            "- **Finding (F-…):** a statement of the model about the sample, bound to evidence and verbatim quotes.",
            "- **confirmed / hypothesis / open:** confirmed = backed by a quote from evidence; hypothesis = plausible but unproven; open = unresolved point without evidence. Answers rely on confirmed findings only.",
            "- **Audit chain:** a log of all steps in which each entry holds the hash of its predecessor; later changes show up on verification.",
            "- **Defanged:** addresses and paths are written so they cannot be opened by accident (for example `hxxp`)."]


def build_report(store: Store, job_id: str, lang: str = "de", model_name: str = "") -> str:
    from collections import Counter

    from sw_analyst.report.derivation import _TOOLS, _FALLBACK
    from sw_analyst.webui.dynamic import REASON, dynamic_plan

    t = T["de" if lang == "de" else "en"]
    de = lang == "de"
    job = store.get_job(job_id)
    if not job:
        raise KeyError(job_id)
    spec = job["spec"]
    live = job["status"] in ("queued", "running")
    all_tasks = store.list_tasks(job_id)
    tasks = [x for x in all_tasks if x["kind"] != "group"]
    findings = store.list_findings(job_id)
    answers = store.list_answers(job_id)
    evidence = [store.get_evidence(e["id"]) for e in store.list_evidence(job_id)]
    audit = verify_file(store.audit_path(job_id))
    plan = dynamic_plan(store, job_id)
    gap_ids = {g["finding_id"] for g in plan["gaps"]}

    def txt(en: str, de_txt: str) -> str:
        if not de:
            return en
        return de_txt if de_txt else f"{t['untranslated']} {en}"

    n_conf = sum(f["status"] == "confirmed" for f in findings)
    n_hyp = sum(f["status"] == "hypothesis" for f in findings)
    n_ans = sum(a["status"] == "answered" for a in answers)
    n_unres = len(answers) - n_ans

    # ---- Kurzfassung (abstract): 3-5 sentences from stored counts, then the stored model summary -------------
    typ, rec = _tok(job["detected_type"]) or "-", _tok(job["recipe"]) or "-"
    if de:
        sentences = [f"Untersucht wurde die Probe {_cell(job['sample_name'])} (SHA-256 `{_hex(job['sample_sha256'][:16])}…`), erkannt als {typ}; Rezept {rec}.",
                     "Die Analyse war rein statisch und offline: Die Probe wurde nie ausgeführt.",
                     (f"Von {len(answers)} Zielfragen sind {n_ans} beantwortet und {n_unres} ungeklärt." if answers else t["no_questions"]),
                     f"Befunde: {n_conf} bestätigt, {n_hyp} als Hypothese geführt.",
                     (f"Lücken, die nur eine dynamische Analyse klärt: {len(gap_ids)}; sie ist {REASON}." if gap_ids else "Dynamische Analyse: " + REASON + ".")]
    else:
        sentences = [f"The sample {_cell(job['sample_name'])} (SHA-256 `{_hex(job['sample_sha256'][:16])}…`) was examined; detected as {typ}, recipe {rec}.",
                     "The analysis was purely static and offline: the sample was never executed.",
                     (f"Of {len(answers)} target questions, {n_ans} are answered and {n_unres} unresolved." if answers else t["no_questions"]),
                     f"Findings: {n_conf} confirmed, {n_hyp} kept as hypotheses.",
                     (f"Gaps that only a dynamic analysis can close: {len(gap_ids)}; it is not executed (analysis VM missing, ADR-0005)." if gap_ids else "Dynamic analysis: not executed (analysis VM missing, ADR-0005).")]

    out: list[str] = [f"# {t['title']} {_tok(job['id'])}: {_cell(spec.get('title'))}"]
    if live:
        out += ["", f"> **{t['live']}**"]
    out += ["", f"## {t['abstract']}", "", " ".join(sentences), "",
            _para(txt(job["summary_en"], job["summary_de"])) or "-", "", t["limits"]]

    # ---- Fragestellungen mit Kurzantwort ----------------------------------------------------------------------
    out += ["", f"## {t['qa']}", ""]
    if answers:
        out += [f"| ID | {t['question']} | {t['answer']} | {t['status']} | {t['evidence']} |", "|---|---|---|---|---|"]
        for a in answers:
            if a["status"] == "answered":
                short, stat = txt(a["answer_en"], a["answer_de"]), t["answered"]
            else:
                short, stat = txt(a["evaluation_en"], a["evaluation_de"]), (t["unresolved"] if a["status"] == "unresolved" else _tok(a["status"]))
            # Every short answer names its proof: finding ids with their evidence; without them it is no fact.
            fids = [x for x in (a.get("finding_ids") or []) if store.get_finding(x)]
            proof = "; ".join(f"{_tok(x)} ({', '.join(_tok(e) for e in store.get_finding(x)['evidence_ids']) or '-'})" for x in fids)
            if a["status"] != "answered":
                short = (("offen, ungeprüfte Einschätzung des Modells: " if de else "open, unverified model assessment: ")
                         + (short or ""))
            out.append(f"| {_tok(a['question_id'])} | {_cell(str(a['text_orig'])[:160])} | {_cell(str(short or '')[:220])} | {stat} | {proof or '-'} |")
    else:
        out.append(t["no_questions"])

    # ---- R6 Auftrag und Probe -----------------------------------------------------------------------------------
    out += ["", f"## {t['mandate']}", ""]
    out.append((f"Die Probe `{_cell(job['sample_name']).replace('`', chr(39))}` mit dem SHA-256 `{_hex(job['sample_sha256'][:16])}…` wurde als {typ} erkannt und nach dem Rezept {rec} untersucht. Die vollständigen Hashes stehen im Anhang."
                if de else f"The sample `{_cell(job['sample_name']).replace('`', chr(39))}` with SHA-256 `{_hex(job['sample_sha256'][:16])}…` was detected as {typ} and examined with the recipe {rec}. Full hashes are in the appendix."))
    out.append("")
    for label, key in (("description", "description"), ("context", "context_info"), ("focus", "focus")):
        if spec.get(key):
            out.append(f"- **{t[label]}:** {_cell(spec[key])}")
    for q in spec["target_questions"]:
        out.append(f"- **{_tok(q['id'])}:** {_cell(q['text_orig'])}")

    # ---- R7 Vorgehen und Methodik -------------------------------------------------------------------------------
    calls = Counter(e["tool"] for e in evidence if e)
    tstat = Counter(x["status"] for x in tasks)
    out += ["", f"## {t['approach']}", ""]
    if de:
        out.append(f"Die Analyse ist rein statisch. Ein Planer leitet aus dem Rezept {rec} Aufgaben ab; jede Aufgabe ruft über ein Gateway feste, lesende Werkzeuge auf der Probe auf, und ein lokales Sprachmodell ({_tok(model_name) or '-'}) ordnet die Ergebnisse ein. Das Modell hat keinen Zugriff auf das Netz und kann keine eigenen Befehle ausführen. Jede Aussage muss durch ein wörtliches Zitat aus einem gespeicherten Beleg gestützt sein; sonst wird sie verworfen oder nur als Hypothese geführt.")
        out += ["", f"Insgesamt entstanden {len(tasks)} Aufgaben ({', '.join(f'{_tok(k)}: {v}' for k, v in sorted(tstat.items())) or '-'}), {len(evidence)} Belege und {sum(calls.values())} Werkzeugaufrufe in {_dur(job['duration_ms'])}. Für jede Zielfrage gibt es eine eigene Aufgabe, deren Herleitung unter R5a nachvollziehbar ist."]
    else:
        out.append(f"The analysis is purely static. A planner derives tasks from the recipe {rec}; each task calls fixed, read-only tools on the sample through a gateway, and a local language model ({_tok(model_name) or '-'}) interprets the results. The model has no network access and cannot run commands of its own. Every statement must be backed by a verbatim quote from a stored evidence item; otherwise it is rejected or kept as a hypothesis.")
        out += ["", f"In total {len(tasks)} tasks ({', '.join(f'{_tok(k)}: {v}' for k, v in sorted(tstat.items())) or '-'}), {len(evidence)} evidence items and {sum(calls.values())} tool calls arose in {_dur(job['duration_ms'])}. Each target question has a task of its own, whose derivation can be retraced under R5a."]
    if calls:
        out += ["", f"### {t['tools_h']}", "", f"| {t['tool']} | {t['calls']} | {t['purpose']} |", "|---|---|---|"]
        out += [f"| {_tok(k)} | {v} | {_cell(_TOOLS.get(k, _FALLBACK)[1 if de else 0])} |" for k, v in sorted(calls.items())]
    out += ["", f"### {t['terms']}", ""] + _glossary(de)

    out += ["", f"### {t['dynamic']}", ""]
    out.append(("Status: **nicht ausgeführt, Analyse-VM fehlt (ADR-0005).** Was nur ein Programmlauf klären kann, wird hier als Lücke geführt, nicht geraten. Ein Lauf bräuchte eine Analyse-VM ohne Netzwerkkarte, einen Snapshot und die Freigabe durch den Auftraggeber."
                if de else "Status: **not executed, analysis VM missing (ADR-0005).** What only a program run can settle is kept here as a gap, not guessed. A run would need an analysis VM without network card, a snapshot and approval by the client."))
    if plan["gaps"]:
        out.append("")
        for g in plan["gaps"]:
            out.append(f"- **{_tok(g['finding_id'])}:** {_cell(g['what']) or '-'}")
            for key, val in (("gap_close", g["close_by"]), ("gap_q", g["question"]), ("gap_in", g["input"])):
                if val:
                    out.append(f"  - {t[key]}: {_cell(val)}")
    else:
        out += ["", f"- {t['none']}"]

    out += ["", f"### {t['tasks_h']}", "", f"| {t['task']} | {t['status']} | {t['origin']} | {t['self_eval']} | {t['duration']} | {t['reason']} | {t['done_when']} |", "|---|---|---|---|---|---|---|"]
    out += [f"| {_tok(x['id'])} {_cell(x['title'])} | {_tok(x['status'])} | {_tok(x['origin'])} | {({True: t['reached'], False: t['not_reached']}.get(x['params'].get('goal_reached'), t['not_rated']))} | {_dur(x['duration_ms'])} | {_cell(x['reason'])[:100]} | {_cell(x['params'].get('done_when'))[:100]} |" for x in tasks]

    # ---- R4 Ergebnisse je Thema ---------------------------------------------------------------------------------
    out += ["", f"## {t['results']}", ""]
    stat_name = {"confirmed": t["confirmed"], "hypothesis": t["hypothesis"], "open": t["open_s"], "rejected": t["rejected"]}
    shown = [f for f in findings if f["status"] in ("confirmed", "hypothesis") and f["id"] not in gap_ids]
    by_task: dict = {}
    for f in shown:
        by_task.setdefault(f["task_id"], []).append(f)
    order = [x["id"] for x in tasks if x["id"] in by_task] + [k for k in by_task if k not in {x["id"] for x in tasks}]
    titles = {x["id"]: x["title"] for x in all_tasks}
    for tid in order:
        out += [f"### {_cell(titles.get(tid) or '-')} ({_tok(tid) or '-'})", ""]
        for f in sorted(by_task[tid], key=lambda f: f["status"] != "confirmed"):
            out.append(f"- **{_tok(f['id'])}** [{stat_name[f['status']]}] ({', '.join(_tok(x) for x in f['evidence_ids']) or t['none']}): {_cell(txt(f['statement_en'], f['statement_de']))}")
            for q in f["quotes"]:
                out.append(f"  - {_tok(q.get('evidence_id'))}: `{_cell(q.get('quote')).replace('`', chr(39))[:240]}`")
            if f["reject_reason"]:
                out.append(f"  - _{_cell(f['reject_reason'])}_")
        out.append("")
    if not order:
        out += [t["no_findings"], ""]

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

    out += derivation_lines(store, job_id, lang, t, txt)

    iocs: dict[tuple, None] = {}
    for f in findings:
        if f["status"] == "confirmed":
            for i in find_iocs(f["statement_en"]):
                iocs[(i["kind"], defang_text(i["value"]))] = None
    out += [f"## {t['iocs']}", ""]
    out += [f"- {k}: `{v}`" for k, v in iocs] or [f"- {t['none']}"]

    out += ["", f"## {t['limits_h']}", "", t["limits"], ""]
    ops = [f for f in findings if f["status"] in ("hypothesis", "open")]
    out += [f"- {_tok(f['id'])}: {_cell(txt(f['statement_en'], f['statement_de']))}" for f in ops] or [f"- {t['none']}"]

    # ---- Anhang -------------------------------------------------------------------------------------------------
    out += ["", f"## {t['appx']}", "", f"### {t['custody']}", "",
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

    out += ["", f"### {t['detect']}", "", f"| # | {t['task']} | {t['tool']} | {t['result']} | {t['evidence']} | {t['time']} |",
            "|---|---|---|---|---|---|"]
    for tk in tasks:
        for s in store.list_steps(tk["id"]):
            if s["kind"] == "tool":
                out.append(f"| {_tok(tk['id'])}.{_tok(s['idx'])} | {_cell(tk['title'])} | {_tok(s['tool'])} | {_cell((s['output_preview'] or '').splitlines()[0] if s['output_preview'] else '')[:120]} | {_tok(s['evidence_id'])} | {_dur(s['duration_ms'])} |")

    out += ["", f"### {t['belegtab']}", "", f"| ID | {t['tool']} | version | SHA-256 | bytes |", "|---|---|---|---|---|"]
    out += [f"| {_tok(e['id'])} | {_tok(e['tool'])} | {_tok(e['tool_version'])} | `{_hex(e['result_sha256'][:16])}...` | {len(e['text'])} |" for e in evidence]

    guard = store.list_guard_events(job_id)
    out += ["", f"### {t['guard_h']}", "", f"**{t['guard']}:** {len(guard)}"]
    out += [f"- {_tok(g['stage'])}/{_tok(g['rule'])} ({_tok(g['severity'])}, {_tok(g['action'])}): `{_cell(g['snippet']).replace('`', chr(39))[:100]}`" for g in guard[:20]]
    return "\n".join(out) + "\n"
