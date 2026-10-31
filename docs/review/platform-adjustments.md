# Plattform-Anpassungen für Lernpfad, Funktionen und Diagramme

Stand: 2026-10-31. Geprüft: `src/sw_analyst/**`, `tests/**` gegen `docs/architecture/dashboard-v2.md`, `chain.md`, `api.md`, `docs/STATUS.md` und Blueprint (insb. `15-walkthroughs-and-visuals.md`, `12`, `13`). Nur im Code belegte Befunde; Unsicheres ist mit **(unsicher)** markiert. Prioritäten: **P1** blockiert die Funktion, **P2** wichtig, **P3** später.

## 1. Kette: Guard, Runner, Prüfer

| Prio | Datei:Zeile | Befund | Anpassung |
|---|---|---|---|
| P1 | `guard/actions.py:274` | `_validate_finish` erlaubt nur `summary, findings, annotations, subtasks, answer`; `functions`, `walkthroughs`, `diagrams` führen zu "unknown key(s)" und die Aktion ist ungültig. | Drei optionale Validatoren (`_validate_function/_walkthrough/_diagram`) nach den Schemas in Blueprint 15 (Limits: 20 Funktionen, 2 Lernpfade à max. 20 Schritte, Schrittspanne max. 12 Zeilen, 3 Diagramme à 20 Knoten/30 Kanten, Textlängen). Finding-Verweise `F-xxxxxx` oder `#n`. |
| P1 | `tests/security/test_guard_actions.py:126` | Test erwartet Ablehnung unbekannter Keys (bleibt richtig). | Neue Tests: gültige/ungültige Einträge je Feld, Limits, `additionalProperties`, Zeilen `line_end >= line_start`. |
| P1 | `orchestrator/runner.py:100` | `max_tokens=2048` für jeden Zug. Ein Lernpfad mit 20 Schritten (je bis 500 Zeichen) passt nicht, JSON wird abgeschnitten, Aktion ungültig. | Für `build_walkthrough`/`build_diagrams` 4096 Ausgabe-Token. Rechnung: `num_ctx` 16384 (`llm/ollama.py:16`) minus `CONTEXT_CHAR_BUDGET` 36000 Zeichen ≈ 9k Token (`runner.py:24`) lässt ca. 7k; 4096 passt, mehr nicht. |
| P1 | `orchestrator/runner.py:166-194` | `_finish` verarbeitet nur `findings` und `annotations`; neue Felder würden verworfen. | Nach den Findings: Funktionen, Lernpfade, Diagramme prüfen (s. u.), lokale IDs (`FN1`, `WT1`, `DG1`, `#n`) auf globale IDs abbilden, speichern, Prüfschritt zählt angenommene/verworfene Elemente. |
| P1 | `orchestrator/runner.py:69-77` | Prompt-Auswahl nur `question` oder sonst `task.analyze`. | Routing nach `task["kind"]`: `explain_function`, `build_walkthrough`, `build_diagrams`. |
| P2 | `orchestrator/verifier.py` (ganze Datei) | Keine Prüfung von Zeilenbereichen, obwohl `chain.md` §4 Punkt 3 das fordert. Annotationen werden ungeprüft gespeichert (`runner.py:180-188`). | `verify_location(job, file, ls, le, evidence_id)`: Datei existiert (`gateway.list_files`), `le <= total_lines`, Evidence gehört zum Job, ihre `source_ref.file == file` und ihr Bereich deckt `ls..le`. Zusätzlich: `name` und Adresse (Hex-Ziffern, ohne Groß/Klein) kommen im Evidence-Text vor. Gilt auch für bestehende Annotationen. |
| P2 | `orchestrator/runner.py:151` + `gateway/dev_gateway.py:691` | `source_ref=result.meta` speichert `{"source_ref":{file,line_start,line_end},"total_lines":n}`, also verschachtelt `source_ref.source_ref`. | Beim Prüfen beide Formen lesen oder in `add_evidence` flach ablegen (P3 Aufräumen). |
| P2 | `orchestrator/runner.py:188` | Annotationen mit `kind=finding` bekommen immer `ids[0]` (erstes Finding der Aufgabe), auch wenn ein anderes gemeint ist. Fehler. | Explizite Referenz `finding_id` (`F-…` oder `#n`) im Annotation-Schema, Abbildung wie bei den neuen Feldern. |
| P2 | `guard/actions.py:131-164` | Parameterschema kennt kein `pattern`. | `pattern` ergänzen (z. B. Adresse `^0x[0-9A-Fa-f]{1,16}$`), nötig für neue Disassembler-Tools. |

## 2. Speicher und API

| Prio | Datei:Zeile | Befund | Anpassung |
|---|---|---|---|
| P1 | `common/store.py:19-59` | Keine Tabellen für Funktionen, Lernpfade, Diagramme. | `functions(id FN-…, job_id, task_id, name, address, file, line_start, line_end, role, summary_en, summary_de, confidence, evidence_id, finding_ids_json)`, `walkthroughs(id, job_id, task_id, function_id, title_en/de, summary_en/de)`, `walkthrough_steps(walkthrough_id, n, file, line_start, line_end, address, block, kind, title_en/de, explanation_en/de, confidence, evidence_id, finding_id)`, `diagrams(id, job_id, task_id, kind, function_id, title_en/de, graph_json, finding_ids_json, origin "model"|"derived")`. Je `add_*`/`list_*` mit `emit` (Ereignistypen `function`, `walkthrough`, `diagram`). `_JSON_COLS` (`store.py:61`) um `graph_json` erweitern. |
| P1 | `webui/app.py:88-299` | Endpunkte `activity`, `functions`, `walkthroughs`, `diagrams` fehlen. | Siehe Tabelle 2a. |
| P2 | `docs/architecture/api.md:42` | SSE-Typen ohne `function`, `walkthrough`, `diagram`, `activity`. | Liste ergänzen; Frontend lädt bei Ereignis neu. |
| P2 | `dashboard-v2.md:12-17` | Antwortformate ohne `evidence_id`, `confidence`, `kind`, `block`, `function_id` (Diagramm). | Felder ergänzen (Blueprint 15 nutzt sie); Code-Viewer zeigt Evidence-Link je Schritt. |

### 2a. Endpunkte und Datenquelle

| Endpunkt | Datenquelle | Hinweis |
|---|---|---|
| `GET /api/jobs/{id}/activity` | `jobs.status`, laufende Aufgabe (`store.queue` → erster Eintrag mit `running`, `store.py:212`), letzter Step mit `status='running'` (`steps`), `recent` = letzte 10 Steps, `next` = nächste 3 aus `queue`, Phase aus `task.kind`/`origin`. | Token: heute nur als Text in `steps.how` (`runner.py:115`, "tokens in/out=…"). P2: Spalten `tokens_in/out` in `steps`, sonst Parsen (fragil). `elapsed_ms` serverseitig aus `started_at`. |
| `GET /api/jobs/{id}/functions` | Tabelle `functions` | `finding_ids` nur bestehende Findings. |
| `GET /api/jobs/{id}/walkthroughs` | `walkthroughs` + `walkthrough_steps` nach `n` | Schritte mit verworfener Prüfung nicht ausliefern. |
| `GET /api/jobs/{id}/diagrams` | `diagrams` (Modell) + deterministisch erzeugt: Aufgabenbaum (`list_tasks`), Analyse-Zeitverlauf (wie `timeline`, `app.py:238`) | Analyse-Zeitverlauf nie vom Modell. |

## 3. Prompts, Rezepte, Engine

| Prio | Datei:Zeile | Befund | Anpassung |
|---|---|---|---|
| P1 | `prompts/registry.py:185-191` | Nur 5 Vorlagen. | `task.explain_function`, `task.build_walkthrough`, `task.build_diagrams` mit Abschnitten Role/Goal/Input/Context/Rules/Output; Rules = Kurzform von Blueprint 15 (Checkliste), Output = nur das jeweilige Feld plus `findings`. |
| P1 | `prompts/registry.py:25-28` | `ACTION_SCHEMA` nennt die neuen Felder nicht. | Je Aufgabentyp ein eigenes, knappes Schema-Snippet statt alles in jedem Prompt (spart Token). |
| P2 | `orchestrator/engine.py:115` | `_plan` setzt immer `kind="analyze"`. | `kind=st.get("kind","analyze")`, erlaubte Werte prüfen. |
| P2 | `recipes/exe.yaml` (alle Schritte) | Keine Schritte für Funktionsliste, Erklärung, Lernpfad, Diagramme. | Nach Verfügbarkeit der Disassembler-Tools: `functions_rank` (Ranking laut Blueprint 02), `explain_top` (`explain_function`), `walkthrough_top` (`build_walkthrough`, Top-3-Funktionen), `diagrams` (`build_diagrams`, vor den Zielfragen, Priorität ~850). Für `script.yaml` sofort möglich (Lernpfad über `sample`-Zeilen). **(unsicher: script.yaml nicht im Detail geprüft)** |
| P3 | `engine.py:118` / `runner.py:60-68` | `tools_hint` wird gespeichert, aber nie in den Prompt gerendert. | In den Task-Prompt aufnehmen (kleines Modell braucht die Führung). |
| P2 | `engine.py:260-270` | `_translate_new` übersetzt nur Findings und Annotationen. | Neue Texte (`summary_en`, `title_en`, `explanation_en`, `label_en`) übersetzen; viele kurze Texte: Cache (`store.py:363`) nutzen, Labels gebündelt. |

## 4. Bericht

| Prio | Datei:Zeile | Befund | Anpassung |
|---|---|---|---|
| P2 | `report/builder.py:57-159` | Keine Funktionen, kein Lernpfad, keine Diagramme; Blueprint 13 fordert Mermaid (`13-report-writing.md:209-216`, R9 Ablauf, R10 Funktionen, R22 Gantt). | R10-Tabelle aus `functions`; R9 Mermaid aus `diagrams` (`flowchart LR`, Kantenlabel mit Finding-ID); Lernpfad als Anhang (Schritt, Zeilen, Erklärung, Evidence). |
| P2 | neu (Mermaid-Erzeugung) | Labels stammen vom Modell bzw. aus dem Sample. | Labels defangen (`defang_text`), `"`, `[`, `]`, `|`, `<`, `>`, Zeilenumbrüche escapen, Knoten-IDs nur `[A-Za-z0-9_]`; sonst Mermaid-/Markdown-Injection. |

## 5. DevGateway: Grenzen für den Assembler-Lernpfad

Befund: `gateway/dev_gateway.py:443-507` registriert 13 Werkzeuge (`sample_info` … `zip_read_text`), keinen Disassembler, keinen Decompiler, keine Funktionsliste, keine Querverweise. Abgeleitete Dateien entstehen nur über `decode_layer` (`dev_gateway.py:198-231`). Der Assembler-Lernpfad ist damit heute **nicht** möglich, nur der Lernpfad über Skript- und Layer-Zeilen. Keine passende Bibliothek in `requirements.in` (nur fastapi, uvicorn, pyyaml).

| Prio | Fehlendes Werkzeug | Ergebnis | Zweck |
|---|---|---|---|
| P1 | `list_functions(sort, max)` | `derived/functions.txt` (Name, Adresse, Größe, Xref-Anzahl) | Ranking, Funktionsliste |
| P1 | `disassemble(function\|address, max_lines)` | `derived/asm_<name>.txt`, nummerierte Zeilen mit Adresse | Lernpfad, Zeilensprung |
| P1 | `decompile(function)` | `derived/c_<name>.txt` | Lernpfad (Dekompilat-Fallback) |
| P2 | `xrefs(address, direction)` | Text | Callgraph mit Beleg |
| P2 | `basic_blocks(function)` | Blockliste mit Zeilen, Kanten | Ablaufplan **deterministisch**; Modell beschriftet nur (senkt Halluzination stark) |

Weg ins Gateway: Ghidra 12.1.4 headless + pyghidra-mcp v0.2.7 (Empfehlung `STATUS.md:41`) im Container (`--network none`, read-only, Limits) hinter einem Gateway-Adapter, der dieselbe Schnittstelle wie `gateway/base.py` erfüllt; jedes Tool mit festem Parameterschema in der Allowlist, Ausgabe als `derived/`-Datei (Dateinamen passen zur Regel in `dev_gateway.py:91-95`) plus Evidence mit `source_ref`. Erweiterung der Allowlist braucht ADR und Freigabe durch Jan (CLAUDE.md Verbot 3); neue Bibliotheken (z. B. ein Python-Disassembler für den Dev-Pfad) nur mit Pin/Hash/Lizenz (Verbot 5). Das MCP-Protokoll darf nicht als generischer Kanal durchgereicht werden (Verbot 4): nur benannte Tools, keine Skript-Ausführung in Ghidra.

## 6. Sicherheit und Halluzination

| Prio | Risiko | Beleg | Maßnahme |
|---|---|---|---|
| P1 | Erfundene Adressen, Namen, Registerwerte | Prüfer prüft nur Zitate (`verifier.py:32-67`) | Ortsprüfung wie in §1; Schritte ohne deckende Evidence verwerfen und im Step-Log zählen. |
| P2 | Erklärtext ist semantisch nicht prüfbar | `chain.md` §4 | UI-Kennzeichnung "KI-Erklärung", `confidence` anzeigen; nie als Finding zählen; Antworten auf Zielfragen nur aus Findings (bleibt). |
| P2 | Erfundene Diagrammkanten | — | Jede Kante braucht `finding_id` oder `evidence_id`, sonst verwerfen; Flussdiagramme bevorzugt aus `basic_blocks`. |
| P2 | XSS über Labels/Erklärungen im SVG/Code-Viewer | `api.md:5` (textContent-Pflicht), CSP `app.py:24` | SVG-Text nur per `textContent`/`createTextNode`; Frontend-Test. **(unsicher: Frontend-Code für SVG noch nicht vorhanden; `static/` enthält kein app.js)** |
| P3 | Injektionstext in neuen Feldern | `taskguard.py:98` prüft die gesamte Rohausgabe auf Wiederholung | Ausreichend; Scanner zusätzlich auf neue Textfelder vor der Übersetzung. |

## 7. Token-Effizienz (16k Kontext)

| Prio | Befund | Beleg | Anpassung |
|---|---|---|---|
| P1 | Evidence im Prompt max. 6000 Zeichen | `runner.py:23` | Ca. 120–150 Assemblerzeilen. Funktionen > 120 Zeilen in Teile schneiden (Teilaufgaben mit Zeilenbereich), `disassemble` mit `max_lines`. |
| P2 | Kompaktierung kürzt ältere Tool-Ausgaben auf die Kopfzeile | `runner.py:197-209` | Lernpfad-Aufgaben: Funktionsbereich einmal lesen, sofort `finish`; Budget dieser Aufgaben auf ca. 3 Züge. Sonst zitiert das Modell Zeilen, die es nicht mehr sieht. |
| P2 | Kontext enthält bis zu 25 bestätigte Findings | `runner.py:51` | Für Funktionsaufgaben nur Findings dieser Funktion plus Einzeilen-Zusammenfassungen der Callees aus `functions`. |
| P3 | Schema im Prompt groß | `registry.py:25-28` | Pro Aufgabentyp nur das benötigte Schema; Beispiele kurz halten. |

## Offene Punkte
- Blueprint-Routing: `00-index.md` und `_STYLE.md` kennen `15-walkthroughs-and-visuals.md` noch nicht (Dateien gehören nicht zu diesem Auftrag).
- ADR für Ghidra-Tools in der Allowlist, Freigabe Jan.
- Frontend-Stand (SVG-Renderer, Lernpfad-Modus) nicht prüfbar, Dateien fehlen noch.
