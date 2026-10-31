# Code-Review aller Modelle: Zusammenfassung

Stand: 2026-10-31. Geprüft wurde der Arbeitsstand auf Basis von Commit `714e6e7`. Zwei andere Sitzungen haben während der Prüfung `src/` verändert, deshalb können Zeilennummern in den Einzeldateien um einige Zeilen abweichen. Die Prüfer haben blind gearbeitet, jeder las nur seine eigene Ausgabedatei.

## Umfang und Ergebnis

| Modell | Pakete | Datei | krit | hoch | mittel | niedrig |
|---|---|---|---|---|---|---|
| Fable 5.1 | B, C | `fable-B-C.md` | 0 | 6 | 8 | 6 |
| Fable 5.1 | D, F | `fable-D-F.md` | 1 | 4 | 10 | 14 |
| Opus 5.5 | A, E | `opus-A-E.md` | 0 | 2 | 6 | 6 |
| Opus 5.5 | B, C | `opus-B-C.md` | 0 | 4 | 6 | 6 |
| Opus 5.5 | D, F, G | `opus-D-F-G.md` | 0 | 4 | 8 | 14 |
| Sonnet 5.5 | A, E | `sonnet-A-E.md` | 0 | 4 | 22 | 17 |
| Sonnet 5.5 | B | `sonnet-B.md` | 0 | 5 | 8 | 7 |
| Sonnet 5.5 | C | `sonnet-C.md` | 0 | 2 | 7 | 11 |
| Sonnet 5.5 | D, F | `sonnet-D-F.md` | 0 | 6 | 19 | 14 |
| Sonnet 5.5 | G, H, I | `sonnet-G-H-I.md` | 0 | 1 | 15 | 20 |
| Haiku 5.5 | G (JS), H, I | `haiku-G-H-I.md` | 0 | 1 | 10 | 15 |
| **Summe** | | | **1** | **39** | **119** | **130** |

Das sind 289 Funde in 11 Dateien. Die Modelle haben dieselben Ursachen oft unter unterschiedlichen Zeilen gemeldet, deshalb ist die Zahl der verschiedenen Probleme deutlich kleiner (siehe unten).

Abdeckung: Die Pakete A bis G haben mindestens zwei Modelle geprüft. Die Pakete H und I haben nur Sonnet und Haiku geprüft, wie in der Verteilung vorgesehen. Die Arbeitsweise war Pflicht-Nachweis per `graphify`, jede Abgabe nennt ihre Abfragen.

Die Abnahmekriterien in `docs/STATUS.md` sind damit zum Teil erfüllt: Alle 9 Pakete wurden von mindestens zwei Modellen geprüft und diese Tabelle liegt vor. Behoben ist noch nichts.

## Bestätigte Funde (mindestens zwei Modelle)

Die Einstufung nimmt der Hauptagent vor. Sie weicht von einzelnen Modellen ab, wo die Wirkung auf die Kerninvariante "keine Aussage ohne Beleg" größer ist. "Reproduziert" bedeutet, dass der Prüfer den Fund mit einem Skript oder Test gezeigt hat. "Aus dem Code" bedeutet, dass der Fund nur gelesen wurde.

| ID | Schwere | Fund | Stelle | Modelle | Nachweis |
|---|---|---|---|---|---|
| F-01 | kritisch | **Das Modell kann sich seinen Beleg selbst erzeugen.** `grep` schreibt das vom Modell gewählte Muster in die Ausgabe (`No matches for /…/`, `grep /…/ in …`). Die Ausgabe wird Evidence, ein Zitat daraus gilt als `confirmed`, und `answer_values_grounded` lässt den erfundenen Wert durch. | `gateway/dev_gateway.py:712,724`, `orchestrator/verifier.py:51,78` | Fable D-F (kritisch), Sonnet D-F, Opus D-F-G | Sonnet D-F: Muster `flag{invented_secret}` steht in der Evidence und ist zitierbar. Alle drei lasen die Stelle. |
| F-02 | hoch | Das Zitat wird nur auf Vorkommen geprüft, nicht auf Bezug zur Aussage. `MIN_QUOTE` ist 4, der Prompt verspricht 8. Selbstauskünfte des Samples ("harmless utility") sind zitierbar. | `verifier.py:16,49-58` | Fable D-F, Fable B-C, Sonnet D-F, Opus D-F-G | aus dem Code |
| F-03 | hoch | Antworten sind nur schwach an Belege gebunden: Es reicht irgendein bestätigtes Finding derselben Antwort, nur Werte der Form `WORD{…}` werden geprüft, das Flag-Regex übersieht `FLAG {x}`. | `engine.py:436`, `runner.py:252`, `verifier.py:78` | Fable D-F, Fable B-C, Sonnet D-F, Opus D-F-G | aus dem Code |
| F-04 | hoch | Die IOC-Liste im Bericht stammt aus dem Aussagetext des Modells, nicht aus den geprüften Zitaten. IOCs ohne Beleg landen im Bericht. | `report/builder.py:139-143` | Fable D-F, Fable B-C, Sonnet D-F | aus dem Code |
| F-05 | hoch | **ReDoS im Regex-Wächter.** Verschachtelte und polynomielle Muster werden durchgelassen (`(a?){25}a{25}`, `.*.*.*x`, `(?x)`-Kommentar, überlappende Alternativen). Das Zeitbudget wird nur zwischen Zeilen geprüft, und der Runner ruft das Gateway synchron auf. Ein Muster des Modells kann den Job dauerhaft blockieren. | `gateway/dev_tools/regex_guard.py:143-155`, `dev_gateway.py:701-705`, `runner.py:207,221` | Fable B-C, Sonnet B, Opus B-C | reproduziert (1,7 s bis über 60 s) |
| F-06 | hoch | Ressourcen in der Triage ohne KI: PE-Sektionsentropie summiert sich bei überlappenden Sektionen (16 MiB: 40 bis 49 s), `scripts.py` mit quadratischen Regeln (20 000 Zeilenumbrüche: 32 s), ZIP-Zentralverzeichnis ohne Obergrenze (etwa 420 bis 460 MB bei 64 MiB). | `dev_tools/pe.py:177-190`, `dev_tools/scripts.py`, `dev_gateway.py` (`zip_*`) | Fable B-C, Sonnet B, Opus B-C | reproduziert (ZIP hochgerechnet) |
| F-07 | hoch | **Audit-Kette: Das Abschneiden der letzten Zeilen ist nicht erkennbar.** Ein Kopf-Hash ist nirgends verankert. Der Kommentar in `test_chain_of_custody.py:57-58` behauptet, er stehe im Store oder Bericht, das stimmt nicht. | `common/audit.py:40,71-76`, `report/builder.py:69` | Opus A-E, Sonnet A-E | aus dem Code |
| F-08 | hoch | **Audit-Kette: Schreibfehler.** `emit` schluckt `OSError` still. Nach einem Teilschreiben hängt der nächste Eintrag an eine Teilzeile, die Kette ist dauerhaft kaputt. Ein Eintrag mit dem Schlüssel `hash` macht sie ungültig, eine JSON-Zeile ohne Objekt löst `TypeError` statt `valid=False` aus. | `common/store.py:121-127`, `common/audit.py` | Opus A-E, Sonnet A-E, Sonnet G-H-I | reproduziert (Sonnet A-E) |
| F-09 | hoch | **Der Worker-Thread kann still sterben.** Nur `try/finally` ohne `except`. Eine Ausnahme aus `_finalize` oder `update_job` beendet den Thread, danach bleiben alle Jobs in der Warteschlange stehen. Dazu ein Race zwischen Abbruch und Jobübernahme. | `orchestrator/worker.py:33-41` | Fable D-F, Sonnet D-F, Opus D-F-G | aus dem Code |
| F-10 | hoch | **Der Job steht als `queued` in der DB, bevor das Sample geschrieben ist.** Der Worker kann die Triage auf einer fehlenden Datei starten, ein Fehler hinterlässt einen verwaisten Job. | `webui/app.py:126-127` | Sonnet G-H-I, Opus D-F-G | aus dem Code |
| F-11 | hoch | **Der Wächter lässt sich als Abbruchhebel benutzen.** Der Tripwire wird nur durch Schwere `high` bewaffnet. Eine einzige ungültige Antwort nach einer Injection blockiert den Task. Nennt das Sample Toolnamen im Injection-Text, bleiben später alle legitimen Aufrufe dieser Tools blockiert, bis hin zu `finish`. | `guard/taskguard.py:92,97,131-138` | Sonnet C, Fable B-C, Opus B-C | reproduziert (Fable B-C, Sonnet C) |
| F-12 | hoch | **Scanner-Lücken.** Griechisches Homoglyphen-Mapping verschoben, Kontraktionen ("you've") fehlen, keine Regeln für Verdikt-Erzwingung und Berichts-Unterdrückung, nur Englisch und Deutsch, zusammengeschriebene Phrasen, Formatierung (hexdump, Zeilenumbruch) zerreißt Phrasen, Base64 mit Kommentar-Führung. Der Hold-out-Test misst Recall 62,4 % statt der 145/145 des Tuning-Korpus. | `guard/scanner.py:52,329,551,685,773`, `guard/sanitize.py:108` | Sonnet C, Fable B-C, Opus B-C, Hold-out-Test | reproduziert, `tests/security/test_guard_holdout.py` |
| F-13 | hoch | **Modelle sind nur als Tag gepinnt**, ohne Digest, und werden zur Laufzeit aus der Registry gezogen. Das widerspricht der Regel "Version- und Hash-Pin". | `scripts/start.ps1:233-234`, `infra/manifest.json:32-37` | Haiku (hoch), Sonnet G-H-I | aus dem Code |
| F-14 | mittel | Defanging-Lücken: `ws://`, `tcp://`, `smb://`, `file://`, `//host`, UNC, TLDs `.in/.cc/.to`, IDN, verschachtelte URL im Query. Backticks und `javascript:`-Links werden im Bericht nicht maskiert. | `report/defang.py:59`, `report/builder.py` | Fable D-F, Sonnet D-F, Opus D-F-G | reproduziert |
| F-15 | mittel | Die Hash-Spalte "SHA-256" im Bericht zeigt bei `decode_layer` den Hash der Werkzeugausgabe, nicht den der Derived-Datei. Prompt-Hashes und Modell stammen vom Abrufzeitpunkt, nicht vom Job. Der System-Prompt wird nicht gespeichert. | `report/builder.py:97-102`, `webui/app.py:322` | Fable D-F, Opus D-F-G, Test `test_artifact_hashes.py` (xfail) | reproduziert (Test) |
| F-16 | mittel | Übersetzung: `done_reason == "length"` wird nicht geprüft, abgeschnittene Texte gelten als `ok` und werden gecacht. Der Cache-Schlüssel enthält kein Modell. | `translate/pipeline.py:204-205,256-273` | Opus A-E, Sonnet A-E | aus dem Code |
| F-17 | mittel | `stop.ps1` setzt den Origin fest auf 8765, bei `-Port` ungleich 8765 scheitert der Abbruch mit 403. | `scripts/stop.ps1:90` | Haiku, Sonnet G-H-I | aus dem Code |
| F-18 | mittel | `index.html` lädt drei nicht vorhandene Skripte (`mock_v2.js`, `view_diagrams.js`, `view_log.js`). Der neue Asset-Test prüft nicht, ob referenzierte Dateien existieren. | `webui/static/index.html:23,29,30` | Haiku, Sonnet G-H-I, Opus D-F-G | bekannt aus STATUS |
| F-19 | mittel | Cleanup prüft nur den Pfadpräfix, keine Junctions. Cleanup beendet jeden `python -m sw_analyst`-Prozess der venv. `test_scripts.py` ist ein reiner Teilstringtest. | `scripts/cleanup.ps1:44-54`, `tests/unit/test_scripts.py:13-15` | Haiku, Sonnet G-H-I | aus dem Code, PS-5.1-Verhalten bei Junctions nicht geprüft |
| F-20 | mittel | Das 64-MiB-Limit greift erst nach dem Spoolen auf die Platte. | `webui/app.py:111` | Sonnet G-H-I, Opus D-F-G | aus dem Code |
| F-21 | mittel | Eine ungültige `expected`-Regex (`re:`) lässt den ganzen Job scheitern, ReDoS möglich. | `orchestrator/engine.py:446` | Sonnet D-F, Opus D-F-G | aus dem Code |
| F-22 | mittel | `source_ref.length` ist bei UTF-16-Strings falsch (11 statt 22 Bytes). | `dev_tools/strings` | Sonnet B, Opus B-C | reproduziert |
| F-23 | mittel | Abbruch und Zeitbudget werden nur zwischen Tasks geprüft. Ein Abbruch während der Host-Pause lässt noch einen Task laufen. | `engine.py:231` | Sonnet D-F, Opus D-F-G | aus dem Code |

## Einzelfunde (ein Modell), zur Bewertung

Diese Funde sind nicht abgelehnt. Sie brauchen vor dem Beheben eine eigene Prüfung.

- `hostguard.py:43-45`: Die RAM-Pause ist außerhalb von Windows still abgeschaltet (Opus A-E). Auf dem Zielrechner (Windows) ohne Wirkung.
- `create_job` ist nicht transaktional (Opus A-E).
- `/log` liefert höchstens 500 Events, `last_seq` springt weiter, das Log ist still unvollständig (`app.py:267`, Sonnet G-H-I). Der SSE-Stream blockiert die Event-Loop (`app.py:303`).
- `markdown.js:78` beachtet das maskierte `\|` nicht, Probeninhalt mit `|` verschiebt Tabellenspalten (Opus D-F-G).
- `<think>`-Tags von qwen3 werden nicht neutralisiert (Fable B-C). Ob Ollama sie im Message-Content als Spezialtoken behandelt, ist nicht geprüft.
- Auf dem letzten Turn gehen alle Erkenntnisse verloren, wenn das Modell ein Tool statt `finish` wählt (`runner.py:240`, Sonnet D-F).
- `_FENCE`-Regex in `actions.py:15` ist quadratisch: 60 KB Leerraum brauchen 4 bis 5 s (Sonnet C).
- Annotationen ohne `evidence_id` werden gespeichert (Fable B-C). `add_finding` erzwingt den Belegzwang nicht (Sonnet A-E).
- `sha256_hex` ist wegen `errors="replace"` nicht injektiv (Sonnet A-E, reproduziert).
- Web-API laut Test `test_api_security.py`: Der Code-Viewer liefert `lines` als Strings, `api.md` und `view_code.js:56` erwarten `{n,text}` (mittel). `StaticFiles` antwortet bei NUL-Byte mit 500 statt 404. Der Fehlerhandler erfasst nur `HTTPException`. `sample_name` behält Bidi-Override U+202E.
- `DevGateway.list_files` cached den Hash nach (Pfad, Größe, mtime) und erkennt eine Manipulation mit wiederhergestelltem mtime nicht (Test `test_artifact_hashes.py`, xfail).
- Viele Plan-Punkte ohne Test: C1, C2, C3, C5, C6, C7, G4, G7, D2, D5, D6, T2 bis T5, S5, S8, K1 (Sonnet G-H-I). C1 bis C3 sind inzwischen durch `test_artifact_hashes.py` abgedeckt.

## Verworfen

| Fund | Grund |
|---|---|
| Dateinamen abgeleiteter Dateien als Prompt-Injection | Sonnet D-F hat ihn geprüft und verworfen: Die Namen erzeugt das Gateway selbst (`derived/layerNN.bin`). |
| Ursprünglicher Rot-Fehler im CSP-Test (`data:,`) | Haiku: Der Test war inzwischen angepasst, nicht mehr gelistet. |
| `docs/STATUS.md` Zeile 207 ("`goal_reached` und `gaps` werden nur geloggt") | Teilweise falsch laut Fable D-F: `agents.py:70,76` werten beides aus, nur die Engine speichert es nicht. Der Arbeitsstand der anderen Sitzung arbeitet diese Lücken gerade ab. |

## Ohne Befund (mehrfach bestätigt)

Pfad-Jail des Gateways (UNC, Laufwerk, ADS, `..`, Symlink, Junction, reservierte Namen), Allowlist und Aktions-Schema, Dekompressionsbomben in den Decodern, Origin- und Host-Prüfung der Web-API, CSP-Header, kein `innerHTML` und kein XSS-Pfad im Frontend, SSE, Neutralisierung von `</untrusted_data>`-Varianten, kein `exec` oder `eval`. Auf die Frage, ob Sample-Inhalt das Modell zu einer nicht erlaubten Aktion bringen kann, fand Fable keinen Weg. Möglich bleiben Denial of Analysis (F-05, F-11) und das Lenken der Analyse.

## Grenzen dieser Prüfung

- Keine Eigenmessung des Hauptagenten. Die Reproduktionen stammen von den Prüfern. F-01 ist von drei Modellen aus dem Code abgeleitet, einer davon hat die Evidence-Aufnahme getestet, aber nicht den kompletten Lauf bis `confirmed`.
- Die Prüfer haben nichts ausgeführt, außer dort, wo "reproduziert" steht.
- Mehrere Dateien wurden parallel von anderen Sitzungen geändert (Engine, Runner, Agents, Builder, Guard-Aktionen). Funde in diesen Dateien müssen vor dem Beheben gegen den dann aktuellen Stand geprüft werden.
- Eine Stichprobe mit einem Autor je Modell. Gleiche Ursachen unter verschiedenen Zeilen zählen hier als ein Fund.

## Nächste Schritte

1. F-01 mit einem Test auf dem vollen Weg (Gateway, Verifier, Antwort) reproduzieren, danach beheben. Das ist die Kerninvariante des Projekts.
2. Hohe Funde beheben, je mit Test: erst F-01 bis F-04 (Belegzwang), dann F-05 und F-06 (Ressourcen), F-07 bis F-10 (Audit, Worker, Job-Anlage), F-11 und F-12 (Guard), F-13 (Pins).
3. Pakete mit gemeinsamen Dateien nach Abschluss der anderen Sitzungen angehen: Engine, Runner, Agents, Builder (F-03, F-04, F-09, F-21, F-23).
4. Danach `/claude-security` und Tag `v0.1.0` (siehe `docs/STATUS.md`).

Hinweis zum Audit-Log (F-07, F-08): Änderungen am Audit-Log brauchen laut `CLAUDE.md` ein ADR und die ausdrückliche Freigabe von Jan. Das gilt für einen verankerten Kopf-Hash und für atomares Anhängen.
