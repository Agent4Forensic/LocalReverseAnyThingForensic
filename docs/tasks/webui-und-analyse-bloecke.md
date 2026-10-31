# Aufgabenblöcke: Analyse-Oberfläche, Hinweise, Ransomware, Code-Sicht

Stand: 2026-10-31. Auftrag von Jan: alle Lücken aus dem Soll-Ist-Abgleich als Blöcke, die günstigere Modelle parallel umsetzen. Dieses Dokument ist zugleich der Vertrag zwischen den Blöcken. Eine Änderung am Vertrag macht nur der Hauptagent.

## 1. Ablauf

| Welle | Blöcke | Parallel | Voraussetzung |
|---|---|---|---|
| 0 | W0 | nein, zuerst allein | keine |
| 1 | A1 A2 A3 A4 A5 A6 A7 A8 A9 A10 B1 R1 R2 L1 | ja | W0 gemergt |
| 2 | A11 I1 S1 R3 B2 | ja | Welle 1 gemergt |
| 3 | B3 | nein | B2, A1 gemergt |
| Gate 1 | G1, G2 | getrennte Prüfer | Welle 3 gemergt |
| 4 | C1 bis C6 | ja | **Freigabe ADR-0006 Paket A durch Jan** |
| 5 | D1 bis D6 | teilweise | **Freigabe ADR-0006 Paket B durch Jan** |
| 6 | E1 | nein | **Freigabe ADR-0005 Stufe 2 durch Jan, Analyse-VM steht** |
| nicht delegierbar | ADR-0005 Stufe 3 | | Isolation, stärkstes Modell, Jan entscheidet |

**Modelle** (CLAUDE.md Subagenten-Regel 2): `haiku` für mechanische Blöcke, `sonnet` für Merkmale, `opus` oder `fable` nur für Gate-Prüfungen. Sicherheitsrelevante Blöcke sind mit **[S]** markiert und werden in G1 geprüft.

**Hauptagent:** startet jede Welle, nimmt die Worktree-Ergebnisse per `git diff` entgegen, committet, merged und prüft im Browser. Er nimmt einen Block nur mit graphify-Nachweis und grünen Tests ab.

## 2. Regeln für jeden Block

1. Start in eigenem Git-Worktree (`isolation: "worktree"`), Basis ist der Branch `feat/webui-analysis`.
2. Zuerst graphify, mit absolutem Pfad, weil `graphify-out/` im Worktree fehlt: `graphify query "<Frage>" --graph D:\Projects\LocalReverseAnything\graphify-out\graph.json`. Danach gezielt `Read` mit Zeilenbereich.
3. Tests: `D:\Projects\LocalReverseAnything\.venv\Scripts\python.exe -m pytest <eigene Tests> -q -p no:warnings`, vor der Abgabe einmal die ganze Suite. Blöcke ohne Python-Anteil lassen zusätzlich `node --test tests/js` laufen.
4. Nur die Dateien des eigenen Blocks ändern. Reicht das nicht: Abbruch mit `BLOCKED: <Datei, Grund>`, kein Umgehen.
5. Nichts committen, nichts pushen, kein Merge.
6. Keine neue Abhängigkeit, kein Netz, kein Modellaufruf, kein Ollama. Tests laufen mit `ScriptedLLM`.
7. Proben nur harmlos und im Test erzeugt. Keine Datei unter `tests/corpus/` anlegen, keine echte Malware (CLAUDE.md Verbot 1 und 2).
8. Frontend: Inhalte aus dem Sample nur als Text über `SW.dom.h` oder `textContent`, nie `innerHTML`. Die CSP verbietet Inline-Styles, also `el.style.x = ...` statt Attribut `style`. Keine Bibliothek, kein CDN. UI-Texte auf Deutsch, Code auf Englisch.
9. Jede neue Ansicht muss unter `?mock=1` mit Beispieldaten laufen (`SW.mockRoutes`, siehe W0).
10. Keine Allowlist-Änderung außer in den Wellen 4 und 5 (CLAUDE.md Verbot 3). `tests/security/test_host_safety.py` nicht aufweichen.
11. Abgabe höchstens 25 Zeilen: Dateien, Teststand (Befehl und Zahl), graphify-Abfragen in je einem Satz, offene Punkte. Keine Dateiinhalte.

**Startauftrag für jeden Agenten** (Modell laut Block):
```
Lies docs/tasks/webui-und-analyse-bloecke.md: Abschnitt 2, Abschnitt 3 und Block <ID>.
Setze nur diesen Block um. Regeln aus Abschnitt 2 sind verbindlich.
Abgabe höchstens 25 Zeilen, mit graphify-Nachweis und Testzahl.
```

## 3. Verträge

### 3.1 Backend-Erweiterung
`webui/app.py` ruft vor dem Static-Mount `mod.register(app, ctx)` für `api_progress, api_hints, api_hex, api_diagrams, api_learn, api_crypto` auf. `ctx` hat `store, gateway, llm, need_job, err, report_model`. Alle Pfade liegen unter `/api/jobs/{job_id}/...`.

### 3.2 Frontend-Erweiterung
- Tabs: `SW.registerTab({id, label, icon, mount(host, ctx) -> {dispose, update}})`. `ctx` hat `st, jobId, route`.
- Reihenfolge: `activity, tree, queue, live, hints, crypto, code, hex, diagrams, log, guard, report`.
- Live-Daten: `SW.store.on('event:<typ>', fn)` für jedes SSE-Ereignis, zusätzlich die vorhandenen Schlüssel über `ui.live`.
- Mock: `SW.mockRoutes['<unterpfad>'] = function (job, query) {...}`.
- CSS je Block in `static/css/<block>.css`.

### 3.3 Synchronisierung
```js
SW.sync.select({source, file, line_start, line_end, offset, length, address, function_id, finding_id, evidence_id, node_id})
SW.sync.on(fn)        // liefert off()
SW.sync.current()
SW.sync.goto(tabId, selection)
```
Eine Ansicht ignoriert Auswahlen mit ihrem eigenen `source`. Felder sind optional. Jede Ansicht reagiert auf die Felder, die sie versteht, und markiert die Stelle.

### 3.4 Antwortformate

**`GET /eta`**
`{state:"waiting|running|finished", eta_s, low_s, high_s, confidence:"none|low|medium|high", pending, running:{id,title,elapsed_s,expected_s}|null, samples, token_rate, budget_left_s, capped_by_budget, reasons:[str], per_task:{task_id:expected_s}}`

**`GET /hints?category=`**
`{items:[{id,category,kind,value,sensitive,confidence,evidence_id,file,offset,line,quote,note_de}], counts:{category:n}, scanned_evidence, complete}`. Bei `sensitive=true` ist `value` maskiert.

**`POST /hints/{hint_id}/reveal`** mit `{reason}`: `{value}`. Der Zugriff steht im Audit-Log, ein leerer Grund ergibt 422.

**`GET /hex?path&offset&length`** (länger als 4096 wird gekappt)
`{path,size,offset,length,rows:[{offset,hex,ascii}]}`, 16 Byte je Zeile.

**`GET /hex/regions?path`**
`{size,type,regions:[{start,end,label,kind,explain_de,entropy}]}`, sortiert und ohne Überlappung.

**`GET /hex/search?path&q&mode=hex|ascii|utf16&offset`**
`{hits:[offset],truncated}`, höchstens 200 Treffer, höchstens 2 s.

**`GET /diagrams?kind=`**
`[{id,kind,origin:"derived|model",layout:"layered|sequence",title_de,title_en,graph:{nodes:[{id,label_de,label_en,type,ref:{file,line,offset}|null,finding_id,evidence_id}],edges:[{from,to,label_de,label_en,finding_id,evidence_id}]},finding_ids}]`

Arten: `task_tree, artifact_chain, timeline, imports, pe_structure, uml_sequence, uml_component, flow, callgraph, dataflow, attack_chain`.

**`GET /functions`, `GET /walkthroughs`:** wie `docs/architecture/dashboard-v2.md` Abschnitt 2, ergänzt um `confidence`, `kind`, `block` je Schritt nach Blueprint 15.

**`GET /crypto`**
`{verdict:"none|indicators|suspected", score, indicators:[{category,label_de,value,evidence_id,offset}], constants:[{offset,candidate,confirm_hint_de,is_crypto}], key_origin:{class:"unknown|hard_coded|derived|generated|received|public_key_wrapped",finding_ids,note_de}, weaknesses:[{label_de,status,finding_ids}], recoverability:{status:"not_assessed|no_weakness_shown|possible_weakness|shown",mechanism_de,finding_ids}, questions:[{id,text_de,status,answer_de,finding_ids}]}`

### 3.5 Maskierung
`sensitive=true` gilt für `private_key`, `api_token`, `key_candidate`, `password_candidate`. Die Maske zeigt Art, Länge und die ersten 4 Zeichen. Ein öffentlicher Schlüssel und eine Wallet-Adresse sind nicht vertraulich. Netzwerkwerte werden entschärft angezeigt (`defang_text`).

### 3.6 Befund-Präfixe (Ransomware)
Das Modell schreibt strukturierte Befunde als Text. Die API liest nur Präfixe:
`KEY-ORIGIN: <class>; ...`, `WEAKNESS: ...`, `RECOVERY: shown; ...`, `RECOVERY: none shown; ...`, `RQ<n>: ...`.
Nur `confirmed` zählt als belegt, `hypothesis` wird als Verdacht angezeigt.

---

## 4. Welle 0

### W0: Gerüst und Erweiterungspunkte (`sonnet`, allein, zuerst) [S]
**Ziel:** Danach können alle Blöcke von Welle 1 arbeiten, ohne eine gemeinsame Datei anzufassen.
**Dateien:** `webui/app.py`, `webui/ctx.py` (neu), Stubs `webui/api_{progress,hints,hex,diagrams,learn,crypto}.py`, `common/store.py`, `orchestrator/runner.py`, `orchestrator/agents.py`, `orchestrator/engine.py`, `orchestrator/sweep.py` (Stub), `gateway/base.py`, `gateway/dev_gateway.py`, `static/index.html`, `static/view_job.js` (nur `TAB_ORDER`), `static/store.js`, `static/mock.js`, `static/sync.js`, Stubs `static/{graph,view_hints,view_hex,view_diagrams,view_log,view_crypto}.js`, leere `static/css/{status,log,hints,hex,graph,diagrams,learn,crypto}.css`, `tests/js/_env.js`, `tests/unit/test_js.py`, `tests/unit/test_webui_contract.py`.
**Vorgaben:**
1. Branch `feat/webui-analysis` legt der Hauptagent vorher an.
2. Backend-Punkt und Tab-Reihenfolge nach 3.1 und 3.2. Tote Skriptverweise (`mock_v2.js`) entfernen.
3. Tabellen in `store.py` mit `add_*`, `list_*`, `get_*` und `emit`: `hints` (eindeutig je `job_id, kind, value`), `hints_scan(job_id, last_evidence)`, `functions`, `walkthroughs`, `walkthrough_steps`, `diagrams` nach `docs/review/platform-adjustments.md` Abschnitt 2. Spalten `tokens_in`, `tokens_out` in `steps`.
4. **Migration:** Eine bestehende Datenbank (`data/sw_analyst.db`) bekommt fehlende Spalten per `PRAGMA table_info` und `ALTER TABLE`. Daten bleiben erhalten.
5. `runner.py` und `agents.py` speichern Token in den neuen Spalten. `/activity` liefert `model.tokens_in`, `model.tokens_out` als Summe des Jobs.
6. `dev_gateway.py`: `read_bytes(job_id, path, offset, length)` (Pfad-Jail, höchstens 64 KiB) neben `read_file_lines`. Diese Methode ist **kein** Werkzeug und nicht in `list_tools()`.
7. `engine.py`: Aufruf `sweep.run(self.store, self.gateway, job_id, "sample")` am Ende von `_plan`, `sweep.run(..., path)` je neuem Artefakt in `_triage_artifacts`. Ein Fehler im Sweep darf den Job nicht beenden und wird geloggt.
8. `store.js`: Jedes SSE-Ereignis löst zusätzlich `event:<typ>` aus. `mock.js`: Vor dem 404 wird `SW.mockRoutes[sub]` geprüft.
9. `sync.js` nach 3.3. `tests/js/_env.js` lädt Dateien aus `static/` mit `node:vm` und minimalem `window`. `tests/unit/test_js.py` ruft `node --test tests/js` auf und überspringt ohne Node.
**Abnahme:**
- `test_webui_contract.py`: Jede in `index.html` referenzierte Datei existiert. Alle sechs `register` laufen. Eine alte Datenbank ohne neue Spalten wird migriert und behält ihre Zeilen. `read_bytes` steht nicht in `list_tools()` und weist `../` zurück. Ein Sweep, der eine Ausnahme wirft, beendet den Job nicht.
- `test_host_safety.py` und die ganze Suite grün, Allowlist unverändert.

---

## 5. Welle 1

### A1: Code-Tab repariert (`haiku`)
**Ziel:** Echte Text- und Skriptdateien erscheinen im Code-Tab.
**Dateien:** `static/view_code.js`, `tests/js/view_code.test.js`.
**Vorgaben:** Das Backend liefert `lines: string[]` und `start`. Normalisierung in `ensure()` zu `{n: start+i, text}`, Objekte aus dem Mock bleiben gültig. HTTP 400 mit Binärmeldung zeigt „Binärdatei“ und eine Schaltfläche, die `SW.sync.goto('hex', {file, offset:0})` aufruft. Auf `SW.sync` mit `file` und `line_start` reagieren und selbst `select` beim Klick auf eine Zeile senden.
**Abnahme:** Test: Antwort mit drei Strings und `start=5` ergibt `n=5,6,7`. Test: 400 mit Binärmeldung zeigt nicht „Die Datei ist leer“.

### A2: Live-Status und Restzeit (`sonnet`)
**Ziel:** Jederzeit sichtbar: was läuft, wo, was wartet, wie lange noch und warum.
**Dateien:** `webui/eta.py` (neu), `webui/api_progress.py`, `static/view_job.js`, `static/css/status.css`, `tests/unit/test_eta.py`, `tests/js/status.test.js`.
**Rechnung** in der reinen Funktion `estimate(tasks, steps, spec, now)`:
1. Erwartung je Aufgabe: Median fertiger Aufgaben gleicher Art (`question` oder Analyse) ab 3 Werten, sonst Median aller fertigen, sonst 90 s (Analyse) und 60 s (Frage).
2. Zuschlag je wartender Analyseaufgabe außer Synthese: mittlere Dauer der `evaluate`-Schritte.
3. `eta_s` = Rest der laufenden Aufgabe (mindestens 0) plus Summe der wartenden.
4. `low_s` = 0,6 × `eta_s`. `high_s` = 1,6 × `eta_s` plus 0,5 × Erwartung × (8 minus benutzte Folgeaufgaben).
5. Kappung an der Restzeit des Budgets, dann `capped_by_budget=true`.
6. `confidence`: `none` ohne Messwert, `low` unter 3, `medium` 3 bis 7, `high` ab 8 Messwerten.
7. `reasons` auf Deutsch, je Einflussgröße ein Satz, zum Beispiel „7 Aufgaben offen, Median 48 s aus 5 Messungen“, „Bis zu 3 Folgeaufgaben können dazukommen“, „Budget endet in 12 min, Schätzung gekappt“, „Modell läuft mit 38 Token/s“.
**Oberfläche:** Im Aktivitätsfeld Spanne („etwa 6 bis 15 min“) mit Kennzeichnung „Schätzung“, aufklappbare Gründe, Phasenleiste. Im Queue-Tab je Aufgabe erwartete Dauer und `reason`. Aktualisierung über `event:task` und `event:step`, höchstens alle 5 s.
**Abnahme:** Tests für: keine Messwerte, 3 Messwerte, Kappung, fertiger Job (`eta_s=0`), wartender Job (`eta_s=null` mit Grund), kein negativer Wert bei Überschreitung. Token-Anzeige zeigt echte Zahlen.

### A3: Log, Guard, Audit (`haiku`)
**Ziel:** Die schon geladenen Daten werden sichtbar.
**Dateien:** `static/view_log.js`, `static/css/log.css`, `tests/js/view_log.test.js`.
**Vorgaben:** Tab `log` mit Filter nach Ebene, Suche und Autoscroll, der beim Hochscrollen pausiert. Tab `guard` mit Regel, Schwere, Aktion, Schnipsel und Link zur Aufgabe, darüber Audit-Status (gültig, Einträge, Kopf-Hash, Bruchstelle). Daten aus `st.log`, `st.guard`, `st.audit` über `ui.live`.
**Abnahme:** Test: Filter und Suche liefern die erwarteten Zeilen. Test: Schnipsel mit `<script>` landet als Text. Beide Tabs laufen unter `?mock=1`.

### A4: Bericht aktualisiert sich (`haiku`)
**Ziel:** Der Bericht folgt dem Lauf ohne Neuladen.
**Dateien:** `static/view_report.js`, `tests/js/view_report.test.js`.
**Vorgaben:** Neu laden bei `findings`, `answers`, `summary`, höchstens alle 10 s, Scroll-Position bleibt. Im Lauf ein Hinweis „Zwischenstand“. Klick auf einen Befund sendet `SW.sync.select({finding_id, evidence_id})`.
**Abnahme:** Test mit falschem Timer: Fünf Ereignisse in 10 s lösen genau einen Abruf aus.

### A5: Hinweis-Extraktor (`sonnet`) [S]
**Ziel:** Jeder Hinweis auf Systeme, Personen, Krypto-Adressen und Schlüssel wird ohne Modell mit Beleg erfasst.
**Dateien:** `report/hints.py` (neu), `webui/api_hints.py`, `tests/unit/test_hints.py`.
**Arten** (`kind` je `category`, `confidence` in Klammern):
- `network`: `ipv4` (öffentlich oder privat in `note_de`), `ipv6`, `domain`, `url`, `email`, `onion` (nur v3, 56 Zeichen), `unc_host`, `user_agent` (validated oder pattern).
- `crypto_address`: `btc_legacy` und `btc_p2sh` mit Base58Check-Prüfsumme (validated), `btc_bech32` mit Bech32-Prüfsumme (validated), `eth` als `0x` plus 40 Hex (EIP-55 prüfen, wenn gemischte Schreibung, sonst pattern), `xmr` als 95 Zeichen Base58 mit Anfang 4 oder 8 (pattern). Fehlt die Prüfsumme, gibt es keinen Treffer.
- `key_material`: `private_key` (PEM-Kopf PRIVATE KEY in allen Varianten), `public_key` (PEM), `certificate`, `api_token` (AWS `AKIA` plus 16, GitHub `ghp_`, JWT mit drei Teilen), `key_candidate` (32, 48 oder 64 Hex oder Base64 in derselben Zeile wie `key`, `iv`, `secret`, `aes`, sonst kein Treffer), `password_candidate` (`password=`, `pwd=`).
- `developer`: `pdb_path`, `user_path` (`C:\Users\<name>`, `/home/<name>`), `build_path`, `compiler` (`GCC: (`, `Go build ID`, `rustc`, `Microsoft (R)`, `PyInstaller`), `copyright`, `vcs` (Git-URL, Commit-Hash neben `commit`), `handle` (`@name` neben `author`, `by`, `coded`).
- `system`: `registry_key`, `windows_path`, `mutex_candidate`, `service_name`.
**Vorgaben:**
1. `extract_hints(text) -> list[Hint]` ist rein und ohne E/A, jede Regex ohne verschachtelte Quantoren, Zeile höchstens 2000 Zeichen.
2. Vorhandene `find_iocs` und `defang_text` aus `report/defang.py` wiederverwenden.
3. `GET /hints` arbeitet inkrementell: Evidence nach `hints_scan.last_evidence` lesen, Treffer speichern, Zeiger setzen. Keine Änderung an der Kette.
4. Datei, Offset und Zeile aus `source_ref` und dem Zeilenpräfix der Evidence.
5. Hinweise sind keine Zuschreibung: `note_de` bei `developer` lautet „Hinweis aus dem Sample, kann gefälscht sein“.
6. Hinweistexte kommen nicht in Prompts. Maskierung nach 3.5, `reveal` schreibt ins Audit-Log.
**Abnahme:** Positiv- und Negativtest je `kind`. Gültige und ungültige Prüfsumme bei BTC und Bech32 mit im Test selbst berechneten Werten. `sensitive` liefert in `GET /hints` nie den Klartext. `reveal` ohne Grund ergibt 422, mit Grund steht ein Audit-Eintrag da. Zweiter Abruf erzeugt keine Dubletten. Text aus 2 MB `a` läuft unter 1 s. Beispielschlüssel im Test werden zur Laufzeit erzeugt und nicht als PEM-Literal eingecheckt, damit der Secret-Scan nicht auslöst.

### A6: Ansicht „Hinweise“ (`sonnet`)
**Ziel:** Ein Tab, in dem alle Hinweise nach Wichtigkeit sortiert und anklickbar sind.
**Dateien:** `static/view_hints.js`, `static/css/hints.css`, `tests/js/view_hints.test.js`.
**Vorgaben:** Gruppen in dieser Reihenfolge: Schlüsselmaterial, Krypto-Adressen, Netzwerk, Entwickler, System. Zähler je Gruppe, Filter und Suche, Vertrauensstufe als Abzeichen. Klick sendet `SW.sync.select({file, offset, line_start, evidence_id})`, dazu Belegchip über `ui.evidenceChip`. „Klartext anzeigen“ nur nach Dialog mit Pflichtgrund, verschwindet beim Tabwechsel. Kopieren nur entschärft. Hinweis bei `complete=false`: „Durchsuchung noch nicht vollständig“. Neue Einträge über `event:hint` und `event:log`. Mock-Route `hints` mit je einem Beispiel pro Gruppe.
**Abnahme:** Test: Maskierter Wert erscheint maskiert, Klartext nur nach Grund. Test: Wert mit HTML landet als Text. Test: Klick löst `select` mit Offset aus.

### A7: Hex-Daten und Struktur (`sonnet`) [S]
**Ziel:** Binärdaten sind seitenweise lesbar und ihre Bereiche erklärt.
**Dateien:** `webui/api_hex.py`, `webui/hex_regions.py` (neu), `tests/unit/test_hex_api.py`.
**Vorgaben:** Endpunkte nach 3.4 über `gateway.read_bytes`, kein Evidence-Eintrag beim Ansehen. Regionen für PE aus `gateway/dev_tools/pe.py`: DOS-Kopf, PE-Signatur, COFF, Optional Header, Sektionstabelle, jede Sektion, Overlay; sonst nur Magic und Rest. Jede Region mit deutschem Satz, was das ist und worauf man achtet, Entropie aus `entropy_from_counts`. Suche mit `bytes.find` in Blöcken und Zeitlimit.
**Abnahme:** Test: Regionen einer im Test gebauten PE sind sortiert, überlappungsfrei, decken die Datei. Pfad-Jail mit `../`. Länge über 4096 wird gekappt. Offset hinter dem Ende ergibt leere Zeilen, keinen Fehler. Kaputter PE-Kopf ergibt 200 mit Fallback-Regionen. Nicht druckbare Bytes sind `.` in `ascii`.

### A8: Hex-Ansicht interaktiv (`sonnet`)
**Ziel:** Der Nutzer versteht, was an einer Stelle steht und was es bedeutet.
**Dateien:** `static/view_hex.js`, `static/css/hex.css`, `tests/js/view_hex.test.js`.
**Vorgaben:** Dateiauswahl, seitenweises Laden beim Scrollen, Farbe je Region mit Legende, Sprung zu Offset, Suche. Klick auf ein Byte zeigt in der Seitenleiste: Offset hex und dezimal, Wert als u8, u16, u32 (Little Endian), Zeichen, Region mit `explain_de`. Marker aus `/hints` (Offset) und Befunden, Klick führt dorthin. Reagiert auf `SW.sync` mit `offset` und `length`, sendet selbst `select`. Bedienbar per Tastatur.
**Abnahme:** Test: u16 und u32 aus Bytes stimmen. Test: Offset in Region zuordnen (Grenzen). Test: `select` mit Offset markiert die Stelle. Läuft unter `?mock=1`.

### A9: Graph-Renderer (`sonnet`)
**Ziel:** Ein wiederverwendbarer SVG-Renderer ohne Fremdbibliothek.
**Dateien:** `static/graph.js`, `static/css/graph.css`, `tests/js/graph.test.js`.
**Schnittstelle:** `SW.graph.render(host, diagram, {onSelect}) -> {highlight(nodeIds), dispose}`, reine Funktion `SW.graph.layout(graph, kind)`.
**Vorgaben:** `layered`: Schichten über längsten Pfad, Kreuzungen per Median-Heuristik, Zyklen über umgedrehte Kanten, begrenzt auf 200 Knoten mit Hinweis. `sequence`: Lebenslinien und Nachrichten in Reihenfolge der Kanten. Zoom, Verschieben, Einpassen, Tastatur, Kantenlabel, Farbe je `type`. Text nur über `textContent`.
**Abnahme:** Test: Layout ist deterministisch, ohne Überlappung, Kanten zeigen in Schichtrichtung. Test: Zyklus terminiert. Test: 201 Knoten werden gekappt mit Hinweis. Test: Label mit `<img onerror>` bleibt Text.

### A10: Diagramme aus gespeicherten Daten (`sonnet`)
**Ziel:** Diagramme ohne Modell, also ohne erfundene Kanten.
**Dateien:** `report/diagrams.py` (neu), `webui/api_diagrams.py`, `tests/unit/test_diagrams.py`.
**Vorgaben:** Reine Funktionen aus der Datenbank:
- `task_tree` aus Aufgaben, `timeline` aus Zeiten.
- `artifact_chain` aus `decode_layer`-Evidence (`source_ref`, `meta.derived`): Eltern-Datei zu Artefakt, Kante mit Methode, `evidence_id` und Hash.
- `imports` und `pe_structure` aus `pe_headers`-Evidence und `hex_regions` (falls schon gemergt, sonst nur `imports`).
- `uml_sequence` (`layout:"sequence"`): Orchestrator, Modell, Gateway, Prüfer aus den letzten 60 Schritten.
- `uml_component`: Sample, Artefakte, DLLs, Netzwerkhinweise.
Dazu gespeicherte Diagramme mit `origin:"model"`. Jede abgeleitete Kante trägt eine `evidence_id`, wo es eine gibt.
**Abnahme:** Test mit `ScriptedLLM`-Lauf aus `tests/ctf`: `artifact_chain` zeigt `sample` zu `derived/layer01.bin`. Test: Jede Kante nennt existierende Knoten. Test: Leerer Job ergibt `[]` ohne Fehler. Test: Gleiche Daten ergeben identisches JSON.

### B1: Modellausgabe-Schema erweitert (`sonnet`) [S]
**Ziel:** Der Guard akzeptiert Funktionen, Lernpfade und Diagramme mit harten Limits.
**Dateien:** `guard/actions.py`, `tests/security/test_guard_actions.py`.
**Vorgaben:** Optionale Felder `functions`, `walkthroughs`, `diagrams` in `finish` nach Blueprint 15 Zeilen 61, 104, 213. Limits: 20 Funktionen, 2 Lernpfade mit je 20 Schritten, Schrittspanne höchstens 12 Zeilen, 3 Diagramme mit je 20 Knoten und 30 Kanten. Finding-Verweise `F-xxxxxx` oder `#n`. Parameter-Schema um `pattern` ergänzen. Unbekannte Schlüssel bleiben Fehler, `line_end >= line_start`.
**Abnahme:** Je Feld gültig, ungültig und über Limit. Bestehender Test auf unbekannte Schlüssel bleibt grün. Kanten ohne `finding_id` und `evidence_id` werden abgelehnt.

### R1: Krypto-Konstanten-Scan (`sonnet`)
**Ziel:** Bekannte Krypto-Konstanten werden ohne Modell mit Offset gefunden.
**Dateien:** `analysis/__init__.py`, `analysis/crypto_scan.py` (neu), `tests/unit/test_crypto_scan.py`.
**Vorgaben:** Reine Funktion `scan(data: bytes) -> list[Hit]` mit der Tabelle aus Blueprint 11 Zeilen 20 bis 32: AES-S-Box vorwärts und invers, `expand 32-byte k`, `expand 16-byte k`, TEA `0x9E3779B9`, MD5 und SHA-1 Startwerte, SHA-256 Startwerte, CRC32-Tabelle (`is_crypto=false`), Base64-Alphabet (`is_crypto=false`), PEM-Köpfe, Bibliotheksnamen. Konstanten in Little und Big Endian. Jeder Treffer nennt `confirm_hint_de` aus der Tabelle und bleibt Hypothese. Höchstens 500 Treffer, 64 MiB unter 5 s.
**Abnahme:** Test je Konstante mit im Test erzeugten Bytes und exaktem Offset. Zufallsdaten liefern keine Treffer. CRC32 ist nicht als Krypto markiert. Zeitgrenze getestet.

### R2: Ransomware-Indikatoren (`sonnet`)
**Ziel:** Ein nachvollziehbarer Verdacht, kein Urteil.
**Dateien:** `analysis/ransom_indicators.py` (neu), `tests/unit/test_ransom_indicators.py`.
**Vorgaben:** Reine Funktion `assess(strings, imports, crypto_hits) -> {verdict, score, indicators}`. Kategorien: `file_enum` (FindFirstFile, FindNextFile), `crypto` (Crypt*, BCrypt*, NCrypt* oder Konstante mit `is_crypto`), `recovery_inhibit` (vssadmin, wbadmin, bcdedit, wmic shadowcopy), `note_text` (Muster wie „your files have been encrypted“, DE und EN), `extension_list` (mindestens 10 Dateiendungen in Folge), `process_kill` (bekannte Dienstnamen, taskkill), `weak_rng` (`rand`, `srand`, `GetTickCount` neben Krypto, nur als Vermerk).
Regeln: `suspected` ab 3 Kategorien, darunter `crypto` und (`file_enum` oder `recovery_inhibit`). `indicators` ab 1 Kategorie außer nur `crypto`. Sonst `none`. **Das Wort „ist Ransomware“ kommt nie vor.** Krypto allein ist ausdrücklich kein Verdacht.
**Abnahme:** Tests für: nur Krypto ergibt `none`; ein Backup-Programm mit Krypto und Datei-API, aber ohne Löschbefehl und Note, ergibt nicht `suspected`; alle Kategorien ergeben `suspected`. Jeder Indikator nennt seine Quelle.

### L1: Layoutfehler (`haiku`)
**Ziel:** Die in `docs/STATUS.md` gemeldeten Fehler sind weg.
**Dateien:** `static/styles.css`.
**Vorgaben:** Kopfzeile des Auftrags ohne ineinanderlaufende Texte, Tabs mit Abstand, bei 12 Tabs Umbruch oder Scrollen. Systemstatus als Kacheln. Breite ab 360 px ohne waagerechtes Scrollen der Seite.
**Abnahme:** Vorher-Nachher im Browser durch den Hauptagenten. Keine neue Farbe außerhalb der Variablen.

---

## 6. Welle 2

### A11: Tab „Diagramme“ (`sonnet`)
**Dateien:** `static/view_diagrams.js`, `static/css/diagrams.css`, `tests/js/view_diagrams.test.js`.
**Ziel und Vorgaben:** Auswahl der Art, Darstellung über `SW.graph`. Klick auf einen Knoten sendet `SW.sync.select` mit `ref`, `finding_id`, `evidence_id` und `node_id`. Eingehende Auswahl hebt passende Knoten hervor. Seitenleiste mit Befund und Beleg. `origin:"model"` trägt das Abzeichen „KI-Vorschlag“. Aktualisierung über `event:diagram`, `event:task`, höchstens alle 10 s. Mermaid-Quelltext zum Kopieren über `report/diagrams.py`-Daten.
**Abnahme:** Test: Klick auf Knoten mit `ref` löst `select` aus. Test: Auswahl mit `finding_id` hebt den Knoten hervor. Läuft unter `?mock=1`.

### I1: Bericht ergänzt (`sonnet`) [S]
**Dateien:** `report/builder.py`, `tests/unit/test_report_sections.py`.
**Ziel und Vorgaben:** Abschnitte „Hinweise“ (ersetzt die IOC-Liste, nach Gruppen, entschärft und maskiert), „Artefakte“ (Hash, Eltern, Methode), Mermaid für `artifact_chain` und `attack_chain`. Bei `verdict != none` ein Abschnitt „Verschlüsselung und Wiederherstellung“. Mermaid-Labels entschärfen und `" [ ] | < >` sowie Zeilenumbrüche entfernen, Knoten-IDs nur `[A-Za-z0-9_]`.
**Abnahme:** Test: Kein Klartext eines `sensitive`-Werts im Bericht. Test: URL ist entschärft. Test: Label mit `]` und `"` bricht Mermaid nicht. Bestehende Berichtstests grün.

### S1: Deterministischer Durchlauf (`sonnet`) [S]
**Dateien:** `orchestrator/sweep.py`, `recipes/ransomware.yaml` (neu), `tests/unit/test_sweep.py`.
**Ziel und Vorgaben:**
1. `sweep.run` holt für den Pfad Strings seitenweise über `gateway.call("strings_extract", ...)`, höchstens 10 Seiten, und speichert sie als Evidence ohne Modell. So werden Hinweise gefunden, auch wenn das Modell nie danach fragt.
2. `read_bytes` plus `analysis.crypto_scan`, Importe aus `pe_headers`, dann `assess`. Ergebnis als Evidence mit Werkzeugnamen `sweep_crypto` und Log-Zeile.
3. Bei `suspected` kommen die Aufgaben aus `ransomware.yaml` einmalig dazu (Priorität 180, Herkunft `recipe`, Grund nennt die Indikatoren).
4. `ransomware.yaml`: Je Frage aus Blueprint 11 Zeilen 54 bis 66 ein Schritt mit `guide` und den Präfixen aus 3.6. Der Leitfaden sagt klar: Ohne Code-Sicht bleibt die Schlüsselfrage offen, und eine Wiederherstellbarkeit darf nur mit gezeigtem Mechanismus behauptet werden. Keine Anleitung zum Bau oder zur Verbesserung von Schadsoftware.
5. Fehlende Seiten werden im Log vermerkt.
**Abnahme:** Test: Harmlose synthetische Probe mit Indikator-Strings ergibt `suspected` und die Aufgaben, ohne dass das Modell sie erfunden hat. Test: Normale Probe ergibt keine Zusatzaufgaben. Test: Zweiter Aufruf dupliziert nichts. Test: Audit-Kette gültig.

### R3: Tab „Verschlüsselung“ und API (`sonnet`)
**Dateien:** `webui/api_crypto.py`, `static/view_crypto.js`, `static/css/crypto.css`, `tests/unit/test_crypto_api.py`, `tests/js/view_crypto.test.js`.
**Ziel und Vorgaben:** `GET /crypto` nach 3.4, Präfixe nach 3.6 aus Befunden. Oberfläche: Verdachtsstufe mit Begründung, Konstanten mit Sprung in die Hex-Ansicht, Schlüsselherkunft, Schwächen, Wiederherstellbarkeit, Fragenliste mit Status. Fester Satz: „Eine Wiederherstellung ist nur belegt, wenn ein Mechanismus gezeigt wurde. Ohne Fehler im Verfahren ist der Schlüssel aus der Probe nicht herleitbar.“ Hypothesen sehen anders aus als Belege.
**Abnahme:** Test: `RECOVERY: shown` als `hypothesis` ergibt nie `status:"shown"`. Test: Ohne Präfixe `not_assessed` und `unknown`. Test: `none` zeigt keinen Alarm. Läuft unter `?mock=1`.

### B2: Kette liefert Funktionen, Lernpfade, Diagramme (`sonnet`) [S]
**Dateien:** `orchestrator/runner.py`, `orchestrator/verifier.py`, `orchestrator/engine.py`, `prompts/registry.py`, `recipes/script.yaml`, `translate/` nur falls nötig, `tests/unit/test_learn_chain.py`.
**Ziel und Vorgaben:**
1. `verify_location`: Datei existiert, Zeilen liegen im Dokument, Evidence gehört zum Job und deckt den Bereich. Name und Adresse kommen im Evidence-Text vor. Gilt auch für bestehende Annotationen (`docs/review/platform-adjustments.md` Abschnitt 1).
2. `_finish` prüft und speichert die neuen Felder, verwirft Falsches und zählt es im Prüfschritt. Abbildung lokaler IDs (`#n`, `FN1`) auf globale. Behebt den Fehler, dass jede Annotation `ids[0]` bekommt.
3. Aufgabenart `build_walkthrough` und `build_diagrams` mit eigener Vorlage und eigenem kurzem Schema, 4096 Antwort-Token, höchstens 3 Züge. Kurzform von Blueprint 15 als `Rules`.
4. `script.yaml`: Schritt `walkthrough` (Priorität 165) und `diagrams` (Priorität 170).
5. `_translate_new` übersetzt die neuen Texte über den Cache.
6. Erklärtexte zählen nie als Befund.
**Abnahme:** Test: Erfundene Zeile, fremde Evidence und erfundene Adresse werden verworfen. Test: Gültiger Lernpfad wird gespeichert. Test: Kante ohne Beleg wird verworfen. Tests in `tests/ctf` grün.

---

## 7. Welle 3

### B3: Lernpfad, synchron mit allem (`sonnet`)
**Dateien:** `webui/api_learn.py`, `static/view_code.js`, `static/css/learn.css`, `tests/unit/test_learn_api.py`, `tests/js/view_learn.test.js`.
**Ziel und Vorgaben:** `/functions`, `/walkthroughs`. Lernpfad-Modus: Schritt anklicken springt, hebt Zeilen hervor und zeigt die Erklärung mit Beleg und Abzeichen „KI-Erklärung“. Jeder Schritt sendet `SW.sync.select`, sodass Diagramm, Hex und Hinweise mitlaufen. Eingehende Auswahl im Diagramm wählt den passenden Schritt. Vor und Zurück per Taste.
**Abnahme:** Test: Schrittwechsel löst `select` mit `file` und Zeilen aus. Test: Eingehende Auswahl wählt den richtigen Schritt. Test: Fehlende Routen zeigen einen Hinweis, keinen leeren Bereich.

---

## 8. Gate 1

### G1: Sicherheitsprüfung (`opus`, nur lesen, getrennt von G2)
Prüft alle [S]-Blöcke auf: Pfad-Traversal in `/hex`, Maskierungslücken, Offenlegung über Log und SSE, XSS über Sample-Text und Mermaid, Prompt-Injection über Hinweise und Diagramme, ReDoS, Ressourcenlimits, Secret-Leaks. Dazu `/claude-security` auf dem Diff. Funde mit Datei, Zeile und Reproduktion. Merge nach `main` erst, wenn keine hohen Funde offen sind (CLAUDE.md Arbeitsweise 9).

### G2: Durchstich im Browser (Hauptagent)
Mit den Proben aus `tests/bench/run_live.py` und echtem Modell: Jeder Tab zeigt Daten, ein Klick im Diagramm springt in Code oder Hex und zurück, ein Neuladen stellt den Zustand wieder her, Restzeit ist plausibel. Ergebnis mit Screenshots in `docs/STATUS.md`.

---

## 9. Welle 4: ADR-0006 Paket A (erst nach Freigabe)
Alle Blöcke ändern `tests/security/test_host_safety.py` nur um den eigenen Werkzeugnamen; bei Parallelbetrieb trägt der Hauptagent die Namen beim Merge ein. Dateien: je Werkzeug eigenes Modul unter `gateway/dev_tools/`, die Anmeldung in `dev_gateway.py` macht der Hauptagent.

| Block | Modell | Werkzeug | Abnahme |
|---|---|---|---|
| C1 [S] | sonnet | `extract_range` | über 8 MiB gekappt, Jail, Quote gemeinsam mit `write_layer`, Hash im Ergebnis, Rekursion greift |
| C2 [S] | sonnet | `zip_extract` | Bomben-Limit, Name vom Gateway vergeben, verschlüsselte Einträge abgelehnt, Zip-Slip getestet |
| C3 [S] | sonnet | `pe_resources`, `pe_metadata` (Rich Header, PDB aus Debug-Verzeichnis, Versionsinfo, Signatur vorhanden) | Fuzz wie `test_pe_parser_fuzz_mutations`, kaputte Eingabe wirft nie |
| C4 [S] | sonnet | `apk_manifest` (Binär-XML), `dex_strings` | Fuzz, im Test gebaute Minimaldatei, Größenlimits |
| C5 [S] | sonnet | `decode_layer`: `base32`, `base85`, `xor_key`, `rc4`, `char_codes` | Testvektoren, Schlüssel nur als Hex-Argument, kein Durchprobieren |
| C6 | sonnet | Rezepte und Leitfäden: GAP-Hinweise entfallen, Hinweis-Extraktor nutzt `pe_metadata` | Tests der Rezepte, `run_live.py` zeigt Treffer |

## 10. Welle 5: ADR-0006 Paket B (erst nach Freigabe)

| Block | Modell | Inhalt | Abnahme |
|---|---|---|---|
| D1 [S] | sonnet | Dockerfile in `infra/docker/`: Ghidra 12.1.4, gepinnt und gehasht, Laufprofil laut ADR-0006, Label `sw-analyst` | Test: Container erreicht kein Netz, Root-Dateisystem schreibgeschützt, Prozesslimit greift; Lizenzen in `docs/dev-environment.md` |
| D2 [S] | sonnet | Adapter `gateway/ghidra_adapter.py`: `list_functions`, `disassemble`, `decompile`, `xrefs`, `basic_blocks`, feste Schemas, kein Skriptkanal | Test mit im Test gebauter Mini-PE, Timeout, Ausgabelimit, Ergebnis als `derived/` plus Evidence |
| D3 [S] | sonnet | `capa_scan`, `yara_scan`, `floss_decode` | Regeln gepinnt, Treffer sind Hypothesen, Timeout |
| D4 [S] | sonnet | `jadx_decompile` | Wie D2, Größenlimit |
| D5 | sonnet | `static/view_asm.js`: Assembler mit Sprungpfeilen, Klick auf einen Sprung erklärt Bedingung, Ziel und Bedeutung, Kontrollflussgraph aus `basic_blocks`, alles über `SW.sync` | Test: Pfeile aus Blockkanten, Sprung wählt Ziel, Graph und Code folgen einander. Bewertung „warum wichtig“ nur aus Befund oder Schritt mit Beleg |
| D6 [S] | sonnet | `exe.yaml`: Ranking nach Blueprint 02, Lernpfad je Top-Funktion, Ransomware-Fragen mit Code-Belegen; `S1` nutzt Funktionen; neuer Modellvergleich | Tests, Lauf mit Mini-PE. Key-Herkunft wird aus Aufrufen belegt |

**Schlüsselprüfung (Teil von D6, nur mit Freigabe von Abhängigkeit und Zweck):** Prüfung eines aus dem Sample belegten Schlüssels gegen einen eingebetteten Blob, Ergebnis als Artefakt. Kein Durchprobieren von Schlüsselräumen über das Modell. Eine Prüfung schwacher Zufallsquellen (`srand(time)`) wird erst nach eigenem ADR geplant.

## 11. Welle 6: ADR-0005 Stufe 2 (erst nach Freigabe)
**E1 [S] (`sonnet`, Prüfung durch `opus`):** `emulate_function(offset, end, input_ref)` mit Unicorn im Container, kein Betriebssystem, keine Host-Aufrufe, Budget für Instruktionen, Zeit und Speicher. Ergebnis als Artefakt, Aussagen bleiben `hypothesis`. Abnahme: harmlose Testroutine (XOR-Schleife) liefert das erwartete Ergebnis, unbekannter Speicherzugriff bricht mit Adresse ab, Budget greift.

**ADR-0005 Stufe 3 wird nicht delegiert.** Einrichtung und Isolation der Detonations-VM brauchen Jans Entscheidung, das stärkste Modell und die Abnahme aus dem ADR.

## 12. Dateibesitz Welle 1 und 2
Keine Datei hat in einer Welle zwei Besitzer.

| Datei | Welle 1 | Welle 2 |
|---|---|---|
| `static/view_code.js` | A1 | |
| `static/view_job.js` | A2 | |
| `static/view_report.js` | A4 | |
| `static/styles.css` | L1 | |
| `webui/api_hints.py`, `report/hints.py` | A5 | |
| `webui/api_hex.py`, `webui/hex_regions.py` | A7 | |
| `static/graph.js` | A9 | |
| `webui/api_diagrams.py`, `report/diagrams.py` | A10 | |
| `guard/actions.py` | B1 | |
| `analysis/*` | R1 (`crypto_scan`, `__init__`), R2 (`ransom_indicators`) | |
| `report/builder.py` | | I1 |
| `orchestrator/sweep.py`, `recipes/ransomware.yaml` | | S1 |
| `orchestrator/runner.py`, `verifier.py`, `engine.py`, `prompts/registry.py`, `recipes/script.yaml` | | B2 |
| `webui/api_crypto.py`, `static/view_crypto.js` | | R3 |
| `static/view_diagrams.js` | | A11 |

R2 legt keine Datei `analysis/__init__.py` an und wartet nicht auf R1. Beim Merge gewinnt die leere Datei von R1.

## 13. Bekannte Grenzen
- Assembler, Sprungansicht und belegte Schlüsselherkunft in PE-Dateien gibt es erst ab Welle 5. Bis dahin bleiben sie als GAP sichtbar.
- Die Restzeit bleibt eine Schätzung, weil Folgeaufgaben während des Laufs entstehen.
- Der Hinweis-Extraktor findet nur, was in Strings oder Tool-Ergebnissen sichtbar ist. Verschlüsselte oder zur Laufzeit gebaute Werte fehlen, bis Dekodierung oder Emulation sie freilegt.
- Die Hinweis-Erkennung ersetzt keine Zuschreibung. Autoren- und Pfadangaben im Sample können gefälscht sein.
- Eine Wiederherstellung ist nur bei einem Fehler im Verfahren möglich. Das System behauptet sie nur mit gezeigtem Mechanismus.
