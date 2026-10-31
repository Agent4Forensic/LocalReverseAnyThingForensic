# Statusübersicht sw-analyst

Stand: 2026-10-31 · Legende: `[x]` erledigt und geprüft · `[~]` begonnen · `[ ]` offen · `[!]` blockiert, braucht Jan

## Phase P: Voraussetzungen (vor jeder Implementierung)

### P1 Inventur
- [x] Hardware: RTX 5060 Ti 16 GB (Treiber 617.42), 31,1 GB RAM, 16 Threads, D: 1,3 TB frei
- [x] Tools vorhanden: git 2.55, Python 3.11.9, Node 24.19, Docker 29.8.2 (Client), Ollama 0.35.1 (Client), JDK 17, uv, gh, WSL2 (kali-linux)
- [x] Tools fehlend: pipx (nicht nötig, uv genügt), cmake (erst bei Bedarf)
- [!] GPU: 12,3 von 16,3 GB VRAM durch Desktop-Apps belegt (Browser, Zotero, Steam-WebHelper, WhatsApp u. a.). Frei für Modelle: ca. 4 GB. Siehe Blocker B2.

### P2 Plugins und Skills (Dev-Rechner)
- [x] Caveman (655b7d9) vorhanden
- [x] graphify 0.8.44 vorhanden (CLI + Skill)
- [x] Ponytail (96608e0) installiert. Audit: keine Netzwerkaufrufe in Hooks; Webhook nur bei Konfiguration.
- [x] claude-security, feature-dev, pr-review-toolkit, mcp-server-dev installiert (claude-plugins-official, nur On-Demand-Befehle, Hooks ohne Netzwerk)
- [x] Bereits vorhanden: engineering:* (code-review, architecture, system-design, testing-strategy, debug, documentation), security-review, code-simplifier, frontend-design
- [x] Verworfen nach Audit: mnemo (Fremd-Hooks auf jedem Tool-Call, Binary-Nachladen), security-guidance (pip-venv beim Start, LLM-Review bei jedem Stop)
- [x] Ponytail userConfig geprüft: Webhook leer (nichts verlässt den Rechner), lokales Ledger bleibt Standard
- [x] Audits mit SHAs in `docs/dev-environment.md`, Entscheidungen in `docs/adr/0000-grundentscheidungen.md`

### P3 Claude-Code-Einstellungen
- [x] Auto-Compact bei 70 % (`.claude/settings.json`)
- [x] Auto-Compact: Schlüssel `autoCompactEnabled` nicht gesetzt = Standard (an); Schwelle 70 % per Projekt-Env
- [x] Repo-Gerüst, `.gitignore`, Pre-Commit-Hook (Test: blockiert .exe in tests/corpus), CLAUDE.md, PROJEKTPLAN.md
- [x] Erster Commit (`5d5a15e`), LF-Erzwingung für Hooks (`342bae3`)

### P4 Laufzeit-Infrastruktur
- [x] Docker Desktop läuft (Engine 29.8.2), GPU-Durchreichung getestet (nvidia-smi im Container, `--network none`)
- [!] `.wslconfig` von 20 auf 24 GB: erfordert `wsl --shutdown` und beendet laufende WSL-Dienste (Kali, anderer Docker-Stack). Freigabe von Jan nötig. Siehe B1.
- [ ] Ollama-Server starten, Umgebung setzen (`OLLAMA_MAX_LOADED_MODELS=1`, `OLLAMA_KEEP_ALIVE`, Flash Attention, KV-Cache-Quantisierung)
- [ ] Modellauswahl automatisiert (Skript prüft VRAM/RAM, wählt Modell, Benchmark mit synthetischen Beispielen)
- [ ] Embedding-Modell wählen und testen
- [!] Hyper-V: Dienst `vmms` läuft, Admin-Rechte fehlen für VM-Anlage. Admin-Skript wird erzeugt (Phase 1).

### P5 Analyse-Werkzeuge (Dev-Test mit harmlosen Proben)
- [~] Ghidra: Version recherchiert und gepinnt (12.1.4, JDK 21, SHA-256 verifiziert), Docker-Image noch nicht gebaut
- [~] REA: von Jan freigegeben (nur statisch, ohne Live-Teile). Tiefenaudit fertig (6.8.0, Pin, Familien- und Tool-Allowlist, Auflagen in dev-environment.md). Einbau ins Docker-Image und manuelles Quellcode-Review stehen aus.
- [ ] jadx, apktool, capa, YARA, FLOSS, radare2, binwalk, pefile, lief, androguard im Image
- [~] Ghidra-MCP: Empfehlung pyghidra-mcp v0.2.7 (kleinste Angriffsfläche, keine Code-Ausführung); ADR folgt nach Funktionstest
- [ ] Alle Downloads mit SHA-256 in `docs/dev-environment.md`

### P6 Abschluss Voraussetzungen
- [x] Verifikationsskript `infra/verify-prereqs.ps1` (Lauf: 24 PASS, 2 FAIL: VRAM, Ollama-Server; 2 WARN: freier RAM, graphify-out)
- [ ] Kompakte Doku `docs/README.md` (Überblick, Entscheidungen, Runbook Kurzform)
- [ ] graphify-Lauf über das Repo, `graphify-out/` vorhanden
- [ ] Freigabe von Jan für Phase 0

## Blocker und offene Fragen an Jan
- B1: `wsl --shutdown` zum Anwenden des 24-GB-Limits erlaubt? (beendet WSL-Instanzen, auch andere Projekte)
- B2: VRAM-Belegung durch Desktop-Apps: Apps schließen oder kleineres Modell akzeptieren?
- B4: Freier RAM beim Test nur 3,7 von 31 GB (Docker Desktop frisch gestartet plus Browser/Apps). 24-GB-Limit ist nur realistisch, wenn andere Programme während der Analyse geschlossen sind.
- B5: erledigt. Jan hat REA ohne Live-Komponenten freigegeben, Bedingungen im Audit.
- B3: Admin-Rechte für Hyper-V-Einrichtung: Du führst das erzeugte Skript selbst aus (bestätigt in Auswahl, Termin offen).

## Aktuelle Arbeit (feat/core-chain)
- [~] Kern: Datenmodell, Gateway-/LLM-Vertrag, Audit-Log (Hash-Kette), SQLite-Store, Ollama-/Fake-Client geschrieben; Tests stehen aus
- [~] Agenten parallel: Frontend, Dev-Gateway, Prompt-Schutz, Übersetzung+Defanging (in Arbeit)
- [~] Blueprint (docs/blueprint/, 15 Dateien, Fable 5.1, 4 Agenten) in Arbeit; Themenliste des Berichts von Jan liegt vor (Übergabe+Hashes, Erkennung je Schritt, logischer Aufbau mit Nachweis, Zielfragen/CTF)
- [~] Audit morluto/rea (Tool-Inventar, npm gegen Repo) läuft
- [~] Orchestrator: geschrieben sind Prompt-Registry, Rezepte (generic/script/exe/apk), JSON-Hilfen, Prüfer (verifier.py) und Task-Runner (runner.py, ungetestet, braucht das Paket guard). FEHLT: Evaluator, Priorisierer, Planer/Engine, Worker, Report-Builder, API-App, Wiring, Tests, CTF-Test, Prompts je Aufgabentyp, API, Bericht, Wiring, CTF-Tests
- [ ] graphify-Lauf über das Repo (nach Abgabe der Agenten)

## Hinweis Limit (2026-10-31)
Sitzung wegen Nutzungslimit beendet. Der Frontend-Agent wurde gestoppt (vorhanden: api.js, dom.js, markdown.js, theme.js, mock.js; es fehlen index.html, app.js, styles.css und der Asset-Test). Hintergrund-Agenten (Dev-Gateway, Dev-Gateway, Prompt-Schutz, Übersetzung, 4 Blueprint-Agenten, REA-Audit, graphify-Extraktion) laufen eventuell weiter und schreiben Dateien. Ergebnisse prüfen: `git status`, dann Tests (`.venv\Scripts\python.exe -m pytest`). graphify: Chunk-Datei `graphify-out/.graphify_chunk_01.json` abwarten, dann Schritte 3 Part C bis 9 des Skills ausführen (AST-Ergebnis liegt in `graphify-out/.graphify_ast.json`).

## Nächste Schritte: alles zum Laufen bringen (Priorität 1, Stand 2026-10-31 abends)
Ziel: ein echter Job läuft im Browser mit echtem Modell von der Eingabe bis zum Bericht, gestartet mit `scripts\start.ps1`.
Abnahme: CTF-Probe (zwei Base64-Schichten, Flagge) wird mit lokalem Modell gelöst, Antwort belegt und als erwartet erkannt; Dashboard zeigt Aktivität, Baum, Queue, Live-Bericht und Log; `stop.ps1` beendet sauber.

| # | Schritt | Ergebnis | Abhängig von |
|---|---|---|---|
| R1 | Arbeitsbaum sichern: Startskripte, Preflight, Fable-Dokumente committen und pushen, `git ls-files -d` prüfen | Stand auf GitHub | nichts |
| R2 | Modell: `qwen3:8b` (existiert sicher, Thinking und Tools) in `D:\Tools\sw-analyst\ollama-models` ziehen, Server auf Port 11435 starten, Smoke-Test JSON-Modus, Geschwindigkeit messen. Parallel prüfen, ob `gemma4:12b-it-q4_K_M` und `ornith:9b-q4_K_M` existieren (VRAM jetzt ca. 14 GB frei) | Modellwahl belegt, ADR-0001 aktualisiert | nichts |
| R3 | Backend-Lauffähigkeit: Origin-Prüfung portabel machen (nicht fest 8765), Endpunkt `/activity`, Antwortbudget für Thinking-Modelle anheben und leere Antworten abfangen, `redact`/Guard im echten Lauf prüfen | `python -m sw_analyst` startet, API antwortet | R2 |
| R4 | Frontend-MVP fertigstellen (Neuer Auftrag, Aktivität, Baum, Queue, Live-Bericht, Log, Bericht), dann Asset-Test | Dashboard bedienbar, `?mock=1` zeigt alle Ansichten | R3 (API-Form) |
| R5 | Erster echter Lauf: CTF-Probe über den Browser, Fehler in Prompts und Schleife beheben (JSON-Zuverlässigkeit, Token, Dauer), danach Skript mit 3 Schichten und kleine synthetische PE | belegte Antwort, Messwerte je Aufgabe | R2 bis R4 |
| R6 | `start.ps1` und `stop.ps1` scharf testen (CHECK, INSTALL aus Pins, OLLAMA, APP, Strg+C, `-Force`) | ein Befehl startet alles | R2, R3 |
| R7 | Abnahme: alle Tests grün, `/claude-security` auf dem Diff, Tag `v0.1.0`, `feat/*` per `--no-ff` nach `main`, Push | lauffähiger `main` | R1 bis R6 |

Danach (Priorität 2, in dieser Reihenfolge): P1-Anpassungen aus `docs/review/platform-adjustments.md` (Guard-Schema, Store-Tabellen, Endpunkte, Antwortbudget), forensische Tests Block 1 und 2, Ghidra-Image und Disassembler-Tools hinter dem Gateway (ADR und Freigabe nötig), Dashboard V2 (Lernpfad, Diagramme), Hyper-V-VM, dynamische Analyse (ADR-0005).

## Strukturierte Code-Review durch alle Modelle (von Jan beauftragt, 2026-10-31)
Ziel: Jedes verfügbare Modell prüft denselben Code nach demselben Raster. Unterschiedliche Modelle finden unterschiedliche Fehler; der Abgleich zeigt, was mehrfach bestätigt ist und was nur ein Modell sieht. Annahme: "alle Modelle" = die Claude-Modelle Fable 5.1, Opus 5.5, Sonnet 5.5, Haiku 5.5. Falls auch die lokalen Ollama-Modelle gemeint sind, bitte melden (anderer Ablauf, siehe Risiken).
Stand: **offen**. Voraussetzung: Security-Review und Tag `v0.1.0` (siehe R7) bleiben davon getrennt (CLAUDE.md Arbeitsweise 9).

### 1. Umfang (feste Pakete, je Paket ein Auftrag je Modell)
| Paket | Pfad | Zeilen (ca.) | Schwerpunkt |
|---|---|---|---|
| A Kern | `src/sw_analyst/common/` | 600 | Audit-Hash-Kette, Store, Datenmodell, Zeitstempel |
| B Gateway | `src/sw_analyst/gateway/` | 2150 | Allowlist, Pfad-Jail, Regex-Guard (ReDoS), Parser-Robustheit |
| C Guard | `src/sw_analyst/guard/` | 1500 | Prompt-Injection-Regeln, Umgehung (Unicode, Kodierung), Aktions-Validierung |
| D Orchestrator | `src/sw_analyst/orchestrator/`, `prompts/`, `recipes/` | 1050 | Schleife, Budget, Belegprüfung (Verifier), Abbruch, Races im Worker |
| E LLM und Übersetzung | `src/sw_analyst/llm/`, `translate/` | 850 | Fehlerbehandlung, leere Antworten, Protect/Restore, Cache |
| F Bericht | `src/sw_analyst/report/` | 390 | Defanging-Lücken, Evidence-Bezug, Reproduzierbarkeit |
| G Web | `src/sw_analyst/webui/` (Python und `static/*.js`) | 350 + JS | Upload, Origin-Prüfung, XSS, Pfade, SSE |
| H Betrieb | `scripts/*.ps1`, `infra/` | - | Löschumfang von Cleanup, Pins/Hashes, Fremdprozesse |
| I Tests | `tests/` | - | Lücken gegen `docs/testing/forensic-test-plan.md`, Schein-Tests |

### 2. Raster (jedes Modell prüft jedes Paket nach denselben 8 Punkten)
1. Korrektheit und Logikfehler, Randfälle
2. Sicherheit: Pfad-Traversal, Injection, Prompt-Injection über Sample-Inhalte, Rechte, Secret-Leaks
3. Forensik: Chain-of-Custody, Hashes, Determinismus, Zeitstempel
4. Belegzwang: kann eine Aussage ohne passende Evidence durchrutschen?
5. Ressourcen: Limits, Timeouts, Endlosschleifen, Speicher
6. Fehlerbehandlung: stille Fehler, Fallbacks, die Fehler verdecken
7. Tests: Abdeckung, Schein-Tests, fehlende Negativfälle
8. Vereinfachung: überflüssiger Code, doppelte Logik (Ponytail-Prinzip)

### 3. Verteilung der Modelle
| Modell | Rolle | Pakete | Hinweis |
|---|---|---|---|
| Fable 5.1 | Tiefenprüfung Architektur und Sicherheit | B, C, D (Verifier), F | stärkstes Modell nur dort, wo Sicherheit zählt (CLAUDE.md Subagenten-Regel 2) |
| Opus 5.5 | Zweitmeinung Sicherheit und Logik | alle A bis G | unabhängig, ohne Fable-Ergebnis lesen |
| Sonnet 5.5 | Breite Prüfung aller Pakete | A bis I | Standardrunde |
| Haiku 5.5 | schnelle mechanische Prüfung | G (JS), H, I | Lint-nahe Funde, Stil, tote Pfade |
Jedes Modell prüft **blind** (kein Zugriff auf die Ergebnisse der anderen), danach erst Abgleich.

### 4. Ablauf
1. Auftrag je Modell und Paket nach Regeln in CLAUDE.md "Subagenten-Regeln": Prompt unter 40 Zeilen, `graphify` zuerst, feste Dateimenge, nichts committen, Abgabe höchstens 25 Zeilen mit graphify-Nachweis.
2. Ausgabeformat je Fund (eine Zeile, maschinenlesbar): `paket | datei:zeile | schwere (krit/hoch/mittel/niedrig) | kategorie (1-8) | problem | fix | konfidenz`.
3. Ablage: `docs/review/code-review/<modell>-<paket>.md`.
4. Abgleich durch den Hauptagenten: `docs/review/code-review/SUMMARY.md` mit Tabelle Fund x Modell (bestätigt = mindestens 2 Modelle, einzeln = 1 Modell, widersprüchlich).
5. Jeder bestätigte Fund mit Schwere hoch oder kritisch wird vor dem Beheben mit einem Test reproduziert. Einzelfunde werden gelesen und bewertet, nicht blind übernommen.
6. Behebung in `fix/review-<paket>`, je Paket ein Merge nach grünen Tests. Offene Funde mit Begründung nach `docs/STATUS.md`.

### 5. Abnahme
- [ ] Alle 9 Pakete von mindestens 2 Modellen geprüft (Pakete B, C, D von allen 4)
- [ ] `SUMMARY.md` mit Fund-x-Modell-Tabelle, Funde getrennt in bestätigt, einzeln, verworfen (mit Grund)
- [ ] Alle kritischen und hohen bestätigten Funde behoben, je mit Test
- [ ] Tests grün, Ergebnis in `docs/STATUS.md` und im Dev-Vault
- [ ] Danach erst Security-Review (`/claude-security`) und Tag `v0.1.0`

### 6. Risiken
- Token-Kosten: Opus und Fable nur auf B, C, D, F voll; Rest über Sonnet/Haiku. Reihenfolge: Sonnet breit, dann gezielte Tiefenprüfung dort, wo Sonnet Funde meldet.
- Halluzinierte Funde: jeder Fund braucht Datei, Zeile und Reproduktion; ohne das gilt er als unbelegt.
- Prompt-Injection über Testproben: Prüfer lesen `tests/corpus/` nur über Manifest, nie Probeninhalte als Anweisung.
- Lokale Ollama-Modelle (`qwen3:8b` u. a.) taugen für diese Prüfung kaum (siehe `docs/review/model-evaluation.md`); nur auf ausdrücklichen Wunsch, dann mit kleineren Paketen und Pflicht-Gegenprüfung.

## README (von Jan beauftragt, 2026-10-31)
- [x] **`README.md` im Repo-Root** (erstellt 2026-10-31; Screenshots und Flussdiagramm-Datei folgen) (fehlt, GitHub zeigt bisher keine Startseite). Inhalt: Zweck und Nicht-Ziele (nur statische Analyse, keine echte Malware im Repo), Architektur in einem Bild (Kette: Triage, Rezept, Queue, Task-Runner, Guard, Prüfer, Antworten, Bericht), Voraussetzungen (Windows 11, Python 3.11, Docker, NVIDIA-GPU, 24 GB RAM-Limit), Schnellstart (`scripts\start.ps1`, `stop.ps1`, Schalter `-NoCleanup`, `-Offline`, `-Update`), Sicherheitsmodell (Isolation, Gateway-Allowlist, Prompt-Schutz, Audit-Kette), Verweise auf `PROJEKTPLAN.md`, `docs/STATUS.md`, `docs/blueprint/`, Teststand, Lizenz. Belegt nur, was läuft; Offenes steht unter "Status". Screenshots des Dashboards erst nach dem ersten echten Lauf.

## Flussdiagramm der umgesetzten Workflows (von Jan beauftragt, 2026-10-31)
- [ ] **Abstraktes Flussdiagramm** (`docs/architecture/workflows.md`, Mermaid, auch als Bild im README): nur was tatsächlich umgesetzt ist, je Workflow ein Diagramm auf hoher Ebene. Vorgesehen: (1) Start/Stopp (CLEAN, CHECK, INSTALL, UPDATE, OLLAMA, MODEL, APP, Statusschleife, Stopp mit Cleanup), (2) Job-Lebenszyklus (Auftrag, Triage, Rezept, Aufgaben-Queue, Task-Runner mit Werkzeug-Schleife, Prüfer, Bewerter, Priorisierer, Antworten, Übersetzung, Bericht), (3) Schutzschichten (Guard vor und nach jedem Modellaufruf, Gateway-Jail, Audit-Kette), (4) Datenfluss Sample bis Bericht mit Hashes und Evidence. Nicht Umgesetztes (Ghidra, Wissensdatenbank, dynamische Analyse) wird gestrichelt und als "offen" markiert. Quellen: `docs/architecture/chain.md`, `scripts/start.ps1`, `orchestrator/*`; graphify-Abfragen vorab, damit das Bild dem Code entspricht und nicht dem Plan.

## Dashboard-Lücken (Stand 2026-10-31 20:15, per Screenshot geprüft)
- [x] App startete nicht: `python-multipart` fehlte (Upload-Route). Gepinnt auf 0.0.32 (Apache-2.0, 0.0.33 vom selben Tag bewusst übersprungen), Test `tests/unit/test_webui_boot.py` sichert den Start ab.
- [ ] `index.html` lädt drei nicht vorhandene Skripte (`mock_v2.js`, `view_diagrams.js`, `view_log.js`, 404). Die Tabs Diagramme, Log und Guard fehlen deshalb; Aktivität zeigt "Noch keine Daten", bis der `/activity`-Endpunkt Daten liefert.
- [ ] Kopfzeile des Auftrags und Tab-Leiste mit Layoutfehlern (Texte laufen ineinander, Tabs ohne Abstand), Systemstatus als eine lange Spalte statt Kacheln.
- [ ] Neuer Auftrag: Sample-Upload und Absenden im Browser noch nicht getestet.

## Aufräumen vor Start und nach Stopp (von Jan beauftragt, 2026-10-31)
- [x] `scripts/cleanup.ps1` (Stage `CLEAN`), von `start.ps1` (`-Phase pre`) und `stop.ps1` (`-Phase post`) aufgerufen; abschaltbar mit `-NoCleanup`, prüfbar mit `cleanup.ps1 -Phase pre|post -DryRun`.
- **pre:** veraiste PID-Dateien, verwaiste eigene App-Prozesse (nicht in `app.pid`), verwaiste Modell-Runner, Laufzeit-Scratch in `data\run`, `data\tmp`, `*.partial`-Installreste, Logs älter als 14 Tage, beendete Docker-Container mit Label `sw-analyst`.
- **post:** zusätzlich alle eigenen Restprozesse, PID-Dateien, `__pycache__` und `.pytest_cache`, Install-Archive in `dl` älter als 1 Tag, abgebrochene Modell-Downloads (`*-partial*`) älter als 3 Tage (nur wenn kein Ollama läuft), alle Docker-Container mit dem Label (erst `stop`, dann `rm -f -v`), Netzwerke, anonyme Volumes und Images mit dem Label.
- **Grenzen:** nur eigene Dinge. Fremde Prozesse, Ollama auf 11434, `~/.ollama` und fremde Docker-Objekte bleiben unberührt. Der Docker-Build-Cache gehört allen Projekten und wird nur mit `stop.ps1 -DockerDeep` (Einträge älter als 7 Tage) angefasst.
- **Konvention:** Jeder Container, jedes Netzwerk und jedes Volume der Plattform wird mit `--label sw-analyst` erzeugt, sonst räumt das Skript es nicht auf.
- Geprüft: Parser 0 Fehler, Trockenlauf beider Phasen, Docker-Test mit Wegwerf-Containern (nur der gelabelte wurde entfernt), 3 statische Tests in `tests/unit/test_scripts.py`. Noch nicht geprüft: ein echter `stop.ps1`-Lauf (läuft erst nach dem Modell-Download, sonst würde er ihn abbrechen).

## Größeres Modell (von Jan beauftragt, 2026-10-31)
Bewertung: `docs/review/model-evaluation.md`. Kurzfassung: Ein größeres Modell hilft wahrscheinlich bei Protokolltreue, Belegtreue und Planung, kostet aber Geschwindigkeit und birgt auf Blackwell Absturzrisiko bei Teil-Offload. **Nutzen ist ohne Messung nicht belegt.** Erst messen, zuerst die billigen Hebel (Schema-Ausgabe, Few-Shot, Denkbudget, Selbstkonsistenz), dann Kandidaten in zwei Stufen (voll im VRAM, dann MoE/Offload). Alle Modell-Tags sind per Registry belegt.

| # | Schritt | Abhängig von |
|---|---|---|
| M0 | Basislinie `qwen3:8b` im ersten Echtlauf messen | R2 bis R5 |
| M1 | Benchmark-Arena `tests/bench/run_arena.py` (Trefferquote, Belegquote, ungültige Aktionen, Züge, Dauer, Token/s, VRAM/RAM, Abstürze) | M0 |
| M2 | Billige Hebel einbauen und messen | M1 |
| M3 | Stufe 1 messen: `qwen3:14b`, `gemma4:12b`, `phi4-reasoning:14b`, `ornith:9b`, `gpt-oss:20b` | M1 |
| M4 | Stufe 2 messen (Offload, nur bei Bedarf): `qwen3:30b`, `gemma4:26b`, `ornith:35b`, `flint:40b`, 24B bis 27B dicht | M3 |
| M5 | ADR-0001 aktualisieren, Rollen `analysis`/`helper`/`translate` im Manifest | M2 bis M4 |
| M6 | Engine wählt Modell je Aufgabentyp, Tests je Rolle | M5 |
| M7 | Entscheidungsvorlage Hardware (GPU mit 24 bis 32 GB) für Jan | M4 |

Risiken: Modellnamen aus der Recherche (`gemma4`, `ornith`, `flint`, `qwen3.8`) sind per Registry-Manifest belegt (Tag und Größe), ihre Qualität ist ungemessen. Fallback `qwen3:8b`. Thinking-Modelle verbrauchen Tokens vor der JSON-Antwort. Blackwell-Absturzmeldungen bei Teil-Offload (ADR-0001): Modell vollständig in den VRAM legen, Kontext 16k. Dev-Gateway ohne Disassembler: Assembler-Lernpfad erst nach dem Ghidra-Adapter.

## Neue Aufträge von Jan (2026-10-31, Nachmittag)
- [x] G-Data-Prüfung: keine getrackte Datei fehlt, Tests grün (202). `scripts.py` war kurz verschwunden, ist da.
- [x] Remote `origin` = Agent4Forensic/LocalReverseAnyThingForensic (öffentlich, leer bei Start). `main` gepusht. Feature-Branch folgt, sobald der Arbeitsbaum sauber ist (Guard-Agent schreibt noch). Workflow in CLAUDE.md.
- [x] Agenten nutzen graphify: Pflichtregel in CLAUDE.md "Subagenten-Regeln" und in jedem neuen Agenten-Prompt. `graphify-out/` bleibt lokal (enthält Pfade), ist ignoriert.
- [x] Token-Effizienz der Agenten: Regeln 2 bis 6 in CLAUDE.md (kurze Prompts, Dateiverweise, feste Dateimengen, Abgabe max 25 Zeilen).
- [~] Dashboard V2 (Spezifikation `docs/architecture/dashboard-v2.md`): Live-Aktivität, Assembler-Lernpfad mit Sprung zur Zeile, Ablaufplan je Funktion, Diagramme. Frontend-Agent läuft. Backend offen: Tabellen functions/walkthroughs/diagrams, Endpunkte activity/functions/walkthroughs/diagrams, Guard-Schema für neue finish-Felder, neue Prompts.
- [~] Bestes Modell (Fable) schreibt Vorgaben `docs/blueprint/15-walkthroughs-and-visuals.md` und Anpassungsliste `docs/review/platform-adjustments.md`: Agent läuft. Antwort auf die Frage: Das Blueprint (15 Dateien) und die Methodik standen auf der Liste; die Vorgaben für Lernpfad/Diagramme und die Anpassungsliste kamen erst jetzt dazu.
- [~] Start/Stop-Skripte mit Preflight, Selbstinstallation aus gepinnten Quellen, Update-Prüfung, Terminal-Log mit Stage-Namen (`scripts/start.ps1`, `stop.ps1`, `infra/manifest.json`): Agent läuft. Konflikt zu klären: automatische Updates widersprechen CLAUDE.md Verbot 5/6; Umsetzung nur aus gepinnten, gehashten Quellen, neue Versionen werden gemeldet.

- [x] Dashboard Startseite und Auftragsmaske (ADR-0006, Branch `feat/dashboard-start`): saubere Pfad-URLs statt `#/`, Übersicht mit aktuellem Auftrag und Kennzahlen (Laufzeit, Aufgaben, Schritte, Werkzeug- und Modellaufrufe, Befunde, Zielfragen) oder Angebot zum Anlegen, Maske mit Beispielauswahl aus `example/` (alles vorausgefüllt, nur eines wählbar), kein Budget mehr (Obergrenzen automatisch). Geprüft: 9 Web-Tests, Gesamtlauf Unit und Security grün, 18 Browser-Prüfungen (Edge headless). Offen: `index.html` lädt `mock_v2.js`, `view_log.js`, `view_diagrams.js`, die im Repository nie vorhanden waren (3 × 404); `styles.css` enthält keine Stile für die Auftragsansicht (Tabs, Aufgabenbaum, Code), nur für Shell, Übersicht, Maske und Prompts; `example/` ist in `feat/workflow-optimization` noch nicht versioniert.
## Tests (von Jan beauftragt, 2026-10-31)
- [ ] **Detaillierte Tests für die forensische Absicherung der Kette.** Plan in `docs/testing/forensic-test-plan.md` mit 8 Blöcken (Chain of Custody, Belegprüfung, Prompt-Injection, Isolation und Jail, Determinismus, Übersetzung und Bericht, Ground-Truth-Korpus, Umsetzung). Vorhanden: 202 Unit-, 160 Sicherheits-, 4 E2E-Tests. Offen sind unter anderem Audit-Manipulationstest, Artefakt-Hash-Abgleich, Netz-Sperr-Test, API-Sicherheitstests, Reproduzierbarkeit des Berichts, Hold-out-Set für den Guard, Live-Modell-Tests und der Ground-Truth-Korpus.

## Backlog (von Jan beauftragt, braucht ADR und Freigabe)
- [ ] **Dynamische Analyse** (ADR-0005, Entwurf): widerspricht Nicht-Ziel 1 des Plans und ist nach CLAUDE.md Verbot 3 nur mit ADR und ausdrücklicher Freigabe umsetzbar. Voraussetzungen: Hyper-V-VM ohne Netzwerkkarte, Snapshot/Rollback, simuliertes Netz, Opt-in pro Job, Audit, Gateway-Tools (`capture_trace`, `emulate_function`), Berichtsregel "niedrigere Konfidenz bis statisch bestätigt". Blueprint-Datei `10-dynamic-analysis.md` beschreibt die Methodik als Wissen.
- [ ] REA: Live-Komponenten (Frida, ADB, Prozess-Capture) bleiben bis zur Freigabe von ADR-0005 aus.

## Phasen 0–12 (laut PROJEKTPLAN.md Abschnitt 7)
Alle offen. Beginn erst nach Abschluss von Phase P und Freigabe.
