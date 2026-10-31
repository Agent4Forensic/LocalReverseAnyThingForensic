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
- [x] Ollama-Server starten, Umgebung setzen: `infra/start-ollama.ps1` (Port 11435, Loopback, Flash Attention, KV-Cache q8_0, `MAX_LOADED_MODELS=1`, `KEEP_ALIVE`); `qwen3:8b` und `qwen3:14b` installiert
- [~] Modellauswahl automatisiert: `infra/select-model.ps1` wählt nach freiem VRAM (Stufen A/B/C). Benchmark mit synthetischen Beispielen: `tests/bench/run_live.py` und `example/` (Stand der Messung siehe Modellabschnitt M0 bis M7)
- [ ] Embedding-Modell wählen und testen
- [!] Hyper-V: Dienst `vmms` läuft, Admin-Rechte fehlen für VM-Anlage. Admin-Skript wird erzeugt (Phase 1).

### P5 Analyse-Werkzeuge (Dev-Test mit harmlosen Proben)
- [~] Ghidra: Version recherchiert und gepinnt (12.1.4, JDK 21, SHA-256 verifiziert), Docker-Image noch nicht gebaut
- [~] REA: von Jan freigegeben (nur statisch, ohne Live-Teile). Tiefenaudit fertig (6.8.0, Pin, Familien- und Tool-Allowlist, Auflagen in dev-environment.md). Einbau ins Docker-Image und manuelles Quellcode-Review stehen aus.
- [ ] jadx, apktool, capa, YARA, FLOSS, radare2, binwalk, pefile, lief, androguard im Image
- [~] Ghidra-MCP: Empfehlung pyghidra-mcp v0.2.7 (kleinste Angriffsfläche, keine Code-Ausführung); ADR folgt nach Funktionstest
- [~] Alle Downloads mit SHA-256 in `docs/dev-environment.md`: erfasst, Lücken stehen unter „Weitere Tests aus dem Plan“

### P6 Abschluss Voraussetzungen
- [x] Verifikationsskript `infra/verify-prereqs.ps1` (Lauf: 24 PASS, 2 FAIL: VRAM, Ollama-Server; 2 WARN: freier RAM, graphify-out)
- [x] Kompakte Doku `docs/README.md` (Dokumentenkarte, Entscheidungen, Begriffe), dazu `docs/runbooks/betrieb.md` und `docs/security/sicherheitsmodell.md` (2026-10-31)
- [x] graphify-Lauf über das Repo, `graphify-out/` vorhanden
- [ ] Freigabe von Jan für Phase 0

## Blocker und offene Fragen an Jan
- B1: `wsl --shutdown` zum Anwenden des 24-GB-Limits erlaubt? (beendet WSL-Instanzen, auch andere Projekte)
- B2: VRAM-Belegung durch Desktop-Apps: Apps schließen oder kleineres Modell akzeptieren?
- B4: Freier RAM beim Test nur 3,7 von 31 GB (Docker Desktop frisch gestartet plus Browser/Apps). 24-GB-Limit ist nur realistisch, wenn andere Programme während der Analyse geschlossen sind.
- B5: erledigt. Jan hat REA ohne Live-Komponenten freigegeben, Bedingungen im Audit.
- B3: Admin-Rechte für Hyper-V-Einrichtung: Du führst das erzeugte Skript selbst aus (bestätigt in Auswahl, Termin offen).

## Aktuelle Arbeit (feat/core-chain)
- [x] Kern: Datenmodell, Gateway-/LLM-Vertrag, Audit-Log (Hash-Kette), SQLite-Store, Ollama-/Fake-Client mit Tests (korrigiert 2026-10-31)
- [x] Dev-Gateway, Prompt-Schutz, Übersetzung und Defanging liegen mit Tests vor (korrigiert 2026-10-31). Frontend: siehe „Dashboard-Lücken“.
- [x] Blueprint (docs/blueprint/, Dateien 00 bis 15) liegt vor (korrigiert 2026-10-31)
- [x] Audit morluto/rea fertig, Auflagen in `docs/dev-environment.md` (korrigiert 2026-10-31)
- [x] Orchestrator: Prompt-Registry, Rezepte, Prüfer, Task-Runner, Evaluator, Priorisierer, Planer, Engine, Worker, Report-Builder, API und CTF-Tests liegen vor (korrigiert 2026-10-31, der Eintrag war veraltet)
- [x] graphify-Lauf über das Repo; `graphify-out/` liegt vor, Post-Commit-Hook hält den Graphen aktuell

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
Stand: **Prüfung abgeschlossen, Behebung offen** (siehe „Behebung der Review-Funde“). Reihenfolge: erst dieses Code-Review mit Behebung, danach der Security-Review (eigener Schritt, CLAUDE.md Arbeitsweise 9) und der Tag `v0.1.0` (siehe R7 und Abnahme unten).

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
- [x] Alle 9 Pakete von mindestens 2 Modellen geprüft (2026-10-31, 11 Berichte, 289 Funde, Haiku nur G, H, I wie vorgesehen)
- [x] `docs/review/code-review/SUMMARY.md` mit Fund-x-Modell-Tabelle, Funde getrennt in bestätigt (23, davon 1 kritisch, 12 hoch), einzeln, verworfen (mit Grund)
- [ ] Alle kritischen und hohen bestätigten Funde behoben, je mit Test (F-01 bis F-13 in SUMMARY.md, noch nichts behoben; F-07 und F-08 brauchen ADR und Freigabe von Jan)
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
- [x] **Abstraktes Flussdiagramm** (erstellt 2026-10-31: `docs/architecture/workflows.md`, 4 Diagramme, im README verlinkt; Bild-Export für das README steht aus) (`docs/architecture/workflows.md`, Mermaid, auch als Bild im README): nur was tatsächlich umgesetzt ist, je Workflow ein Diagramm auf hoher Ebene. Vorgesehen: (1) Start/Stopp (CLEAN, CHECK, INSTALL, UPDATE, OLLAMA, MODEL, APP, Statusschleife, Stopp mit Cleanup), (2) Job-Lebenszyklus (Auftrag, Triage, Rezept, Aufgaben-Queue, Task-Runner mit Werkzeug-Schleife, Prüfer, Bewerter, Priorisierer, Antworten, Übersetzung, Bericht), (3) Schutzschichten (Guard vor und nach jedem Modellaufruf, Gateway-Jail, Audit-Kette), (4) Datenfluss Sample bis Bericht mit Hashes und Evidence. Nicht Umgesetztes (Ghidra, Wissensdatenbank, dynamische Analyse) wird gestrichelt und als "offen" markiert. Quellen: `docs/architecture/chain.md`, `scripts/start.ps1`, `orchestrator/*`; graphify-Abfragen vorab, damit das Bild dem Code entspricht und nicht dem Plan.

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

## Tests (von Jan beauftragt, 2026-10-31)
- [~] **Detaillierte Tests für die forensische Absicherung der Kette.** Neu 2026-10-31: `tests/forensic/test_chain_of_custody.py` (16 Tests: C4 Audit-Manipulation mit Zeilenposition, G1 bis G3 Belegprüfung, C8 Berichts-Reproduzierbarkeit, I4 nur Loopback-Endpunkt); Plan-Status in `forensic-test-plan.md` nachgezogen. Plan in `docs/testing/forensic-test-plan.md` mit 8 Blöcken (Chain of Custody, Belegprüfung, Prompt-Injection, Isolation und Jail, Determinismus, Übersetzung und Bericht, Ground-Truth-Korpus, Umsetzung). Vorhanden: 202 Unit-, 160 Sicherheits-, 4 E2E-Tests. Offen sind unter anderem Audit-Manipulationstest, Artefakt-Hash-Abgleich, Netz-Sperr-Test, API-Sicherheitstests, Reproduzierbarkeit des Berichts, Hold-out-Set für den Guard, Live-Modell-Tests und der Ground-Truth-Korpus.

## Backlog (von Jan beauftragt, braucht ADR und Freigabe)
- [ ] **Dynamische Analyse** (ADR-0005, Entwurf): widerspricht Nicht-Ziel 1 des Plans und ist nach CLAUDE.md Verbot 3 nur mit ADR und ausdrücklicher Freigabe umsetzbar. Voraussetzungen: Hyper-V-VM ohne Netzwerkkarte, Snapshot/Rollback, simuliertes Netz, Opt-in pro Job, Audit, Gateway-Tools (`capture_trace`, `emulate_function`), Berichtsregel "niedrigere Konfidenz bis statisch bestätigt". Blueprint-Datei `10-dynamic-analysis.md` beschreibt die Methodik als Wissen.
- [ ] REA: Live-Komponenten (Frida, ADB, Prozess-Capture) bleiben bis zur Freigabe von ADR-0005 aus.

## Phasen 0–12 (laut PROJEKTPLAN.md Abschnitt 7)
Alle offen. Beginn erst nach Abschluss von Phase P und Freigabe.

## Beispielfälle zum Evaluieren (von Jan beauftragt, 2026-10-31)
- [x] `example/` mit `start_eval.ps1` (Menü zur Auswahl der Challenge), 4 Challenges mit Beschreibung und Ziel (`example/challenges/*/challenge.json`), Proben-Generatoren (`example/samples.py`) und automatischer Prüfung: `run_eval.py` sucht die Flagge im finalen Bericht (PASS/FAIL, Exit-Code). Anleitung: `example/README.md`.
- [~] Echtlauf: Challenge 01 mit `qwen3:8b` bestanden (2,4 min, Status partial, Audit gültig, auf noch nicht committetem `src/`-Stand, daher kein Vergleichswert). Challenges 02 bis 04 ungetestet, weil eine zweite Sitzung die Ollama-Warteschlange belegte.
- [x] `example/` committet auf `feat/workflow-optimization` (d2ca81e), nicht gepusht, nicht in `main`.

## Prüfung iterativer Analyseprozess (2026-10-31, umgesetzt nach ADR-0007)
Bestätigt: Die Schleife aus Aufgabe, Bewertung, Folgeaufgaben und Priorisierung läuft, die Belegprüfung der Findings ist mechanisch. Die Punkte unten sind mit einem geskripteten Modell getestet (`tests/unit/test_workflow.py`).

Lücken:
- [x] Unbeantwortete Zielfrage läuft einmal neu, wenn neue bestätigte Findings vorliegen (`_reopen_questions`).
- [x] Hypothesen und offene Punkte erreichen spätere Analyseaufgaben, Evaluator und Planer (`open_points_text`). Zielfragen sehen sie bewusst nicht.
- [x] `goal_reached` und `gaps` werden ausgewertet: Selbstbewertung in den Task-Parametern und im Bericht, Lücken als Findings mit Status `open` (`_record_evaluation`).
- [x] Nach der Synthese entsteht eine Lückenrunde, deren Folgeaufgaben nicht erneut bewertet werden.
- [x] Der Planer ergänzt nach dem Rezept höchstens 4 Aufgaben aus dem Job-Ziel (`_plan_from_goal`). Jede Aufgabe trägt ein Abnahmekriterium `done_when`.
- [ ] Vor und nach den Änderungen Challenges 01 bis 04 messen. Erster Lauf nur teilweise gültig: Ab 22:14:52 fiel Ollama weg, zeitgleich lief `scripts/start.ps1` (Bereinigung um 22:14:57). Gültig sind Basislauf 01 (PASS) und 02 (FAIL, Budget). Basislauf 03 und 04 sowie alle Nachher-Läufe werden wiederholt.
- [ ] Messergebnis in ADR-0007, `docs/STATUS.md` und `docs/roadmap.html` eintragen, Bestätigtes und Offenes getrennt, dann nach `main` nachmergen.
- [ ] `/claude-security` über den gemergten Stand laufen lassen. Vor dem Merge von `feat/workflow-optimization` (2026-10-31) lief nur ein manuelles Security-Review des Diffs. Ein Versuch am 2026-10-31 startete nicht, weil der Sitzung das Workflow-Werkzeug fehlte (`/config`, Dynamic workflows).
- [ ] `scripts/start.ps1` beendet laufende Ollama-Server anderer Prozesse und meldete um 22:19:00 "nothing listens on port 11435", obwohl der Port antwortete. Beides prüfen.
- [ ] Bericht-Tabellen: echten Markdown-Sanitizer statt des Leerzeichens nach `<` einbauen (`shortcut` in `report/builder.py`, `_cell`).

Sicherheitsreview des Änderungsstands (2026-10-31):
- [x] Modelltext hatte im Prompt Anweisungsrang: Titel, Ziel, Begründung und `done_when` modellgeschriebener Aufgaben stehen jetzt im Datenblock, `_injected` greift ab mittlerer Schwere.
- [x] Unbelegte Werte konnten als Antwort erscheinen: `{hypotheses}` aus dem Zielfragen-Prompt entfernt, Indikatoren einer Antwort müssen in einem Beleg stehen.
- [x] Offener Punkt konnte mit fremdem Zitat `confirmed` werden: Indikatoren der Aussage müssen im Zitat stehen.
- [x] Notizen über geblockte Aufgaben kamen als Arbeitsauftrag zurück: Präfix `GUARD:`, nicht mehr in `open_points_text`.
- [x] Modellgeschriebene Ziele senkten den Tool-Schutz: sie zählen im `TaskGuard` nicht mehr als Aufgabentext (`guard_task_text`).
- [x] Bericht: `open` nur noch unter „Offene Fragen und Hypothesen“, `goal_reached` als Selbstbewertung des Modells benannt.
- [x] `done_when` steht jetzt im Bericht (Methodik-Tabelle) und in der Queue (`f76190f`). Tabellenzeilen halten Striche, Backslashes und Zeilenumbrüche aus Modelltext aus, Bericht und Dashboard lesen dieselbe Zelle (`c2308fc`).
- [x] `_cell` neutralisiert rohes HTML mit einem Leerzeichen nach `<` (`f76190f`). Bekannte Grenze: `List<String>` liest sich im Bericht als `List< String>`, der exakte Text bleibt in der Evidence.
- [x] Geklärt: `translate/pipeline.py:198` maskiert vor dem Modell nur Token (`protect`), keine Anweisungen; in `translate/` läuft kein Scanner. Das Übersetzungsmodell hat keine Werkzeuge, sein Ergebnis landet nur in den `_de`-Feldern. Restrisiko: Sample-Text in einer Aussage könnte die deutsche Fassung verfälschen, die englische bleibt daneben erhalten. Die Rückübersetzungsprüfung T3 ist dafür vorgesehen und offen.
- [!] `.claude/settings.json` enthält 7 neue `enabledPlugins` ohne Eintrag in `docs/dev-environment.md` (Verbot 8), bleibt uncommittet, Entscheidung bei Jan.

Bewusst nicht umgesetzt: engere Verankerung von Folgeaufgaben (`agents.py`), Verankerung neuer Aufgaben des Priorisierers, numerische Bewertung durch das Modell. Ungültiges `done_when` weist die `finish`-Aktion weiter ab, wie jedes andere ungültige Feld auch: das Modell bekommt den Grund und kann korrigieren.

## Weitere Tests aus dem Plan (2026-10-31)
- [x] I3 Netz-Sperr-Test, C1 bis C3 Artefakt-Hash-Abgleich (`tests/forensic/test_network_isolation.py`, `test_artifact_hashes.py`: 14 grün, 2 xfail).
- [x] I6, I7 API-Sicherheitstests (`tests/forensic/test_api_security.py`: 173 grün, 6 xfail).
- [x] S2 Guard-Hold-out (`tests/security/test_guard_holdout.py`, `injection_holdout.json`, Bericht `docs/review/guard-holdout-result.md`): Recall 62,4 % statt 145/145 im Tuning-Korpus, 32 Fälle als xfail.
- [x] Download-Pins in `docs/dev-environment.md` erfasst; Lücken dort benannt (Ghidra und REA in `manifest.json` noch "pending", Ollama-Client 0.35.1 gegen Pin 0.40.13, JDK 17 gegen 21).
- Testlauf gesamt (2026-10-31, `c2308fc`): 787 grün, 40 xfail (strict). Testplan: C1 und C2 vollständig, C3 teilweise (Artefakt-Hash im Bericht fehlt, F-15), 22 von 52 Prüfungen vollständig.

## Behebung der Review-Funde (von Jan beauftragt, 2026-10-31)
Quelle: `docs/review/code-review/SUMMARY.md` (Stellen, Modelle, Nachweis je Fund). Jeder Fund wird zuerst mit einem Test reproduziert, danach behoben. Behoben ist bisher nichts. Arbeit in einem eigenen Git-Worktree, nicht im geteilten Arbeitsbaum. Engine, Runner, Agents und Builder erst nach Abschluss der anderen Sitzungen.

### Entscheidungen von Jan (offen)
- [x] Push von `main`: `origin/main` steht auf `d80987a` und enthält `feat/workflow-optimization` und `feat/model-equipment`. Die Freigabe von Jan ist nur von der Sitzung gemeldet, die gepusht hat. Die Commits `71bb4d3` und `794a6df` enthalten im Verlauf einen lokalen Laufwerkspfad ohne Benutzernamen, im aktuellen Stand ist er ersetzt (`3d0548c`).
- [!] Freigabe von ADR-0006 bestätigen: Die Freigabe für Paket A und B steht nur im uncommitteten ADR-Text von `feat/static-tools`, sie ist von der anderen Sitzung eingetragen und hier nicht geprüft.
- [ ] `feat/static-tools` und `feat/dashboard-start` sind nicht nach `main` gemergt. Sie brauchen je einen abgeschlossenen Stand, grüne Tests und ein Security-Review.
- [!] Freigabe, die hohen Funde jetzt zu beheben (Worktree, Reihenfolge unten).
- [!] ADR-Nummer doppelt: Der Worktree `feat/dashboard-start` enthält uncommittet `docs/adr/0006-dashboard-urls-beispiele-budget.md`, im Repo ist 0006 die Werkzeug-Allowlist. Vor dem Merge umnummerieren. Auch `webui/app.py` und `view_job.js` sind dort geändert, Konflikte beim Merge sind möglich.
- [!] F-07 und F-08 (verankerter Kopf-Hash, atomares Anhängen im Audit-Log): braucht ein ADR und die ausdrückliche Freigabe (CLAUDE.md Verbot 3).
- [!] REA-Commit klären: `docs/dev-environment.md` nennt zwei Commits (60149282fcfc mit Datum 2026-11-01, 160d821ac9a0). Das Datum liegt nach dem Stand.
- [!] Modell-Pins mit Digest (F-13): Die Digests lassen sich nur mit einem Netzzugriff beim Pull ermitteln. Freigabe und Vorgehen klären.

### Belegzwang (zuerst)
- [ ] F-01 kritisch: `grep` gibt das Modell-Muster in der Ausgabe zurück, daraus entsteht ein `confirmed`-Beleg (`dev_gateway.py:712,724`, `verifier.py:51,78`). Test über den vollen Weg (Gateway, Verifier, Antwort), dann Muster aus der Evidence-Prüfung ausnehmen oder nicht echoen.
- [ ] F-02 Zitat muss zur Aussage passen; `MIN_QUOTE` von 4 auf den im Prompt versprochenen Wert (`verifier.py:16,49-58`).
- [ ] F-03 Antwortprüfung: Werte jeder Antwort an Belege binden, nicht nur `WORD{...}` (`engine.py:436`, `runner.py:252`). Wartet auf die andere Sitzung.
- [ ] F-04 IOC-Liste aus geprüften Zitaten, nicht aus dem Aussagetext (`builder.py:139-143`). Wartet auf die andere Sitzung.

### Ressourcen und Robustheit
- [ ] F-05 ReDoS im Regex-Wächter plus harter Timeout für `grep` (`regex_guard.py:143-155`, `dev_gateway.py:701-705`, `runner.py:207,221`).
- [ ] F-06 Kostendeckel für PE-Sektionsentropie, quadratische Regeln in `scripts.py`, Obergrenze für ZIP-Einträge.
- [ ] F-09 Worker: `except` mit Fehlerstatus, Race zwischen Abbruch und Übernahme (`worker.py:33-41`).
- [ ] F-10 Job erst nach dem Schreiben des Samples auf `queued` setzen (`app.py:126-127`).
- [ ] F-20 Upload-Limit vor dem Spoolen durchsetzen (`app.py:111`).
- [ ] F-21 Ungültige `expected`-Regex abfangen (`engine.py:446`).
- [ ] F-23 Abbruch und Zeitbudget auch innerhalb eines Tasks prüfen (`engine.py:231`).

### Audit-Kette (braucht Freigabe, siehe oben)
- [ ] F-07 Kopf-Hash außerhalb der Datei verankern; Kommentar in `test_chain_of_custody.py:57-58` korrigieren.
- [ ] F-08 Atomares Anhängen; `emit` darf Schreibfehler nicht verschlucken; Feld `hash` und Nicht-Objekt-Zeilen in `verify_file` behandeln.

### Guard
- [ ] F-11 Tripwire: nicht als Abbruchhebel nutzbar machen (eine ungültige Antwort blockiert den Task, Toolnamen im Sample sperren `finish`) (`taskguard.py:92,97,131-138`).
- [ ] F-12 Scanner-Lücken schließen (Homoglyphen `scanner.py:52`, Kontraktionen, Verdikt-Erzwingung, weitere Sprachen, zerrissene Phrasen). Danach ein frisches drittes Hold-out-Set, das Set `injection_holdout.json` ist nach Sichtung verbraucht.

### Bericht und Betrieb
- [ ] F-13 Modelle mit Digest pinnen (`start.ps1:233-234`, `manifest.json:32-37`).
- [ ] F-14 Defanging: `ws://`, `tcp://`, `smb://`, `file://`, UNC, weitere TLDs, IDN, Backticks, `javascript:`.
- [ ] F-15 Hash-Spalte im Bericht (Artefakt-Hash statt Ausgabe-Hash), Prompt-Hashes und Modell aus dem Job speichern (`builder.py:97-102`).
- [ ] F-16 Übersetzung: `done_reason == "length"` prüfen, Modell in den Cache-Schlüssel (`pipeline.py:204-273`).
- [ ] F-17 `stop.ps1`: Origin aus `-Port` ableiten (`stop.ps1:90`).
- [ ] F-18 `index.html`: fehlende Skripte entfernen oder anlegen, Asset-Test auf Existenz erweitern.
- [ ] F-19 Cleanup: Junctions prüfen, nur eigene Prozesse beenden; echten Test statt Teilstring-Test (`cleanup.ps1:44-54`, `test_scripts.py`).
- [ ] F-22 `source_ref.length` bei UTF-16 korrigieren.
- [ ] Einzelfunde aus `SUMMARY.md` bewerten (HostGuard außerhalb Windows, `create_job` transaktional, `/log`-Begrenzung, SSE, `markdown.js` und `\|`, `<think>`-Tags, Letzter Turn ohne `finish`, `_FENCE`-Regex, Annotationen ohne Beleg, `sha256_hex`, Code-Viewer-Vertrag, `list_files`-Cache).
- [ ] Danach: Tests grün, strikte xfails der neuen Tests auflösen, Ergebnis hier und im Dev-Vault festhalten, dann `/claude-security` und Tag `v0.1.0`.

