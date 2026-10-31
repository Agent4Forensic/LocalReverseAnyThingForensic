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

Risiken: Modellnamen aus der Recherche sind unverifiziert (`gemma4`, `ornith`), Fallback `qwen3:8b`. Thinking-Modelle verbrauchen Tokens vor der JSON-Antwort. Blackwell-Absturzmeldungen bei Teil-Offload (ADR-0001): Modell vollständig in den VRAM legen, Kontext 16k. Dev-Gateway ohne Disassembler: Assembler-Lernpfad erst nach dem Ghidra-Adapter.

## Neue Aufträge von Jan (2026-10-31, Nachmittag)
- [x] G-Data-Prüfung: keine getrackte Datei fehlt, Tests grün (202). `scripts.py` war kurz verschwunden, ist da.
- [x] Remote `origin` = Agent4Forensic/LocalReverseAnyThingForensic (öffentlich, leer bei Start). `main` gepusht. Feature-Branch folgt, sobald der Arbeitsbaum sauber ist (Guard-Agent schreibt noch). Workflow in CLAUDE.md.
- [x] Agenten nutzen graphify: Pflichtregel in CLAUDE.md "Subagenten-Regeln" und in jedem neuen Agenten-Prompt. `graphify-out/` bleibt lokal (enthält Pfade), ist ignoriert.
- [x] Token-Effizienz der Agenten: Regeln 2 bis 6 in CLAUDE.md (kurze Prompts, Dateiverweise, feste Dateimengen, Abgabe max 25 Zeilen).
- [~] Dashboard V2 (Spezifikation `docs/architecture/dashboard-v2.md`): Live-Aktivität, Assembler-Lernpfad mit Sprung zur Zeile, Ablaufplan je Funktion, Diagramme. Frontend-Agent läuft. Backend offen: Tabellen functions/walkthroughs/diagrams, Endpunkte activity/functions/walkthroughs/diagrams, Guard-Schema für neue finish-Felder, neue Prompts.
- [~] Bestes Modell (Fable) schreibt Vorgaben `docs/blueprint/15-walkthroughs-and-visuals.md` und Anpassungsliste `docs/review/platform-adjustments.md`: Agent läuft. Antwort auf die Frage: Das Blueprint (15 Dateien) und die Methodik standen auf der Liste; die Vorgaben für Lernpfad/Diagramme und die Anpassungsliste kamen erst jetzt dazu.
- [~] Start/Stop-Skripte mit Preflight, Selbstinstallation aus gepinnten Quellen, Update-Prüfung, Terminal-Log mit Stage-Namen (`scripts/start.ps1`, `stop.ps1`, `infra/manifest.json`): Agent läuft. Konflikt zu klären: automatische Updates widersprechen CLAUDE.md Verbot 5/6; Umsetzung nur aus gepinnten, gehashten Quellen, neue Versionen werden gemeldet.

## Tests (von Jan beauftragt, 2026-10-31)
- [ ] **Detaillierte Tests für die forensische Absicherung der Kette.** Plan in `docs/testing/forensic-test-plan.md` mit 8 Blöcken (Chain of Custody, Belegprüfung, Prompt-Injection, Isolation und Jail, Determinismus, Übersetzung und Bericht, Ground-Truth-Korpus, Umsetzung). Vorhanden: 202 Unit-, 160 Sicherheits-, 4 E2E-Tests. Offen sind unter anderem Audit-Manipulationstest, Artefakt-Hash-Abgleich, Netz-Sperr-Test, API-Sicherheitstests, Reproduzierbarkeit des Berichts, Hold-out-Set für den Guard, Live-Modell-Tests und der Ground-Truth-Korpus.

## Backlog (von Jan beauftragt, braucht ADR und Freigabe)
- [ ] **Dynamische Analyse** (ADR-0005, Entwurf): widerspricht Nicht-Ziel 1 des Plans und ist nach CLAUDE.md Verbot 3 nur mit ADR und ausdrücklicher Freigabe umsetzbar. Voraussetzungen: Hyper-V-VM ohne Netzwerkkarte, Snapshot/Rollback, simuliertes Netz, Opt-in pro Job, Audit, Gateway-Tools (`capture_trace`, `emulate_function`), Berichtsregel "niedrigere Konfidenz bis statisch bestätigt". Blueprint-Datei `10-dynamic-analysis.md` beschreibt die Methodik als Wissen.
- [ ] REA: Live-Komponenten (Frida, ADB, Prozess-Capture) bleiben bis zur Freigabe von ADR-0005 aus.

## Phasen 0–12 (laut PROJEKTPLAN.md Abschnitt 7)
Alle offen. Beginn erst nach Abschluss von Phase P und Freigabe.
