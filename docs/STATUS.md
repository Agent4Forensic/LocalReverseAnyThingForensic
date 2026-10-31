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
- [!] REA: Reputationswarnung (414k Sterne/103k Forks bei 6 Monaten Alter). Erst tiefere Prüfung (native/, patches/, install.sh, npm gegen Repo), dann entscheiden. Siehe B5.
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
- B5: REA zurückstellen und pyghidra-mcp als Primärweg nehmen? (Empfehlung: ja, REA später optional nach Tiefenprüfung)
- B3: Admin-Rechte für Hyper-V-Einrichtung: Du führst das erzeugte Skript selbst aus (bestätigt in Auswahl, Termin offen).

## Aktuelle Arbeit (feat/core-chain)
- [~] Kern: Datenmodell, Gateway-/LLM-Vertrag, Audit-Log (Hash-Kette), SQLite-Store, Ollama-/Fake-Client geschrieben; Tests stehen aus
- [~] Agenten parallel: Frontend, Dev-Gateway, Prompt-Schutz, Übersetzung+Defanging (in Arbeit)
- [~] Blueprint (docs/blueprint/, 15 Dateien, Fable 5.1, 4 Agenten) in Arbeit; Themenliste des Berichts von Jan liegt vor (Übergabe+Hashes, Erkennung je Schritt, logischer Aufbau mit Nachweis, Zielfragen/CTF)
- [~] Audit morluto/rea (Tool-Inventar, npm gegen Repo) läuft
- [~] Orchestrator: geschrieben sind Prompt-Registry, Rezepte (generic/script/exe/apk), JSON-Hilfen, Prüfer (verifier.py) und Task-Runner (runner.py, ungetestet, braucht das Paket guard). FEHLT: Evaluator, Priorisierer, Planer/Engine, Worker, Report-Builder, API-App, Wiring, Tests, CTF-Test, Prompts je Aufgabentyp, API, Bericht, Wiring, CTF-Tests
- [ ] graphify-Lauf über das Repo (nach Abgabe der Agenten)

## Hinweis Limit (2026-10-31)
Sitzung wegen Nutzungslimit beendet. Hintergrund-Agenten (Frontend, Dev-Gateway, Prompt-Schutz, Übersetzung, 4 Blueprint-Agenten, REA-Audit, graphify-Extraktion) laufen eventuell weiter und schreiben Dateien. Ergebnisse prüfen: `git status`, dann Tests (`.venv\Scripts\python.exe -m pytest`). graphify: Chunk-Datei `graphify-out/.graphify_chunk_01.json` abwarten, dann Schritte 3 Part C bis 9 des Skills ausführen (AST-Ergebnis liegt in `graphify-out/.graphify_ast.json`).

## Backlog (von Jan beauftragt, braucht ADR und Freigabe)
- [ ] **Dynamische Analyse** (ADR-0005, Entwurf): widerspricht Nicht-Ziel 1 des Plans und ist nach CLAUDE.md Verbot 3 nur mit ADR und ausdrücklicher Freigabe umsetzbar. Voraussetzungen: Hyper-V-VM ohne Netzwerkkarte, Snapshot/Rollback, simuliertes Netz, Opt-in pro Job, Audit, Gateway-Tools (`capture_trace`, `emulate_function`), Berichtsregel "niedrigere Konfidenz bis statisch bestätigt". Blueprint-Datei `10-dynamic-analysis.md` beschreibt die Methodik als Wissen.
- [ ] REA: Live-Komponenten (Frida, ADB, Prozess-Capture) bleiben bis zur Freigabe von ADR-0005 aus.

## Phasen 0–12 (laut PROJEKTPLAN.md Abschnitt 7)
Alle offen. Beginn erst nach Abschluss von Phase P und Freigabe.
