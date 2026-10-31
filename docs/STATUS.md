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
- [ ] Ponytail userConfig (4 Optionen) prüfen und setzen
- [ ] Ergebnisse der Audits in `docs/dev-environment.md` mit SHAs festhalten

### P3 Claude-Code-Einstellungen
- [x] Auto-Compact bei 70 % (`.claude/settings.json`)
- [ ] Prüfen, dass Auto-Compact global aktiv ist (`autoCompactEnabled`)
- [~] Repo-Gerüst, `.gitignore`, Pre-Commit-Hook, CLAUDE.md angelegt
- [ ] Erster Commit (initiales Gerüst)

### P4 Laufzeit-Infrastruktur
- [ ] Docker Desktop starten, Daemon erreichbar, GPU-Durchreichung (`--gpus all`) testen
- [!] `.wslconfig` von 20 auf 24 GB: erfordert `wsl --shutdown` und beendet laufende WSL-Dienste (Kali, anderer Docker-Stack). Freigabe von Jan nötig. Siehe B1.
- [ ] Ollama-Server starten, Umgebung setzen (`OLLAMA_MAX_LOADED_MODELS=1`, `OLLAMA_KEEP_ALIVE`, Flash Attention, KV-Cache-Quantisierung)
- [ ] Modellauswahl automatisiert (Skript prüft VRAM/RAM, wählt Modell, Benchmark mit synthetischen Beispielen)
- [ ] Embedding-Modell wählen und testen
- [!] Hyper-V: Dienst `vmms` läuft, Admin-Rechte fehlen für VM-Anlage. Admin-Skript wird erzeugt (Phase 1).

### P5 Analyse-Werkzeuge (Dev-Test mit harmlosen Proben)
- [ ] Ghidra (aktuelle Version, JDK-Anforderung prüfen) im Docker-Image, headless
- [ ] REA (`morluto/rea`, Commit 6014928) in Container, nur statische Tools, Version pinnen
- [ ] jadx, apktool, capa, YARA, FLOSS, radare2, binwalk, pefile, lief, androguard im Image
- [ ] Lokale MCP-Server prüfen (Ghidra-MCP-Kandidaten), Auswahl per ADR
- [ ] Alle Downloads mit SHA-256 in `docs/dev-environment.md`

### P6 Abschluss Voraussetzungen
- [ ] Verifikationsskript `infra/verify-prereqs.ps1` (prüft alles oben, Ausgabe grün/rot)
- [ ] Kompakte Doku `docs/README.md` (Überblick, Entscheidungen, Runbook Kurzform)
- [ ] graphify-Lauf über das Repo, `graphify-out/` vorhanden
- [ ] Freigabe von Jan für Phase 0

## Blocker und offene Fragen an Jan
- B1: `wsl --shutdown` zum Anwenden des 24-GB-Limits erlaubt? (beendet WSL-Instanzen, auch andere Projekte)
- B2: VRAM-Belegung durch Desktop-Apps: Apps schließen oder kleineres Modell akzeptieren?
- B3: Admin-Rechte für Hyper-V-Einrichtung: Du führst das erzeugte Skript selbst aus (bestätigt in Auswahl, Termin offen).

## Phasen 0–12 (laut PROJEKTPLAN.md Abschnitt 7)
Alle offen. Beginn erst nach Abschluss von Phase P und Freigabe.
