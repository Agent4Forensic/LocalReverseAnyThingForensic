# Entwicklungsumgebung: geprüfte Komponenten

Stand: 2026-10-31. Jede Komponente wurde vor der Installation statisch geprüft (Hooks, Netzwerkaufrufe, Nachladen von Binaries). Nur der Entwicklungsrechner ist betroffen, nie die Analyse-VM.

## Claude-Code-Plugins

| Komponente | Version / Commit | Ergebnis der Prüfung | Entscheidung |
|---|---|---|---|
| caveman (JuliusBrussee) | 655b7d9c5431 | bereits installiert, wird genutzt | im Einsatz |
| ponytail (DietrichGebert) | 5.3.3, Repo-Commit 96608e078b2d | Hooks lokal. Einziger ausgehender Aufruf ist ein optionaler Webhook, nur aktiv wenn `webhookUrl` gesetzt ist (Standard leer). Lokales Ledger unter `~/.config/ponytail/band/`. | installiert (user scope) |
| claude-security | 0.12.0 (claude-plugins-official) | Befehle nur auf Anforderung. Hooks zeigen Banner und Scan-Vorschläge, keine Netzwerkaufrufe. | installiert |
| feature-dev, pr-review-toolkit, mcp-server-dev | claude-plugins-official | Nur Befehle, Agenten und Skills, keine Hooks. | installiert |
| mnemo (xyrlan) | Repo-Commit 3b978eec5ea6 | Vier Hooks (SessionStart, UserPromptSubmit, PreToolUse auf Bash/Read/Edit/Write, SessionEnd). Lädt beim ersten Start ein Binary von GitHub-Releases (SHA-256-geprüft). Optionales Rerank sendet Regeltexte an `api.typesafe.ai` (Standard aus). | **nicht installiert**: zu viel Eingriffstiefe, siehe ADR-0000 |
| security-guidance | 2.0.17 (claude-plugins-official) | Legt beim Sessionstart eine pip-venv an (Netzwerk), LLM-Review bei jedem Stop (Token-Kosten). | **nicht installiert** |

## Externe Repositories

| Repository | Commit | Lizenz | Prüfung | Entscheidung |
|---|---|---|---|---|
| morluto/rea | 60149282fcfc (2026-11-01 laut Commit-Metadaten) | MIT | Enthält Funktionen zum Starten von Anwendungen und Netzwerk-Capture (DISCLAIMER.md, Abschnitt "Runtime, network, and device operations"). `npx rea-agents setup` ändert Agent-Konfigurationen. | Nur statische Tools, nur hinter dem Gateway, Version pinnen, kein `setup`. Details in ADR-0000. |

## Laufzeit auf dem Dev-Rechner

| Komponente | Stand |
|---|---|
| NVIDIA RTX 5060 Ti | 16.311 MiB gesamt, Treiber 617.42. Beim Test 4.521 MiB frei (Rest durch Desktop-Apps). |
| Docker | Engine 29.8.2, Runtime `nvidia` verfügbar, Container-GPU-Test erfolgreich (`nvidia/cuda:12.6.0-base-ubuntu24.04`) |
| Ollama | Client 0.35.1, Server noch nicht gestartet |
| WSL | kali-linux (WSL2), `.wslconfig`: 20 GB RAM, 8 Prozessoren, 8 GB Swap (Ziel: 24 GB, ausstehend) |
| Python / Node / JDK | 3.11.9 / 24.19.0 / Temurin 17.0.20 |
| graphify | 0.8.44 |

Weitere Downloads (Ghidra, jadx, capa u. a., Modelle) werden hier mit URL, Version und SHA-256 ergänzt, sobald sie eingebunden sind.

## Analyse-Werkzeuge: Recherche vom 2026-10-31 (noch nicht eingebunden)

Quellen: GitHub-API und READMEs. SHA-256 nur dort eingetragen, wo ich sie selbst per GitHub-API verifiziert habe. Alle anderen Hashes werden beim Einbau berechnet und hier ergänzt.

| Komponente | Version | Quelle / Hash | Anmerkung |
|---|---|---|---|
| Ghidra (Ziel) | 12.1.4 (2026-09-21), braucht JDK 21 | `ghidra_12.1.4_PUBLIC_20260921.zip`, SHA-256 `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db` | Alle drei geprüften Ghidra-MCP-Server sind auf 12.1.4/JDK 21 getestet. |
| Ghidra (neueste) | 12.2 (2026-10-22), braucht JDK 25 | `ghidra_12.2_PUBLIC_20261016.zip`, SHA-256 `2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67` | MCP-Kompatibilität nicht belegt, daher vorerst nicht. |
| pyghidra-mcp | v0.2.7 (2026-09-25), Apache-2.0 | clearbluejar/pyghidra-mcp | **Empfehlung**: headless, stdio, keine Skript-/Code-Ausführungstools, schreibt nur in die Ghidra-Projekt-DB. Version 0.x, Ghidra-Version nicht dokumentiert, vor Nutzung testen. |
| bethington/ghidra-mcp | v7.0.0, Apache-2.0 | 209 Tools | Reserve. `run_ghidra_script` und `run_script_inline` sind nur mit `GHIDRA_MCP_ALLOW_SCRIPTS=1` aktiv und blieben aus. Große Angriffsfläche. |
| LaurieWired/GhidraMCP | 2.0, Apache-2.0 | | Reserve. Plugin-Brücke ohne Authentifizierung. |
| mrphrazer/ghidra-headless-mcp | | GPL-2.0 | **Verworfen**: `ghidra.eval`/`ghidra.call`/`ghidra.script` führen beliebigen Code aus, kein dokumentierter Schalter. |
| jadx | v1.5.6 | skylot/jadx | |
| apktool | v3.0.3 | iBotPeaches/Apktool | |
| capa / capa-rules | v10.0.0 | mandiant/capa | |
| FLOSS | v3.2.0 | mandiant/flare-floss | |
| yara-x | v1.22.1 | VirusTotal/yara-x | YARA 4.6.0 als klassische Variante. |
| radare2 | 6.2.4 | radareorg/radare2 | |
| binwalk | v3.1.0 (Rust) | ReFirmLabs/binwalk | Seit Okt. 2024 unverändert. |
| LIEF / pefile / androguard | 1.0.0 / 2024.8.26 / 4.1.4 | PyPI bzw. GitHub | pefile ohne Release seit 2 Jahren. |
| Qiling | v1.4.11, GPL-2.0 | | Nur für Phase 11 (Emulation), Lizenz vorher prüfen. |

### REA: Reputationswarnung
`morluto/rea` zeigt laut GitHub-API 414.640 Sterne und 103.713 Forks bei einem Alter von rund sechs Monaten (angelegt 2026-04-14). Der Betreiber hat 12.119 Follower, die beiden nächsten Mitwirkenden haben je rund 590 Commits. Diese Zahlen sind für mich nicht erklärbar und können auf künstlich erzeugte Beliebtheit hindeuten. Das beweist keine Schadfunktion, ist aber ein Warnsignal für die Lieferkette.

Folgerung: REA wird **nicht** vor einer tieferen Prüfung eingebunden (Quellcode von `native/`, `patches/`, `install.sh`, npm-Paket gegen Repo vergleichen). pyghidra-mcp ist der Primärweg für Ghidra. REA bleibt optional und nur mit der Allowlist `REA_MCP_TOOL_FAMILIES` (statische Familien: `session,native,android,artifact,firmware,managed,flutter`; `frida`, `adb`, `direct`, `application` weglassen). REA sagt in `SECURITY.md` selbst, es sei keine Sandbox. Laut Doku starten `capture_process_scenario`, Frida- und ADB-Tools echte Prozesse, die Zuordnung der Tools zu Familien ist unbelegt und muss nach dem Start über `tools/list` geprüft werden.
