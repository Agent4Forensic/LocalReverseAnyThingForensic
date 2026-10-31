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
