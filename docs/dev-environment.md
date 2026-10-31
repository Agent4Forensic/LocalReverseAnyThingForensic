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

## Audit bethington/ghidra-mcp (2026-10-31, statisch, kein Voll-Review der ca. 80.000 Zeilen Java)

| Punkt | Befund |
|---|---|
| Pin | Tag `v7.0.0`, Commit `19e64c75f1be1fcbe413e845f65e549f2361b928` (Tag unsigniert). Nicht `dev` verwenden (seit dem Tag +34k/-9k Zeilen, 11 neue Tools). Release-Assets: `GhidraMCP-7.0.0.zip` (SHA-256 beginnt `d133c4c8`), `ghidra_mcp_bridge-7.0.0-py3-none-any.whl` (beginnt `a7505006`). Vollständige Hashes beim Einbau aus dem Release lesen und hier eintragen. |
| Lieferkette | Java-Laufzeit praktisch nur Ghidra 12.1.4 und gson. Python-Bridge `mcp>=1.28.1,<2` und `pydantic>=2` als ungepinnte Bereiche, `uv.lock` wird vom Dockerfile nicht genutzt. Docker-Basisimages ohne Digest. Alle GitHub-Actions auf Commit-SHA gepinnt. |
| Laufzeit | Kein `Runtime.exec`, `ProcessBuilder` oder ScriptEngine in `src/main`. Netzaufruf nur zu `GHIDRA_MCP_ARCHIVE_URL` (ohne Variable deaktiviert). Keine Telemetrie gefunden. Beispielskripte `ghidra_scripts/*Claude*.java` starten Prozesse: nicht installieren. |
| Tools | ca. 218 auf `dev`, 209 in v7.0.0: ca. 105 lesend, 88 schreibend (nur Ghidra-Projekt-DB), 25 destruktiv (nur Projekt-DB). Code-Ausführung: `run_ghidra_script`, `run_script_inline` (Standard aus, `GHIDRA_MCP_ALLOW_SCRIPTS`). Debugger (`/debugger/*`, startet echte Prozesse) nur im GUI-Plugin, nicht headless. Emulation (`emulate_function`, `emulate_hash_batch`) nutzt Ghidras P-Code-Interpreter in der JVM (Daten, kein Prozess; 100.000 Schritte, 10 s Limit). |
| Schwächen der Voreinstellung | `GHIDRA_MCP_FILE_ROOT` ungesetzt = keine Pfadbeschränkung für Import/Export/Löschen. Docker bindet `0.0.0.0` (Token Pflicht). Compose ohne `read_only`, `cap_drop`, `network: none`. Die Bridge hat keine Tool-Denylist. |
| Reputation | 6.025 Sterne, 368 Forks, Einzelmaintainer (884 Commits). Stargazer-Stichprobe nicht möglich (API 404), Fork-Besitzer unauffällig. Unauffällig, aber nicht abschließend belegt. |
| Risiko | Mittel wie ausgeliefert, niedrig bis mittel mit den Auflagen. |

Auflagen: Gateway nutzt eine **Allowlist** (keine Denylist, weil `dev` ständig Tools ergänzt). Zu sperren sind mindestens `run_ghidra_script`, `run_script_inline`, alle `debugger*`, alle `/server/*`, `checkin_program`, `archive_*`, `exit_ghidra`, Projekt-/Dateiverwaltung (`open_project`, `create_project`, `delete_project`, `delete_file`, `move_*`, `export_program`, `import_program`, `restore_project`), `decompile_tree_*`, `list_scripts`, `set_program_option`, `set_image_base`. `import_file` nur mit erzwungenem Pfad `/samples`. Umgebung: `GHIDRA_MCP_ALLOW_SCRIPTS` ungesetzt, `GHIDRA_MCP_FILE_ROOT=/samples`, zufälliges `GHIDRA_MCP_AUTH_TOKEN`, `GHIDRA_MCP_ARCHIVE_URL` leer, `GHIDRA_DEBUGGER_TOOLS=0`, `GHIDRA_MCP_BIND_ADDRESS=127.0.0.1`. Container: `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`, Server und Bridge in einem Container (stdio), Bridge per `uv sync --frozen` bauen. Empfehlung: **parallel zu pyghidra-mcp** betreiben (nicht ersetzen), mit getrennten Projektkopien.

Zusatznutzen gegenüber pyghidra-mcp: Emulation einzelner Funktionen (API-Hash-Auflösung, String-Entschlüsselung), Datentypen/Strukturen, P-Code/Datenfluss, Malware-Heuristiken (`detect_crypto_constants`, `find_anti_analysis_techniques`, `extract_iocs_with_context`), Funktionsvergleich. Fehlt dort: semantische Suche.

## Audit morluto/rea 6.8.0 (2026-10-31, statisch, nichts ausgeführt)

Freigabe: Jan hat die Nutzung von REA ohne Live-Komponenten ausdrücklich verlangt. Dieses Audit legt die Bedingungen fest.

| Punkt | Befund |
|---|---|
| Pin | npm `rea-agents@6.8.0`, integrity `sha512-9QDeRnGqEDzABZyr04eLnBXBv/c6I9/TWu/6M0MD4pEfkySI/BIgwTODIbAReX3C1x6hjw9+Jlx4A2yUSPZ9ww==`. Quellcode-Review am Commit `160d821ac9a0` (Tag `rea-agents-6.8.0`), nicht am Repo-HEAD (846 Commits weiter, abweichende Abhängigkeiten). |
| Herkunft | SLSA-Provenance vorhanden (GitHub Actions, npm OIDC), ein Maintainer, 34 Versionen, 6.x in rund 3 Wochen veröffentlicht. |
| Lieferkette | Kein `preinstall`/`install`/`postinstall` im Paket. 43 exakt gepinnte Abhängigkeiten, aber kein Shrinkwrap im Tarball. Optionale Abhängigkeit `frida` hat ein Install-Skript: Installation mit `--ignore-scripts --omit=optional`. `dist/` (50 MB) ist nur im Tarball, Gleichheit mit dem Quellcode ist nicht selbst belegt. Vorkompilierte `rea-windows-x64.node` nur für Windows, unter Linux irrelevant. `install.sh` ohne Hash-Prüfung: nicht verwenden, ebenso nicht `rea update`. |
| Laufzeit | Keine Telemetrie gefunden. Externe Hosts nur bei `rea setup` (hopperapp.com) und `rea update` (GitHub/npm). Prozessstart ohne Shell (`cross-spawn`). Ghidra läuft read-only im privaten Temp-Projekt, jadx nur als Dekompilierer. SECURITY.md: "not a sandbox". |
| Reputation | 414.706 Sterne und 103.723 Forks bei Repo-Alter 6,5 Monate. Stargazer-Daten in dieser Umgebung nicht abrufbar (API 404). Fork-Besitzer-Stichprobe (32) unauffällig (Median Kontoalter 4,3 Jahre). Burst-Muster 8. bis 15. Oktober (viral oder gebottet, nicht unterscheidbar). Reputation ist kein Sicherheitsargument, Vertrauen stützt sich auf Pinning und Review. |
| Tools | 229 Tools in 18 Familien. |
| Risiko | Niedrig bis mittel im Container (`--network none`, read-only, non-root, Allowlist). |

Familien-Allowlist (`REA_MCP_TOOL_FAMILIES`): `session,direct,enhanced,artifact,managed,firmware,android,apktool,flutter,pcap,application`. Ausgeschlossen: `frida`, `adb`, `browser`, `electron`, `javascript-runtime`, `jeb`. `native` nur mit Einzelsperren. Die Familienliste ist laut REA-Doku ein Advertising-Filter und keine Sicherheitsgrenze, deshalb **zusätzlich Allowlist nach Tool-Namen im Gateway**.

Einzeln zu sperren trotz erlaubter Familie: `capture_process_scenario` (startet das Ziel als Prozess) sowie in `native` alle Live-Tools (`observe_native_ui`, `capture_native_ui_scenario`, `observe_native_calls`, `execute_rizin_command`, `cutter_command`, `list_cutter_sessions`, `start_gdb_session`, `gdb_console`, `gdb_session_status`, `close_gdb_session`, `start_rizin_debug_session`, `rizin_debug_command`, `rizin_debug_session_status`, `close_rizin_debug_session`). Rein statische Einzeltools aus ausgeschlossenen Familien nur per Einzelfreigabe: `analyze_web_bundle`, `inspect_web_network_capture`, `compare_web_captures`, `compare_web_screenshots`, `inspect_electron_fuses`, `analyze_javascript_application`, `reconcile_javascript_runtime`.

Umgebung: `REA_ANALYSIS_PROVIDER=ghidra`, `GHIDRA_INSTALL_DIR`, `JAVA_HOME`, `REA_JADX_MCP_JAR` (SHA-256 selbst gegen `6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75` prüfen, REA lehnt Abweichungen nicht ab), Timeouts und Heap-Limits setzen, nur stdio, nicht `rea mcp --http`. `REA_BROWSER_EXECUTABLE`, `REA_ADB_PATH`, `REA_GDB_COMMAND`, `REA_RIZIN_COMMAND`, `REA_DOCKER_COMMAND` nicht setzen.

Vor dem Einsatz: Quellen am Commit 160d821a manuell prüfen (`src/ghidra/GhidraLauncher.ts`, `src/android/Jadx*.ts`, `src/contracts/toolEffects.ts`, `src/application/UpdateRuntime.ts`, `scripts/rea.mjs`, `bridge/`), `npm ls --all` und Install-Skripte der transitiven Abhängigkeiten ansehen und beim ersten Lauf Netzwerk-/Syscall-Monitoring in einer Wegwerf-VM durchführen.

## Downloads und Pins

Stand: 2026-10-31. Abgleich von `infra/manifest.json`, `requirements.lock` und den Angaben in diesem Dokument. Es wurde kein Netzwerkzugriff ausgeführt und nichts heruntergeladen. Hashes der Python-Pakete stehen in `requirements.lock` und sind hier bewusst nicht kopiert. "nicht erfasst" bedeutet: Der Wert fehlt in den Repo-Dateien und ist nicht geraten.

| Komponente | Version | Quelle (URL) | SHA-256 | Commit-SHA | Prüfstatus |
|---|---|---|---|---|---|
| Ollama (Server) | 0.40.13 | https://github.com/ollama/ollama/releases/download/v0.40.13/ollama-windows-amd64.zip | 7afa38624fa62ee5d8293422d0ab084c1bb4603134c7f4dafce11a033b57cc19 | nicht erfasst | Bestätigt: Pin in `infra/manifest.json`. Offen: Download nicht gegen Hash geprüft. Installierter Client ist 0.35.1, Abweichung zum Pin. |
| Ghidra 12.1.4 (Ziel) | 12.1.4 (2026-09-21) | Repo laut Manifest: NationalSecurityAgency/ghidra. Download-URL nicht erfasst (`pending`). | ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db | nicht erfasst | Bestätigt: Hash in Manifest und Doku identisch. Offen: URL und Zielpfad sind `pending`. |
| Ghidra 12.2 (nur Doku) | 12.2 (2026-10-22) | nicht erfasst (Asset `ghidra_12.2_PUBLIC_20261016.zip`) | 2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67 | nicht erfasst | Offen: nicht gepinnt, MCP-Kompatibilität nicht belegt. Nicht einbinden. |
| JDK | Temurin 17.0.20 (installiert) | nicht erfasst | nicht erfasst | nicht erfasst | Offen: Ghidra 12.1.4 braucht laut Doku JDK 21, ein JDK-21-Pin fehlt. |
| Python / Node | 3.11.9 / 24.19.0 (installiert) | nicht erfasst | nicht erfasst | nicht erfasst | Offen: keine Pins oder Hashes erfasst. |
| Python-Abhängigkeiten | annotated-doc 0.0.5, annotated-types 0.8.0, anyio 4.15.1, click 8.5.0, fastapi 0.128.0, h11 0.16.0, idna 3.20, pydantic 2.14.2, pydantic-core 2.50.2, python-multipart 0.0.33, pyyaml 6.0.3, starlette 0.50.0, typing-extensions 4.16.0, typing-inspection 0.4.4, uvicorn 0.40.0 | PyPI-Index (nicht in `requirements.lock` erfasst) | in `requirements.lock` je Paket (nicht kopiert) | nicht erfasst | Bestätigt: Versionen und Hashes in Lock-Datei vorhanden. Offen: Index-URL fehlt, `requirements.in` nicht gegen Lock abgeglichen. |
| pyghidra-mcp | v0.2.7 | GitHub clearbluejar/pyghidra-mcp | nicht erfasst | nicht erfasst | Offen: Commit-Pin und Hash fehlen. Empfohlener Primärweg, vor Nutzung testen. |
| bethington/ghidra-mcp | v7.0.0 | GitHub bethington/ghidra-mcp, Release v7.0.0 | Präfix `d133c4c8` (GhidraMCP-7.0.0.zip) und `a7505006` (Bridge-Wheel), volle Hashes nicht erfasst | 19e64c75f1be1fcbe413e845f65e549f2361b928 | Bestätigt: Tag und Commit in Doku. Offen: volle Hashes beim Einbau aus dem Release eintragen. Tag unsigniert. |
| morluto/rea (npm `rea-agents`) | 6.8.0 | npm `rea-agents@6.8.0` (URL nicht erfasst) | nicht erfasst (npm-Integrity ist sha512 und steht im Audit-Abschnitt) | 160d821ac9a0 (Tag `rea-agents-6.8.0`) | Offen: `infra/manifest.json` ist `pending`, SHA-256 fehlt. Doku nennt zusätzlich Repo-Commit 60149282fcfc mit Datum 2026-11-01, das nach dem Stand liegt. Widerspruch klären. |
| REA: jadx-MCP-JAR | nicht erfasst | nicht erfasst | 6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75 (Prüfwert aus REA-Audit) | nicht erfasst | Offen: Datei und Herkunft nicht erfasst, nur Prüfwert bekannt. |
| jadx | v1.5.6 | GitHub skylot/jadx | nicht erfasst | nicht erfasst | Offen: nicht eingebunden, Pin fehlt. |
| apktool | v3.0.3 | GitHub iBotPeaches/Apktool | nicht erfasst | nicht erfasst | Offen: nicht eingebunden, Pin fehlt. |
| capa / capa-rules | v10.0.0 | GitHub mandiant/capa | nicht erfasst | nicht erfasst | Offen: nicht eingebunden, Pin fehlt. |
| FLOSS | v3.2.0 | GitHub mandiant/flare-floss | nicht erfasst | nicht erfasst | Offen: nicht eingebunden, Pin fehlt. |
| yara-x | v1.22.1 | GitHub VirusTotal/yara-x | nicht erfasst | nicht erfasst | Offen: nicht eingebunden, Pin fehlt. |
| radare2 | 6.2.4 | GitHub radareorg/radare2 | nicht erfasst | nicht erfasst | Offen: nicht eingebunden, Pin fehlt. |
| binwalk | v3.1.0 | GitHub ReFirmLabs/binwalk | nicht erfasst | nicht erfasst | Offen: nicht eingebunden, Pin fehlt. |
| LIEF / pefile / androguard | 1.0.0 / 2024.8.26 / 4.1.4 | PyPI bzw. GitHub (Index nicht erfasst) | nicht erfasst | nicht erfasst | Offen: nicht eingebunden, Pin fehlt. |
| Qiling | v1.4.11 (GPL-2.0) | GitHub, Repo nicht erfasst | nicht erfasst | nicht erfasst | Offen: nur für Phase 11, Lizenz vorher prüfen. |
| caveman (JuliusBrussee) | nicht erfasst | GitHub, Autor JuliusBrussee (URL nicht erfasst) | nicht erfasst | 655b7d9c5431 | Bestätigt: Prüfung dokumentiert. Offen: Version fehlt. |
| ponytail (DietrichGebert) | 5.3.3 | GitHub, Autor DietrichGebert (URL nicht erfasst) | nicht erfasst | 96608e078b2d | Bestätigt: Prüfung dokumentiert. |
| claude-security | 0.12.0 | claude-plugins-official | nicht erfasst | nicht erfasst | Offen: Commit fehlt. |
| feature-dev, pr-review-toolkit, mcp-server-dev | nicht erfasst | claude-plugins-official | nicht erfasst | nicht erfasst | Offen: Version und Commit fehlen. |
| nvidia/cuda (Docker-Testimage) | 12.6.0-base-ubuntu24.04 | Docker Hub (URL nicht erfasst) | nicht erfasst | nicht erfasst | Offen: nur Test, Digest fehlt. |
| Ollama-Modelle | qwen3:14b, qwen3:8b, qwen3:4b, qwen3-embedding:0.6b | Ollama-Bibliothek (URL nicht erfasst) | nicht erfasst | nicht erfasst | Offen: noch kein Pull belegt. Digest nach dem Pull erfassen. |

### Bestätigt
- Ollama 0.40.13 ist mit URL und SHA-256 in `infra/manifest.json` gepinnt.
- Der Ghidra-12.1.4-Hash ist in `infra/manifest.json` und in dieser Doku identisch.
- Die Commit-Pins für ponytail, caveman und bethington/ghidra-mcp v7.0.0 stehen in diesem Dokument.

### Offen
- `infra/manifest.json`: Ghidra (`url`, `target`) und REA (`version`, `url`, `sha256`, `target`) stehen auf `pending`. Das Feld `target` von Ollama enthält einen lokalen Pfad. Er gehört nicht in ein Repo-Dokument und wurde hier nicht übernommen.
- Ollama: installierter Client 0.35.1 weicht vom Pin 0.40.13 ab.
- JDK: Ghidra 12.1.4 braucht JDK 21, installiert ist Temurin 17.
- REA: zwei Commits in der Doku (60149282fcfc und 160d821ac9a0). Klären, welcher gilt. Kein SHA-256 für das npm-Paket.
- Modelle und Docker-Testimage haben keine Digests.
- Analyse-Werkzeuge sind nur recherchiert, nicht eingebunden. Ihnen fehlen URLs und Hashes.
- `requirements.in` wurde nicht gegen `requirements.lock` abgeglichen.
