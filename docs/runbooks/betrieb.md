# Runbook: Betrieb

Gilt für den Entwicklungsrechner (Windows 11). Echte Proben gehören nicht hierher, sondern in die geplante Analyse-VM ohne Netzwerkkarte ([ADR-0000](../adr/0000-grundentscheidungen.md)). Auf diesem Rechner werden nur harmlose, selbst erzeugte Proben verwendet.

## Voraussetzungen

- Windows 11, PowerShell
- Python 3.11: `winget install --id Python.Python.3.11 --exact`
- uv (optional, schneller als pip): `winget install --id astral-sh.uv --exact`
- Git: `winget install --id Git.Git --exact`
- Docker Desktop (optional, nur für Ghidra, capa, FLOSS, YARA und jadx): `winget install --id Docker.DockerDesktop --exact`, danach starten
- Werkzeug-Images einmalig bauen (Netz nötig, ca. 3 GB, kann 10 Minuten dauern): `infra\tools\build-images.ps1` oder `scripts\start.ps1 -BuildTools`. Ohne Images oder bei gestopptem Docker läuft die Plattform mit den eigenen Python-Werkzeugen weiter; der Preflight meldet das als Warnung.
- Testwerkzeuge: `uv pip install --python .venv\Scripts\python.exe --require-hashes -r requirements-dev.lock`
- Ollama (portabel unter `D:\Tools\sw-analyst`, wird von `start.ps1` aus `infra/manifest.json` installiert, Hash geprüft)
- NVIDIA-GPU. Die Modellstufe richtet sich nach dem freien VRAM (siehe unten)
- Kein Administratorrecht im Normalbetrieb

## Starten

```powershell
scripts\start.ps1
```

`start.ps1` arbeitet diese Stufen ab. Jede Zeile im Terminal beginnt mit Uhrzeit und Stufenname und steht auch in `data\logs\start-<datum>.log`.

| Stufe | Was passiert |
|---|---|
| CLEAN | räumt Reste eigener Prozesse, Scratch-Dateien, alte Logs und gelabelte Docker-Objekte auf |
| CHECK | Preflight: Python, Umgebung, Ports, Platz, GPU, Modell |
| INSTALL | legt bei Bedarf `.venv` an und installiert aus `requirements.lock` (`--require-hashes`) und `infra/manifest.json` (SHA-256-Prüfung, Abweichung bricht ab) |
| UPDATE | meldet neuere Versionen, spielt sie nie automatisch ein |
| OLLAMA | startet Ollama auf `127.0.0.1:11435` |
| MODEL | wählt das Modell nach freiem VRAM, lädt es bei Bedarf, wärmt es auf |
| APP | startet die Anwendung auf `127.0.0.1:8765` und öffnet das Dashboard |
| WORKER | Statusschleife, zeigt Änderungen des Workers und des Modellservers |

Schalter: `-Model`, `-Port`, `-OllamaPort`, `-NoCleanup`, `-Offline`, `-Update`, `-SkipUpdateCheck`, `-NoBrowser`, `-BuildTools`.

**Modellstufen** (`infra/select-model.ps1`, nach freiem VRAM): Stufe A ab 11.000 MiB `qwen3:14b`, Stufe B ab 7.000 MiB `qwen3:8b`, sonst Stufe C `qwen3:4b` (langsam, auf Blackwell absturzgefährdet bei Teil-Offload). Mit `-Model` lässt sich ein Tag erzwingen. Die Modellwahl ist noch nicht endgültig ([ADR-0001](../adr/0001-modellwahl.md)).

## Stoppen

```powershell
scripts\stop.ps1            # wartet, bis ein laufender Job fertig ist
scripts\stop.ps1 -Force     # bricht einen laufenden Job ab
```

`stop.ps1` beendet nur eigene Prozesse (App, Ollama auf Port 11435). Fremde Prozesse, ein anderes Ollama auf Port 11434 und `~/.ollama` bleiben unberührt. Danach räumt `cleanup.ps1 -Phase post` PID-Dateien, Caches, gelabelte Container, Netze und Volumes auf. Vorschau ohne Löschen: `scripts\cleanup.ps1 -Phase pre|post -DryRun`.

**Wichtig:** `Strg+C` im `start.ps1`-Fenster löst ebenfalls den Stopp aus und beendet damit Ollama. Das unterbricht laufende Modellaufrufe (Fehler `WinError 10061`, Verbindung abgelehnt). Wer parallel Benchmarks fährt, startet dafür ein eigenes Ollama auf einem anderen Port.

## Ablage und Logs

| Pfad | Inhalt |
|---|---|
| `data/sw_analyst.db` | SQLite-Store (Jobs, Aufgaben, Evidence, Findings, Antworten) |
| `data/jobs/<job>/sample` | die Probe, schreibgeschützt, nie ausgeführt |
| `data/jobs/<job>/derived/` | abgeleitete Artefakte (dekodierte Ebenen), nie ausführbar |
| `data/logs/<job>/audit.jsonl` | hash-verketteter Audit-Log des Jobs |
| `data/logs/start-<datum>.log` | Protokoll von `start.ps1` |
| `data/run/` | PID-Dateien und Laufzeit-Scratch |
| `data/eval/<zeitstempel>/` | Ergebnisse der Beispielfälle (siehe unten) |

`data/` ist git-ignoriert. Proben und Berichte gehören nie ins Repository.

## Beispielfälle prüfen

```powershell
example\start_eval.ps1                         # Menü
example\start_eval.ps1 -Challenge all          # alle
example\start_eval.ps1 -Challenge 01-layered-flag -Model qwen3:8b -Minutes 15
```

Jede Challenge ist eine harmlose Probe mit einer Flagge. Das Skript lässt die ganze Kette laufen und sucht die Flagge im finalen Bericht (`PASS` oder `FAIL`, Exit-Code 0 nur bei allem bestanden). Einzelheiten und das Anlegen eigener Fälle: [`../../example/README.md`](../../example/README.md). Die Läufe nutzen den aktuellen Arbeitsstand von `src/` und belegen die GPU. Zwei Läufe gleichzeitig verfälschen die Zeitbudgets, weil Ollama Aufträge nacheinander abarbeitet.

## Tests

```powershell
.venv\Scripts\python.exe -m pytest
```

Läuft ohne Modell und ohne GPU (Skript-Modell, harmlose Proben aus dem Speicher). Stand: 469 Tests, etwa 25 Sekunden. Der Live-Benchmark mit echtem Modell ist kein Teil von `pytest`: `tests/bench/run_live.py`.

## Fehlerbehebung

| Symptom | Ursache und Abhilfe |
|---|---|
| `WinError 10061` oder „Verbindung abgelehnt“ im Job | Ollama ist weg (gestoppt oder abgestürzt). `infra\start-ollama.ps1` starten. Drei aufeinanderfolgende Modellfehler beenden den Job. |
| Job endet `failed` | keine Analyseaufgabe wurde fertig, meist Modell nicht erreichbar. Zuerst Ollama prüfen. |
| Job endet `partial` | Lücken oder Budget (Aufgaben, Schritte, Minuten) erschöpft. Der Bericht nennt die offenen Punkte samt Grund. |
| Job pausiert | `HostGuard`: zu wenig RAM oder Platz oder zu hohe GPU-Temperatur. Nach 15 Minuten ohne Besserung endet der Job als `partial`. |
| `Port 11435 already in use` | läuft schon ein Ollama der Plattform. Nicht ein zweites starten. |
| Modell fehlt | `start.ps1` lädt es nach, oder `ollama pull <tag>` mit `OLLAMA_HOST=127.0.0.1:11435`. |
| Hash-Abweichung beim Install | Datei wurde gelöscht, nichts installiert. Pin in `infra/manifest.json` und Quelle prüfen, nicht umgehen. |
| Dashboard-Tabs „Diagramme“, „Log“ fehlen | bekannte Lücke: `index.html` lädt Skripte, die noch nicht existieren (siehe [`../STATUS.md`](../STATUS.md)). |
| Datei fehlt nach einem Agentenlauf | Virenscanner (G Data) hat sie kurz entfernt. `git ls-files -d` prüfen, Ausnahme ist eingetragen. |

## Parallelarbeit im selben Arbeitsbaum

Zwei Sitzungen im selben Arbeitsbaum dürfen keine Branches wechseln oder stashen und sollten getrennte Dateimengen haben. Sauberer ist ein eigener Git-Worktree je Sitzung (`git worktree add`).
