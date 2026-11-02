# Runbook: Betrieb

Gilt für den Entwicklungsrechner (Windows 11). Echte Proben gehören nicht hierher, sondern in die geplante Analyse-VM ohne Netzwerkkarte ([ADR-0000](../adr/0000-grundentscheidungen.md)). Auf diesem Rechner werden nur harmlose, selbst erzeugte Proben verwendet.

## Voraussetzungen

- Windows 11, PowerShell
- Python 3.11: `winget install --id Python.Python.3.11 --exact`
- uv (optional, schneller als pip): `winget install --id astral-sh.uv --exact`
- Git: `winget install --id Git.Git --exact`
- Docker Desktop (optional, nur für Ghidra, capa, FLOSS, YARA und jadx): `winget install --id Docker.DockerDesktop --exact`, danach starten
- Werkzeug-Images einmalig bauen (Netz nötig, ca. 3 GB, kann 10 Minuten dauern): `scripts\start.ps1` baut fehlende Images beim Start selbst (nach dem Docker-Start; `-NoBuild` überspringt das, `-Offline` baut nichts, ein fehlgeschlagener Bau verhindert den Start nicht). Von Hand: `infra\tools\build-images.ps1`. Ohne Images oder bei gestopptem Docker läuft die Plattform mit den eigenen Python-Werkzeugen weiter; der Preflight meldet das als Warnung.
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

## Colibri mit DeepSeek V4 Flash (ADR-0012)

Standard ist Ollama. `scripts\start.ps1 -EnableColibri` schaltet Colibri einmalig dauerhaft ein, wenn die Hardware es trägt: vollständiges Modell, mindestens 23 GB RAM eingebaut, 20 GB frei, rund 1450 MB/s auf dem Modell-Datenträger. Sonst nennt der Start die Gründe und bleibt bei Ollama. `scripts\start.ps1 -DisableColibri` schaltet zurück. Die Befehle darunter sind für Messläufe und überspringen diese Prüfung.

```powershell
python infra\fetch-colibri-model.py     # einmalig, 167 GB auf die SSD ki_data
python infra\fetch-colibri-model.py --verify   # alle Hashes prüfen, ohne Netz
python -m sw_analyst.colibri_settings    # zeigt, was die Hardware hergibt (PYTHONPATH=src)
scripts\start.ps1 -Llm colibri -ColibriPrepare -NoDocker   # einmalig: doctor, plan, tune, Cache anwärmen; stoppt danach selbst
scripts\start.ps1 -Llm colibri -ColibriGate -NoDocker      # erster echter Test, stoppt danach selbst
scripts\start.ps1 -Llm colibri           # Dashboard mit Colibri; Standard bleibt Ollama
scripts\start.ps1 -Llm colibri -RamGb 18 # RAM-Budget von Hand
```

Die SSD muss den Namen `ki_data` tragen, der Laufwerksbuchstabe ist egal. Fehlen Datenträger oder Dateien, oder weicht ein Hash vom Repository ab, startet nichts. Die Hash-Prüfung dauert bei jedem Start rund 6 Minuten; `-SkipModelHash` überspringt sie mit Warnung. Die Einstellungen wählt `colibri_settings.py` aus RAM, VRAM und Datenträger. Mehr freier RAM bedeutet mehr Tempo, also vorher andere Programme schließen; `-NoDocker` spart zusätzlich Speicher, wenn keine Container-Werkzeuge gebraucht werden. Die Ergebnisse des Tests stehen unter `data\eval\colibri-gate-*\gate.json`. „Abbrechen“ im Dashboard wirkt innerhalb von Sekunden und gibt die GPU frei.

Eine Kopie auf einem internen Laufwerk teilt die Lesezugriffe und belegt dort 167 GB:

```powershell
robocopy E:\sw-analyst\colibri\deepseek-v4-flash-0731 D:\Tools\sw-analyst\colibri-mirror /E /XF *.part .coli_*
scripts\start.ps1 -Llm colibri -ColibriMirror D:\Tools\sw-analyst\colibri-mirror
``` Das Tempo hängt an der SSD: Colibri ist hier eine Stapelverarbeitung und lädt beim Start bis zu 30 Minuten. Das Log steht unter `data\logs\colibri-*.log`.

Vor dem Abziehen der SSD `scripts\stop.ps1` ausführen.

## Stoppen

```powershell
scripts\stop.ps1            # wartet, bis ein laufender Job fertig ist
scripts\stop.ps1 -Force     # bricht einen laufenden Job ab
```

`stop.ps1` beendet nur eigene Prozesse (App, Ollama auf Port 11435). Fremde Prozesse, ein anderes Ollama auf Port 11434 und `~/.ollama` bleiben unberührt. Danach räumt `cleanup.ps1 -Phase post` PID-Dateien, Caches, gelabelte Container, Netze und Volumes auf. Vorschau ohne Löschen: `scripts\cleanup.ps1 -Phase pre|post -DryRun`.

Ablauf von `stop.ps1`: laufenden Job abwarten oder abbrechen, App stoppen, Modelle per API aus der GPU entladen, eigenes Ollama beenden, danach im Log den belegten GPU-Speicher ausgeben (Warnung ab 1500 MiB, es wird nichts Fremdes beendet), aufräumen. Docker Desktop startet `start.ps1` selbst, wenn der Daemon nicht läuft (nicht mit `-NoDocker`); `stop.ps1` beendet es nur dann wieder, wenn `start.ps1` es gestartet hat (Marker `data\run\docker.pid`), und nicht mit `-KeepDocker`. Scheitert der Start nach dem Ollama-Start, räumt `start.ps1` selbst per `stop.ps1 -Force` auf. Schließt man das Fenster statt `Strg+C`, übergibt PowerShell das Beenden an ein verstecktes `stop.ps1 -Force` (Best Effort, nicht belegt).

**Wichtig:** `Strg+C` im `start.ps1`-Fenster löst ebenfalls den Stopp aus und beendet damit Ollama. Das unterbricht laufende Modellaufrufe (Fehler `WinError 10061`, Verbindung abgelehnt). Wer parallel Benchmarks fährt, startet dafür ein eigenes Ollama auf einem anderen Port.

## Ablage und Logs

| Pfad | Inhalt |
|---|---|
| `data/sw_analyst.db` | SQLite-Store (Jobs, Aufgaben, Evidence, Findings, Antworten) |
| `data/jobs/<job>/sample` | die Probe, schreibgeschützt, nie ausgeführt |
| `data/jobs/<job>/derived/` | abgeleitete Artefakte (dekodierte Ebenen), nie ausführbar |
| `data/logs/<job>/audit.jsonl` | hash-verketteter Audit-Log des Jobs |
| `data/logs/start-<datum>.log` | Protokoll von `start.ps1` |
| `data/jobs/<job>/tool-cache/` | Ergebnisse der Werkzeug-Container (Ghidra-Export usw.), Cache für Modell und Datei-Ansicht |
| `data/run/` | PID-Dateien und Laufzeit-Scratch |
| `data/tmp/` | Python-Temp und Upload-Spool (statt `%TEMP%`) |
| `data/imports/I0001/` | importierte Analyse: eigener, schreibgeschützter Store, Audit-Kette, Dateien, Originalpaket unter `bundle/` |
| `data/exports/` | Kopie jedes Exports (ZIP) |
| `data/examples.json` | welcher Auftrag aus welchem Beispiel gestartet wurde |
| `data/eval/<zeitstempel>/` | Ergebnisse der Beispielfälle (siehe unten) |

`data/` ist git-ignoriert. Proben und Berichte gehören nie ins Repository.

**Alles liegt im Projektordner.** Der Server legt beim Start alle Ordner oben an, egal aus welchem Verzeichnis er gestartet wird: Ein relatives `--data-dir` zählt ab dem Projekt-Root. Temp-Dateien und Uploads über 1 MiB landen in `data\tmp`, nicht in `%TEMP%`. Grund: Nur der Projektordner hat eine Ausnahme im Virenschutz; außerhalb kann er Proben, Regeln oder Zwischenstände löschen. Liegt der Datenordner außerhalb, meldet die Startzeile `[DATA]` eine Warnung, das Dashboard zeigt es in der Kachel „Datenablage“.

## Dashboard: Beispiele, Datei-Ansicht, Export und Import

- **Beispiele** (Navigation „Beispiele“): Challenges aus `example/`, sortiert leicht, mittel, schwer, mit Größe der Probe und dem Ort des Codes (Ordner, `challenge.json`, Erzeugerfunktion mit Zeile in `example/samples.py`). „Code und Probe ansehen“ zeigt den Erzeuger, die Beschreibung, die Probe als Text oder Hex und auf Wunsch die Lösung. Links Beispiel wählen, rechts „Beispiel starten“. Fehlt das Modell oder ein benötigtes Werkzeug (Beispiel 05 braucht Ghidra), ist der Knopf gesperrt und die Seite nennt, was fehlt. Läuft das Beispiel schon, führt der Knopf zum laufenden Auftrag. „Alle startbereiten nacheinander starten“ reiht alle ein. Budget kommt aus `challenge.json`. Nach dem Lauf steht „bestanden“ oder „nicht bestanden“ auf der Seite und im Auftragskopf.
- **Tab „Datei“** im Auftrag: Größe, Art, SHA-256 und Ablage der Datei, Hex mit Blättern und Sprung zu Offset. Bei PE, ELF und Mach-O zusätzlich Funktionsliste, Assembler mit Erklärung je Befehl und Pseudocode (Ghidra). Voraussetzung: Docker Desktop läuft und das Image ist gebaut (`scripts\start.ps1 -BuildTools`, einmalig, braucht Netz); danach den Server neu starten. Der erste Aufruf je Datei dauert Minuten, danach kommt das Ergebnis aus dem Cache. Die Erklärungen sind eine feste Tabelle, keine KI-Aussage.
- **Export:** Im Auftragskopf „Exportieren“ (nur bei beendeten Aufträgen). Standard ohne Sample; „mit Sample“ packt Sample, abgeleitete Dateien und Ghidra-Cache dazu. Das Paket enthält Daten, Audit-Kette, Bericht DE/EN und Prüfsummen. Eine Kopie bleibt in `data\exports\`. Den Paket-SHA-256 (steht im Log des Auftrags) getrennt notieren, er belegt später die Herkunft.
- **Import:** Übersicht, „Analyse importieren“, ZIP wählen. Geprüft werden Prüfsummen jedes Eintrags, Audit-Kette, jedes Ereignis gegen die Kette und ob der Bericht bytegleich neu entsteht. Die Analyse erscheint als `I0001-J-…`, schreibgeschützt, mit dem Prüfergebnis im Kopf. Dasselbe Paket zweimal ergibt keinen zweiten Import.

## Beispielfälle prüfen

```powershell
example\start_eval.ps1                         # Menü
example\start_eval.ps1 -Challenge all          # alle
example\start_eval.ps1 -Challenge 01-layered-flag -Model qwen3:8b -Minutes 15
```

Alternativ im Dashboard unter „Beispiele“ (siehe oben). Dort läuft der Auftrag über den normalen Worker und erscheint in der Übersicht.

Jede Challenge ist eine harmlose Probe mit einer Flagge. Das Skript lässt die ganze Kette laufen und sucht die Flagge im finalen Bericht (`PASS` oder `FAIL`, Exit-Code 0 nur bei allem bestanden). Einzelheiten und das Anlegen eigener Fälle: [`../../example/README.md`](../../example/README.md). Die Läufe nutzen den aktuellen Arbeitsstand von `src/` und belegen die GPU. Zwei Läufe gleichzeitig verfälschen die Zeitbudgets, weil Ollama Aufträge nacheinander abarbeitet.

## Tests

```powershell
.venv\Scripts\python.exe -m pytest
```

Läuft ohne Modell und ohne GPU (Skript-Modell, harmlose Proben aus dem Speicher). Stand 2026-10-31: 1023 Tests grün, 10 übersprungen (Docker-Images, Windows-Pfade), 38 bekannte xfails, etwa 40 Sekunden. Der Live-Benchmark mit echtem Modell ist kein Teil von `pytest`: `tests/bench/run_live.py`.

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
| Tab „Datei“: „Ghidra-Werkzeuge sind nicht geladen“ | Docker Desktop starten, `scripts\start.ps1` neu starten (baut fehlende Images selbst). Hex, Größe und Art gehen auch ohne. |
| Tab „Datei“: „Kein Maschinencode“ | Text, Skript oder Container: Assembler und Pseudocode gibt es nur für PE, ELF, Mach-O. Text zeigt der Tab „Code“. |
| Import abgelehnt (`checksum_mismatch`, `audit_invalid`) | Paket verändert oder beschädigt. Nicht reparieren, beim Absender ein neues Paket anfordern und den Paket-SHA-256 vergleichen. |
| Auftrag nach Neustart `failed` mit „job interrupted by restart“ | Server wurde während des Laufs beendet. Ein Lauf lässt sich nicht sicher fortsetzen; neu starten. Daten und Audit-Kette bis zum Abbruch bleiben erhalten. |
| Tab „Diagramme“ fehlt | noch nicht gebaut (Dashboard V2, siehe [`../STATUS.md`](../STATUS.md)). |
| Datei fehlt nach einem Agentenlauf | Virenscanner (G Data) hat sie kurz entfernt. `git ls-files -d` prüfen, Ausnahme ist eingetragen. |

## Parallelarbeit im selben Arbeitsbaum

Zwei Sitzungen im selben Arbeitsbaum dürfen keine Branches wechseln oder stashen und sollten getrennte Dateimengen haben. Sauberer ist ein eigener Git-Worktree je Sitzung (`git worktree add`).
