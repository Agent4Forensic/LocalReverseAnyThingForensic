# ADR-0008: Datei-Ansicht, Beispiele, Laufzeitordner und Export/Import im Dashboard

Status: vorgeschlagen am 2026-10-31 (Auftrag von Jan, umgesetzt auf `feat/dashboard-integration`). Freigabe durch Jan steht aus.

## Kontext
Jan hat nach eigenen Versuchen am 2026-10-31 diese Punkte gemeldet:
- Bei den Beispielen ist unklar, wo ihr Code liegt. Sie sollen nach Schwierigkeit sortiert sein und ihre Dateigröße zeigen.
- Laufzeitordner müssen im Projektordner liegen. Der Virenschutz hat nur dort eine Ausnahme und löscht sonst Regeln oder Dateien.
- Zu einer bearbeiteten Datei will Jan Größe, Hex, Assembler mit Erklärung und Pseudocode sehen.
- Eine Analyse soll sich exportieren und wieder importieren lassen.

Die Prüfung des Ist-Stands ergab dazu:
- Der Code-Viewer zeigte keine Zeilen, weil `/files/content` reine Strings statt `{n, text}` lieferte. Binärdateien endeten in einem Fehler 400.
- Starlette legt Uploads über 1 MiB im System-Temp (`%TEMP%`) ab.
- `--data-dir data` hing vom Arbeitsverzeichnis des Prozesses ab.
- `index.html` lud drei Skripte, die es nicht gibt. Für Auftragsansicht, Tabs, Baum und Code fehlte das CSS ganz.
- IDs (`J-0001`, `T-000001`, `EV-000001`, `F-000001`) sind je Installation fortlaufende Zähler. Ein Import in die Hauptdatenbank würde kollidieren.

## Optionen
**Export/Import:**
1. Import in die Hauptdatenbank mit neuen IDs. Das bricht jede Referenz im Bericht, in Zitaten und in der Audit-Kette. Diese Option ist verworfen.
2. Nur den ganzen Datenordner sichern und zurückspielen. Das ist kein Austausch einzelner Analysen. Diese Option ist verworfen.
3. **Gewählt:** Jede importierte Analyse bekommt einen eigenen, schreibgeschützten Store unter `data/imports/I0001/`. Die Original-IDs bleiben unverändert. Das Dashboard adressiert die Analyse als `I0001-J-0003`.

**Assembler und Pseudocode:**
1. Neue Abhängigkeit (zum Beispiel Capstone) im Host-Prozess. Pseudocode gäbe es damit nicht, und CLAUDE.md Verbot 5 verlangt Begründung, Lizenzprüfung und Pin. Diese Option ist verworfen.
2. **Gewählt:** Den Ghidra-Export aus ADR-0006 lesen, also denselben Container und denselben Cache wie die Modellwerkzeuge. Ohne Image nennt das Dashboard den Grund und den Befehl `scripts\start.ps1 -BuildTools`.

**Erklärungen zu Assembler-Befehlen:**
1. Das Modell erklärt jede Zeile. Das ist langsam, bindet die Ollama-Warteschlange und ist ohne Beleg. Diese Option ist verworfen.
2. **Gewählt:** Eine feste deutsche Tabelle beschreibt, was ein Befehl allgemein tut (`webui/inspect.py`). Was eine Funktion im Sample bewirkt, zeigen nur die Befunde mit Evidence. Das Dashboard schreibt das ausdrücklich dazu.

## Entscheidung
1. **Laufzeitordner** (`common/paths.py`): Ein relatives `--data-dir` zählt ab dem Projekt-Root. Beim Start entstehen `jobs`, `logs`, `run`, `tmp`, `imports`, `exports` und `eval`. Python-Temp und Upload-Spool liegen in `data/tmp`, auch `TMP`, `TEMP` und `TMPDIR` für Kindprozesse. Ein Datenordner außerhalb des Projekts erzeugt eine Warnung. Der Preflight-Selbsttest des Gateways nutzt ebenfalls `data/tmp`.
2. **Beispiele** (`webui/examples.py`, `GET /api/examples`, `GET /api/examples/{id}`, `POST /api/examples/{id}/job`): Quelle bleibt `example/`. Die Liste ist nach Stufe sortiert (leicht, mittel, schwer) und nennt Größe und SHA-256 der Probe, den Ordner, `challenge.json`, den Erzeuger mit Zeile in `samples.py` und den Skriptlauf. Die Flagge steht nicht in der Liste und geht nicht an den Job. Nach dem Lauf vergleicht das Dashboard sie mit den akzeptierten Antworten, mit derselben Regel wie `run_eval.py`. Das Budget beim Start ist 20 Aufgaben, 200 Schritte und 10 Minuten, wie bei `run_eval.py`. Neu ist Beispiel `05-pe-xor-routine` mit echter x86-Routine, damit Assembler und Pseudocode etwas zeigen. Beispiel 03 bleibt bytegleich.
3. **Datei-Ansicht** (Tab „Datei“): `GET /api/jobs/{id}/inspect`, `/inspect/hex`, `/inspect/functions` und `/inspect/function`. Dazu kommen die Gateway-Extras `read_bytes` und `ghidra_export`. Die Extras haben dasselbe Pfad-Jail wie die Werkzeuge, sind aber keine Modellwerkzeuge, die Allowlist bleibt unverändert. Ghidra-Aufrufe aus dem Dashboard stehen als Debug-Ereignis im Log und damit in der Audit-Kette des Jobs. Ein Lock in `ContainerTools` verhindert doppelte Containerläufe, wenn Worker und Dashboard dieselbe Datei anfragen.
4. **Code-Viewer:** `/files/content` hält den dokumentierten Vertrag (`lines:[{n, text}]`, `binary`). Binärdateien kommen als Hexzeilen.
5. **Export** (`GET /api/jobs/{id}/export?include_files=0|1`): Der Export ist ein ZIP mit `manifest.json` (SHA-256 und Größe je Eintrag, Kopf-Hash der Audit-Kette), `job.json` (alle Zeilen des Jobs), `audit.jsonl` (bytegleich) und `report.de.md` und `report.en.md`. Mit `include_files=1` kommen Sample, abgeleitete Dateien und Ghidra-Cache dazu. Laufende Jobs werden nicht exportiert. Eine Kopie bleibt in `data/exports/`. Der Export steht als Log-Ereignis in der Audit-Kette der Quelle.
6. **Import** (`POST /api/imports`): Das Paket gilt als feindliche Eingabe. Grenzen sind 256 MiB Upload, 2000 Einträge und 1 GiB entpackt. Erlaubt sind nur feste Eintragsnamen, kein `extractall`, Schreibziele sind fest. SHA-256 und Größe jedes Eintrags werden vor der Übernahme geprüft. Die Audit-Kette muss gültig sein, und jedes Ereignis aus `job.json` braucht einen passenden Audit-Eintrag (`data_sha256`). Spalten kommen nur aus einer Allowlist. Danach wird der Bericht neu gebaut und mit dem mitgelieferten verglichen (`report_reproducible`). Der Store ist schreibgeschützt (`PRAGMA query_only`), Abbrechen liefert 409.
7. **Robustheit:** Ein Auftrag steht auf `uploading`, bis sein Sample geschrieben ist (F-10). Der Worker übersteht Ausnahmen der Engine (F-09). Nach einem Neustart schließt er auch hängende Aufgaben und Schritte. Uploads über dem Limit lehnt die Middleware über `Content-Length` ab, bevor gespoolt wird (F-20).

## Folgen
- Jan bekommt die gewünschten Ansichten. Assembler und Pseudocode brauchen Docker Desktop und das Ghidra-Image, ohne beides zeigt der Tab Größe, Art, Ablage und Hex.
- Ein Paket ist nicht signiert. Wer Manifest, Zeilen und Audit-Kette zusammen fälscht, besteht die Prüfung. Die Herkunft belegt nur der Abgleich des Paket-SHA-256 (Header `X-Bundle-SHA256`, Log-Eintrag der Quelle) über einen zweiten Kanal. Eine Signatur bräuchte Schlüsselverwaltung und ein eigenes ADR.
- Ein Export mit Sample enthält bei echten Proben Schadcode. Er gehört nur auf die Analyse-VM oder in eine geschützte Ablage. Standard ist ohne Sample.
- Importierte Analysen bleiben auf der Platte, bis Jan sie löscht. Ein Löschknopf fehlt bewusst, damit nichts Beweisrelevantes per Klick verschwindet.
- Neue Ereignisse in der Audit-Kette: Ghidra-Ansicht (Debug) und Export (Info). Das Format der Kette bleibt unverändert (CLAUDE.md Verbot 3 betrifft die Mechanik, nicht neue Ereignisse über `emit`). Jan bestätigt das bitte mit der Freigabe dieses ADR.
