# Code-Review Haiku G/H/I (nur lesend, keine Quelländerung)

Stand: Arbeitsbaum am 2026-10-31 (uncommitted Änderungen in dom.js, tests/forensic/* sind untracked).
Pfade relativ zu D:\Projects\LocalReverseAnything.

Kategorien: 1 Injektion/XSS/Pfad, 2 Fremdressourcen/Netz, 3 fehlende oder tote Pfade, 4 Lint/Bug,
5 Löschumfang/Datensicherheit, 6 Pins/Hashes/Versionen, 7 Fremdprozesse, 8 Test-Schwäche oder Lücke.

Format: paket | datei:zeile | schwere | kategorie | problem | fix | konfidenz

## Funde

G | src/sw_analyst/webui/static/index.html:23 | mittel | 3 | mock_v2.js referenziert, Datei fehlt (Verzeichnisliste geprueft), 404 bei jedem Laden | Tag entfernen oder Datei anlegen | hoch
G | src/sw_analyst/webui/static/index.html:29 | mittel | 3 | view_diagrams.js referenziert, Datei fehlt, keine Route oder Tab registriert | Tag entfernen | hoch
G | src/sw_analyst/webui/static/index.html:30 | mittel | 3 | view_log.js referenziert, Datei fehlt, keine Registrierung in SW.views/SW.tabs | Tag entfernen | hoch
G | src/sw_analyst/webui/static/index.html:19 | niedrig | 1 | mock.js wird immer geladen; Mock-Code liegt im Produktivpfad und ist nur durch ?mock=1 aktiv (api.js:6) | Mock nur bei ?mock=1 nachladen | mittel
G | src/sw_analyst/webui/static/store.js:121,131,139 und view_code.js:48 | niedrig | 1 | Route-ID aus dem Hash wird ungeprueft in den API-Pfad gesetzt; "../" wird vom Browser normalisiert. Serverseitig validiert, Wirkung gering | encodeURIComponent(st.id) | mittel
G | src/sw_analyst/webui/static/ui.js:154 | niedrig | 1 | Evidence-Pfad mit unkodierter jobId und id (id aus data-ev) | encodeURIComponent auf jobId und id | mittel
G | src/sw_analyst/webui/static/view_overview.js:266 | niedrig | 1 | Prompt-Pfad mit unkodierter id | encodeURIComponent(id) | mittel
G | src/sw_analyst/webui/static/markdown.js:139 | niedrig | 4 | var head zweimal im selben Funktionsscope (Ueberschrift Zeile 114, Tabelle Zeile 139); funktional korrekt, lint no-redeclare | Tabellenkopf eigener Name (headCells) | hoch
G | src/sw_analyst/webui/static/ui.js:101 | niedrig | 3 | ui.go definiert, Grep findet keinen Aufrufer im Frontend | entfernen | mittel
G | src/sw_analyst/webui/static/markdown.js:33 | niedrig | 1 | Berichtslinks mit Anker erlauben Hash-Navigation auf jede Route (#/job/<id>/...); keine Code-Ausfuehrung, nur Navigation | nur Anker ohne "/" zulassen | mittel
H | scripts/stop.ps1:90 | mittel | 4 | Origin hart auf http://127.0.0.1:8765 statt $Base; bei -Port ungleich 8765 scheitert Cancel mit 403 (Origin-Pruefung, vgl. tests/forensic/test_api_security.py:62); -Force laeuft ohne Abbruch weiter | -Headers @{ Origin = $Base } | hoch
H | scripts/start.ps1:247-250 | mittel | 7 | app.pid wird nur ueber Get-Process geprueft; bei PID-Wiederverwendung wird ein fremder Prozess als eigene App angehaengt. stop.ps1 prueft dagegen mit Test-OwnApp | Test-OwnApp-Logik auch hier, sonst app.pid verwerfen | hoch
H | scripts/start.ps1:233-234; infra/select-model.ps1:30; infra/manifest.json:32-37 | hoch | 6 | Modelle nur als Tags (qwen3:14b/8b/4b, qwen3-embedding:0.6b), Pull aus der Registry zur Laufzeit, kein Digest-Pin; Tag kann upstream wandern. CLAUDE.md verlangt Version- und Hash-Pin | Digest je Modell im Manifest pinnen und vor dem Pull pruefen | mittel
H | infra/manifest.json:13-17 | niedrig | 6 | ghidra hat sha256 gesetzt, url und target sind pending; widerspricht der Manifest-Regel (pending = nicht gepinnt). Hash ohne pruefbare Quelle | sha256 auf pending zuruecksetzen bis URL geprueft ist | mittel
H | infra/start-ollama.ps1:6; infra/select-model.ps1:7 | mittel | 6 | Ollama-Pfad mit Version ollama-0.40.13 hart kodiert, parallel zu infra/manifest.json; ein Versions-Update zieht diese Stellen nicht mit | Pfad aus Manifest oder Parameter von start.ps1 uebergeben | hoch
H | scripts/cleanup.ps1:44-54; scripts/cleanup.ps1:152-153 | mittel | 5 | Test-Deletable prueft nur GetFullPath-Praefix, keine Reparse-Point-Pruefung. Remove-Item -Recurse auf Eintraegen in data\tmp und run\ kann Junctions folgen (PS 5.1). Scope ist ganz data\ | Reparse-Points (Attributes ReparsePoint) ablehnen; Scope auf Unterordner begrenzen | mittel
H | scripts/cleanup.ps1:26 | niedrig | 4 | New-Item laeuft auch im -DryRun und Write-Stage schreibt Logzeilen; Widerspruch zur Meldung "nothing is removed" nur formal | New-Item nur ohne DryRun, oder Meldung praezisieren | hoch
H | scripts/cleanup.ps1:208 | niedrig | 5 | -DockerDeep prunt den Build-Cache anderer Projekte (opt-in, mit WARN) | im Runbook benennen; belassen | hoch
H | infra/select-model.ps1:12-13 | niedrig | 4 | Bei mehreren GPUs liefert nvidia-smi mehrere Zeilen; -split ',' ergibt dann Cast-Fehler. Ohne try; Fallback nur in start.ps1:84 | erste Zeile nehmen (Select-Object -First 1) | mittel
I | tests/unit/test_scripts.py:13-15 | mittel | 8 | Schein-Test: prueft nur Teilstring "cleanup.ps1" in start.ps1/stop.ps1, keine Aussage zur Loeschlogik | durch Verhaltenstest ersetzen (naechste Zeile) | hoch
I | tests/unit/test_scripts.py:1-26 | mittel | 8 | Luecke: keine Tests fuer Test-Deletable/Remove-Own (Loeschumfang, Reparse-Points, DryRun). graphify path cleanup.ps1 -> audit.jsonl liefert keine Verbindung, Schutz ist nur ueber Dateiauswahl gegeben | Python-Nachbildung der Pfadregeln mit Testfaellen | mittel
I | tests/unit/test_scripts.py:18-26 | niedrig | 8 | Docker-Regel prueft nur Zeilen mit 'prune'; docker rm/stop-Aufrufe in cleanup.ps1:195-196 und stop.ps1 werden nicht gegen den Label-Filter geprueft | alle docker-Aufrufe gegen $filter pruefen | mittel
I | tests/forensic/test_api_security.py:355 | niedrig | 8 | pytest.skip bei fehlenden Symlink-Rechten: unter Windows ohne Entwicklermodus entfaellt der Symlink-Traversal-Test; er zaehlt nur als skipped | Bericht muss skipped-Zahl ausweisen; Plan vermerken | mittel
I | tests/forensic/test_api_security.py:522-530 | mittel | 8 | Luecke: kein Test prueft, dass relative src/href in index.html existieren. mock_v2.js, view_diagrams.js, view_log.js (index.html:23,29,30) fehlen, Test bleibt gruen | Existenzpruefung fuer relative Referenzen ergaenzen | hoch
I | docs/testing/forensic-test-plan.md (Status-Spalte) | niedrig | 8 | Status veraltet: I3 [ ] trotz tests/forensic/test_network_isolation.py:56; C3 [ ] trotz tests/forensic/test_artifact_hashes.py:99; D6 [ ] trotz tests/unit/test_workflow.py:95 | Status aktualisieren | hoch
I | docs/testing/forensic-test-plan.md (T3, K1) | niedrig | 8 | Keine Tests gefunden fuer T3 (Rueckuebersetzung) und K1 (Ground-Truth-Korpus); Status [ ] ist korrekt, Luecke bleibt | als offene Luecke im Plan belassen | mittel

Hinweis: tests/forensic/test_api_security.py:522 erlaubt inzwischen "data:," (ref == "data:,"). Der beim Lesen gefundene Rot-Fehler ist damit behoben und wird nicht als Fund gefuehrt.

## graphify-Nachweis
- graphify query "webui static javascript innerHTML and index.html script tags": Treffer nur Doku (docs/architecture/api.md, "Sample-Inhalte nur als Text"), kein Code-Knoten, daher gezielte Reads.
- graphify query "cleanup script deletion scope and infra pins hashes": Treffer scripts/cleanup.ps1 (L1) und docs/runbooks/betrieb.md, Ausgangspunkt fuer Reads.
- graphify query "tests skipped or placeholder assertions and forensic test plan coverage": Treffer Testplan-Bloecke und xfail-Knoten, Abgleich mit Plan-Status.
- graphify query "where audit log file and sample storage are placed under data dir": AuditLog (common/audit.py:26), logs/<job>/audit.jsonl (common/store.py:114).
- graphify explain "cleanup.ps1": 12 Verbindungen, alle contains-Kanten zu Funktionen in scripts/cleanup.ps1.
- graphify path "cleanup.ps1" "audit.jsonl": keine gerichtete Verbindung gefunden (Schutz der Audit-Dateien nur ueber Dateiauswahl).
