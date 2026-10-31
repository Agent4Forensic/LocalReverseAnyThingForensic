# Sicherheitsmodell

Quelle der Regeln: [`../../PROJEKTPLAN.md`](../../PROJEKTPLAN.md) Abschnitt 2 und [`../../CLAUDE.md`](../../CLAUDE.md) (Absolute Verbote). Dieses Dokument ordnet die Schutzschichten, benennt, wodurch sie geprüft werden, und hält fest, was noch **nicht** abgesichert ist.

## Wovor geschützt wird

| Werte | Bedrohung |
|---|---|
| Entwicklungsrechner und Daten darauf | Ausführung der Probe, Ausbruch aus einer Umgebung |
| Richtigkeit des Berichts | erfundene oder aus dem Sample gesteuerte Aussagen |
| Nachvollziehbarkeit (Chain of Custody) | unbemerkte Änderung von Beweisen oder Protokollen |
| Host-Ressourcen | Speicher-, Platten-, GPU-Überlastung durch Proben oder Schleifen |

Der Angreifer ist die **Probe selbst**: Ihr Inhalt (Strings, Kommentare, Ressourcen, Dateinamen, dekodierte Ebenen) kann Anweisungen an die KI enthalten oder Parser in Fehler treiben. Alles, was aus der Probe stammt, ist unvertrauenswürdige Eingabe.

## Schichten

| # | Schicht | Wirkung | Umsetzung | Prüfung |
|---|---|---|---|---|
| 1 | Probe = Daten | Kein Werkzeug startet die Probe. Sie liegt schreibgeschützt in `data/jobs/<job>/sample`. | `gateway/` | `test_dev_gateway.py`, Plan C2, I1 |
| 2 | Gateway statt Shell | Feste Allowlist, validierte Argumente, Pfad-Jail, Größen- und Zeitlimits. Kein `run_command`, `eval`, `exec`, `shell=True`. | `gateway/` | `test_dev_gateway.py`, `test_host_safety.py`, Plan I1, I2, I5 |
| 3 | Herkunftsmarkierung | Werkzeugergebnisse stehen im Prompt nur in `<untrusted_data>`-Blöcken. | `guard/sanitize.py` | `test_guard_sanitize.py` |
| 4 | Scanner | Erkennt Anweisungsmuster (EN, DE, auch kodiert oder unsichtbar). Treffer hoher Schwere werden im Prompt geschwärzt, das Original bleibt als Beleg. | `guard/scanner.py` | `test_guard_scanner.py`, `injection_corpus.json` (Plan S1) |
| 5 | Aktionsprüfung | Nur Tools der Allowlist, Argumente nach Schema. Anderes wird abgelehnt und gezählt. | `guard/actions.py` | `test_guard_actions.py` (Plan S4) |
| 6 | Wächter | Nach einem Treffer hoher Schwere und einer unzulässigen Aktion wird die Aufgabe `blocked`, der Vorfall steht als Befund im Bericht. Vom Modell formulierte Ziele werden vor dem Anlegen gescannt. | `guard/taskguard.py` | `test_guard_taskguard.py`, CTF-Test (Plan S3) |
| 7 | Belegzwang | `confirmed` nur, wenn Evidence-ID im selben Job existiert und das Zitat wörtlich vorkommt. Antworten nur aus `confirmed` Findings. | `orchestrator/verifier.py` | `test_chain_of_custody.py` (Plan G1 bis G3, G5, G6) |
| 8 | Audit-Kette | Jeder Aufruf wird hash-verkettet protokolliert. Ändern, Löschen, Vertauschen oder Einfügen einer Zeile wird mit Zeilenposition erkannt. | `common/audit.py` | `test_chain_of_custody.py` (Plan C4) |
| 9 | Host-Schutz | Vor jeder Aufgabe Prüfung von RAM, Platz und GPU-Temperatur. Pause, nach 15 Minuten `partial`. Das Modell erreicht diese Prüfung nicht. | `common/hostguard.py` | `test_host_safety.py` |
| 10 | Nur Loopback | Der Modellclient lehnt jeden anderen Host als Loopback ab. | `llm/ollama.py` | `test_chain_of_custody.py` (Plan I4) |
| 11 | Defanging | IOCs im Bericht entschärft (`hxxp://`, `[.]`), nie Payload-Bytes. | `report/defang.py` | `test_defang.py` (Plan T5) |
| 12 | Aufräumen | Start und Stopp entfernen nur eigene Prozesse, Dateien und gelabelte Docker-Objekte. | `scripts/*.ps1` | `test_scripts.py` |
| 13 | Lieferkette | Installation nur aus gepinnten, gehashten Quellen. Fremde Plugins und Repositories werden vor der Nutzung statisch geprüft und mit Commit in `dev-environment.md` festgehalten. | `infra/manifest.json`, `requirements.lock` | `test_preflight.py`, Hash-Prüfung in `start.ps1` |

Die Schichten 1 bis 11 sind umgesetzt und getestet. Die Isolation durch eine Hyper-V-VM ohne Netzwerkkarte mit gehärteten Docker-Containern (`--network none`, read-only, `--cap-drop ALL`) ist **geplant und noch nicht umgesetzt** (Plan I8).

## Was bewusst nicht gilt

- Das Modell hat keine Shell und keine Schreibwerkzeuge außer Notizen und Annotationen im Job-Arbeitsbereich.
- Es gibt keine dynamische Analyse. Ein Bedarf wird als offene Lücke (`GAP`) im Bericht benannt, nicht umgesetzt. Entwurf: [ADR-0005](../adr/0005-dynamische-analyse.md), keine Umsetzung ohne ausdrückliche Freigabe.
- Neue Werkzeuge (Ghidra, jadx, capa und weitere) kommen nur hinter dem Gateway und nur nach Freigabe der Allowlist ([ADR-0006](../adr/0006-statische-werkzeuge-allowlist.md)).

## Bekannte Grenzen und offene Punkte

| Grenze | Folge | Stand |
|---|---|---|
| Zitat stimmt, Schluss geht zu weit | Der Prüfer vergleicht Text, nicht Bedeutung. Der Bewerter und Stichproben von Hand fangen das teilweise ab. | Plan G9, offen |
| Mehrstufige Injektion (Anweisung über mehrere Evidences verteilt) | Gegenmaßnahmen (Systemprompt, Allowlist) wirken, sind aber nicht gemessen. | Plan S6, offen |
| Scanner auf dem eigenen Korpus justiert | Der Recall von 145 von 145 ist optimistisch. Ein unabhängiges Hold-out-Set fehlt. | Plan S2, offen |
| Gekürztes Ende des Audit-Logs | Das Entfernen der letzten Zeilen ist aus der Datei allein nicht erkennbar. Der Kopf-Hash muss separat festgehalten werden. | im Test als Grenze dokumentiert |
| Kein Netz-Sperr-Test | Dass ein voller Job keine ausgehende Verbindung außer Loopback öffnet, ist nur durch Codeprüfung belegt, nicht durch einen Sockettest. | Plan I3, offen |
| Web-API und Frontend | Origin- und Host-Prüfung, Upload-Grenzen und Pfad-Traversal im Code-Viewer sind nicht als eigene Sicherheitstests vorhanden. | Plan I6, I7, offen |
| Modell mit Teil-Offload auf Blackwell | Absturzmeldungen in der Community. Modell vollständig in den VRAM legen. | [ADR-0001](../adr/0001-modellwahl.md) |
| VM-Flucht | Lässt sich nie vollständig ausschließen. Echte Schadsoftware gehört auf einen dedizierten Rechner ohne Anbindung an Produktivnetze. | Restrisiko |

## Regeln für Änderungen

1. Änderungen an VM-Isolation, Gateway-Allowlist oder Audit-Log nur mit ADR und ausdrücklicher Freigabe.
2. Keine neuen Abhängigkeiten ohne Begründung, Lizenzprüfung, Version- und Hash-Pin.
3. Vor jedem Merge ein Security-Review als eigener Schritt (Pfad-Traversal, Injection, Prompt-Injection über Sample-Inhalte, Rechte, Ressourcenlimits, Secret-Leaks).
4. Keine echte Malware beschaffen, öffnen, ausführen oder analysieren. Tests nur mit harmlosen Proben, die im Test selbst erzeugt werden (`tests/corpus/` und `example/samples.py`).
