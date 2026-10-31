# Dokumentation: Forensic Reverse Engineering Plattform

Dieses Verzeichnis beschreibt die Plattform, ihre Entscheidungen und ihren Betrieb. Das Repository heißt weiterhin `sw-analyst`, das Python-Paket `sw_analyst`. Die Plattform analysiert unbekannte Software (Windows-EXE, Android-APK, Skripte) **ausschließlich statisch**: Sie startet eine Probe nie, sie liest nur ihre Bytes. Jede Aussage im Bericht verweist auf eine Evidence-ID und ein wörtliches Zitat, das der Prüfer gegen das gespeicherte Werkzeugergebnis vergleicht.

## Wo steht was

| Ich möchte … | Dokument |
|---|---|
| verstehen, wozu die Plattform da ist und was sie nicht tut | [`../PROJEKTPLAN.md`](../PROJEKTPLAN.md) (Quelle der Wahrheit), [`../README.md`](../README.md) |
| starten, stoppen, Fehler beheben | [`runbooks/betrieb.md`](runbooks/betrieb.md) |
| einen Beispielfall laufen lassen und automatisch prüfen | [`../example/README.md`](../example/README.md) |
| den Ablauf als Bild sehen | [`architecture/workflows.md`](architecture/workflows.md), [`roadmap.html`](roadmap.html) (Workflow, Werkzeuge, Stand) |
| die Analysekette im Detail verstehen | [`architecture/chain.md`](architecture/chain.md) |
| die Web-API nutzen oder das Frontend ändern | [`architecture/api.md`](architecture/api.md), [`architecture/dashboard-v2.md`](architecture/dashboard-v2.md) |
| wissen, wie die Plattform geschützt ist | [`security/sicherheitsmodell.md`](security/sicherheitsmodell.md) |
| die Methodik der Analyse nachlesen (Phasen, Werkzeugwahl, Berichte) | [`blueprint/00-index.md`](blueprint/00-index.md) |
| prüfen, was getestet wird und was nicht | [`testing/forensic-test-plan.md`](testing/forensic-test-plan.md) |
| nachvollziehen, warum etwas so entschieden wurde | [`adr/`](adr/) |
| den aktuellen Stand und offene Aufgaben sehen | [`STATUS.md`](STATUS.md) |
| wissen, welche Komponenten geprüft und gepinnt sind | [`dev-environment.md`](dev-environment.md) |
| Modelle bewerten oder wechseln | [`review/model-evaluation.md`](review/model-evaluation.md) |

## Kurzüberblick

Eine Datei geht durch diese Kette: Triage (Typ und Hashes, ohne KI) → Rezept (`exe`, `apk`, `script`, `generic`) → Aufgaben-Queue → Task-Runner (das lokale Modell wählt in jedem Zug genau ein Werkzeug) → Guard (Prompt-Schutz) → Gateway (Allowlist, Pfad-Jail) → Prüfer → Bewerter und Priorisierer → Antworten auf die Zielfragen → Bericht mit entschärften IOCs. Der Ablauf ist in [`architecture/workflows.md`](architecture/workflows.md) in vier Diagrammen dargestellt.

Das Modell läuft lokal über Ollama (Loopback, Port 11435). Die Plattform greift zur Laufzeit nie auf das Netzwerk zu.

## Entscheidungen im Überblick

| ADR | Inhalt | Stand |
|---|---|---|
| [0000](adr/0000-grundentscheidungen.md) | Isolation (Hyper-V-VM mit Docker darin), Ressourcenlimit 24 GB, REA nur statisch, Dev-Vault ohne mnemo | akzeptiert |
| [0001](adr/0001-modellwahl.md) | Lokales Modell, Ollama nativ unter Windows, Modellstufen nach freiem VRAM | Entwurf, Benchmark läuft |
| [0003](adr/0003-stack-und-paketstruktur.md) | Python 3.11, FastAPI, SQLite, hash-verketteter Audit-Log, JSON-Aktionsprotokoll | akzeptiert für die Entwicklung |
| [0005](adr/0005-dynamische-analyse.md) | Dynamische Analyse (Stufenmodell) | Entwurf, nicht aktiv, braucht Freigabe |
| [0006](adr/0006-statische-werkzeuge-allowlist.md) | Erweiterung der Werkzeug-Allowlist (Disassembler, Android-Werkzeuge) | vorgeschlagen, wartet auf Freigabe |

Änderungen an Isolation, Gateway-Allowlist oder Audit-Log erfordern ein neues ADR und die ausdrückliche Freigabe des Projektinhabers.

## Begriffe

- **Evidence:** gespeichertes Ergebnis eines Werkzeugaufrufs mit ID (`EV-000123`) und SHA-256 des Ergebnistexts.
- **Finding:** Aussage des Modells mit Status `confirmed` (Zitat wörtlich in der Evidence gefunden), `hypothesis` (Beleg vorhanden, Schluss ungeprüft) oder `rejected` (mit Grund).
- **Rezept:** YAML-Datei mit den Analyseschritten je Dateityp (`src/sw_analyst/recipes/`).
- **Gateway:** einzige Stelle, an der Werkzeuge laufen. Feste Allowlist, validierte Argumente, Pfad-Jail, Größen- und Zeitlimits.
- **Guard:** Prompt-Schutz. Schwärzt Anweisungsmuster aus dem Sample, prüft jede Modellaktion und hält Vorfälle fest.
- **Job-Status:** `done` (alles beantwortet), `partial` (Lücken oder Budget erschöpft, mit Grund), `failed` (keine Analyseaufgabe fertig), `cancelled`.

## Regeln für diese Dokumentation

1. Belegtes, Hypothesen und Offenes werden getrennt benannt. Was nur geplant ist, steht als geplant da.
2. Nach jeder Arbeitsrunde werden [`STATUS.md`](STATUS.md) und die Daten im Skript von [`roadmap.html`](roadmap.html) gemeinsam aktualisiert.
3. Eine Entscheidung mit Auswirkung bekommt ein ADR (Kontext, Optionen, Entscheidung, Folgen).
4. Keine Proben, keine Secrets und keine lokalen Pfade in Dokumenten.
