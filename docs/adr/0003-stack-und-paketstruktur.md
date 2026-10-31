# ADR-0003: Stack und Paketstruktur (Entwurf, in Umsetzung)

Status: akzeptiert für die Entwicklungsphase, Überprüfung zum Abschluss von Phase 1.

## Kontext
Die Analysekette muss auf dem Host offline laufen, nachvollziehbar und testbar sein. Der Projektplan nennt Python für den Orchestrator. Das Plattform-Gateway läuft später in der VM. Bis dahin braucht die Entwicklung ein sicheres Ersatz-Gateway mit rein lesenden, rein statischen Werkzeugen.

## Entscheidung
- **Sprache:** Python 3.11. Alle Pakete liegen unter `src/sw_analyst/` (Namensraum, vermeidet Kollisionen mit generischen Paketnamen wie `common`). Das ersetzt die Verzeichnisaufteilung `src/<modul>/` aus dem Projektplan, die Zuordnung der Module bleibt gleich.
- **Laufzeit-Abhängigkeiten (gepinnt mit Hashes in `requirements.lock`):** `fastapi` und `uvicorn` für die lokale Web-API mit Server-Sent-Events, `pyyaml` für Rezepte. `pydantic` kommt mit FastAPI. Alles andere ist Standardbibliothek (`sqlite3`, `urllib`, `hashlib`, `threading`).
- **Test-Abhängigkeiten (`requirements-dev.lock`):** `pytest`, `httpx`.
- **Persistenz:** SQLite im WAL-Modus, ein Schreibzugriff über eine Verbindung pro Thread, plus ein hash-verketteter Audit-Log als JSON-Lines-Datei je Job.
- **LLM-Anbindung:** Ollama-HTTP-API (`/api/chat`) über `urllib`, hinter der Schnittstelle `LLMClient`. Die Agenten-Schritte verwenden ein modellunabhängiges JSON-Aktionsprotokoll statt der nativen Tool-Call-Funktion der Modelle (siehe `docs/architecture/chain.md`). Tests laufen mit einem skriptbaren Fake-Client, ohne Modell.
- **Frontend:** statische Dateien ohne Build-Schritt und ohne externe Ressourcen (kein CDN, keine Webfonts), ausgeliefert vom FastAPI-Server auf `127.0.0.1`.
- **Gateway in der Entwicklung:** `DevGateway` mit rein lesenden Python-Werkzeugen auf Bytes, Pfad-Jail, Größen- und Zeitlimits. Es startet nie ein Sample. In Phase 1 wird dahinter das echte VM-Gateway gesteckt, die Schnittstelle `ToolGateway` bleibt gleich.

## Folgen
- Neue Abhängigkeiten brauchen Begründung, Lizenzprüfung und Hash-Pin (CLAUDE.md, Verbot 5).
- Ein einziger Worker-Thread führt Jobs sequenziell aus. Das erfüllt die Vorgabe "ein Job zur Zeit" und schützt die GPU.
- Das JSON-Aktionsprotokoll macht jeden Schritt als Datensatz speicherbar (was, wie, warum, Dauer) und unabhängig vom gewählten Modell.
