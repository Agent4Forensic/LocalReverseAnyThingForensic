# ADR-0006: Dashboard mit sauberen URLs, Beispielauswahl und automatischem Budget

Status: umgesetzt auf `feat/dashboard-start`, Datum 2026-10-31.

## Kontext
Jan hat drei Änderungen am Dashboard verlangt. Die Adresse `http://127.0.0.1:8765/#/` mit Fragment ist unschön. Die Übersicht soll den aktuellen Auftrag samt Kennzahlen zeigen und, wenn keiner läuft, das Anlegen eines Auftrags anbieten. Die Maske „Neuer Auftrag“ soll kein Budget abfragen („wie lange es dauert ist egal, das Ergebnis entscheidet“) und Beispiele aus `example/` vorausgefüllt anbieten, von denen genau eines gewählt wird.

## Optionen
1. **URLs:** (a) Fragment-Routing behalten, (b) Pfad-Routing mit History API und Fallback auf `index.html`.
2. **Beispiele:** (a) Beispiele im Frontend fest einbauen, (b) der Server liest `example/challenges/*/challenge.json` und erzeugt die Beispieldatei aus `example/samples.py` im Speicher.
3. **Budget:** (a) Felder im Formular lassen, (b) Server setzt die Obergrenzen selbst, das Formular sendet kein Budget.

## Entscheidung
- Pfad-Routing: `/`, `/new`, `/prompts`, `/job/<id>/<tab>`. Der Server liefert für Pfade ohne Dateiendung außerhalb von `/api/` die `index.html` aus. Alte Links mit `#/` werden im Browser umgeschrieben.
- Beispiele: `GET /api/examples` liefert Titel, Stufe, Beschreibung, Beispieldatei, englische Auftragsbeschreibung und Zielfragen. Flagge, Ziel und Testnotizen verlassen den Server nicht. `POST /api/jobs` nimmt statt `sample` ein Feld `example` (ID aus dieser Liste, keine freie Pfadangabe). Die Beispieldatei entsteht im Speicher und wird nie ausgeführt. Eine eigene Datei bleibt als zweiter Weg erhalten.
- Budget: Die Standardwerte des Dashboards sind die Obergrenzen (300 Aufgaben, 5000 Schritte, 1440 Minuten). Die Maske zeigt kein Budget mehr. Die API akzeptiert die Felder weiter.

## Folgen
- Die erwartete Antwort wird bei Beispielen wie in `example/run_eval.py` nicht mitgegeben, damit die Berichtsprüfung nicht ohne Analyse besteht.
- Ein Auftrag kann bis zu 24 Stunden laufen und belegt in der Zeit Worker und Modell. Abbrechen bleibt über `POST /api/jobs/{id}/cancel` möglich.
- Das Laden von `example/samples.py` führt Repository-eigenen Code beim Start aus. Fehlt der Ordner oder ist er fehlerhaft, bleibt die Beispielliste leer und die App startet normal.
- Die Reserve-Logik der Engine (ab 75 % des Budgets nur noch Zielfragen) greift bei den hohen Obergrenzen praktisch nicht mehr; die Aufgabenobergrenze begrenzt weiter.
- Nicht berührt: VM-Isolation, Gateway-Allowlist, Audit-Log.
