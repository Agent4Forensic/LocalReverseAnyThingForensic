# ADR-0011: Aufträge im Dashboard löschen, Audit-Log bleibt erhalten

Status: angenommen am 2026-11-01 (Auftrag von Jan: „Aufträge sollen relativ einfach gelöscht werden können“). ADR-0008 hatte einen Löschknopf bewusst ausgelassen; dieses ADR ersetzt diese Stelle.

## Kontext
Jan möchte abgeschlossene Aufträge einfach aus dem Dashboard entfernen. CLAUDE.md, Verbot 3, untersagt Änderungen am Audit-Log ohne ADR und Freigabe. Ein Audit-Log zu vernichten, würde die Chain of Custody des Auftrags beenden.

## Optionen
1. **Alles löschen, auch das Audit-Log:** Das ist verworfen. Danach ließe sich nicht mehr nachweisen, was mit einer Probe geschehen ist.
2. **Nur ausblenden:** Das ist verworfen. Sample und abgeleitete Dateien blieben liegen, und der Speicher würde nicht frei.
3. **Löschen mit Archiv:** Diese Option ist gewählt. Arbeitsdaten werden gelöscht, der Nachweis wird archiviert.

## Entscheidung
1. Löschen ist nur bei eigenen Aufträgen in einem Endzustand möglich (nicht `queued`, `running` oder `uploading`). Importierte Analysen bleiben schreibgeschützt. Die Route verlangt einen Origin-Header aus der Allowlist; das Dashboard fragt vorher nach.
2. Das Audit-Log des Auftrags wird **bytegleich verschoben**, nie gelöscht: Es kommt nach `data/deleted/<Auftrag>-<Zeit>/audit/`, zusammen mit `rows.json`, dem Export aller Datenbankzeilen des Auftrags.
3. Vor dem Löschen der Datenbankzeilen wird ein Nachweis an `data/deleted_jobs.jsonl` angehängt. Er enthält Zeit, Auftrag, Titel, Sample-SHA-256, Grund, SHA-256 der Audit-Datei, Kopf-Hash und Zahl der Audit-Einträge, die Gültigkeit der Kette, SHA-256 von `rows.json` und den SHA-256 der vorherigen Nachweiszeile (Hash-Kette).
4. Danach werden die Datenbankzeilen sowie Sample und abgeleitete Dateien gelöscht. Die Pfade werden aus der geprüften Auftrags-ID neu gebildet; Symlinks werden nie verfolgt.

## Folgen
- **Chain of Custody:** Die Kette eines gelöschten Auftrags bleibt prüfbar (`verify_file` auf das archivierte Audit-Log). Das Sample selbst ist danach weg; sein Hash steht im Nachweis.
- **Speicher:** Speicher wird frei, nur Audit-Log und `rows.json` bleiben.
- **Offen:** Wer das Archiv endgültig vernichten will, tut das außerhalb der Plattform und mit eigener Begründung. Das bleibt Jans Entscheidung.
