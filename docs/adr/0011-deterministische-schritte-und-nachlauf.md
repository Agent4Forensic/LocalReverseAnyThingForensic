# ADR-0011: Deterministische Schritte, strengere Belegprüfung und Nachlauf

Status: umgesetzt auf `fix/job-j0001-findings` (2026-11-01), Anlass ist der Auftrag von Jan, die Probleme aus Job J-0001 zu beheben. Die Nummer 0010 ist für die ADR aus `feat/dashboard-start` reserviert (siehe `docs/STATUS.md`).

## Kontext
Job J-0001 (Beispiel 03) lieferte für Q2 den falschen Wert `BENC-42`. Das Modell hatte die Base64-Zeichenkette im Kopf dekodiert, zitierte sie als Beleg, und die Prüfung bestätigte den Befund, weil das Zitat wörtlich im Beleg stand. Der richtige Wert aus `decode_layer` (`BENCH-42`) wurde herabgestuft. 26 Minuten gingen zu einem großen Teil in wiederholte Dekodierversuche.

## Optionen
1. Nur die Prompts schärfen. Verworfen: Das Modell kann weiter im Kopf rechnen, die Prüfung bliebe blind.
2. Nur die Prüfung verschärfen. Verworfen: Der Wert fiele weg, das Budget ginge weiter in die Dekodierung.
3. Deterministische Schritte vor dem Modell und eine strengere Prüfung danach. Gewählt.

## Entscheidung
- **Deterministische Schritte vor der Modellplanung (nur PE):** `pe_headers`, Dekodieren des Overlays mit `decode_layer` (`auto`, bis zu 3 Schichten), bei vorhandenem Ghidra-Image `list_functions`, `disassemble` und `decompile` der Einstiegsfunktion. Jede abgeleitete Datei bekommt `identify_type`, `hash_file` und `strings_extract`.
- **`decode_layer`:** Eine Kennung wie `CFG:` wird nur übersprungen, wenn dahinter genau ein sauberer Blob steht, und das steht im Beleg. Der Beleg nennt Vorschau, Hex und die Felder eines JSON-Objekts.
- **Plattform-Befunde:** Jedes JSON-Feld wird ein bestätigter Befund mit Zitat aus dem Dekodier-Beleg, nach Prüfung durch den Prompt-Schutz. Eine Zielfrage, die genau ein solches Feld nennt, wird ohne Modell beantwortet.
- **Prüfung:** Ein behaupteter Wert muss in der Ausgabe eines zitierten Werkzeugs stehen. Eine Abwesenheit braucht ein Zitat, das sie zeigt. Die Musterzeile von `grep` zählt nicht als Beleg (F-01). Zitate sind tolerant gegen Leerraum und Escapes; gespeichert wird immer der Text des Werkzeugs, nie der des Modells.
- **Widersprüche:** Zwei Werte zum selben Feld entscheidet der Dekodier-Beleg, die anderen werden `rejected` mit Grund `refuted by …`. Ohne solchen Beleg entsteht ein offener Punkt `CONFLICT:`, und der Auftrag endet höchstens als `partial`.
- **Offene Punkte:** Neue Lücken werden nach Ähnlichkeit zusammengefasst. Beantwortete Lücken, Fragen und Packing-Hypothesen erhalten den neuen Status `closed` mit Grund.
- **Nachlauf:** `python -m sw_analyst --follow-up <Job>` prüft einen beendeten Auftrag ohne Modell neu. Er fügt Belege, Befunde und Aufgaben hinzu; jede Änderung eines Befunds oder einer Antwort ist ein Ereignis in der bestehenden Audit-Kette. Beginn, Ende und Dauer des ursprünglichen Laufs bleiben. Ein zweiter Nachlauf ändert nichts, bei laufender App verweigert er den Start.

Am Audit-Log, an der Gateway-Allowlist und an der VM-Isolation ändert sich nichts: Es entsteht kein neuer Ereignistyp, kein neues Werkzeug, kein neuer Pfad nach außen.

## Folgen
- Bestätigt (Tests in `tests/unit/test_job_findings.py`): Beispiel 03 beantwortet Q2 ohne Modellaufruf mit `BENCH-42`; ein Nachlauf auf der Kopie von J-0001 ergab Status `done`, die Audit-Kette blieb gültig.
- **Die Beispiele messen das Modell nicht mehr vollständig:** Beispiel 03 prüft nun vor allem die Plattform. Messwerte vor und nach dieser ADR sind für diese Frage nicht vergleichbar.
- **Mehr Befunde werden herabgestuft:** Aussagen wie „No network capability hints found“ mit einem Zitat, das die Abwesenheit nicht zeigt, sind nun Hypothesen. Die Wirkung auf echte Modellläufe ist noch nicht gemessen.
- **Heuristiken mit bekannten Grenzen:** Die Erkennung behaupteter Werte verlangt Buchstaben und Ziffern im selben Wort; ein Wert aus reinen Buchstaben bleibt ungeprüft. Die Feld-Zuordnung beruht auf Mustern wie `id=X` oder `id value is X`. Das Schließen offener Punkte beruht auf Wortvergleich und kann einen Punkt zu früh schließen; der Grund steht jeweils beim Punkt und im Bericht.
- **Status `done` nach einem Nachlauf:** Übersprungene Aufgaben blockieren ihn nicht, sie bleiben in der Zusammenfassung genannt. Das folgt dem Auftrag von Jan (`partial` zu fertig), ein Nachlauf ersetzt aber keine übersprungene Analyse.
- Der Import vergleicht den Bericht eines Pakets bytegenau mit dem Neubau. Pakete von vor dieser ADR werden weiter importiert, zeigen aber `report_reproducible: false`, sobald ihr Bericht vom neuen Aufbau abweicht.
- Noch nicht umgesetzt: deterministisches Dekodieren in Skripten und Ressourcen, nur das PE-Overlay ist abgedeckt.
