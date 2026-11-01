# ADR-0012: Expertenprüfung der Analyseschleife (lokales Modell plus Werkzeuge)

Status: umgesetzt auf `fix/job-j0001-findings` (2026-11-01), Anlass ist der Auftrag von Jan, den Algorithmus als Reverse-Engineering-Experte zu prüfen, Fehler zu beheben und Verbesserungen umzusetzen, damit eine Software vollständig und sicher bis zum Ende analysiert und ein ordentlicher forensischer Bericht erzeugt wird. Laufzeit des lokalen Modells ist ausdrücklich kein Kriterium.

## Kontext
Die Schleife (Triage, Rezept, Aufgabenlauf, Prüfer, Selbstbewertung, Zielfragen, Bericht) stand nach ADR-0011. Die Prüfung des Codes fand sieben Stellen, an denen ein lokales Modell Ergebnisse verliert oder falsch ablegt, ohne dass ein Werkzeug fehlt:

1. Deterministisches Dekodieren gab es nur für das PE-Overlay. Skripte und Textdateien (Beispiele 01, 02, 04) mussten vom Modell selbst dekodiert werden, was in J-0001 den Großteil des Budgets kostete.
2. Eine `GAP:`-Aussage des Modells ohne Beleg-ID wurde als „hypothesis without any evidence“ verworfen, obwohl die Systemregel f sie genau so verlangt. Der Reparaturdurchlauf kostete zusätzlich Runden, die Lücke fehlte im Bericht.
3. Eine Zielfrage brauchte einen bestätigten Befund *in derselben Antwort*: Das Modell musste ein Zitat zeichengenau abschreiben. Ein Tippfehler im Zitat machte eine richtige Antwort „unresolved“.
4. Die Hilfsagenten (Bewertung, Priorisierung, Planung) brachen bei abgeschnittener Antwort (Denkanteil über 2000 Token) still ab: keine Bewertung, keine Folgeaufgaben.
5. Bei erschöpftem Budget blieben offene Aufgaben für immer `pending`; der Bericht nannte sie nicht als nicht ausgeführt.
6. Kontextgrenzen (36000 Zeichen, 6000 Zeichen je Werkzeugausgabe, 25 bekannte Befunde, 12 Belege im Index) waren für 16k Kontext fest verdrahtet und wuchsen mit `--num-ctx` nicht mit.
7. Der Bericht nannte abgeleitete Dateien nicht mit eigenem Hash (Testplan C3, bekannter Fehlschlag) und verschwieg verworfene Aussagen des Modells.

## Optionen
1. Nur Prompts schärfen. Verworfen: Punkte 1, 4, 5, 6, 7 liegen in der Plattform, nicht im Modell.
2. Neues Gateway-Werkzeug „encoded_runs“ für Punkt 1. Verworfen: Die Allowlist darf ohne Freigabe nicht wachsen (CLAUDE.md, Verbot 3). `strings_extract` liefert die Fundstellen bereits.
3. Plattform-Schritte und Prüfregeln anpassen, Prompts nur dort ergänzen, wo die Plattform etwas Neues anbietet. Gewählt.

## Entscheidung
- **Deterministisches Dekodieren für Skripte und Text:** Vor dem ersten Modellaufruf ruft die Plattform `strings_extract` (ASCII, mindestens 24 Zeichen) und dekodiert bis zu 4 lange kodierte Läufe (längste zuerst) mit `decode_layer auto`, bis zu 4 Schichten tief. Die Kette läuft auch über gzip/zlib-Zwischenschichten weiter. `strings_extract` zeigt dafür die Länge jeder Zeichenkette; `decode_layer` schneidet nachfolgenden Text derselben Zeile (Anführungszeichen, Kommentar) ab und nennt den genauen Bereich im Beleg. Umbrochene und UTF-16-Blobs bleiben beim Modell.
- **Custody-Befund je abgeleiteter Datei:** Jede Datei aus `decode_layer`, `extract_range` oder `zip_extract` wird ein bestätigter Befund mit Herkunft (Datei, Offset, Länge, Methode), Größe und SHA-256; das Zitat ist die Hash-Zeile des Werkzeugs. Jeder Prompt listet die abgeleiteten Dateien mit Typ.
- **Ghidra:** Zusätzlich zur Einstiegsfunktion werden die 6 größten benannten Funktionen deterministisch dekompiliert, damit Bericht und Modell den Kern des Codes ohne Modellaufruf haben.
- **`GAP:` ohne Beleg wird ein offener Punkt** (`open`), kein verworfener Befund und kein Reparaturgrund; doppelte Lücken werden nicht erneut angelegt.
- **`answer.based_on`:** Eine Antwort darf die IDs bestätigter Befunde des Auftrags nennen. Nur Befunde dieses Auftrags mit Status `confirmed` zählen; die Wertprüfung der Antwort gegen die Belege bleibt.
- **Hilfsagenten:** Antwortbudget 3000 Token; bei `done_reason=length` oder leerer Antwort genau ein Wiederholungsversuch mit 4096 Token, im Schritt vermerkt.
- **Budget-Stopp:** Offene Aufgaben erhalten Status `skipped` mit dem Grund (`skipped: step budget exhausted` usw.).
- **Kontextskalierung:** Die Grenzen des Aufgabenlaufs wachsen linear mit `num_ctx` (Faktor 1 bis 4, Antwortbudget bis Faktor 2). Mehr Runden je Aufgabe (12 statt 10), 60 statt 25 bekannte Befunde, 30 statt 12 Belege im Index, alte Modellantworten werden beim Verdichten gekürzt.
- **Bericht:** Tabelle „Abgeleitete Dateien“ in R2 (Datei, Herkunft, Werkzeug, Bytes, SHA-256, Beleg) und Anhang „verworfene Aussagen des Modells“ mit Grund, klar als Nicht-Ergebnis markiert.
- Prompt-Paket 1.3.0: Regel g (abgeleitete Dateien lesen statt neu dekodieren), Zusatz zu Regel f, Abschnitt „Derived files“, Antwortregel mit `based_on`.

Am Audit-Log, an der Gateway-Allowlist und an der VM-Isolation ändert sich nichts: kein neues Werkzeug, kein neuer Ereignistyp, kein Pfad nach außen.

## Folgen
- Bestätigt mit Tests (`tests/unit/test_expert_review.py`, 19 Tests): Beispiel 02 wird bis zum inneren PowerShell-Skript gepeelt, Beispiel 01 bis zur Flagge, Beispiel 04 bis zur Markierung, jeweils ohne Modell; Testplan C3 (Hash abgeleiteter Dateien im Bericht) besteht jetzt, der `xfail`-Marker ist entfernt.
- Die Beispiele 01, 02 und 04 messen das Modell nun beim Lesen und Belegen, nicht mehr beim Dekodieren. Messwerte vor und nach dieser ADR sind dafür nicht vergleichbar (wie ADR-0011 für Beispiel 03).
- Mehr Werkzeugaufrufe vor dem ersten Modellaufruf (Strings, bis zu 16 Dekodierungen, bis zu 6 Dekompilierungen). Laufzeit ist laut Auftrag kein Kriterium; die Aufrufe zählen als Triage und nicht gegen das Aufgabenbudget, wohl aber gegen das Schrittbudget.
- `strings_extract` hat eine neue Spalte `len`; Verbraucher des alten Formats sind angepasst (`tests/unit/test_dev_gateway.py`).
- Offen: Ressourcen (`pe_resources`) und Archivmitglieder werden nicht deterministisch dekodiert; ein Modelllauf mit dem neuen Stand ist nicht gemessen; `--num-ctx` bleibt bei 16384, weil die VRAM-Belegung durch Desktop-Programme (Blocker B2) Jans Entscheidung ist. Empfehlung: `--num-ctx 32768`, sobald der VRAM frei ist.
