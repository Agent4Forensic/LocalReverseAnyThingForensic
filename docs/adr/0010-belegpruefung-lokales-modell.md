# ADR-0010: Strengere Belegprüfung und Hilfen für das lokale Modell

Status: angenommen am 2026-11-01 (Auftrag von Jan: „Qualität mit dem vorhandenen lokalen Modell verbessern“). Die Wirkung auf die Trefferquote ist noch nicht gemessen.

## Kontext
Ein größeres Modell oder ein Online-Modell ist auf der vorhandenen Hardware nicht vorgesehen. Die Qualität muss daher aus der Kette kommen, nicht aus dem Modell. Zwei bestätigte Funde des Reviews (F-01, F-02) erlaubten falsche `confirmed`-Befunde:
- **F-01:** `grep` gibt das Suchmuster des Modells in der Kopfzeile zurück. Ein erfundener Wert, nach dem das Modell sucht, stand damit wörtlich in einer Evidence und galt als belegt, auch in Antworten.
- **F-02:** Ein Zitat musste nur 4 Zeichen lang sein (der Prompt verspricht 8) und brauchte keinen Bezug zur Aussage. Eine wahre, aber fremde Zeile konnte jede Behauptung tragen.

Kleine Modelle scheitern außerdem oft am exakten Abschreiben: Ein Zitat weicht in einem Zeichen ab, die Aussage wird verworfen.

## Optionen
1. **Gateway ändert die Ausgabe** (kein Echo des Musters): Das ist verworfen. Ein Echo hilft dem Menschen beim Lesen, und andere Werkzeuge echoen ebenfalls Argumente.
2. **Prüfer filtert den zitierbaren Text:** Diese Option ist gewählt. Sie wirkt für alle Werkzeuge, und die Evidence bleibt unverändert und bytegleich.
3. **Größeres Modell:** Diese Option scheidet aus (Hardware).

## Entscheidung
1. `quotable_text(ev)`: Aus der Kopfzeile einer Evidence werden die Argumente des Aufrufs entfernt (außer `path`): Strings voll und gekürzt, Zahlen dezimal und hexadezimal. Plattformzeilen (`[note] …`, „key … (given) used“) sind nie zitierbar, ebenso eine Evidence, die mit `[tool error]` beginnt. Das gilt für Zitate, für die Prüfung der Antwortwerte und für das Protokoll von Injektionsversuchen.
1a. **Gateway:** String-Argumente dürfen keinen Zeilenumbruch und kein Steuerzeichen enthalten. Sonst könnte ein Muster mit Zeilenumbruch erfundenen Text aus der Kopfzeile in eine zitierbare Zeile schieben (Security-Review vom 2026-11-01). Die Allowlist bleibt unverändert; die Prüfung macht nur die Eingabe strenger.
2. `MIN_QUOTE = 8`, wie im Prompt versprochen.
3. **Bezug:** Ein `confirmed`-Zitat muss mit der Aussage zwei Inhaltswörter teilen (Stoppwörter ausgenommen) oder einen spezifischen Wert, also ein Wort mit Ziffer oder ab 8 Zeichen. Sonst wird die Aussage zur Hypothese herabgestuft.
4. **Reparaturhilfe:** Wird ein Zitat nicht gefunden, schickt der Prüfer die ähnlichste echte Zeile dieser Evidence (difflib, Schwelle 0,55) als `untrusted_data`-Block in die Reparaturrunde. Das Modell kann sie wörtlich übernehmen, wenn sie die Aussage trägt. Bestätigt wird weiterhin nur, was wörtlich in der Evidence steht.
5. **Indikator-Hinweise:** Nach jedem Werkzeugergebnis hängt die Plattform die per festen Mustern gefundenen IOCs (höchstens 8) als `untrusted_data`-Block an. Das Modell muss sie nicht selbst finden und abschreiben. Ein Indikator allein bleibt keine Verhaltensaussage (Prompt-Regel b).

6. **Hex-Ansicht:** Ein Befundzitat wird in einer Datei nur gesucht, wenn sein Beleg genau diese Datei gelesen hat. Treffer heißen „Zitat-Fundstelle“ (Textsuche), nicht Fundort. Die Suche ist begrenzt (200 Zitate, 16 MiB) und wird zwischengespeichert.

## Folgen
- **Strengere Prüfung:** Es gibt weniger falsche `confirmed`-Befunde. Einige bisher bestätigte, unpräzise Aussagen werden zur Hypothese. Zwei bestehende Tests waren genau so formuliert („x“, „The question is answered.“) und wurden an die Regel angepasst.
- **Prompt-Inhalte:** Die Hinweise sind Sample-Text und laufen durch `sanitize_untrusted`. Sie sind in der Größe gedeckelt (1200 Zeichen) und erweitern das Aktionsschema nicht. Die Gateway-Allowlist bleibt unberührt.
- **Grenzen:** Die Bezugsregel ist lexikalisch. Sie prüft, ob Zitat und Aussage über dasselbe sprechen, nicht, ob die Aussage aus dem Zitat folgt. Eine Aussage, die nur in einer anderen Sprache als das Zitat formuliert ist, wird herabgestuft.
- **Reproduzierbarkeit:** Das Prompt-Pack bleibt bei 1.2.1, weil sich nur die Laufzeitnachrichten ändern. Sie stehen vollständig in den gespeicherten Schritten.
- **Offen:** Die Wirkung wird mit den Challenges 01 bis 04 gemessen (Trefferquote und Anteil falsch bestätigter Befunde).
