# ADR-0007: Iterativer Analyseprozess mit Planer und Lückenrunde

Status: angenommen am 2026-10-31 (Auftrag von Jan). Die Wirkung ist noch nicht gemessen.

## Kontext
Eine Prüfung der Kette ergab, dass sie Aufgaben abarbeitet, aber kaum aus ihren eigenen Ergebnissen weiterarbeitet:
- **Plan:** Der Plan entsteht nur aus dem Rezept. `HelperAgents.split` hat keinen Aufrufer.
- **Abnahme:** Aufgaben haben kein Abnahmekriterium.
- **Selbstbewertung:** `goal_reached` und `gaps` stehen nur im Log und erreichen den Bericht nicht.
- **Hypothesen:** Hypothesen erreichen spätere Aufgaben nicht.
- **Zielfragen:** Eine offene Zielfrage bekommt keinen zweiten Versuch.
- **Synthese:** Die Synthese erzeugt keine Arbeit, auch wenn sie Widersprüche benennt.

## Optionen
1. **So lassen:** Es entstehen keine zusätzlichen Modellaufrufe, aber die genannten Schwächen bleiben.
2. **Planung vollständig durch das Modell ersetzen:** Diese Option ist verworfen. Die lokalen Modelle sind klein, und das Rezept gibt eine verlässliche Mindestabdeckung.
3. **Rezept bleibt Grundlage, das Modell plant ergänzend mit harten Grenzen:** Die Mindestabdeckung bleibt erhalten, und das Modell kann Aufgaben ergänzen, die das Rezept nicht kennt.

## Entscheidung
Option 3 gilt mit diesen Regeln:
1. **Abnahmekriterium:** Jede Aufgabe trägt `done_when` als Parameter (`params_json`). Das Datenbankschema ändert sich dadurch nicht.
2. **Planer:** `agent.split` läuft einmal vor der Synthese oder der ersten Zielfrage und ergänzt höchstens 4 Aufgaben mit der Herkunft `planner`. Ab 75 % des Budgets läuft er nicht mehr.
3. **Lückenrunde:** Der Evaluator bewertet auch die Synthese. Deren Folgeaufgaben werden nicht erneut bewertet, sodass es bei einer Lückenrunde bleibt.
4. **Zielerreichung:** `goal_reached` steht in den Task-Parametern und in einer eigenen Spalte des Berichts.
5. **Lücken:** Lücken werden als Findings mit dem Status `open` ohne Beleg gespeichert, höchstens 12 je Job.
6. **Weitergabe:** Hypothesen und offene Punkte (ohne `GAP:` und `GUARD:`) erreichen spätere Analyseaufgaben, Evaluator und Planer als gekennzeichneter Datenblock. Zielfragen sehen sie nicht, damit kein unbelegter Wert als Antwort erscheint.
7. **Zielfragen:** Eine offene Zielfrage läuft einmal neu, wenn neue bestätigte Findings vorliegen.
8. **Modelltext:** Titel, Ziel, Begründung und `done_when` von Aufgaben, die das Modell formuliert hat, stehen im Prompt als Datenblock und zählen im `TaskGuard` nicht als Aufgabentext. `_injected` verwirft sie schon ab mittlerer Schwere.
9. **Indikatoren:** Ein Indikator in einer `confirmed`-Aussage muss im Zitat stehen, sonst wird sie zur Hypothese. Ein Indikator in einer Antwort muss in einem Beleg des Jobs stehen.

## Folgen
- **Kosten:** Es entstehen mehr Modellaufrufe: ein Planer-Aufruf je Job, ein Evaluator-Aufruf für die Synthese und je Zielfrage höchstens ein zweiter Versuch.
- **Belegpflicht:** `open`-Einträge sind keine Aussagen, sondern offene Punkte. Sie stehen im Bericht nur unter „Offene Fragen und Hypothesen“. `goal_reached` ist eine ungeprüfte Selbstbewertung des Modells und ist im Bericht so bezeichnet.
- **Sicherheit:** Das Aktionsschema wird um ein Textfeld erweitert, die Gateway-Allowlist bleibt unberührt. Ein Sicherheitsreview fand vor dem Commit, dass Modelltext Anweisungsrang hatte und unbelegte Werte als Antwort erscheinen konnten; die Regeln 6, 8 und 9 beheben das.
- **Restrisiko:** Der Datenblock ist eine Kennzeichnung, keine Garantie. Der Scanner erkennt im Hold-out 62,4 % der Angriffe in hoher und 75,3 % ab mittlerer Schwere, bei 4 % Fehlalarmen ab mittlerer Schwere (Hold-out-Lauf vom 2026-10-31). Umformulierter Sample-Text kann ihn passieren, und ein Fehlalarm verwirft eine legitime Folgeaufgabe. Die Bindung aus Regel 9 prüft nur Indikatoren, nicht die Aussage als Ganzes.
- **Prompts:** Das Prompt-Pack steigt auf Version 1.2.0.
- **Offen:** Die Wirkung auf die Trefferquote ist nicht belegt. Sie wird mit den Challenges 01 bis 04 gemessen.
