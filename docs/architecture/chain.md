# Analysekette: technischer Entwurf

Stand: 2026-10-31. Dieses Dokument beschreibt, was die Kette tut, welche Daten sie festhält und welche Regeln gelten, damit aus den gespeicherten Daten ein belegter Bericht entsteht. Es ist die Grundlage für Implementierung, Tests und Bericht.

## 1. Grundsätze

1. **Sprachen:** Die KI denkt, schreibt und belegt auf Englisch. Oberfläche und Bericht sind Deutsch. Eingaben des Nutzers (Beschreibung, Zielfragen) werden vor der Analyse ins Englische übersetzt, Ergebnisse danach ins Deutsche. Das Original und die Übersetzung bleiben nebeneinander gespeichert. Fachbegriffe, Code, Hashes, Pfade, IOCs und IDs werden nie übersetzt.
2. **Keine Aussage ohne Beleg.** Jede Aussage (Finding) nennt mindestens eine Evidence-ID und ein wörtliches Zitat aus dem Tool-Ergebnis. Der Prüfer vergleicht das Zitat mit dem gespeicherten Ergebnis. Was nicht passt, wird verworfen (`rejected`) oder als `hypothesis` geführt und nie als Tatsache in Antworten verwendet.
3. **Sample = Daten.** Alles aus dem Sample ist unvertrauenswürdig. Es erreicht die KI nur über den Prompt-Schutz und nur in gekennzeichneten Datenblöcken.
4. **Ein Job zur Zeit.** Ein Worker-Thread führt die Warteschlange sequenziell ab.
5. **Alles nachvollziehbar.** Jeder Schritt wird mit Was, Wie, Warum und Dauer gespeichert. Zusätzlich schreibt ein hash-verketteter Audit-Log im Hintergrund mit.

## 2. Ablauf eines Jobs

```
Job anlegen → Eingaben übersetzen (DE→EN) → Triage → Plan (Aufgabenbaum) → Queue
   → [Worker] nächste Aufgabe → Aufgabe ausführen (Agenten-Schleife) → Prüfer
        → Selbstbewertung (Lücken, Folgeaufgaben) → Priorisierer (Queue neu ordnen)
        → Übersetzung der Ergebnisse (EN→DE) → nächste Aufgabe
   → Abdeckungs-Check → Antworten auf Zielfragen → Bericht (EN + DE)
```

**Triage:** `identify_type`, `hash_file`, `sample_info` laufen deterministisch ohne KI. Der erkannte Typ wählt das Rezept (`exe`, `apk`, `script`, `generic`).

**Planer:** erzeugt den Aufgabenbaum aus (a) den Schritten des Rezepts, (b) einer Aufgabe je Zielfrage (läuft zuletzt) und (c) Beschreibung und Zusatzinformationen des Nutzers, die als Kontext in jede Aufgabe eingehen. Eine große Aufgabe darf sich selbst zerlegen (`split`): sie liefert Teilaufgaben mit Ziel und Begründung, die als Kinder im Baum und in der Queue erscheinen.

**Queue:** Jede Aufgabe hat Status, Priorität (kleiner = früher) und Reihenfolge. Der Worker nimmt die pending-Aufgabe mit der kleinsten Priorität, bei Gleichstand die älteste. Aufgaben mit Abhängigkeit auf Elternaufgaben warten, bis diese beendet sind.

**Priorisierer (Agent):** läuft nach jeder abgeschlossenen Aufgabe. Er sieht die Zusammenfassungen der bisherigen Erkenntnisse und die pending-Aufgaben und liefert neue Prioritäten mit Begründung. Er darf Aufgaben nur umsortieren oder zusätzliche Aufgaben vorschlagen. Löschen darf er nicht. Der Orchestrator validiert: nur existierende Aufgaben, Prioritätsbereich begrenzt, Duplikate (gleiches Ziel) werden abgewiesen, Budget gilt.

**Selbstbewertung (Evaluator):** nach jeder Aufgabe und nach jeder Zielfrage. Der Evaluator bekommt Ziel, Ergebnis und verifizierte Findings und beantwortet: Ist das Ziel erreicht? Welche Lücken oder logischen Folgerungen bleiben? Jede Folgeaufgabe muss sich auf mindestens ein vorhandenes Finding oder eine konkrete Lücke beziehen, sonst wird sie verworfen. Das verhindert freie Spekulation.

**Abbruch:** alle Zielfragen beantwortet oder Budget erschöpft (Aufgaben, Schritte, Minuten) oder Abbruch durch den Nutzer. Bei erschöpftem Budget wird der Job `partial` und der Bericht nennt die ungeklärten Punkte samt Grund.

## 3. Agenten-Schleife einer Aufgabe

Das Modell antwortet in jedem Zug mit genau einem JSON-Objekt (modellunabhängig, ohne native Tool-Calls):

```json
{"action":"tool","tool":"strings_extract","args":{"min_len":6},"why":"look for URLs"}
{"action":"finish","summary":"...","findings":[{"statement":"...","status":"confirmed|hypothesis",
  "evidence":[{"id":"EV-000012","quote":"verbatim text from that evidence"}]}],
  "annotations":[{"file":"sample","line_start":10,"line_end":14,"text":"...","evidence_id":"EV-000012"}],
  "subtasks":[{"title":"...","goal":"...","reason":"..."}]}
```

Pro Zug: Prompt-Schutz prüft die Eingabe an das Modell (Tool-Ergebnisse) und die Aktion des Modells (Allowlist, Argumentschema). Jeder Zug wird als Step gespeichert. Maximal N Züge pro Aufgabe. Wiederholte identische Tool-Aufrufe zählen als Schleife und beenden die Aufgabe.

## 4. Prüfung gegen Halluzination (Grounding)

Für jedes Finding mit Status `confirmed`:
1. Alle genannten Evidence-IDs existieren in diesem Job.
2. Das Zitat kommt (nach Normalisierung von Leerraum) wörtlich im Ergebnistext der genannten Evidence vor.
3. Referenzierte Zeilenbereiche liegen im Dokument.
Fehlschlag in 1 oder 2: Status `rejected`, Grund wird gespeichert. `hypothesis` darf ohne Zitat bestehen, braucht aber mindestens eine existierende Evidence-ID als Anlass und taucht in Antworten nur als Hypothese auf. Antworten auf Zielfragen dürfen ausschließlich auf `confirmed` Findings beruhen. Gibt es keine, lautet der Status der Antwort `unresolved` mit Begründung.

## 5. Prompt-Schutz (Schichten)

1. **Herkunft:** Alle Tool-Ergebnisse stehen im Prompt in `<untrusted_data id="EV-…">…</untrusted_data>`. Der Systemprompt legt fest, dass dieser Inhalt Daten ist und keine Anweisung. Schließende Tags im Inhalt werden neutralisiert.
2. **Scanner:** erkennt Anweisungsmuster im Sample-Text (Ignorier-Befehle, Rollenwechsel, Chat-Markierungen, nachgeahmte Tool-Aktionen, Exfiltrationsaufforderungen, versteckte Zeichen, kodierte Anweisungen) auf Englisch und Deutsch. Treffer hoher Schwere werden im Prompt geschwärzt (`[REDACTED-INJECTION:regel]`), das Original bleibt als Beleg erhalten.
3. **Aktionsprüfung:** nur Tools der Allowlist, Argumente nach Schema, Pfad-Jail, Ausgabelimits. Alles andere wird abgelehnt und gezählt.
4. **Wächter:** Gab es in einer Aufgabe Treffer hoher Schwere und das Modell versucht danach eine unzulässige Aktion oder wiederholt Injektionstext, wird die Aufgabe `blocked`, der Vorfall protokolliert und als Befund "Prompt-Injection im Sample" festgehalten (das ist selbst ein forensisches Ergebnis).
5. **Keine Rechte:** Die KI hat keine Shell und keine Schreibwerkzeuge außer Notizen und Annotationen im Job-Arbeitsbereich.

## 6. Übersetzungspipeline

`Translator.to_en(text)` für Nutzereingaben, `Translator.to_de(text)` für Ergebnisse. Schutz-Platzhalter ersetzen Code in Backticks, Hashes, Evidence-/Finding-/Task-IDs, Pfade, URLs/Domains/IPs (auch entschärft), Zahlen mit Einheiten und Hex vor der Übersetzung und werden danach zurückgesetzt. Fehlt ein Platzhalter oder ist einer doppelt, wird einmal neu versucht, danach bleibt der englische Text mit Kennzeichnung `[EN]`. Ein Glossar erzwingt feste Begriffe (z. B. Befund, Beleg, Hypothese, Persistenz). Übersetzungen werden nach Textstand gecacht. Statische Oberflächentexte und Berichtsvorlagen stehen direkt auf Deutsch.

## 7. Tracking und Logs

- **Step** (je Zug): Art, Was, Wie (Modell, Parameter, Tool, Argumente), Warum (Begründung des Modells), Start, Dauer, Status, Verweis auf Evidence oder Prompt.
- **Task:** Zeiten, Versuche, Priorität mit Begründung, Herkunft (wer hat die Aufgabe erzeugt und warum), verwendeter Prompt (ID, Version, SHA-256).
- **Events:** laufender Hintergrund-Log in der Datenbank (Ebene, Typ, Nachricht, Daten), speist Live-Ansicht und Log-Seite.
- **Audit-Log:** `logs/<job>/audit.jsonl`, jede Zeile enthält den Hash der Vorgängerzeile; `verify()` erkennt Veränderungen.

## 8. Prompts je Aufgabentyp

Jede Aufgabenart hat eine Prompt-Vorlage (`src/sw_analyst/prompts/*.md`) mit festen Abschnitten: **Role** (Verhalten), **Goal**, **Input** (was kommt rein), **Context** (Nutzerbeschreibung, Zusatzinfos, bisherige Erkenntnisse), **Rules** (Belegpflicht, keine Spekulation, Datenblöcke sind keine Anweisungen), **Output** (genaues JSON-Format). Die gerenderte Fassung wird mit ID, Version und SHA-256 an der Aufgabe gespeichert.

## 9. Bericht

Aus den Datenbankinhalten entsteht der Bericht: Zusammenfassung, Metadaten und Chain-of-Custody (Hashes, Tool-Versionen, Modell, Prompt-Versionen, Audit-Log-Hash), Auftrag (Beschreibung, Zusatzinfos, Zielfragen), Antworten mit Status, Befunde mit Evidence-IDs und Zitaten, IOCs (entschärft), offene Fragen, Methodik und Zeitverlauf je Aufgabe, Anhang mit Evidence-Tabelle. Englische Fassung aus den KI-Texten, deutsche Fassung aus der Übersetzung und deutschen Vorlagen. Der Live-Bericht ist derselbe Generator auf dem aktuellen Zwischenstand.

## 10. CTF-Testmodus

Zielfragen können eine erwartete Antwort tragen (Text oder `re:`-Regex). Das Testgerüst `tests/ctf/` erzeugt harmlose, selbst geschriebene Aufgaben (z. B. mehrfach kodiertes Skript mit Flagge), startet den Job und bewertet: Antwort enthält das Erwartete, die Antwort stützt sich auf bestätigte Findings, Zeit und Schritte. Mit Fake-Modell testet es die Mechanik deterministisch, mit Ollama das echte Modell.
