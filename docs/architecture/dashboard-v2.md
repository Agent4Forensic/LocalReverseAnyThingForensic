# Dashboard V2: Live-Aktivität, Assembler-Lernpfad, Diagramme, Start/Stop

Ergänzung zu `api.md` und `chain.md` (Wunsch von Jan, 2026-10-31). Status: Spezifikation, Backend teilweise offen (siehe `docs/STATUS.md`).

## 1. Was macht die KI gerade (Aktivitätsanzeige)
`GET /api/jobs/{id}/activity` →
`{"state":"idle|working|finished","phase":"triage|planning|analysis|evaluation|prioritization|translation|finalizing","task":{id,title,goal,origin,started_at,elapsed_ms}|null,"step":{id,kind,what,how,why,tool,started_at,elapsed_ms,input_preview}|null,"model":{name,tokens_in,tokens_out},"recent":[{ts,kind,what,status,duration_ms}],"queue_length":int,"next":[{task_id,title}]}`.
Das Dashboard zeigt oben dauerhaft: Phase, aktuelle Aufgabe mit Ziel, aktueller Schritt mit Was/Wie/Warum und laufender Zeit, die nächsten drei Aufgaben, letzte zehn Schritte. Aktualisierung über SSE (`step`/`task`), Neuladen der Seite stellt den Zustand über diesen Endpunkt wieder her.

## 2. Funktionen und Assembler-Lernpfad
Quelle: Tool-Ergebnisse (Disassembly/Dekompilat) werden als Dateien (`derived/…`) mit Zeilennummern gespeichert. Die KI liefert im `finish`-Ergebnis optionale Felder `functions` und `walkthroughs` (Schema unten), die der Prüfer gegen Evidence und Zeilenbereiche validiert (Zeilen müssen existieren, Evidence muss zum Job gehören).
- `GET /api/jobs/{id}/functions` → `[{id,name,address,file,line_start,line_end,role,summary_en,summary_de,finding_ids:[…]}]`
- `GET /api/jobs/{id}/walkthroughs` → `[{id,function_id|null,title_en,title_de,summary_en,summary_de,steps:[{n,file,line_start,line_end,address,title_en,title_de,explanation_en,explanation_de,evidence_id|null,finding_id|null}]}]`
Frontend: Code-Viewer mit Modus "Lernpfad": links Schrittliste (Ablaufplan einer Funktion), rechts Code. Klick auf einen Schritt oder "Weiter/Zurück" springt zur Zeile (`line_start`), hebt `line_start..line_end` hervor und zeigt die Erklärung (was passiert, warum, Bedeutung der Befehle/Register in einfachen Worten) als Randnotiz. Funktionsliste mit Rolle (Entry, Decoder, Netzwerk, Krypto, Persistenz …) und Sprung zur Funktion. Assembler-Erklärungen sind Annotationen mit Evidence, keine freie Spekulation.

## 3. Diagramme
`GET /api/jobs/{id}/diagrams` → `[{id,kind:"flow|callgraph|dataflow|timeline|architecture|attack_chain",title_en,title_de,graph:{nodes:[{id,label_en,label_de,type,ref:{file,line}|null,finding_id|null}],edges:[{from,to,label_en,label_de}]},finding_ids:[…]}]`.
Das Frontend rendert `graph` selbst als SVG (eigenes geschichtetes Layout, keine Fremdbibliothek, keine CDN). Knoten mit `ref` springen in den Code-Viewer. Der Berichtsgenerator erzeugt aus demselben `graph` Mermaid-Quelltext. Erzeugung: deterministisch aus gespeicherten Daten (Aufgabenbaum, Zeitverlauf, Aufrufbeziehungen aus Evidence) plus KI-Vorschläge, die nur Knoten/Kanten mit Beleg enthalten dürfen.

## 4. Start/Stop und Preflight
- `scripts\start.ps1` und `scripts\stop.ps1` steuern alles. Start: Preflight-Check, fehlende Teile aus den gepinnten Lockfiles/Manifesten nachinstallieren, Ollama starten, Modell prüfen, Anwendung starten, URL ausgeben. Stop: Anwendung und Ollama sauber beenden.
- Terminalausgabe: je Zeile `[HH:mm:ss] [STAGE] Meldung` (Stufen: CHECK, INSTALL, UPDATE, OLLAMA, MODEL, APP, WORKER, JOB, GUARD, STOP).
- Installation und Updates nur aus gepinnten Quellen mit Hash-Prüfung (CLAUDE.md Verbot 5). Neuere Versionen werden gemeldet, aber erst nach Pin-Update im Manifest eingespielt.
