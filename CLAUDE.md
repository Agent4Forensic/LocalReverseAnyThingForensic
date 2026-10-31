# Projekt sw-analyst – Verhaltensregeln für Claude Code

Sprache: Antworten an Jan auf Deutsch. Code, Bezeichner, Commit-Typen auf Englisch.
Stil: technisch, knapp, effizient (Caveman im Dialog). Dokumentation und Sicherheitshinweise in vollständigen Sätzen.
Quelle der Wahrheit: `PROJEKTPLAN.md`. Aktueller Stand und offene Aufgaben: `docs/STATUS.md` (nach jeder Aufgabe aktualisieren).

## Token-Effizienz (verbindlich)
1. Vor Fragen zur Codebasis zuerst `graphify-out/` (GRAPH_REPORT.md, `graphify query/path/explain`) nutzen, nicht blind Dateien lesen.
2. Nach größeren Änderungen `graphify` aktualisieren (`/graphify . --update`).
3. Auto-Compact ist aktiv (`.claude/settings.json`, Schwelle 70 %). Vor einem Compact `docs/STATUS.md` aktuell halten, damit nichts verloren geht.
4. Parallele Subagenten für unabhängige Aufgaben (Recherche, Audits, Tests). Kurze, präzise Aufträge, Ergebnis als Zusammenfassung.

## Subagenten-Regeln (verbindlich, spart Token)
1. **graphify zuerst.** Jeder Subagent-Prompt beginnt mit: "Lies `graphify-out/GRAPH_REPORT.md`, nutze `graphify query "<Frage>"`, `graphify explain "<Knoten>"` und `graphify path "A" "B"`, bevor du Dateien durchsuchst. Danach gezielt `Read` mit Zeilenbereich." Fehlt `graphify-out/` (lokal erzeugt, nicht im Repo), zuerst `/graphify .` ausführen. Nach größeren Änderungen `/graphify . --update`. **Nachweispflicht:** Die Abgabe jedes Agenten nennt die ausgeführten `graphify`-Abfragen (Befehl und Ergebnis in einem Satz). Fehlt der Nachweis, gilt die Arbeit als nicht abgenommen und der Hauptagent fragt nach. Durchsetzung: PreToolUse-Hook (`.claude/settings.local.json`, lokal, enthält Maschinenpfade und bleibt außerhalb von Git; neu erzeugen mit `graphify claude install` und den Hook-Block nach `settings.local.json` verschieben), Git-Hook `.githooks/post-commit` (aktualisiert den Graphen nach jedem Commit im Hintergrund, nur AST, keine Kosten).
2. **Modell passend wählen.** Suche und mechanische Edits: `cavecrew-investigator` / `cavecrew-builder` oder Haiku/Sonnet. Das stärkste Modell nur für Blueprint, Architektur-Review und Sicherheitsprüfung.
3. **Kurze Aufträge.** Prompt unter ca. 40 Zeilen, auf Dateien verweisen statt Text zu kopieren (`docs/architecture/*.md`, `docs/blueprint/_STYLE.md`). Abgabe höchstens 25 Zeilen: Dateien, Teststand, offene Punkte. Keine Dateiinhalte zurückspiegeln.
4. **Eigene Dateien.** Jeder Agent bekommt eine feste Dateimenge, nie dieselbe Datei wie ein anderer. Parallel nur bei unabhängigen Teilen.
5. **Klein schreiben.** Dateien zuerst anlegen (Gerüst), dann ausbauen, damit ein Abbruch (Limit, Virenscanner) nichts kostet.
6. **Nichts committen im Agenten.** Der Hauptagent committet, pusht und merged.

## Git-Workflow (Remote ab 2026-10-31 freigegeben)
- Remote: `origin` = `https://github.com/Agent4Forensic/LocalReverseAnyThingForensic.git`.
- Branches: `main` (stabil), `feat/core-chain` (Kern, Gateway, Guard, Engine, API), `feat/dashboard` (Frontend), `feat/launcher` (Start/Stop-Skripte), `docs/blueprint` bei Bedarf.
- Push nach jedem abgeschlossenen Baustein und mindestens nach jeder Arbeitsrunde. Vor jedem Push: `git status`, keine Samples, keine Secrets, keine lokalen Pfade (`graphify-out/` ist ignoriert).
- Am Ende alle Feature-Branches per `--no-ff` nach `main` mergen, nach grünen Tests und Security-Review, dann `main` pushen.
- Ein Virenscanner (G Data) hat während der Entwicklung einmal Dateien kurz entfernt; Ausnahme ist eingetragen. Nach Agentenläufen `git ls-files -d` prüfen.

## Entscheidungen von Jan (2026-10-31)
- Isolation: Echte Proben nur in Hyper-V-VM ohne NIC. Darin laufen die Tools in Docker-Containern (`--network none`, read-only, `--cap-drop ALL`, Ressourcenlimits). Entwicklung und Tests mit harmlosen Proben auf Docker/WSL2.
- Ressourcen: Hartes Limit 24 GB RAM für WSL/Docker/Modelle zusammen, Windows behält mindestens 7 GB. GPU (RTX 5060 Ti, 16 GB) wird für Ollama genutzt. Jedes Container hat eigene Speicher- und CPU-Limits.
- REA (`morluto/rea`): nur statische Tools, nur hinter unserem Gateway, nur in Analyse-VM/Container. Kein `npx rea-agents setup`, keine automatische Konfigurationsänderung, Version und Commit gepinnt. Dynamische REA-Funktionen (Programmstart, Netzwerk-Capture) bleiben deaktiviert.
- Dev-Vault: kein mnemo. Markdown-Vault unter `docs/dev-vault/` plus graphify-Graph.

## Absolute Verbote
1. Keine echte Malware beschaffen, herunterladen, öffnen, ausführen oder analysieren. Tests nur mit harmlosen, selbst erzeugten Proben aus `tests/corpus/`.
2. Keine Samples ins Repository, nie. `.gitignore` und Pre-Commit-Hook (`.githooks/pre-commit`) erzwingen das.
3. Keine Änderung an VM-Isolation, Gateway-Allowlist oder Audit-Log ohne ADR und ausdrückliche Freigabe durch Jan.
4. Kein generisches `run_command`, `eval`, `exec` oder `shell=True` im Gateway.
5. Keine neuen Abhängigkeiten ohne Begründung, Lizenzprüfung, Version- und Hash-Pin.
6. Keine Netzwerkzugriffe der Plattform zur Laufzeit.
7. Nicht raten: Unklares, Widersprüchliches oder Sicherheitsrelevantes führt zur Rückfrage an Jan.
8. Fremde Plugins, Skills, MCP-Server und Repositories werden vor der Installation statisch geprüft (Hooks, Netzwerkaufrufe, Nachladen von Binaries) und mit Commit-SHA in `docs/dev-environment.md` festgehalten.

## Arbeitsweise
1. Plan zuerst: Vor jeder Phase kurzer Plan, dann Umsetzung in kleinen Schritten. Erst Konsole/Spike, dann Skript, dann Modul.
2. Test zuerst oder zugleich. Eine Aufgabe ist erst fertig, wenn Tests grün sind und die Abnahmekriterien der Phase erfüllt sind.
3. Eine Entscheidung mit Auswirkung = ein ADR in `docs/adr/` (Kontext, Optionen, Entscheidung, Folgen).
4. Bestätigt vs. offen: In Berichten, Docs und Commits sauber trennen zwischen belegten Fakten, Hypothesen und offenen Fragen.
5. Jede Aussage im Bericht braucht einen Beleg (Evidence-ID). Keine Aussage ohne Beleg.
6. Reproduzierbar: Versionen, Hashes, Seeds und Parameter festhalten.
7. Ponytail-Prinzip: kleinste ausreichende Lösung, aber Sicherheit, Validierung und Tests bleiben immer.
8. Gerichtsfeste Nachvollziehbarkeit hat Vorrang vor Eleganz: Chain-of-Custody, Hashes, Tool-Versionen, Zeitstempel.
9. Vor jedem Merge: Security-Review (Pfad-Traversal, Injection, Prompt-Injection über Sample-Inhalte, Rechte, Ressourcenlimits, Secret-Leaks) als eigener Schritt, getrennt von `/ponytail-review`. Werkzeuge: `/claude-security`, `/security-review`, `engineering:code-review`.
10. Ergebnisse in `docs/` und im Dev-Vault festhalten; am Ende jeder Phase Statusbericht an Jan (erledigt, offen, Risiken).

## Repository-Regeln
- Ein Repository `sw-analyst`, lokal initialisiert mit Git. Remote nur auf ausdrückliche Anweisung von Jan.
- Branches: `main` (immer lauffähig, geschützt), Feature-Branches `feat/<phase>-<thema>`, Fixes `fix/<thema>`.
- Kein direkter Commit auf `main` (Ausnahme: initiales Gerüst). Merge per `--no-ff` nach grünem Testlauf und Security-Review.
- Commits: Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`, `security:`), klein, atomar, signiert, falls ein Signaturschlüssel vorhanden ist.
- Tags am Phasenende: `v0.<phase>.0`.
- Lockfiles und Hashes committen (`requirements.lock` mit `--require-hashes`). Offline-Wheelhouse in `vendor/` (ohne Samples und ohne Modelle).
- Secrets nie im Repo. Pre-Commit: Secret-Scan, Formatter, Linter, Typprüfung.

## Struktur
```
sw-analyst/
├─ CLAUDE.md · PROJEKTPLAN.md
├─ docs/ (adr/, architecture/, security/, runbooks/, dev-vault/, STATUS.md, dev-environment.md)
├─ src/
│  ├─ orchestrator/   Planer, Queue, Prüfer, Abdeckung
│  ├─ gateway/        MCP-Server (läuft in der VM)
│  ├─ recipes/        exe.yaml, apk.yaml, script.yaml
│  ├─ knowledge/      Ingest, Chunking, Index, Lücken-Analyse
│  ├─ vault/          Notiz-Writer (Obsidian-Markdown)
│  ├─ report/         Vorlagen, Evidence, Diagramme, Defanging
│  ├─ webui/          lokale Weboberfläche
│  └─ common/         Logging (hash-verkettet), Konfiguration, Modelle
├─ infra/             Hyper-V-Skripte, VM-Härtung, Docker, Bundle-Build
├─ tests/ (unit/, integration/, security/, corpus/)
└─ vendor/ · pyproject.toml · requirements.lock
```

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- When graphify-out/graph.json exists, run `graphify query "<question>"` before your first grep, search or source-file read for a codebase question, and put this rule in every subagent prompt that explores code. Read raw files only for lines the graph or an earlier read already located. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
- A committed graphify-out/graph.json is rewritten whole on every build, so a large diff to it in a pull request is expected. Do not flag it as churn or suggest skipping the graph rebuild or its hooks.
