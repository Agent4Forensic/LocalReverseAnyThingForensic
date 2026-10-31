# Projekt sw-analyst – Verhaltensregeln für Claude Code

Sprache: Antworten an Jan auf Deutsch. Code, Bezeichner, Commit-Typen auf Englisch.
Stil: technisch, knapp, effizient (Caveman im Dialog). Dokumentation und Sicherheitshinweise in vollständigen Sätzen.
Quelle der Wahrheit: `PROJEKTPLAN.md`. Aktueller Stand und offene Aufgaben: `docs/STATUS.md` (nach jeder Aufgabe aktualisieren).

## Token-Effizienz (verbindlich)
1. Vor Fragen zur Codebasis zuerst `graphify-out/` (GRAPH_REPORT.md, `graphify query/path/explain`) nutzen, nicht blind Dateien lesen.
2. Nach größeren Änderungen `graphify` aktualisieren (`/graphify . --update`).
3. Auto-Compact ist aktiv (`.claude/settings.json`, Schwelle 70 %). Vor einem Compact `docs/STATUS.md` aktuell halten, damit nichts verloren geht.
4. Parallele Subagenten für unabhängige Aufgaben (Recherche, Audits, Tests). Kurze, präzise Aufträge, Ergebnis als Zusammenfassung.

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
