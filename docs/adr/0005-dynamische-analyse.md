# ADR-0005: Dynamische Analyse (Entwurf, wartet auf Freigabe)

Status: vorgeschlagen. Keine Umsetzung vor ausdrücklicher Freigabe durch Jan.

## Kontext
Der Projektplan schließt dynamische Analyse aus (Nicht-Ziel 1, Sicherheitsgrundsatz 3). Jan hat am 2026-10-31 festgehalten, dass die Plattform eine dynamische Analyse braucht. Statische Analyse stößt bei Packern, verschlüsselten Konfigurationen und C2-Protokollen an Grenzen. CLAUDE.md Verbot 3 verlangt für Änderungen an der VM-Isolation ein ADR und Jans Freigabe.

## Optionen
1. **Gar nicht** (Status quo): sicherste Variante, aber Lücken bei Packern und Konfigurationen.
2. **Emulation einzelner Routinen** (Qiling, Unicorn, angr, Ghidra-P-Code-Emulation): Das Sample läuft nie als Prozess, nur Funktionen in einer simulierten CPU. Plan 6.6 sieht das bereits vor, standardmäßig aus.
3. **Kontrollierte Ausführung in der Analyse-VM** (Hyper-V ohne Netzwerkkarte, Snapshot vor und Rollback nach jedem Lauf, simuliertes Netz mit Fake-Diensten, Instrumentierung per Debugger/Frida/Tracing).

## Empfehlung
Stufenweise: zuerst Option 2 (Phase 11), danach Option 3 nur in der Hyper-V-VM, nie auf dem Host und nie in Docker auf dem Host. Jeder Lauf nur per Opt-in mit Begründung im Dashboard, vollständig im Audit-Log, Ergebnisse nur als gehashte Daten (Trace, Speicherabbild), Berichtsregel: dynamisch gewonnene Aussagen tragen niedrigere Konfidenz, bis sie statisch bestätigt sind.

## Anforderungen an Option 3 (Mindestumfang)
- VM ohne Netzwerkkarte oder rein interner Switch ohne Routing, Host-Firewall-Regeln; simulierte Dienste (DNS, HTTP, SMTP) innerhalb der VM.
- Keine Integrationsdienste, keine geteilten Ordner, keine Zwischenablage; Transport nur über Read-only-Images.
- Snapshot vor jedem Lauf, Rollback danach, Zeit- und Ressourcenlimits, Abbruch bei Auffälligkeiten.
- Neue Gateway-Tools mit Allowlist und Schema; weiterhin kein generisches `run_command`.
- Threat-Model-Erweiterung (VM-Flucht, Persistenz im Gast, Netz-Leck) und eigene Isolationstests (Phase 12).

## Folgen
- Plan-Abschnitte 1 (Nicht-Ziele), 2.3 und 6.6 müssen bei Freigabe angepasst werden.
- REA-Live-Funktionen (Frida, ADB, Prozess-Capture) bleiben bis dahin deaktiviert.
- Offene Frage an Jan: Soll zuerst nur Emulation (Option 2) freigegeben werden, oder direkt die VM-Ausführung?
