# ADR-0005: Dynamische Analyse (Entwurf, wartet auf Freigabe)

Status: vorgeschlagen, überarbeitet am 2026-10-31. Keine Umsetzung vor ausdrücklicher Freigabe durch Jan.

## Kontext
Der Projektplan schließt dynamische Analyse aus (Nicht-Ziel 1, Sicherheitsgrundsatz 3). Jan hat am 2026-10-31 festgehalten, dass die Plattform eine dynamische Analyse braucht. Statische Analyse stößt bei Packern, verschlüsselten Konfigurationen und C2-Protokollen an Grenzen. CLAUDE.md Verbot 3 verlangt für Änderungen an der VM-Isolation ein ADR und Jans Freigabe.

Die Kette kennt seit Prompt-Pack 1.1.0 einen einheitlichen Lückenvermerk: `GAP: static analysis could not determine <X>. Would be closed by <dynamic step>; question: <...>; input: <...>.` Damit lässt sich messen, wie oft welche dynamische Stufe überhaupt gebraucht würde, bevor etwas gebaut wird.

## Stufenmodell
Jede Stufe setzt die vorige voraus und wird einzeln freigegeben. Ausführung beginnt erst mit Stufe 3.

| Stufe | Was läuft | Wo | Risiko für den Host | Was das Modell darf |
|---|---|---|---|---|
| 0 Statisch (heute) | eigene Python-Parser, nur Lesen | Host (nur harmlose Proben), später Analyse-VM | Parserfehler im App-Prozess | 13 Werkzeuge der Allowlist |
| 1 Statische Fremdwerkzeuge (ADR-0006) | Ghidra, capa, YARA, FLOSS, jadx | Container (`--network none`), echte Proben nur in der Analyse-VM | Parserfehler im Container | benannte Werkzeuge mit festem Schema |
| 2 Emulation einzelner Routinen | Unicorn: Bytes aus dem Sample in simulierter CPU, ohne Betriebssystem, ohne Prozess | wie Stufe 1 | Fehler im Emulator; keine Ausführung auf echter CPU | `emulate_function(offset, end, input_ref)` mit Budget; Fund ohne Bestätigung `hypothesis` |
| 3 Kontrollierte Ausführung | das Sample als Prozess | eigene Detonations-VM, bevorzugt eigener Rechner | VM-Ausbruch als Restrisiko | nur Antrag über den GAP-Vermerk, kein Start, keine Parameter |

## Empfehlung
1. Stufe 1 und 2 freigeben, sobald die Analyse-VM steht. Emulation deckt die häufigsten Lücken (String- und Konfigurationsentschlüsselung, API-Hashes, einfache Entpackschleifen), ohne dass das Sample jemals als Prozess läuft.
2. Stufe 3 erst entscheiden, wenn die GAP-Statistik aus echten Läufen zeigt, dass Stufe 2 nicht reicht. Dann auf einem eigenen Rechner ohne Anbindung an Produktivnetze, nicht auf dem Entwicklungsrechner (Plan 2.11).

**Sicherheitshinweis:** Auf dem Entwicklungsrechner liegen andere Projekte, Zugangsdaten und ein Docker-Stack. Eine VM-Flucht ist nicht mit Sicherheit auszuschließen. Die Entscheidung, Stufe 3 dort trotzdem zu betreiben, liegt bei Jan und ist dann ausdrücklich als Restrisiko festzuhalten.

## Harte Regeln für Stufe 3
**Isolation**
- Eigene Detonations-VM, getrennt von der statischen Analyse-VM. Windows-Proben brauchen einen Windows-Gast; die im Plan vorgesehene Linux-Analyse-VM reicht dafür nicht.
- Nie auf dem Host und nie in Docker. Container teilen den Kernel mit WSL2 und sind keine Grenze gegen Schadcode. Docker bleibt den statischen Werkzeugen vorbehalten.
- Kein Netzwerkadapter. Falls simulierte Dienste nötig sind: laufen im selben Gast oder in einer zweiten VM an einem **privaten** Hyper-V-Switch. Ein interner Switch ist unzulässig, weil er dem Host eine Netzwerkkarte gibt und ihn damit erreichbar macht. Dies korrigiert die frühere Fassung dieses ADR.
- Keine Integrationsdienste, keine Hyper-V-Sockets, kein Enhanced Session, keine geteilten Ordner, keine Zwischenablage, kein USB.
- Keine GPU in der VM: weder GPU-Partitionierung noch Durchreichen. Das Modell bleibt auf dem Host, die VM sieht die Grafikkarte nie.
- Im Gast keine Zugangsdaten, keine Konten, keine echten Daten.

**Schutz der Hardware**
- VHDX fester Größe auf einem eigenen Datenträger, nicht auf dem Systemlaufwerk; die Größe begrenzt Schreibvolumen und Platzverbrauch.
- Fester RAM ohne dynamischen Speicher, CPU-Obergrenze über `Set-VMProcessor -Maximum`, Laufzeitlimit pro Lauf.
- Der Host schaltet hart ab (`Stop-VM -TurnOff`), der Gast entscheidet das nicht. Danach zwingend Rücksetzen auf den Prüfpunkt und Hash-Abgleich des Prüfpunkts.
- Der `HostGuard` der Plattform pausiert auch diese Läufe bei wenig RAM, wenig Platz oder hoher Temperatur.

**Datenwege**
- Hinein: einmalig angehängtes Read-only-Image, Sample als Daten.
- Heraus: Der Gast schreibt auf ein Export-Image. Der Host hängt dieses Image **nie** ein, denn das Dateisystem darin hat das Sample in der Hand und würde vom Host-Treiber geparst. Eine eigene Bereinigungs-VM liest es offline, erzeugt daraus nur Text und Hashes (Trace, Prozessbaum, Datei- und Registry-Differenz) und schreibt ein neues Image für den Host.
- Binärdaten aus dem Lauf gehen nur in die Analyse-VM zur erneuten Triage, nie zum Host.

**Steuerung durch die KI**
- Das Modell kann keinen Lauf starten. Es schreibt einen GAP-Vermerk; die Oberfläche zeigt ihn als Antrag.
- Jan gibt pro Lauf frei, mit Begründung und festem Profil (Laufzeit, Umgebung). Es gibt keine vom Modell gewählten Parameter und kein generisches `run_command`.
- Freigabe, Start, Abbruch, Rücksetzen und Export stehen im Audit-Log.
- Laufergebnisse gelangen nur über `sanitize_untrusted` in den Prompt. Text aus einem Lauf ist genauso unvertrauenswürdig wie Text aus dem Sample.

**Bericht**
- Eigene Evidence-Felder: Lauf-ID, Prüfpunkt-Hash, Umgebungsprofil, Uhrversatz.
- Dynamische Aussagen bleiben `hypothesis`, bis sie statisch an Code gebunden sind. Negativbefunde gelten nur für Laufzeit und Umgebung des Laufs, weil Proben Analyseumgebungen erkennen können.

## Abnahme vor der ersten echten Probe
Mit einer harmlosen, selbst geschriebenen Testprobe aus `tests/corpus/`, die nur ihre eigene Isolation prüft:
1. DNS, HTTP und der direkte Zugriff auf Host und Router schlagen fehl oder landen in den simulierten Diensten.
2. Host-Pfade, Freigaben und Hyper-V-Sockets sind aus dem Gast nicht erreichbar.
3. Volllaufen der Platte und Speicherfressen bleiben in der VM und der Host bleibt bedienbar.
4. Nach dem Rücksetzen ist die Testdatei weg und der Hash des Prüfpunkts stimmt.
5. Der Host-Timer schaltet einen hängenden Gast ab.

## Folgen
- Plan-Abschnitte 1 (Nicht-Ziele), 2.3 und 6.6 müssen bei Freigabe angepasst werden.
- REA-Live-Funktionen (Frida, ADB, Prozess-Capture) bleiben bis dahin deaktiviert.
- Threat-Model-Erweiterung (VM-Flucht, Persistenz im Gast, Netz-Leck, Export-Image) und eigene Isolationstests (Phase 12).

## Offene Fragen an Jan
1. Stufe 1 und 2 nach Fertigstellung der Analyse-VM freigeben?
2. Stufe 3: eigener Rechner oder Entwicklungsrechner mit dokumentiertem Restrisiko?
3. Android: Für APKs bräuchte Stufe 3 ein eigenes Emulator-Abbild; soll das mitgeplant werden?
