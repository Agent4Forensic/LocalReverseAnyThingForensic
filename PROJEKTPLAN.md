# Projektplan: Offline-KI zur statischen Reverse-Engineering-Analyse von Software

Stand: 2026-10-31 · Auftraggeber: Jan · Ausführung: Claude Code
Arbeitstitel: `sw-analyst`

Hinweis: Dies ist der Originalplan von Jan. Spätere Entscheidungen, die vom Plan abweichen oder ihn präzisieren, stehen in `CLAUDE.md` (Abschnitt "Entscheidungen von Jan") und in `docs/adr/`.

---

## 1. Ziel

Eine lokal laufende KI-Plattform, die eine unbekannte Datei (Windows-EXE, Android-APK, Skript) entgegennimmt, **ohne sie auszuführen** vollständig reverse-engineert und einen vollständigen, belegten Bericht mit Diagrammen schreibt. Der Ablauf ist automatisch: Dateityp erkennen, passendes Rezept laden, Aufgaben zerlegen, abarbeiten, Abdeckung prüfen, Lücken nachziehen, Bericht erzeugen.

Zielproben ausdrücklich inklusive Schadsoftware bis hin zu Ransomware. Deshalb gilt: Sicherheit und Korrektheit vor Komfort und Geschwindigkeit.

### Muss-Anforderungen

- Vollständig offline lauffähig (air-gapped Windows-Host).
- Lokale KI mit Reasoning (Thinking-Modus), Ziel-GPU: NVIDIA RTX 5060 Ti, 16 GB.
- Große Aufgabe wird automatisch in Teilaufgaben zerlegt, bis alles erledigt ist.
- Web-Interface: Datei übergeben, Fokus-Vorgaben und Pflichtfragen angeben, Live-Status sehen, Wissen hinterlegen, Bericht abrufen.
- Wissensdatenbank (Bücher, Doku, Notizen; Ablage und Suche lokal) zur Verbesserung der KI.
- Obsidian-Vault: automatische Dokumentation aller Erkenntnisse und Schritte.
- Isolierte VM: Alles, was mit dem Sample in Berührung kommt, passiert nur dort. Die KI hat ausschließlich über ein Tool-Gateway (MCP) Zugriff darauf.
- Abschlussbericht mit Diagrammen; Pflichtfragen werden garantiert beantwortet, dann wird Stück für Stück erweitert.
- Rezepte pro Dateityp (EXE, APK, Skript).
- Emulation optional, standardmäßig aus, mit zusätzlichen Sicherheitsgrenzen.

### Nicht-Ziele

- Keine dynamische Analyse: Das Sample wird nie als Prozess gestartet.
- Keine Internetverbindung der Analyse-Umgebung.
- Keine Exploit-Entwicklung, keine Weiterverbreitung.

---

## 2. Sicherheitsgrundsätze (hart, nicht verhandelbar)

1. **Zwei Welten.** Entwicklungsrechner (online, hier arbeitet Claude Code) und Analyse-Umgebung (offline, hier landen echte Samples) sind getrennt. Echte Malware berührt nie den Entwicklungsrechner und nie Claude Code.
2. **Claude Code baut nur die Plattform.** Getestet wird ausschließlich mit harmlosen, selbst erzeugten Testproben (Abschnitt 11). Claude Code lädt keine Malware herunter, beschafft keine und analysiert keine.
3. **Sample = Daten, nie Code.** Das Sample liegt in der VM als nicht ausführbare, schreibgeschützte Datei (`.bin`, `noexec`-Mount, Hash-geprüft). Kein Tool im Gateway startet es.
4. **Prompt-Injection ist ein reales Risiko.** Strings, Kommentare und Ressourcen im Sample können Anweisungen an die KI enthalten. Alles, was aus dem Sample stammt, ist unvertrauenswürdige Eingabe: klar abgegrenzt in den Prompt einbetten, nie als Anweisung behandeln. Die KI hat keine Shell und keine Schreibtools außer Notizen und Berichtsentwurf.
5. **Gateway statt Shell.** Der MCP-Server bietet nur eine Allowlist fester Tools mit validierten Argumenten, Pfad-Jail, Ressourcenlimits und Timeouts. Kein generisches `run_command`.
6. **Netz-Isolation.** VM ohne Netzwerkkarte. Kommunikation Host zu VM nur über Hyper-V-Sockets (AF_HYPERV / vsock). Fallback: rein interner Switch ohne Routing und ohne Internet, mit Host-Firewall-Regeln. Entscheidung per ADR nach einem Spike (Abschnitt 12).
7. **Keine Komfort-Brücken.** Integrationsdienste, Zwischenablage, Enhanced Session, Shared Folders und Drag-and-Drop sind deaktiviert. Datentransport nur in definierter Richtung über Read-only-Images (VHDX/ISO).
8. **Wegwerf-Umgebung.** Checkpoint vor jedem Job, Rollback nach jedem Job. Analyse-Ergebnisse werden über ein bereinigtes Export-Image entnommen.
9. **Defanging.** Im Bericht stehen IOCs, URLs, Domains und IPs entschärft (z. B. `hxxp://`, `[.]`). Ausführbare Payloads werden nie als Klartext oder Base64 in den Bericht kopiert.
10. **Audit-Log.** Jeder Tool-Aufruf wird mit Zeitstempel, Parametern, Ergebnis-Hash und Tool-Version in ein manipulationssicheres (hash-verkettetes) Log geschrieben.
11. **Restrisiko offen benennen.** Eine VM-Flucht lässt sich nicht mit absoluter Sicherheit ausschließen. Deshalb Defense in Depth und die dringende Empfehlung, die Analyse auf einem dedizierten Rechner ohne Anbindung an Produktivnetze zu betreiben.
12. **Lieferkette.** Alle Abhängigkeiten, Plugins und Tool-Bundles werden version- und hash-gepinnt. Der Import in die Offline-Umgebung erfolgt über ein signiertes bzw. hash-geprüftes Bundle.

---

## 3. Architektur

```
Host (Windows, offline)
├─ Web-UI (lokal)               Upload, Fokus, Pflichtfragen, Status, Wissen, Bericht
├─ Orchestrator (Python)        Planer, Aufgaben-Queue, Prüfer, Abdeckungs-Check
├─ Lokale KI (Ollama/llama.cpp) Reasoning-Modell + Embedding-Modell (GPU)
├─ Wissensdatenbank             Bücher/Doku, Chunking, Vektor- und Volltextsuche
├─ Obsidian-Vault (Markdown)    automatische Erkenntnisse und Protokolle
├─ Berichtsgenerator            Text + Diagramme (Mermaid, offline gerendert)
└─ Hyper-V
   └─ Analyse-VM (Linux, ohne NIC)
      ├─ MCP-Tool-Gateway       einziges Tor zur VM
      ├─ Statische Tools        Ghidra headless, jadx, apktool, capa, YARA, FLOSS, radare2, binwalk, ...
      ├─ Skript-Dekoder         eigene Deobfuskations-Routinen
      └─ Emulation (optional)   Qiling / Unicorn / angr, nur per Opt-in
```

Hinweis zur Platzierung: Die KI läuft auf dem Host (GPU). Das Sample selbst verlässt die VM nie. Die KI sieht nur Text-Ergebnisse der Tools (Disassembly, Dekompilat, Strings, Metadaten), angefordert über das Gateway.

---

## 4. Plugins und Skills vor der Umsetzung installieren

Installation nur auf dem **Entwicklungsrechner** (online), nie in der Analyse-VM. Vor der Installation jeweils Repository, Hooks und Skripte kurz prüfen und die verwendete Version bzw. den Commit in `docs/dev-environment.md` festhalten.

| Plugin | Zweck | Installation |
|---|---|---|
| Caveman (inkl. cavecrew) von JuliusBrussee | Knappe Arbeitskommunikation, spart Output-Tokens | `claude plugin marketplace add JuliusBrussee/caveman`, dann `claude plugin install caveman@caveman` |
| Ponytail von DietrichGebert | YAGNI: nur den Code schreiben, den die Aufgabe braucht | `/plugin marketplace add DietrichGebert/ponytail`, danach als **separate** Eingabe `/plugin install ponytail@ponytail` (Node.js im PATH nötig) |
| mnemo (xyrlan/mnemo) | Obsidian-Vault, der sich aus den Claude-Code-Sitzungen selbst füllt (lokale Knowledge Base) | `pipx install mnemo-claude`, dann `mnemo init --project`; optional `/plugin marketplace add xyrlan/mnemo` und `/plugin install mnemo@mnemo-marketplace` |

Annahme zum Obsidian-Plugin: Du hast kein konkretes Plugin genannt. mnemo passt am besten zu "speichert direkt und baut lokal eine Knowledge Base auf". Alternativen: `AgriciDaniel/claude-obsidian` (wiki-artiger Vault mit Skills) oder `guhcostan/claude-mega-brain` (lädt Projektwissen automatisch in jede Sitzung). Wenn du ein anderes meinst, hier ersetzen.

(Entscheidung 2026-10-31: mnemo wird nicht installiert, siehe CLAUDE.md.)

Regeln für die Plugins:

- **Caveman** gilt für Arbeitsdialog und Statusmeldungen. **Nicht** für: Code-Kommentare, Dokumentation, ADRs, Berichtsvorlagen, Sicherheitswarnungen, Commit-Beschreibungen. Dort volle, eindeutige Sätze.
- **Ponytail** darf nie Validierung, Fehlerbehandlung, Logging, Sicherheitsprüfungen oder Tests wegsparen. Es ist ein Werkzeug gegen Überengineering, kein Argument gegen Härtung. `/ponytail-review` deckt Korrektheit, Sicherheit und Performance nicht ab. Dafür läuft zusätzlich ein eigener Security-Review (CLAUDE.md, Arbeitsweise 9).
- **mnemo/Vault:** Der Entwicklungs-Vault (Claude-Code-Sitzungen) und der Analyse-Vault (Erkenntnisse zu Samples) sind getrennte Verzeichnisse. In den Analyse-Vault schreibt nur die Plattform.
- Wenn ein Plugin nicht installierbar ist oder Hooks Netzwerkzugriffe machen, die nicht nachvollziehbar sind: Abbruch und Rückfrage, nicht umgehen.

---

## 5. CLAUDE.md-Block

Siehe `CLAUDE.md` im Repo-Root (enthält den Block des Originalplans, ergänzt um die Entscheidungen vom 2026-10-31).

---

## 6. Komponenten im Detail

### 6.1 Analyse-VM und Tool-Bundle

- Linux-Gast unter Hyper-V, keine NIC, alle Integrationsdienste außer dem für Sockets nötigen aus, kein Enhanced Session.
- Tool-Bundle wird auf dem Online-Rechner gebaut: Ghidra (headless, mit Java), jadx, apktool, capa (+ Regeln), YARA (+ Regeln), FLOSS, radare2, binwalk, `file`, `exiftool`, Python-Umgebung mit Parsern (pefile, lief, androguard o. ä.). Alles versions- und hash-gepinnt, als Read-only-VHDX in die Offline-Umgebung importiert.
- Intake: Sample kommt über ein einmalig gemountetes Read-only-Image in die VM, wird gehasht (SHA-256, SHA-1, MD5), als `noexec` abgelegt und nie mit Ausführungsrechten versehen.
- Export: nur das Berichts-Paket, über ein neu erzeugtes Image, vorher geprüft (nur Text, Bilder, Markdown; keine Binärdaten aus dem Sample).

### 6.2 MCP-Tool-Gateway (in der VM)

> **Stand 2026-10-31 (ADR-0006):** Das Gateway ist derzeit eine interne Allowlist (`DevGateway`), kein MCP-Server, und es gibt keine `.mcp.json`. Fremdwerkzeuge laufen hinter dem Gateway in Containern. Abweichende Namen im Code: `decompile` (`decompile_function`), `extract_range` (`extract_overlay`), `decode_layer` (`script_deobfuscate_layer`), `pe_headers` enthält `pe_imports`; `ghidra_analyze` läuft automatisch beim ersten Ghidra-Aufruf. Noch offen sind `apktool_decode`, `list_native_libs`, `extract_embedded`, `emulate_function` und `notes_write`. Die VM-Variante und damit die Frage nach MCP entscheidet der VM-Baustein.

Nur lesende/analysierende Tools, jedes mit Schema, Validierung, Timeout, Speicher- und Ausgabelimit, Pfad-Jail:

- `sample_info`, `hash_file`, `identify_type`, `entropy_map`
- `pe_headers`, `pe_imports`, `pe_resources`, `extract_overlay`
- `strings_extract`, `floss_decode`
- `capa_scan`, `yara_scan`
- `ghidra_analyze` (Job), `list_functions`, `decompile_function`, `disassemble`, `xrefs`
- `apk_manifest`, `jadx_decompile`, `apktool_decode`, `list_native_libs`
- `script_detect`, `script_deobfuscate_layer` (Dekoder-Bibliothek, keine Ausführung)
- `extract_embedded` (binwalk-artig, Ergebnisse als neue Artefakte mit Hash)
- `emulate_function` (nur wenn Emulation für den Job freigegeben, Abschnitt 6.6)
- `notes_write` (nur in den Job-Arbeitsbereich)

Jedes Ergebnis erhält eine Evidence-ID (Job, Tool, Version, Parameter, Ergebnis-Hash, Zeitstempel).

### 6.3 Lokale KI

- Reasoning-Modell im Thinking-Modus plus Embedding-Modell, betrieben über Ollama oder llama.cpp.
- **Modellauswahl per Benchmark-Spike (Phase 0), nicht festgelegt.** Kandidaten laut Kenntnisstand: gpt-oss-20b, Qwen3-14B, jeweils quantisiert; Embedding: bge-m3 oder Qwen3-Embedding. Vor der Entscheidung gegen aktuelle Releases prüfen. Kriterien: Tool-Calling-Zuverlässigkeit, Reasoning-Qualität auf Dekompilat, Speicherbedarf bei nötigem Kontext, Geschwindigkeit.
- 16 GB begrenzen den Kontext. Deshalb: kleine Teilaufgaben, Zwischenergebnisse als Notizen, Planer arbeitet mit Zusammenfassungen und Evidence-Referenzen, nicht mit Rohdaten.

### 6.4 Orchestrator (Aufgabenzerlegung bis zum Ziel)

Ablauf pro Job:

1. **Triage:** Dateityp per Magic Bytes und Struktur, Rezept laden, Pflichtfragen und Fokus aus der Eingabe übernehmen.
2. **Planer:** erzeugt einen Aufgabenbaum (Rezept-Schritte, Fokus, Pflichtfragen, dynamische Funde wie "Packer erkannt").
3. **Aufgaben-Queue:** Teilaufgaben werden einzeln abgearbeitet (Reasoning, Tool-Aufrufe über das Gateway). Neue Erkenntnisse können neue Teilaufgaben erzeugen (Rekursion, z. B. extrahierte Payload geht erneut durch Triage).
4. **Prüfer:** validiert jedes Ergebnis (Evidenz vorhanden? Widerspruch zu früheren Funden? Plausibilität?). Unbelegtes wird als Hypothese markiert oder verworfen.
5. **Notiz-Writer:** jede Teilaufgabe erzeugt eine Vault-Notiz (Vorgehen, Ergebnis, Evidence-IDs, Status).
6. **Abdeckungs-Check:** Pflichtfragen beantwortet? Rezept-Pflichtschritte erledigt? Unaufgelöste Funktionen oder Schichten? Wenn nein: neue Teilaufgaben, zurück zu 3.
7. **Abbruchkriterien:** alle Pflichtfragen beantwortet und Abdeckung erreicht oder Budget (Zeit/Schritte) erschöpft. Dann ehrlicher Bericht mit Markierung "nicht vollständig geklärt" samt Begründung.
8. **Bericht** (Abschnitt 6.7).

Robustheit: Checkpointing des Job-Zustands, Wiederaufnahme nach Abbruch, Schleifenerkennung, Budget- und Ressourcenlimits.

### 6.5 Rezepte (YAML, erweiterbar)

Jedes Rezept definiert: Pflichtschritte, optionale Schritte, Pflichtfragen, Abdeckungskriterien, Berichtsabschnitte. Beispiel (gekürzt):

```yaml
id: exe
detect: { magic: ["MZ"], pe: true }
steps:
  - id: static_triage      # Hash, Header, Sektionen, Entropie, Packer
  - id: strings_floss
  - id: capa_yara
  - id: ghidra_full        # Dekompilierung, Priorisierung nach Relevanz
  - id: unpack_if_needed   # nur statisch bzw. optional Emulation
  - id: resources_overlay
  - id: crypto_config_ioc  # Krypto-Konstanten, Konfig-Blöcke, IOCs
required_questions:
  - Was tut die Software (Hauptfunktion)?
  - Persistenz-, Kommunikations- und Verschlüsselungsmechanismen?
  - Welche IOCs lassen sich statisch ableiten?
  - Gibt es Hinweise auf Schwachstellen oder Schwächen (z. B. Kill-Switch, Schlüsselhandhabung)?
coverage:
  functions_reviewed_min: 0.9   # Anteil relevanter Funktionen
report_sections: [overview, metadata, capabilities, techniques, iocs, crypto, weaknesses, open_questions, appendix]
```

- **EXE:** Hash/PE-Header/Sektionen/Entropie/Packer, Strings und FLOSS, Imports, capa, YARA, Ghidra-Dekompilierung, Ressourcen und Overlay, eingebettete Dateien, Krypto-Konstanten, Konfigurationen, IOCs.
- **APK:** Manifest/Berechtigungen/Komponenten/Zertifikat, jadx und apktool, Endpunkte und Krypto, Reflection und dynamisch geladene DEX, native Libraries über Ghidra, statische Obfuskations-Auflösung.
- **Skript** (PowerShell, JS, VBS, Python, Bash, Batch): Spracherkennung, schichtweise Deobfuskation ohne Ausführung (Base64, XOR, Concatenation, eval-Ketten über eigene Dekoder), eingebettete Payloads rekursiv in das passende Rezept.

Zusatz für Ransomware-relevante Fragen (in allen Rezepten als optionale Fragen): Verschlüsselungsverfahren und Schlüsselverwaltung, Dateiauswahl, Notfall- und Löschroutinen (Shadow Copies/Backups), Kommunikation, Erpresserschreiben/Konfiguration, Schwächen im Schlüsselmaterial.

### 6.6 Emulation (optional, aus per Default)

- Werkzeuge: Qiling, Unicorn, angr. Das Sample läuft **nie** als Prozess, nur einzelne Routinen in einer simulierten CPU/OS-Schicht innerhalb der Analyse-VM.
- Aktivierung nur pro Job per ausdrücklichem Opt-in in der Web-UI, mit Begründung (z. B. "Entpacker-Routine bei Offset X"), im Audit-Log vermerkt.
- Zusätzliche Grenzen: keine Netzwerk-Backends, Syscalls/API-Aufrufe gestubbt oder blockiert, Dateisystem nur virtuell/leer, Ausführungsbudget (Instruktionen, Zeit, Speicher), Abbruch bei Auffälligkeiten, Ergebnis nur als Daten (Speicherabbild, Trace) mit Hash.
- Bericht kennzeichnet emulationsbasierte Aussagen separat und mit niedrigerer Konfidenz, solange sie nicht statisch bestätigt sind.

### 6.7 Bericht

- Gliederung: Zusammenfassung, Metadaten und Chain-of-Custody, Eingabevorgaben (Fokus/Pflichtfragen), Fähigkeiten und Verhalten (statisch abgeleitet), Techniken (MITRE-ATT&CK-Zuordnung, wo belegbar), Krypto/Schlüssel, IOCs (entschärft), Schwächen/Schwachstellen, offene Fragen, Methodik und Tool-Versionen, Anhang (Evidence-Tabelle).
- Jede Aussage: Evidence-ID(s) und Status `bestätigt` / `Hypothese` / `offen`.
- Diagramme (automatisch erzeugt, offline gerendert): Kontrollfluss/Funktions-Aufrufgraph, Architektur des Samples, Ablauf (z. B. Verschlüsselungsroutine), Datenfluss, Zeitachse der Analyse. Quellformat Mermaid bzw. Graphviz, Ausgabe SVG/PNG.
- Vorgaben pro Job: Pflichtfragen werden garantiert beantwortet oder explizit als "nicht klärbar, weil …" ausgewiesen. Danach schrittweiser Ausbau über Zusatzfragen (Folge-Jobs auf demselben Arbeitsstand).
- Export: Markdown und PDF.

### 6.8 Wissensdatenbank

- Quellen: E-Books, Schulungsunterlagen, Papers, eigene Notizen. Ingest: Textextraktion, Chunking, Metadaten (Quelle, Seite, Datum), Vektor- und Volltextindex, lokal.
- Funktionen: Abfrage mit Quellenangabe, Lückenanalyse ("dazu fehlt Wissen"), Versionierung der Quellen, Nachweis, welcher Bericht welche Wissensquelle genutzt hat.
- Web-UI: Seite zum Hochladen und Pflegen, Statusanzeige des Ingests.
- Hinweis: Lizenz- und Urheberrecht der Quellen liegt bei dir. Der Index bleibt lokal.

### 6.9 Obsidian-Vault (Analyse)

- Pro Job ein Ordner: `00-Index`, `Aufgaben/`, `Funde/`, `Funktionen/`, `IOCs/`, `Hypothesen/`, `Offene-Fragen/`, `Bericht/`.
- Notizen mit Frontmatter (Job-ID, Evidence-IDs, Status, Zeitstempel) und `[[Links]]`, damit der Graph die Zusammenhänge zeigt.
- Wird ausschließlich von der Plattform geschrieben und ist Teil des Chain-of-Custody-Exports.

### 6.10 Web-UI

- Lokal, ohne externe Ressourcen (keine CDNs).
- Seiten: Job anlegen (Upload, Fokus, Pflichtfragen, Emulation-Opt-in), Live-Status (Aufgabenbaum, aktuelle Aufgabe, Tool-Aufrufe, Abdeckung, Logs), Wissen pflegen, Berichte, Einstellungen/Sicherheitsstatus (VM-Zustand, Checkpoint, Isolation-Checks).
- Hinweis: Ansicht von Sample-Inhalten stets als reiner Text, escaped (kein Rendering von Sample-HTML/JS).

---

## 7. Phasenplan mit Abnahmekriterien

| Phase | Inhalt | Abnahme |
|---|---|---|
| 0 | Dev-Umgebung, Plugins (Abschnitt 4), Repo-Gerüst, ADR-0001 bis -0003 (Modell, Kanal Host-VM, Sprache/Stack), Modell-Benchmark-Spike | Plugins laufen, Repo-Regeln aktiv, Modellwahl begründet |
| 1 | Analyse-VM, Härtung, Kanal Host-VM, Gateway-Skelett mit `sample_info`/`hash_file`, Audit-Log | Isolation-Tests grün (kein Netz, keine Brücken), Rollback funktioniert |
| 2 | Intake, Triage, Dateityp-Erkennung, Rezept-Engine, Korpus-Gerüst (Hash-Manifest, Struktur, Auswertungs-Skript für Flare-On-Lösungen) | Typen auf Testkorpus korrekt erkannt; Korpus-Struktur steht, erste Flare-On-Aufgabe eingebunden |
| 3 | Skript-Rezept (Dekoder-Bibliothek, rekursive Schichten) | Korpus-Skripte vollständig entschichtet, ohne Ausführung |
| 4 | APK-Rezept | Manifest, Code, Endpunkte auf Korpus korrekt |
| 5 | EXE-Rezept inkl. Ghidra-Pipeline | Funktionen, Imports, Strings, Krypto im Korpus korrekt |
| 6 | Wissensdatenbank (Ingest, Suche, Lückenanalyse) | Abfragen liefern Quellen; Retrieval-Tests grün |
| 7 | Vault-Writer | Notizen mit Evidence-Links, Graph konsistent |
| 8 | Orchestrator-Schleife (Zerlegung, Prüfer, Abdeckung, Checkpointing) | Job läuft autonom bis Abdeckung oder Budget, Wiederaufnahme klappt |
| 9 | Web-UI | Alle Seiten funktionsfähig, Live-Status korrekt, Eingaben validiert |
| 10 | Berichtsgenerator inkl. Diagramme und Defanging | Bericht erfüllt Gliederung, jede Aussage mit Evidenz |
| 11 | Emulation (optional) | Nur per Opt-in; Grenzen und Logging nachgewiesen |
| 12 | Härtung und Red-Team (eigene Tests) | Prompt-Injection-, Pfad-Traversal-, Ressourcen-, Isolations-Tests bestanden; Security-Report |

Jede Phase endet mit: Tests grün, Security-Review, Doku und ADRs aktuell, Tag, Statusbericht an Jan.

---

## 8. Korrektheit nachweisen

Ziel "alles korrekt verstanden" wird messbar gemacht:

- **Ground-Truth-Korpus** (`tests/corpus/`): selbst geschriebene, harmlose Programme, Skripte und APKs mit bekanntem Verhalten (z. B. Beispiel-Verschlüsselungsroutine mit bekanntem Schlüssel, mehrfach verschleierte Skripte, absichtlich gepackte Hello-World-Programme, APK mit bekannten Endpunkten). Dazu eine Antwortdatei mit den erwarteten Befunden.
- Metriken: Trefferquote der Pflichtfragen, Anteil belegter Aussagen (Ziel 100 %), Fehlaussagen (Halluzinationen) pro Bericht, Abdeckung, Reproduzierbarkeit (zwei Läufe, gleiche Befunde).
- Regressionstests bei jedem Modell-, Prompt- oder Tool-Update.
- Aussagen ohne Beleg werden vom Prüfer entfernt oder als Hypothese markiert. Das ist eine Plattform-Invariante, kein Wunsch.

Ehrliche Grenze: Bei stark verschleierter, gepackter oder verschlüsselter Software kann rein statische Analyse unvollständig bleiben. Das wird im Bericht ausdrücklich so ausgewiesen (Status "teilweise analysiert" mit Begründung) und nicht überspielt.

---

## 9. Dokumentation und Nachvollziehbarkeit

- ADRs für jede relevante Entscheidung.
- `docs/security/threat-model.md`: Bedrohungsmodell (Sample-Flucht, Prompt-Injection, Lieferkette, Datenabfluss), Gegenmaßnahmen, Restrisiken.
- `docs/runbooks/`: Betrieb (Bundle importieren, Job starten, VM zurücksetzen, Bericht exportieren).
- Chain-of-Custody je Job: Eingangs-Hashes, Zeitstempel, Tool-Versionen, Modell-Version, Prompt-Versionen, Audit-Log-Hash.

---

## 10. Betrieb

- Updates der Tools, Regeln und Modelle ausschließlich über das Bundle-Verfahren (online bauen, Hash prüfen, offline importieren).
- Vor jedem Job: Selbsttest (VM ohne Netz, Checkpoint vorhanden, Gateway-Allowlist unverändert, Log-Kette intakt).
- Nach jedem Job: Rollback, Export-Prüfung, Log-Versiegelung.

---

## 11. Testkorpus für die Entwicklung

Festgelegt: **Flare-On-Challenges** (Mandiant/FireEye, jährliches CTF) sind die primäre Quelle für den Ground-Truth-Korpus. Begründung: Die Binaries sind absichtlich mit echten Malware-Techniken gebaut (Packer, Anti-Debugging, String-Obfuskation, einfache "C2"-Simulation), aber garantiert harmlos, und es gibt offizielle Lösungen/Write-ups, gegen die sich die automatisch erzeugten Berichte prüfen lassen (Trefferquote, Abdeckung).

Zusammensetzung von `tests/corpus/`:

- **Flare-On-Aufgaben** (ausgewählte Jahrgänge/Level, aufsteigender Schwierigkeitsgrad): Haupt-Testkorpus für das EXE- und Skript-Rezept. Pro Aufgabe: Original-Binary/-Skript, offizielle Musterlösung als Antwortdatei (erwartetes Verhalten, erwartete Strings/Konfiguration/Flag), SHA-256 der Originaldatei zur Versionsprüfung.
- **capa-testfiles** (`mandiant/capa-testfiles`) als Ergänzung: kleine, gezielte Beispiele für einzelne Capabilities, gut für Unit-Tests einzelner Gateway-Tools (z. B. `capa_scan`), nicht nur für den Gesamt-Orchestrator.
- **Eigene Minimalbeispiele** (Claude Code selbst erzeugt): einfache kompilierte Programme mit bekannter, dokumentierter Verschlüsselung (fester Schlüssel), Packer-Nachbildung, Test-APKs, verschleierte Skripte. Dienen den frühen Phasen (2–5), bevor der Flare-On-Korpus eingebunden ist, und als schnelle Regressionstests.
- **EICAR-Testdatei**: nur für den Intake-/Triage-Pfad (Hashing, Typ-Erkennung, noexec-Handling), nicht für die Tiefenanalyse, da sie keine echte Struktur hat.
- **OWASP MASTG "UnCrackable Apps"** bzw. vergleichbare didaktische Android-Beispiele: Korpus für das APK-Rezept.

Bereitstellung: Jan lädt die Flare-On-Archive (offiziell, von `flare-on.com` bzw. dem GitHub-Repo der Challenges) herunter und legt sie manuell in `tests/corpus/flare-on/` ab, inklusive der offiziellen Lösungen. Claude Code bezieht diese Dateien nicht selbst aus dem Netz (Regel 6 der Verbote: keine Netzwerkzugriffe der Plattform), sondern erzeugt nur das Hash-Manifest, die Verzeichnisstruktur und die Auswertungs-Skripte, die den generierten Bericht gegen die Musterlösung vergleichen.

Echte Schadsoftware wird ausschließlich von Jan selbst in der Offline-Umgebung eingebracht, nie in `tests/corpus/` oder in das Repository.

---

## 12. Offene Entscheidungen (per ADR in Phase 0/1 klären)

1. Kanal Host-VM: Hyper-V-Sockets (bevorzugt) oder rein interner Switch.
2. Konkrete Modelle und Quantisierung (Benchmark-Spike).
3. Dedizierter Analyse-Rechner (empfohlen) oder bestehender Host.
4. Vektordatenbank/Index (lokal, offline).
5. Welches Obsidian-Plugin (entschieden: kein mnemo, eigener Dev-Vault).
6. Remote-Repository (aktuell: nur lokal).
7. Berichtsformate und Vorlagen-Layout (Dienst-Vorgaben).
8. Konkrete Flare-On-Jahrgänge/Level für den Korpus und Reihenfolge nach Schwierigkeitsgrad (ADR-0004, Phase 2).

---

## 13. Start-Prompt für Claude Code

```
Lies PROJEKTPLAN.md und CLAUDE.md vollständig. Beginne mit Phase 0.

1. Prüfe, ob die Plugins aus Abschnitt 4 installiert sind (Caveman, Ponytail, mnemo). Falls nicht: gib mir die Befehle und warte. Prüfe vorher je Plugin kurz Hooks und Skripte und berichte Auffälligkeiten.
2. Lege das Repository-Gerüst nach Abschnitt 5 an (lokales Git, kein Remote), mit .gitignore, Pre-Commit-Hooks und leerem Testkorpus.
3. Schreibe ADR-0001 (Modellwahl-Spike), ADR-0002 (Kanal Host-VM), ADR-0003 (Stack) als Entwürfe mit Optionen und Empfehlung. Lege zusätzlich das Gerüst für ADR-0004 (Flare-On-Korpusauswahl) an, zu befüllen in Phase 2 sobald ich die Archive abgelegt habe.
4. Führe den Modell-Benchmark-Spike nur mit synthetischen Beispielen durch und berichte die Ergebnisse.
5. Halte an, sobald Phase 0 die Abnahmekriterien erfüllt, und gib mir einen Statusbericht (erledigt, offen, Risiken). Beginne Phase 1 erst nach meiner Freigabe.

Beachte durchgehend die Verbote und Arbeitsregeln in CLAUDE.md. Echte Malware wird nie angefasst. Bei Unklarheit: fragen.
```
