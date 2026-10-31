# Testplan: forensische Belastbarkeit der Reverse-Engineering-Kette

Stand: 2026-10-31. Ziel: Jede Aussage des Berichts ist nachweisbar, jeder Lauf reproduzierbar, jede Manipulation erkennbar, und kein Sample-Inhalt kann die Analyse steuern. Dieser Plan legt fest, was getestet wird, womit und wann ein Test als bestanden gilt. Status: `[x]` vorhanden und grün, `[~]` teilweise, `[ ]` offen.

## 1. Beweiskette und Integrität (Chain of Custody)
| ID | Prüfung | Abnahme | Status |
|---|---|---|---|
| C1 | Eingangs-Hash: SHA-256 des hochgeladenen Samples gleich dem Hash im Job, in der Evidence (`hash_file`) und im Bericht | alle drei identisch | [x] `test_c1_sample_hash_job_file_report_agree` |
| C2 | Sample unverändert: Datei nach dem Job byteidentisch, Schreibschutz gesetzt, zweites `store_sample` wird abgelehnt | Hash vor und nach dem Job gleich | [x] `test_c2_sample_is_byte_identical_and_read_only_after_job` |
| C3 | Abgeleitete Artefakte (`derived/layerNN.bin`): jeder Hash steht in Evidence und Bericht, Neuberechnung stimmt | Hash der Datei = Evidence-Hash | [~] Hash in Evidence und Neuberechnung grün; Artefakt-Hash im Bericht fehlt (xfail, F-15) |
| C4 | Audit-Kette: Änderung, Löschen, Umordnen oder Einfügen einer Zeile wird von `verify_file` erkannt, Position stimmt | `broken_at` = manipulierte Zeile | [x] `tests/forensic/test_chain_of_custody.py` (Ändern, Löschen, Vertauschen, Einfügen; Kürzen am Ende nur über gemerkten Kopf-Hash erkennbar, als Grenze getestet) |
| C5 | Audit vollständig: jede Store-Änderung (Task, Step, Evidence, Finding, Answer) erzeugt einen Audit-Eintrag in Event-Reihenfolge | Zahl der DB-Events = Zahl der Audit-Zeilen | [ ] |
| C6 | Zeitstempel monoton, UTC, ISO-8601; Dauer je Task passt zur Summe der Steps (Toleranz) | keine negativen Dauern, keine Rückwärtssprünge | [~] |
| C7 | Versionsnachweis: Modellname, Prompt-ID/Version/SHA-256, Tool-Version und Guard-Version stehen in Task bzw. Bericht | Felder gefüllt, Prompt-SHA = Hash des gespeicherten Prompttexts | [~] Prompt-SHA wird gespeichert, Gegenprüfung fehlt |
| C8 | Bericht-Reproduzierbarkeit: gleicher Datenbankstand ergibt byteidentischen Bericht | Hash zweier Erzeugungen gleich | [x] `test_c8_report_is_reproducible` (EN und DE, einfacher Datenstand) |

## 2. Beleg- und Halluzinationsprüfung
| ID | Prüfung | Abnahme | Status |
|---|---|---|---|
| G1 | Zitat muss wörtlich im Evidence-Text stehen (Whitespace-normalisiert) | erfundenes Zitat → `hypothesis` bzw. `rejected` | [x] `test_wrong_answer_is_not_accepted_without_grounding` |
| G2 | Evidence-ID eines fremden Jobs oder nicht existent | `rejected` mit Grund | [x] `test_g2_…` |
| G3 | Zu kurzes Zitat (unter 4 Zeichen) zählt nicht als Beleg | nicht `confirmed` | [x] `test_g3_…` |
| G4 | Zitat über eine Schwärzung (`[REDACTED-INJECTION…]`) hinweg | Verhalten dokumentiert und getestet | [ ] |
| G5 | Antwortwerte der Form `WORT{…}` müssen in einer Evidence vorkommen | sonst `unresolved` | [x] |
| G6 | Antwort ohne bestätigtes Finding wird nicht `answered` | `unresolved` mit Begründung | [x] |
| G7 | Zeilenverweise in Annotationen und Lernpfad existieren in der Datei | ungültig → verworfen | [ ] (mit Dashboard V2) |
| G8 | Halluzinationsrate: Golden-Set mit bekannten Fakten, Anteil unbelegter oder falscher `confirmed` | Ziel 0 % `confirmed` ohne Beleg, Fehlaussagen je Bericht gezählt | [ ] braucht echtes Modell |
| G9 | Zitat stimmt, Schluss geht zu weit (bekannte Lücke des Prüfers) | Stichprobe von Hand, Evaluator-Prüfung | [ ] |

## 3. Prompt-Injection und Agentensicherheit
| ID | Prüfung | Abnahme | Status |
|---|---|---|---|
| S1 | Scanner-Korpus EN/DE inklusive Obfuskation (Zero-Width, Homoglyphen, base64/hex) | Recall ≥ 95 %, 0 Fehlalarme high auf harmlosen Strings | [x] 145 von 145; Wert auf dem Korpus justiert, daher optimistisch |
| S2 | Unabhängiges Hold-out-Set (nicht zum Tuning verwendet), mindestens 100 neue Positive und Negative | Recall und Fehlalarmrate gemessen und dokumentiert | [x] |
| S3 | Tripwire: nach high-Fund unzulässige Aktion → Task `blocked`, Vorfall als Befund | im E2E | [x] |
| S4 | Aktionsvalidierung: unbekanntes Tool, unbekannte Argumente, Pfadtricks, Mehrfachobjekt, Übergröße | abgelehnt | [x] |
| S5 | Injektion in Metadaten (Dateiname, Zip-Member-Name, PE-Ressourcen, Strings, Kommentare, Base64-Schicht nach Dekodierung) | erkannt, nie befolgt | [~] Scanner ja, E2E für dekodierte Schichten und Metadaten fehlt |
| S6 | Mehrstufige Injektion (Anweisung über mehrere Evidences verteilt) | als Grenze dokumentiert, Gegenmaßnahmen (Systemprompt, Allowlist) geprüft | [ ] |
| S7 | Live-Modell-Test mit bekannten Jailbreak-Texten im Sample | 0 unzulässige Aktionen in N Läufen | [ ] braucht Modell |
| S8 | Keine Sample-Binärdaten oder ausführbaren Payloads in Findings und Bericht | `redact_payloads` greift | [~] Einheitentests da, E2E fehlt |

## 4. Isolation, Jail und Ressourcen
| ID | Prüfung | Abnahme | Status |
|---|---|---|---|
| I1 | Pfad-Jail: `..`, absolut, Laufwerk, UNC, NUL, Backslash, Gerätenamen, Symlink, Junction | abgelehnt | [x] DevGateway |
| I2 | Kein Prozessstart im Code der Plattform (AST-Prüfung über `src/`) | kein `subprocess`, `os.system`, `eval`, `exec` außer an freigegebenen Stellen | [~] nur im Gateway; auf gesamtes `src/` ausdehnen |
| I3 | Kein Netzwerk zur Laufzeit: Test sperrt Sockets außer Loopback und fährt einen vollen Job | keine ausgehende Verbindung | [x] |
| I4 | LLM-Endpunkt nur Loopback (`OllamaClient` lehnt fremde Hosts ab) | `ValueError` | [x] `test_i4_…` |
| I5 | Ressourcenlimits: Ausgabe 20.000 Zeichen, Regex-Zeit, Dekompressionsgröße, Dateigröße 64 MiB, ReDoS-Muster | Limits greifen, kein Hängen | [x] DevGateway |
| I6 | Web-API: Origin- und Host-Prüfung, CSP-Header, Upload über 64 MiB, leere Datei, Pfad-Traversal im Code-Viewer, Fehlerformat | erwartete Statuscodes | [x] |
| I7 | Frontend: kein `innerHTML`, keine Fremdressourcen, Sample-Text nur als Text | Asset-Test grün | [x] |
| I8 | Container und VM (Phase 1): kein Netz, read-only, Rollback, Allowlist unverändert | Isolationstests grün | [ ] Phase 1 |
| I9 | Gateway-Allowlist für REA und ghidra-mcp: gesperrte Tools nicht aufrufbar (Namensliste in `dev-environment.md`) | Aufruf scheitert | [ ] mit Einbau |

## 5. Determinismus, Wiederholbarkeit, Robustheit
| ID | Prüfung | Abnahme | Status |
|---|---|---|---|
| D1 | Werkzeuge deterministisch: gleiche Eingabe, gleiches Ergebnis, gleicher Hash | zwei Läufe identisch | [x] DevGateway |
| D2 | Zwei Gesamtläufe mit Skript-Modell: gleiche Befunde, Antworten, Statuswerte | identisch bis auf Zeitstempel | [ ] |
| D3 | Zwei Läufe mit echtem Modell (niedrige Temperatur, fester Seed): Überschneidung der bestätigten Findings | Messwert dokumentiert, Ziel ≥ 90 % | [ ] |
| D4 | Wiederaufnahme nach Abbruch (Prozess endet mitten im Job) | Job als `failed` oder fortsetzbar, Audit-Kette gültig | [~] Worker markiert Reste als `failed`, Fortsetzung fehlt |
| D5 | Schleifenerkennung, Budgetgrenzen (Aufgaben, Schritte, Minuten), Abbruch durch Nutzer | Job endet `partial` oder `cancelled` mit Grund | [~] Logik vorhanden, Tests fehlen |
| D6 | Ausfälle: Modell nicht erreichbar, ungültiges JSON, leere Antwort, Timeout | Task `failed` nach Wiederholung, Job läuft weiter | [ ] |
| D7 | Fuzzing: Müll, abgeschnittene PE/ZIP/APK, riesige Zeilen, Binärdaten als Text | kein Absturz, saubere Fehler | [~] 400 PE-Mutationen |

## 6. Übersetzung (EN↔DE) und Bericht
| ID | Prüfung | Abnahme | Status |
|---|---|---|---|
| T1 | Geschützte Tokens (Hashes, IDs, Pfade, IOCs, Code) bleiben bytegenau erhalten | 100 % | [x] 124 Tests |
| T2 | Rückfall bei Platzhalterverlust: Originaltext mit `[EN]`, `ok=False`, Bericht kennzeichnet es | sichtbar im Bericht | [~] |
| T3 | Rückübersetzung DE→EN ergibt dieselben Fakten (Stichprobe, Abgleich von Zahlen, IDs, Hashes) | identisch | [ ] |
| T4 | Bericht-Vollständigkeit: jede Zielfrage, jedes bestätigte Finding, jede Evidence-ID, Hash-Tabelle, Audit-Kopf, Guard-Ereignisse | Abgleich Datenbank ↔ Bericht | [~] Stichproben im E2E |
| T5 | Defanging: URLs, Domains, IPs, E-Mails entschärft, keine ausführbaren Payloads, idempotent | `find_iocs` auf dem Bericht findet nur entschärfte Formen | [~] Einheitentests da, Gesamttest für Bericht fehlt |
| T6 | Status-Disziplin: `confirmed` nur mit verifiziertem Zitat, Hypothesen getrennt | im Bericht | [x] |

## 7. Korrektheit gegen Wahrheit (Ground Truth)
| ID | Prüfung | Abnahme | Status |
|---|---|---|---|
| K1 | Eigenes harmloses Minimal-Korpus: Skript mit n Schichten, PE mit bekannten Imports und Sektionen, Mini-APK mit bekannten Endpunkten, Krypto-Beispiel mit festem Schlüssel; je `*.expected.json` | Trefferquote der Pflichtfragen ≥ 90 %, Belegquote 100 % | [ ] |
| K2 | Flare-On-Korpus (legt Jan ab): Hash-Manifest, Auswerteskript gegen die Musterlösung, Lösungen nie im Prompt | Trefferquote, Abdeckung, Zeit je Aufgabe | [ ] Phase 2 |
| K3 | capa-testfiles für Einzeltools | Ergebnisse stimmen mit der capa-Erwartung | [ ] |
| K4 | Regression bei jedem Wechsel von Modell, Prompt oder Tool: Messwerte aus K1, K2, G8, S7 vergleichen | keine Verschlechterung über Schwelle | [ ] |
| K5 | EICAR nur für Intake und Triage (Hash, Typ, noexec) | Typ erkannt, nichts ausgeführt | [ ] |

## 8. Umsetzung
- Testordner: `tests/forensic/` (C, G, D, T), `tests/security/` (S, I), `tests/corpus/` (K, im Repo nur Manifest und `*.expected.json`), `tests/ctf/` (E2E mit Skript-Modell und optional echtem Modell).
- Marker: `live_model` für Tests mit Ollama (standardmäßig übersprungen), `corpus` für Tests mit abgelegten Proben.
- Metrikbericht je Lauf (`tests/reports/<datum>.json`): Trefferquote, Belegquote, Halluzinationsrate, Guard-Recall, Determinismus, Dauer. Vergleich mit der letzten Basislinie.
- Reihenfolge: zuerst Block 1 und 2 (ohne Modell, schnell), dann 3 bis 6, danach Korpus und Live-Modell.
- Abschluss jeder Phase: Security-Review, dieser Plan aktualisiert, Basislinie festgehalten.
