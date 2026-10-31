# Bewertung: größeres lokales Modell für die Analysekette

Stand: 2026-10-31. Frage von Jan: Gibt es ein größeres Modell, das die Ergebnisse verbessert, und wie setzen wir es um? Dieses Dokument trennt **belegte Fakten** (Registry-Abfrage), **Rechenwerte** (Schätzungen aus Speicherbandbreite) und **Hypothesen** (erwartete Qualitätsgewinne, noch nicht gemessen).

## 1. Rahmen
- GPU RTX 5060 Ti: 16.311 MiB VRAM (bei geschlossenen Apps ca. 14,5 GB frei), Speicherbandbreite ca. 448 GB/s.
- RAM 31 GB, hartes Limit 24 GB für WSL, Docker und Modelle zusammen (ADR-0000), Windows braucht mindestens 7 GB.
- Kontext 16k bis 32k Token, KV-Cache `q8_0`. Ein Modell bleibt geladen (`OLLAMA_MAX_LOADED_MODELS`), Wechsel kostet Ladezeit von der SSD.
- Bekanntes Risiko: Ollama-Meldungen zu Abstürzen mit Blackwell-Karten bei Teil-Offload (ADR-0001, Issues #18232, #19122, #18276).

## 2. Kandidaten (Größen aus `registry.ollama.ai`, alle Tags existieren)
| Gruppe | Tag | Größe | Passt in VRAM? | Geschwindigkeit (Schätzung) |
|---|---|---|---|---|
| Basislinie | `qwen3:8b` | 5,2 GB | ja, mit viel Kontext | ca. 40 bis 60 Token/s |
| voll im VRAM | `qwen3:14b` | 9,3 GB | ja | ca. 25 bis 35 |
| voll im VRAM | `gemma4:12b` | 8,0 GB | ja | ca. 30 bis 40 |
| voll im VRAM | `phi4-reasoning:14b` | 11,1 GB | knapp bei 32k | ca. 25 |
| voll im VRAM | `ornith:9b` | 5,6 GB | ja | ca. 40 bis 55 |
| knapp | `gpt-oss:20b` (MoE, wenige aktive Parameter) | 13,8 GB | nur bei freier GPU | ca. 60 bis 100 |
| Teil-Offload, dicht | `magistral:24b`, `devstral:24b`, `mistral-small3.2:24b` | 14,3 bis 15,2 GB | Gewichte ja, KV-Cache nein | ca. 12 bis 20 |
| Teil-Offload, dicht | `qwen3.5:27b`, `qwen3.8:27b`, `gemma3:27b` | 17,4 bis 17,7 GB | nein (2 bis 4 GB im RAM) | ca. 8 bis 12 |
| Teil-Offload, dicht | `qwen3:32b`, `deepseek-r1:32b`, `qwen2.5-coder:32b` | 19,9 bis 20,2 GB | nein (5 bis 6 GB im RAM) | ca. 6 bis 9 |
| Teil-Offload, MoE | `qwen3:30b`, `qwen3-coder:30b`, `gemma4:26b` | 18,6 bis 18,7 GB | nein, aber wenige aktive Parameter | ca. 20 bis 40 |
| Teil-Offload, MoE | `ornith:35b`, `flint:40b` | 21,2 und 22,9 GB | nein (5 bis 7 GB im RAM) | ca. 15 bis 30 |
| zu groß | `gpt-oss:120b` | 65,4 GB | nein | nicht nutzbar |

Rechenweg der Geschwindigkeit: Token pro Sekunde ist etwa Bandbreite geteilt durch die je Token gelesenen Gewichte, mit Abschlag auf 60 bis 70 Prozent. Teile im Arbeitsspeicher laufen mit 40 bis 90 GB/s und bremsen stark. Alle Werte sind **nicht gemessen**.

## 3. Würde ein größeres Modell die Ergebnisse verbessern?
**Wahrscheinlich ja, aber nicht in dem Maß, das die Größenzahl suggeriert, und nicht ohne Kosten. Belegt ist bisher nichts, weil noch kein Lauf mit echtem Modell stattfand.**

Wo ein größeres Modell erwartbar hilft (Hypothesen, jeweils messbar):
1. **Protokolltreue:** weniger ungültige JSON-Aktionen und weniger Wiederholungen (Metrik: ungültige Aktionen je Aufgabe).
2. **Belegtreue:** weniger verworfene oder herabgestufte Findings durch erfundene Zitate (Metrik: Anteil `rejected` und `hypothesis`).
3. **Werkzeugwahl und Planung:** weniger Züge bis zur Antwort, bessere Zerlegung (Metrik: Züge und Dauer je Aufgabe).
4. **Dekompilat-Verständnis:** erst relevant, wenn der Ghidra-Adapter existiert; der Dev-Gateway liefert nur Skript- und Strukturdaten.
5. **Mehrschrittiges Rechnen** (Dekodierketten, Flaggen): Metrik Trefferquote auf dem CTF-Set.

Was dagegen spricht:
- **Geschwindigkeit:** Ein Job mit 20 Aufgaben und je 6 Zügen mit je 1.500 Token (inklusive Denkphase) sind etwa 180.000 Token. Bei 40 Token/s sind das ca. 75 Minuten, bei 8 Token/s rund 6 Stunden.
- **Stabilität:** Teil-Offload ist die gemeldete Absturzquelle auf Blackwell unter Windows.
- **Kontext:** Größere Modelle haben mehr KV-Cache je Token, also weniger Kontext im VRAM.
- **Der Prüfer fängt viele Fehler schon ab.** Ein kleines Modell kostet dann vor allem Zeit durch Wiederholungen, nicht Korrektheit. Ein größeres Modell spart Zeit, wenn es weniger Wiederholungen braucht; das kann die Mehrkosten pro Token ausgleichen.

## 4. Andere Hebel, die oft mehr bringen als ein größeres Modell
| Hebel | Wirkung | Aufwand |
|---|---|---|
| Schema-gebundene Ausgabe (Ollama `format` mit JSON-Schema statt freiem `json`) | beseitigt ungültige Aktionen fast vollständig | klein |
| Few-Shot-Beispiele aus dem Blueprint (vom stärksten Claude-Modell geschrieben) in den Aufgaben-Prompts | verbessert Protokoll, Zitieren, Werkzeugwahl | mittel |
| Selbstkonsistenz für Zielfragen (3 Antworten, Mehrheit, Beleg prüfen) | weniger falsche Antworten, dreifache Kosten nur dort | klein |
| Denkbudget je Aufgabentyp (Denkphase an für Planung und Fragen, aus für Übersetzung und Routine) | spart Token und Zeit | klein |
| Wissensdatenbank (Phase 6) mit Blueprint-Abschnitten statt alles im Prompt | kürzerer Kontext, gezieltes Wissen | mittel |
| Zwei Modelle: kleines schnelles für Triage, Evaluator, Priorisierer, Übersetzung; großes für Analyse und Zielfragen | Qualität, wo sie zählt, ohne Dauerlast | mittel |
| Feinabstimmung (LoRA) auf Analysespuren | hoher Gewinn möglich, hoher Aufwand und Datenbedarf | groß, später |
| Mehr Hardware (GPU mit 24 bis 32 GB VRAM, oder zweite GPU) | große dichte Modelle (24B bis 32B) voll im VRAM, kein Offload-Risiko | Kosten, Entscheidung Jans |
| Entfernte Modelle (Cloud) | nicht erlaubt: Analyseumgebung offline | entfällt |

## 5. Empfehlung
1. **Zuerst messen, dann entscheiden.** Die Basislinie `qwen3:8b` läuft im ersten Echtlauf (Plan-Schritt R5). Ohne diese Zahlen ist jede Aussage zum Nutzen eines größeren Modells Spekulation.
2. **Zuerst die billigen Hebel** aus Abschnitt 4 (Schema-Ausgabe, Few-Shot, Denkbudget). Sie sind unabhängig vom Modell und senken den Abstand zwischen kleinen und großen Modellen.
3. **Dann eine kontrollierte Arena** mit den Kandidaten aus Abschnitt 2, Reihenfolge nach Risiko: erst alles, was voll in den VRAM passt, danach MoE mit Teil-Offload, zuletzt dichte 24B bis 32B.
4. **Voraussichtliches Zielbild:** zwei Rollen. Hilfsmodell (schnell, voll im VRAM) für Triage-Fragen, Evaluator, Priorisierer und Übersetzung; Analysemodell (das beste, was stabil und schnell genug läuft) für Analyse- und Zielfragen-Aufgaben. Die Entscheidung folgt den Messwerten.

## 6. Umsetzungsplan
| # | Schritt | Ergebnis | Abhängig von |
|---|---|---|---|
| M0 | Basislinie: erster Echtlauf mit `qwen3:8b` (CTF-Probe), Messwerte erfassen | Zahlen für Züge, ungültige Aktionen, Dauer, Tokens/s | Plan R2 bis R5 |
| M1 | Benchmark-Arena `tests/bench/run_arena.py`: feste Aufgaben (CTF mit 2 und 3 Schichten, Skript-Entschichtung, synthetische PE-Fragen, Injektionstext, JSON-Treue), je Modell mehrere Läufe, Bericht `tests/reports/<datum>-arena.json` mit Trefferquote, Belegquote, ungültige Aktionen, `rejected`-Anteil, Züge, Dauer, Tokens/s, VRAM- und RAM-Spitze, Abstürze | reproduzierbarer Vergleich | M0 |
| M2 | Billige Hebel einbauen und in der Arena messen: Schema-gebundene Ausgabe, Few-Shot, Denkbudget, Selbstkonsistenz für Zielfragen | Messwerte vorher und nachher | M1 |
| M3 | Kandidaten ziehen und messen, Stufe 1 (voll im VRAM): `qwen3:14b`, `gemma4:12b`, `phi4-reasoning:14b`, `ornith:9b`, `gpt-oss:20b` | Rangliste | M1 |
| M4 | Stufe 2 (Teil-Offload, mit Absturzüberwachung und Ollama-Log): `qwen3:30b`, `qwen3-coder:30b`, `gemma4:26b`, `ornith:35b`, `flint:40b`, `mistral-small3.2:24b`, `devstral:24b`, `qwen3.8:27b`. Nur wenn Stufe 1 die Qualität nicht ausreichend hebt oder Jan größere Modelle will | Rangliste, Stabilitätsbericht | M3 |
| M5 | Entscheidung per Update von ADR-0001: Einzelmodell oder zwei Rollen; Konfiguration `models.analysis`, `models.helper`, `models.translate` in `infra/manifest.json`, Engine, `start.ps1` und `select-model.ps1` | Modellwahl belegt | M2 bis M4 |
| M6 | Rollen im Code: Engine wählt das Modell je Aufgabentyp, Modellwechsel mit Ladezeit im Aktivitätsanzeiger, Tests mit Skript-Modell je Rolle | zwei Rollen lauffähig | M5 |
| M7 | Hardware-Option dokumentieren (GPU mit 24 bis 32 GB VRAM, Vergleich Preis und Gewinn laut Arena) für Jans Entscheidung | Entscheidungsvorlage | M4 |

Speicherbedarf der Downloads: Stufe 1 ca. 50 GB, Stufe 2 ca. 150 GB (Laufwerk D: hat 1,3 TB frei). Netzwerk nur im Dev-Rechner (Pull), nie in der Analyseumgebung.

## 7. Offene Punkte und Unsicherheiten
- Geschwindigkeiten und Qualitätsgewinne sind Schätzungen; die Arena (M1) liefert die Belege.
- Ollama-Teil-Offload arbeitet je Schicht; ob und wie neuere Versionen Experten gezielt auslagern (günstig für MoE), ist nicht geprüft.
- Die Qualität der Modelle auf Dekompilat ist erst mit dem Ghidra-Adapter testbar.
- Lizenzen der Modelle sind vor einem produktiven Einsatz zu prüfen (Registry nennt sie nicht verlässlich).
