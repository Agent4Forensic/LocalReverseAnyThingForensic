# ADR-0001: Wahl des lokalen Modells (Entwurf)

Status: Entwurf. Die Entscheidung fällt nach dem Benchmark-Spike (Phase 0) und nach Klärung des VRAM-Blockers B2.

## Kontext
Ziel-GPU ist die RTX 5060 Ti mit 16 GB VRAM (Compute Capability 12.0, Blackwell). Beim Test waren durch Desktop-Anwendungen nur 4,5 bis 5 GB VRAM frei. Das Modell muss Reasoning (Thinking), zuverlässiges Tool-Calling über MCP und gutes Code-/Dekompilatverständnis liefern, auf Deutsch und Englisch. Das RAM-Limit beträgt 24 GB für alle Dienste zusammen (ADR-0000).

## Recherchestand (2026-10-31)
Quelle: Ollama-Library-Seiten und GitHub-Issues, gelesen durch einen Recherche-Agenten. **Die VRAM-Werte sind Schätzungen (Gewichte plus KV-Cache bei q8_0 plus ca. 0,5 GB), nicht gemessen. Es gibt keine unabhängigen Reverse-Engineering-Benchmarks.** Tool-Calling-Qualität in MCP-Ketten ist für keines der Modelle geprüft. Die Modellnamen stammen aus der Recherche und werden beim `ollama pull` verifiziert.

| Rang | Tag | Größe | VRAM bei 32k Kontext (geschätzt) | Lizenz |
|---|---|---|---|---|
| 1 | `gemma4:12b-it-q4_K_M` | 8,0 GB | 10 bis 11 GB | nicht angegeben |
| 2 | `ornith:9b-q4_K_M` | 5,6 GB | 7 bis 8 GB | MIT |
| 3 | `qwen3.5:9b-q4_K_M` | 6,6 GB | 8 bis 9 GB | unklar |
| 4 | `gpt-oss:20b` | 14 GB | 15 bis 16 GB, nur bei komplett freier GPU | Apache 2.0 |
| 5 | `ornith:35b` (MoE) | 21 GB | ca. 12 GB GPU plus 10 GB RAM | MIT |

Fallback für etwa 8 GB: `ornith:9b-q4_K_M` oder `gemma4:e4b-it-q4_K_M` (6,6 GB).
Embedding: `qwen3-embedding:0.6b` (639 MB, 100+ Sprachen, Code, 32K), Alternativen `embeddinggemma-2:440m` und `bge-m3`.

## Betriebsentscheidungen (vorläufig)
- Ollama läuft **nativ unter Windows**, nicht in Docker. Grund: gemeldete Blackwell-Probleme mit CUDA in WSL2 sowie Abstürze unter Docker/WSL2; die Analyse-Werkzeuge laufen weiterhin in Docker. Das weicht von Jans Wunsch "Ollama und Docker" ab und wird hier begründet.
- Portable Ollama 0.40.13 in `D:\Tools\sw-analyst\ollama-0.40.13`, eigenes Modellverzeichnis `D:\Tools\sw-analyst\ollama-models`. Die bestehende Ollama 0.35.1 und `~/.ollama` (29 GB Modelle anderer Projekte) bleiben unverändert.
- Umgebung nur über das Startskript `infra/start-ollama.ps1`, nicht dauerhaft per `setx`: `OLLAMA_FLASH_ATTENTION=1`, `OLLAMA_KV_CACHE_TYPE=q8_0`, `OLLAMA_CONTEXT_LENGTH` je nach freiem VRAM (16384 oder 32768), `OLLAMA_NUM_PARALLEL=1`, `OLLAMA_MAX_LOADED_MODELS=2`, `OLLAMA_KEEP_ALIVE=10m`.
- Modellstufe automatisch nach freiem VRAM (`infra/select-model.ps1`): mindestens 11 GB frei: Rang 1, mindestens 7 GB: Rang 2, sonst Fallback `gemma4:e4b`.

## Bekannte Risiken
- Offene Ollama-Issues mit Blackwell/RTX 5060 Ti unter Windows: Absturz "CUDA shared object initialization failed" beim Teil-Offload (#18232, #19122), Flash-Attention-Abstürze (#18276), CUDA-Erkennung mit 0 B VRAM (#18581). Eskalation bei Instabilität: zuerst Treiber wechseln, dann `OLLAMA_FLASH_ATTENTION=0`, dann `CUDA_MODULE_LOADING=EAGER`. Ein größeres Pagefile kann helfen.
- Bei 5 GB freiem VRAM passt keines der Top-Modelle vollständig auf die GPU. Teil-Offload ist langsamer und löst genau die oben genannten Abstürze aus.

## Offen bis zur Entscheidung
- Benchmark mit synthetischen Beispielen: Tool-Calling-Trefferquote, Antwortqualität auf synthetischem Dekompilat, Tokens pro Sekunde, Spitzen-VRAM und -RAM.
- Freigabe von Jan zu B2 (Apps schließen oder kleineres Modell).
