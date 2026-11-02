# ADR-0012: Colibri als Inferenz-Engine mit DeepSeek V4 Flash auf der SSD `ki_data`

Status: angenommen am 2026-11-02 (Auftrag von Jan: „Baue das neue Tool und lade auf die SSD ki_data das Model aus der Anmerkung“, „Für Colibri ist nur DeepSeek V4 Flash zu laden“). Ollama bleibt der Standard, bis ein echter Lauf vorliegt; Colibri wird mit `scripts\start.ps1 -Llm colibri` gewählt.

## Kontext
Jan will sehr große Modelle auf dem vorhandenen Rechner betreiben (Ryzen 7 7800X3D, 31 GB RAM, RTX 5060 Ti mit 16 GB). Colibri (`JustVugg/colibri`, Apache-2.0) hält nur den dichten Teil eines Mixture-of-Experts-Modells im Speicher und liest die Experten bei Bedarf von der Platte.

## Optionen
1. **DeepSeek V4 Flash auf `ki_data`:** Diese Option ist gewählt, Jan hat Modell und Datenträger festgelegt.
2. **Qwen3.6-35B-A3B:** Das Modell war zunächst empfohlen, weil es laut Colibri-Doku im RAM und VRAM läuft und damit um eine Größenordnung schneller ist. Jan hat es verworfen.
3. **Linux oder Vulkan statt Windows-CUDA:** Das ist nicht nötig. Das Windows-Paket von v2.1.0 enthält `coli_cuda_dsv4.dll` und `coli_cuda_dsv4_dg.dll` (geprüft im Archiv). Die Annahme, CUDA mit DeepSeek gehe nur unter Linux, trifft auf diese Version nicht zu.

## Entscheidung
- **Engine:** Colibri 2.1.0 aus den gepinnten Release-Archiven mit SHA-256 (`infra/manifest.json`), installiert unter `D:\Tools\sw-analyst\colibri-2.1.0`. Genutzt wird nur `coli serve` auf `127.0.0.1`. `START-HERE`, `coli setup`, `coli web` und `coli mcp` bleiben ungenutzt, weil dort Downloads, Websuche und Fremdkonfiguration liegen.
- **Modell:** `deepseek-ai/DeepSeek-V4-Flash-0731`, Revision `7872f01b1d1fe23eabc4c98b48bffcef5a386062`, Lizenz MIT. Geladen werden nur Gewichte und Metadaten (`infra/fetch-colibri-model.py`). Der Python-Code im Modell-Repository (`encoding/`, `inference/`) wird nicht geladen.
- **Ablage und Integrität:** Der Datenträger wird über den Namen `ki_data` gefunden, nicht über den Laufwerksbuchstaben. Weil er austauschbar ist und exFAT keine Rechte kennt, belegt sein Inhalt nichts über sich selbst: Größen und Hashes aller Dateien stehen im Repository (`infra/colibri-model.files.json`). Der Preflight prüft bei jedem Lauf die Größen, `start.ps1` vor dem Laden alle Hashes (rund 6 Minuten, `-SkipModelHash` überspringt das mit Warnung). Bei Abweichung startet nichts; es gibt keinen Rückfall auf einen anderen Pfad.
- **Zugriff:** Pro Start ein zufälliger Schlüssel, nie auf der Platte. Nur `coli serve` und die App bekommen ihn, die App entfernt ihn aus ihrer Umgebung, bevor sie Kindprozesse startet. Der Client spricht nur Loopback an und folgt weder Proxy-Einstellungen noch Weiterleitungen.
- **Installation:** Die Engine wird wie Ollama einmalig beim ersten Start mit `-Llm colibri` von der gepinnten URL geladen. `-Offline` verhindert das. Im laufenden Betrieb baut die Plattform keine Verbindung nach außen auf (Verbot 6).
- **Einstellungen aus der Hardware:** `src/sw_analyst/colibri_settings.py` ermittelt freien RAM, GPU, freien VRAM, Bus und Lesetempo des Datenträgers und wählt daraus die Einstellungen; `start.ps1` wendet sie nach dem Start von Docker an und legt sie unter `data\run\colibri-settings.json` ab.
    - **RAM:** `--ram` ist ein Planungswert und wird vom Betriebssystem nicht erzwungen. Gewählt wird der freie RAM minus 4 GB, weil die HostGuard einen Auftrag unter 3 GB freiem RAM pausiert. Die Obergrenze sind 20 GB, weil das Limit von 24 GB für WSL, Docker und Modelle gemeinsam gilt, und nie mehr als der Gesamtspeicher minus 7 GB für Windows. Die Untergrenze sind 12 GB (gemessen mit `coli plan`: 5,8 GB dichte Gewichte und 5,9 GB Laufzeit). `-RamGb` setzt den Wert von Hand.
    - **GPU:** Es gilt die Kartentabelle der Colibri-Doku, angewandt auf den freien VRAM: ab 11 GB die volle GPU-Stufe, ab 7 GB ohne Prefill-Bank, ab 4,5 GB ohne dichte Spiegel, darunter nur CPU.
    - **Kontext:** 16384 Token, darauf sind die Prompts des Runners ausgelegt.
    - `coli tune` misst danach auf dem Rechner und speichert ein Profil, das `coli serve` selbst liest.
- **Anpassungen der Kette an das Tempo:** Der Client wartet bis zu 10 Stunden auf eine Antwort. Das Zeitbudget eines Auftrags gilt mit Faktor 30 (`budget_factor`), weil dasselbe Werk sonst abgeschnitten würde. Thinking ist aus, weil es bei diesem Tempo Stunden kostet.
- **Erster echter Test:** `scripts\start.ps1 -Llm colibri -ColibriGate` startet `tests/bench/colibri_gate.py`. Dieser Lauf prüft Wiederholbarkeit, die Quote gültiger JSON-Antworten mit der Prüfung des Runners, Speicher, ausgehende Verbindungen und einen echten Auftrag, und schreibt die Ergebnisse nach `data\eval\colibri-gate-*`. Colibri wird erst Standard, wenn dieser Test bestanden ist und der Vergleich mit `qwen3:14b` das trägt.

## Folgen
Belegt:
- **Kein Seed:** Colibri ignoriert `seed` (`docs/api.md`), und DeepSeek V4 läuft nur greedy. Der Client führt deshalb keinen Seed, damit kein Bericht einen nennt. Reproduzierbar ist ein Lauf nur bei gleicher Eingabe, gleichem Modell, gleicher Engine und gleichem Backend; der Modellname in Schritten und Berichten nennt deshalb Revision und Engine-Version. Den Backend-Wechsel dokumentiert die Doku als mögliche Abweichung.
- **Kein Schema-Zwang:** Ein JSON-Schema wird nicht beim Sampling erzwungen, und auf diesem Motor gibt es keine Grammatik. Die erlaubten Antworten stehen ohnehin als Text im Prompt. Das Schema wird nicht zusätzlich angehängt, weil es jeden Prompt verlängern würde und ein Prefill hier Minuten kostet. Ungültige Antworten laufen über die vorhandene Rückmeldung im Runner, und `validate_action` bleibt die Schutzgrenze. Diese Prüfung wird nicht gelockert.
- **Protokoll:** Die Schritte des Runners halten nun dauerhaft `think` und `seed` fest. Zuvor überschrieb `finish_step` diese Angaben, und `think=on` stand fest im Code.
- **Prüfung der Netzwerk-Clients:** Der Sicherheitstest `test_only_the_llm_client_talks_to_a_network_library` erlaubt nun `ollama.py` und `colibri.py`. Beide weisen Adressen außerhalb von Loopback ab, das prüft `test_llm_client_refuses_anything_but_loopback`.
- **Tempo:** Die SSD ist über USB angebunden. Gemessen wurden 450 MB/s ungepuffert bei zufälligen Lesezugriffen von 12,6 MB (15 Sekunden, während der Download lief).

Hypothese, nicht gemessen:
- Die Doku nennt rund 230 Experten-Fehlzugriffe pro Token bei 32 GB RAM und 16 GB VRAM. Daraus folgen rund 0,16 Token pro Sekunde allein durch die Platte, also rund 52 Minuten für 500 Token. Mit weniger RAM als 32 GB kann es langsamer werden. Colibri ist auf diesem Datenträger damit eine Stapelverarbeitung, keine interaktive Nutzung.
- Eine Kopie auf der internen NVMe (`COLI_MODEL_MIRROR`) würde die Lesezugriffe aufteilen und belegt dort 167 GB. Das ist nicht umgesetzt, weil Jan `ki_data` festgelegt hat.

Offen:
- Der erste echte Lauf steht aus, bis das Modell geladen ist: Tempo, Speicher, Quote gültiger JSON-Antworten, Wiederholbarkeit, Vergleich mit `qwen3:14b`.
- **Freigabe durch Jan offen:** Verbot 8 verlangt eine statische Prüfung vor der Installation. Sie ist erfolgt, aber nur als Stichprobe: Die Binaries (rund 3 MB C-Code) und der Python-Server (557 KB) lassen sich so nicht vollständig auditieren, und sie sind nicht signiert. Die Engine läuft wie Ollama auf dem Host und verarbeitet über den Prompt Inhalte aus Proben. Daher gilt sie nur für harmlose Testproben; echte Proben bleiben der VM vorbehalten.
- Die Engine liest auf dem Datenträger auch die Dateien `.coli_usage` und `.coli_ssd`, die sie selbst schreibt und die nicht gepinnt werden können. Ein manipulierter Inhalt dieser Dateien ist nicht geprüft.
- Ob nach dem Abziehen der SSD laufende Aufträge sauber enden, ist nicht geprüft.
- **Abbrechen dauert:** Ein Auftrag prüft den Abbruch zwischen zwei Aufgaben, und der Client wartet ohne Streaming auf die ganze Antwort. Bei diesem Tempo reagiert „Abbrechen“ im Dashboard daher erst nach Stunden. `scripts\stop.ps1 -Force` beendet sofort.
- Die Attrappe im Trockenlauf belegt nur den Weg durch Launcher, Schlüssel, Prüfungen und Auftrag, nichts über die echte Engine.
