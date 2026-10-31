# ADR-0006: Erweiterung der Werkzeug-Allowlist für die statische Analyse

Status: **angenommen** am 2026-10-31. Jan hat Paket A und Paket B ausdrücklich freigegeben (CLAUDE.md Verbot 3). Paket B entsteht zuerst auf dem Entwicklungsrechner und nur mit harmlosen Proben. MCP bleibt intern, REA ist zurückgestellt.

## Kontext
Die lokale KI hat 13 lesende Werkzeuge. Für Skripte reicht das weitgehend. Bei PE und APK endet die Analyse an der Oberfläche:
- **PE:** Header, Importe, Strings und Blobs sind sichtbar, Code nicht. Fragen nach Kontrollfluss, Schlüsselhandhabung oder Fähigkeiten bleiben Hypothesen. Das Ranking aus Blueprint 02 ist nicht anwendbar.
- **APK:** `strings_extract` sieht komprimierte Einträge nicht, `zip_read_text` verweigert Binär-XML und DEX. Manifest, Berechtigungen und Endpunkte sind damit nicht lesbar. Das Rezept kann sein Ziel heute nicht erreichen und benennt die Lücke deshalb als GAP.
- **Verschachtelung:** Eingebettete Dateien lassen sich nur herauslösen, wenn sie kodiert sind. Ein unkodiert angehängtes PE erreicht die Rekursion nicht.

Der Plan (Abschnitt 6.2) sieht diese Werkzeuge bereits vor. Die Allowlist selbst braucht trotzdem eine Freigabe.

## Optionen
1. **Status quo:** kein Mehrrisiko, aber PE und APK bleiben oberflächlich.
2. **Paket A:** kleine eigene Python-Werkzeuge ohne neue Abhängigkeit, gleiche Risikoklasse wie heute.
3. **Paket A und B:** zusätzlich Fremdwerkzeuge im Container.

## Entscheidung
Option 3. Paket A zuerst, Paket B danach in der Reihenfolge Ghidra-Werkzeuge, capa, FLOSS und YARA, jadx.

## Paket A: eigene Werkzeuge, nur Python-Standardbibliothek
| Werkzeug | Zweck | Grenzen |
|---|---|---|
| `extract_range(path, offset, length)` | Bereich als `derived/` ablegen (Overlay, Ressource), damit die Rekursion greift | max. 8 MiB, Quote wie `decode_layer` |
| `zip_extract(path, member)` | Eintrag als `derived/` ablegen | Bomben-Limit, kein Pfad aus dem Archiv, Name vom Gateway vergeben |
| `pe_resources(path)` | Ressourcenbaum mit Offset, Größe, Entropie | nur Lesen, gleiche Robustheitstests wie `pe_headers` |
| `apk_manifest(path)` | Binär-XML des Manifests zu Text | eigener Parser, Fuzz-Test Pflicht |
| `decode_layer`, neue Methoden | `base32`, `base85`, `xor_key` und `rc4` mit Schlüssel als Hex-Argument, Zeichencode-Listen | Schlüssel muss aus einem Beleg stammen; kein Ausprobieren von Schlüssellisten |

## Paket B: Fremdwerkzeuge im Container
`list_functions`, `disassemble`, `decompile`, `xrefs`, `basic_blocks` (Ghidra headless), `capa_scan`, `yara_scan`, `floss_decode`, `jadx_decompile`.

Vorgaben:
- Container mit `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit --memory --cpus`, Benutzer ohne Root, `tmpfs` für Arbeitsdateien, Probe `ro,noexec`, Label `sw-analyst`.
- Nur benannte Werkzeuge mit festem Schema. Das MCP-Protokoll wird nicht durchgereicht. Keine Ghidra-Skripte vom Modell (Verbot 4).
- Version, Hash und Lizenz je Abhängigkeit (Verbot 5). Regeln von capa und YARA gepinnt.
- Treffer von capa und YARA gelten als Hypothese, bis Code sie belegt. Flussdiagramme entstehen aus `basic_blocks`, das Modell beschriftet nur.
- Timeout und Ausgabelimit je Aufruf, Ergebnis als `derived/`-Datei plus Evidence.

**Sicherheitshinweis:** Auch Paket A parst unvertrauenswürdige Bytes im App-Prozess auf dem Host. Das bleibt vertretbar, weil dort nur harmlose Proben liegen dürfen. Echte Proben brauchen in jedem Fall den VM-Gateway.

## Umsetzung (2026-10-31)
Bestätigt durch `tests/security/test_container_runner.py` und `tests/integration/test_tool_images.py` (echte Images, harmlose Proben):
- **Drei Images:** `sw-analyst/ghidra`, `sw-analyst/triage` (capa, FLOSS, yara-x), `sw-analyst/jadx`. Basis-Images per Digest, Downloads per SHA-256 in `infra/tools/Dockerfile` und `infra/manifest.json`. Lizenzen: Apache-2.0 (Ghidra, capa, FLOSS, jadx), BSD-3-Clause (yara-x).
- **Kein Modelltext im Container:** Jede Datei läuft pro Werkzeug einmal als fester Batch. Das Ergebnis liegt in `<job>/tool-cache/`, die Werkzeuge filtern es danach nur noch in Python. Der Container erhält nur eine feste Operation aus `OPS`.
- **Ghidra ohne MCP:** `analyzeHeadless` mit dem festen Skript `ExportAll.java` statt `pyghidra-mcp`. Das spart MCP-Client, Python-Abhängigkeiten und eine weitere Angriffsfläche. Es gibt deshalb keinen MCP-Server und keine `.mcp.json`; das Gateway bleibt eine interne Allowlist.
- **YARA:** eigener kleiner Regelsatz `infra/tools/rules/sw_analyst.yar`, mit dem Image gepinnt.
- **Eine Ausnahme vom Prozessverbot:** `gateway/container_runner.py` ist das einzige modellnahe Modul, das `subprocess` importieren darf. `test_host_safety.py` und `test_container_runner.py` halten das fest.
- **Ohne Docker oder Images** bleiben diese Werkzeuge aus der Allowlist und die Rezeptschritte mit `requires_tools` werden nicht geplant.
- **Nicht Teil dieses ADR, weiter offen:** `apktool_decode`, `list_native_libs`, `extract_embedded`, `emulate_function`, radare2, binwalk, REA.

**Nach dem Security-Review ergänzt:** Der Parser für Binär-XML, `pe_resources` und der tar-Leser von jadx haben Obergrenzen für Rechenzeit und Speicher (`tests/unit/test_review_fixes.py`). Container starten mit `--pull never` und `--log-driver none`, jedes Werkzeug im Container endet nach 590 s. Ein Ergebnis über Zeit-, Speicher- oder Ausgabelimit wird bis zum Neustart nicht wiederholt. JSON-Ausgaben sind auf 128 MiB begrenzt, die tar-Ausgabe von jadx auf 256 MiB.

**Abweichungen von den Vorgaben, bitte zur Kenntnis nehmen:**
1. **Probe nicht als `ro,noexec`-Mount:** Docker bietet `noexec` für Bind-Mounts nicht an. Die Probe kommt stattdessen über stdin in ein `noexec`-tmpfs und ist dort nur per Dateimodus 0444 schreibgeschützt. Dafür wird kein Hostpfad in den Container gemountet.
2. **`/tmp` im Triage-Image ist ausführbar:** capa und FLOSS sind PyInstaller-Binaries und laden ihre Bibliotheken von dort. Ein Angreifer, der einen Parser in diesem Container übernimmt, könnte also dort Code ablegen und starten, bleibt aber ohne Netz, ohne Capabilities, ohne Root und ohne Hostmount. In den Images für Ghidra und jadx ist `/tmp` `noexec`.
3. **Ergebnis liegt nicht unter `derived/`,** sondern in `tool-cache/`, sonst würde die Artefakt-Rekursion jedes Ergebnis erneut analysieren. Evidence entsteht wie bei allen Werkzeugen aus dem Werkzeugergebnis.

**Sicherheitshinweis:** Container auf dem Entwicklungsrechner ersetzen die Hyper-V-VM nicht. Echte Proben bleiben auf diesem Rechner verboten.

## Folgen
- `tests/security/test_host_safety.py` führt die Allowlist als feste Liste und schlägt bei jeder Änderung fehl. Die Liste wird mit diesem ADR angepasst, nicht vorher.
- Rezepte und Leitfäden werden nach der Freigabe erweitert (GAP-Hinweise entfallen, Ranking aus Blueprint 02 wird anwendbar).
- Das Modell braucht bei Dekompilat mehr Kontext. Die Modellwahl wird danach neu gemessen (`docs/review/model-evaluation.md`).
- Die Arena-Proben aus `tests/bench/run_live.py` werden um Fälle mit Code ergänzt.
