# ADR-0006: Erweiterung der Werkzeug-Allowlist für die statische Analyse (Entwurf, wartet auf Freigabe)

Status: vorgeschlagen am 2026-10-31. Keine Umsetzung vor ausdrücklicher Freigabe durch Jan (CLAUDE.md Verbot 3).

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

## Empfehlung
Paket A jetzt, Paket B danach in dieser Reihenfolge: Ghidra-Werkzeuge, capa und FLOSS, jadx. **Sicherheitshinweis:** Auch Paket A parst unvertrauenswürdige Bytes im App-Prozess auf dem Host. Das bleibt vertretbar, weil dort nur harmlose Proben liegen dürfen. Echte Proben brauchen in jedem Fall den VM-Gateway.

## Folgen
- `tests/security/test_host_safety.py` führt die Allowlist als feste Liste und schlägt bei jeder Änderung fehl. Die Liste wird mit diesem ADR angepasst, nicht vorher.
- Rezepte und Leitfäden werden nach der Freigabe erweitert (GAP-Hinweise entfallen, Ranking aus Blueprint 02 wird anwendbar).
- Das Modell braucht bei Dekompilat mehr Kontext. Die Modellwahl wird danach neu gemessen (`docs/review/model-evaluation.md`).
- Die Arena-Proben aus `tests/bench/run_live.py` werden um Fälle mit Code ergänzt.

## Offene Frage an Jan
Paket A freigeben? Paket B freigeben, und soll es erst auf dem Entwicklungsrechner mit harmlosen Proben entstehen und dann in die VM wandern?
