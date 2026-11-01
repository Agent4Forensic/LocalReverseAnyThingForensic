# ADR-0009: Harmlose Beispielproben im Repository

Status: angenommen am 2026-11-01 auf ausdrückliche Anweisung von Jan.

## Kontext
CLAUDE.md Verbot 2 schließt Samples im Repository aus. Bisher erzeugte `example/samples.py` die Proben der Challenges nur im Speicher. Jan will die Beispieldaten (auch die PE-Dateien) im Repository haben, mit einem Verweis auf ihre Herkunft.

## Optionen
1. **Weiter nur erzeugen:** Das Repository bleibt frei von Proben. Die Dateien sind dann aber nicht direkt greifbar.
2. **Alle Proben erlauben:** Das ist verworfen, weil damit echte Schadsoftware durchrutschen könnte.
3. **Gewählt:** Nur die selbst erzeugten, harmlosen Beispielproben sind erlaubt. Jede ist an Erzeuger, Pfad und Hash gebunden.

## Entscheidung
1. Ablage: `example/challenges/<id>/sample/<name>`. Der Name kommt aus `challenge.json` (`sample.name`).
2. Quelle bleibt die Erzeugerfunktion in `example/samples.py`. Die Datei ist nur eine Kopie ihrer Ausgabe. `example/samples.manifest.json` nennt je Datei Erzeuger, Challenge, Größe und SHA-256.
3. `python example/build_samples.py` schreibt Dateien und Manifest, `--check` prüft beides gegen die Erzeuger. `tests/unit/test_example_samples.py` führt die Prüfung bei jedem Testlauf aus.
4. Der Pre-Commit-Hook lässt eine Datei unter `example/challenges/*/sample/` nur durch, wenn Pfad und SHA-256 im gestagten Manifest stehen. Jede andere Probe, auch eine veränderte Beispielprobe, wird blockiert. Die übrigen Sperren (`.exe` und andere Endungen, `tests/corpus`, Secrets, Größe) bleiben unverändert.
5. In `.gitignore` gilt eine Ausnahme nur für genau diesen Pfad. Laut `.gitattributes` sind die Dateien binär, damit Windows die Zeilenenden nicht umschreibt und der Hash gültig bleibt.

## Folgen
- Die Proben liegen direkt im Repository. Das Dashboard zeigt den Pfad und ob die Datei noch der Ausgabe des Erzeugers entspricht.
- Der Virenschutz kann die PE-Proben (minimal, nicht lauffähig) heuristisch melden. Die Ausnahme für den Projektordner deckt sie ab. Wenn eine Probe verschwindet, stellt `python example/build_samples.py` sie wieder her.
- Eine neue Challenge braucht nach dem Anlegen einen Lauf von `build_samples.py`, sonst schlägt der Test fehl.
- Für echte Malware gilt Verbot 2 weiter ohne Ausnahme.
