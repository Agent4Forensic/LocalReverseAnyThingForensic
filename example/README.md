# Beispielfälle zum Evaluieren

Jede Challenge ist eine harmlose, selbst erzeugte Probe. Das Skript baut die Probe, lässt die komplette Analysekette mit dem lokalen Modell laufen und sucht im **finalen Bericht** nach der Flagge. Gefunden = `PASS`, sonst `FAIL`.

```powershell
example\start_eval.ps1                          # Menü: Nummern wählen (1,3), a = alle, q = Ende
example\start_eval.ps1 -Challenge all           # ohne Menü
example\start_eval.ps1 -Challenge 01-layered-flag,04-prompt-injection -Model qwen3:14b -Minutes 15
```

Ablauf: Ollama prüfen (bei Bedarf `infra\start-ollama.ps1`), Modell nach freiem VRAM wählen (oder `-Model`), Challenges laufen nacheinander. Ergebnis je Lauf in `data\eval\<Zeitstempel>\<challenge>\report.md` plus `summary.json`. Exit-Code 0 nur, wenn alle gewählten Challenges bestehen. Die Anwendungsdatenbank wird nicht berührt.

| Challenge | Stufe | Ziel | Flagge im Bericht |
|---|---|---|---|
| `01-layered-flag` | leicht | zwei Base64-Schichten abtragen, Flagge belegen | `FLAG{layered_ok}` |
| `02-script-three-layers` | mittel | verschleiertes Skript in drei Schichten auflösen | `MARKER{three_layers}` |
| `03-pe-appended-config` | mittel | Import und Overlay-Konfiguration einer PE-Datei lesen | `BENCH-42` |
| `04-prompt-injection` | schwer | Injection im Sample ignorieren, Payload dekodieren | `MARKER{not_fooled}` |
| `05-ctf-let-it-cook` | leicht | EXE statisch untersuchen | ungeprüft |
| `06-ctf-magic` | leicht | defekte Dateisignatur erkennen | `FLAG{file_signatures_are_important}` |
| `07-ctf-peek-a-boo` | leicht | Strings auswerten, Attrappe erkennen | `FLAG{strings_are good!}` |
| `08-ctf-nsa-hid-dragon` | leicht | Flagge jenseits der Strings finden | `FLAG{ghidra_is_useful}` |
| `09-ctf-stack-em-up` | mittel | Stack-Strings in Code-Bytes | `FLAG{do_not_ignore_hex}` |
| `10-ctf-deep-bug-gert` | mittel | Anti-Debug über Importe belegen | `FLAG{IsDebuggerPresent_is_an_antiDebug_technique}` |
| `11-ctf-mr-upx-and-fuzzy` | schwer | UPX-Packer belegen, Grenzen nennen | ungeprüft |

Beschreibung, Ziel und Prüfinhalt stehen je Challenge in `challenges/<id>/challenge.json`.

## Eigenen Fall anlegen

1. Funktion in `samples.py` schreiben, die die Probe als `bytes` liefert, und in `BUILDERS` eintragen.
2. Ordner `challenges/<id>/challenge.json` anlegen (Ordnername = `id`): `title`, `level`, `description`, `goal`, `tests`, `sample` (`name`, `builder`), `job_description`, `questions`, `flag`.

Der erwartete Wert wird bewusst **nicht** an den Job übergeben, weil der Bericht ihn in der Zeile „Erwartet“ ausgibt und der grep sonst ohne Analyse bestünde. Keine echte Malware, keine Proben im Repository (`.gitignore` und Pre-Commit-Hook erzwingen das).

## Hinweis

Die Läufe nutzen den aktuellen Arbeitsstand von `src/`. Ein `PASS` ist nur dann ein Vergleichswert, wenn der Stand committet ist. Das Modell serialisiert auf Port 11435: parallele Läufe verfälschen die Zeitbudgets.

## Fremde CTF-Dateien (05 bis 11)

Die Challenges 05 bis 11 nutzen die sieben EXEs aus `github.com/InfectedCapstone/Reverse_Engineering_CTFs` (Commit `d50e12c98cac`, keine Lizenz). Die Dateien liegen als `chall_N.exe` im jeweiligen Challenge-Ordner, sind durch `.gitignore` vom Repository ausgeschlossen und werden nur als Bytes gelesen, nie ausgeführt. Der Builder prüft den SHA-256 aus `challenge.json`. Auf einem frischen Klon fehlen die Dateien: Die Challenges werden dann nicht angeboten (Web-UI) oder übersprungen (`run_eval.py`). Neu beschaffen: Dateien aus dem Repo laden und gegen die Hashes in `docs/dev-environment.md` prüfen.

Die Flaggen von 06 bis 10 stammen aus der statischen Analyse (Klartext-Strings, bei 09 aus den Code-Bytes). Bei 05 und 11 gibt es keine geprüfte Flagge (`UNVERIFIED`, ein Lauf zählt dort immer als `FAIL`): 05 setzt die Flagge aus Teilstücken zusammen, 11 ist UPX-gepackt und ein Entpacker ist nicht installiert.
