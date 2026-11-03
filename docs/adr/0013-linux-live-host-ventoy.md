# ADR-0013: Linux-Live-Host über Ventoy statt Windows mit WSL und Hyper-V

Status: **angenommen am 2026-11-03.** Jan hat den Plan `docs/tasks/linux-live-ventoy.md` mit „Go“ freigegeben. Die offenen Fragen F1 bis F8 hat Jan nicht einzeln beantwortet. Umgesetzt sind deshalb die Empfehlungen des Plans; sie stehen unten als **Standard bis zur Bestätigung durch Jan** und lassen sich ohne Umbau ändern. Windows bleibt lauffähig: Die PowerShell-Skripte sind unverändert (F5).

## Kontext
Jan will die Plattform unter Linux als Live-System von einer externen SSD (Ventoy) betreiben, um RAM und GPU voll zu nutzen. Unter Windows belegen Desktop-Apps rund 12 GB VRAM (B2), WSL und Docker sind auf 24 GB begrenzt, Windows behält 7 GB (B1, B4), und Hyper-V scheitert an fehlenden Admin-Rechten (B3).

## Optionen
1. **Ventoy mit Linux-vDisk (`.vtoy`, installiertes Debian 13 als Image) plus eigene ext4-Datenpartition:** normale Installation mit Kernel-Updates, DKMS und Docker `overlay2`; System-Image und Daten getrennt. **Gewählt.**
2. **Ventoy mit Live-ISO und `persistence.dat`:** einfach, aber Docker auf Overlay-Root, NVIDIA-Treiber an die ISO gebunden, keine Kernel-Updates. Nur Rückfall.
3. **Feste Installation auf der SSD ohne Ventoy:** robust, verliert aber das Ventoy-Menü.
4. **Bei Windows bleiben:** Engpässe B1 bis B4 bleiben.

## Entscheidung
- **Host:** Debian 13 minimal mit Xfce als vDisk; Daten auf der Partition `SWDATA` unter `/srv/sw-analyst` (`SW_ROOT`). Einrichtung mit `infra/linux/provision.sh` (nur Debian-Pakete), Ablauf in `docs/runbooks/linux-ventoy.md`.
- **Launcher:** `scripts/start.sh`, `stop.sh` und `cleanup.sh` sind dünne Hüllen um `src/sw_analyst/launcher.py` (nur Standardbibliothek, mit Tests). Das ersetzt eine Bash-Kopie der 525 Zeilen von `start.ps1`, weil Python-Logik testbar ist und Preflight und Colibri-Einstellungen ohnehin in Python liegen.
- **Zwei Modi:** `start.sh --setup` lädt einmalig online aus den Pins (Ollama, venv, Modell, Images). Ein normaler Start lädt nie etwas und verweigert sich, solange der Host online ist (Preflight `net:offline`: keine Standardroute, keine aktive physische Verbindung). `--allow-online` hebt das nur mit Warnung auf.
- **Netz:** `infra/linux/sw-mode offline|online`. Offline ist Standard beim Booten (`sw-offline.service`): NetworkManager aus, Funk gesperrt, eigene nftables-Tabelle verwirft alles außer Loopback, auch Weiterleitung.
- **Austausch mit der internen Platte:** `infra/linux/sw-share` hängt die Windows-Partition (ntfs3, exFAT, BitLocker über `cryptsetup bitlk`) unter `/run/sw-analyst/hostd` (0700 root) ein und bindet nur `SHARE_DIR` nach `/mnt/host-share`, immer `noexec,nosuid,nodev`, auf Wunsch `ro`. Der Preflight meldet eine Freigabe ohne diese Optionen als Fehler und eine eingehängte als Warnung.
- **Ressourcen (F2):** Der Host behält 3 GB. App, Ollama und Colibri laufen in der systemd-Benutzer-Slice `sw-analyst.slice` mit `MemoryMax` = RAM gesamt minus 3 GB und ohne Swap; Container behalten ihre eigenen Limits. zram (2 GB) statt Swap auf der USB-SSD. Unter Windows gilt die 24-GB-Regel unverändert.
- **GPU:** bleibt beim Host für Ollama. Kein `nvidia-container-toolkit`, weil kein Werkzeug-Container die GPU braucht.
- **Pins:** `infra/manifest.json` trägt unter `linux` die Linux-Archive: Ollama 0.40.13 `ollama-linux-amd64.tar.zst` (SHA-256 am 2026-11-03 selbst über den vollständigen Download gemessen, gleich der Upstream-Liste), Colibri 2.1.0 `colibri-v2.1.0-linux-x86_64.tar.gz` (selbst gemessen). Entpackt wird mit dem `data`-Filter von `tarfile` (keine absoluten Pfade, kein `..`, keine Links nach außen, keine setuid-Bits).

### Standards für F1 bis F8 (bis Jan anders entscheidet)
| Frage | Standard | Wo änderbar |
|---|---|---|
| F1 Isolation echter Proben | KVM/QEMU-VM ohne NIC mit vsock als Nachfolger der Hyper-V-VM. **Noch nicht umgesetzt** (I8); bis dahin keine echten Proben auf dem Live-Host. | eigener Plan nach Abnahme |
| F2 Ressourcen | Host behält 3 GB, Rest für die Plattform | `linuxhost.HOST_RESERVE_GB` |
| F3 Secure Boot | aus (sonst MOK für Ventoy und NVIDIA) | Runbook 1 |
| F4 SWDATA verschlüsseln | ja, LUKS2 | Runbook 3.1 |
| F5 Windows-Skripte | bleiben unverändert | – |
| F6 Docker | Root-Dienst `docker.io` aus Debian, Benutzer in Gruppe `docker` | `provision.sh` |
| F7 Colibri-Modell | weiter über das Label `ki_data`; Spiegel mit `--colibri-mirror` | `manifest.json` |
| F8 SSD | offen; Layout für mindestens 512 GB NVMe am USB 3.2 | Runbook |

## Folgen
Belegt (Tests in diesem Repository):
- `tests/unit/test_linuxhost.py` und `tests/unit/test_launcher.py`: Speicher, Listener, Mounts, Routen, cgroup-Grenze, Offline-, Freigabe- und SWDATA-Prüfung, Eigentumsprüfung von Prozessen, Löschgrenzen, gepinnter Download, sicheres Entpacken, Slice-Grenze, Modellwahl nach VRAM.
- `tests/unit/test_colibri_settings.py` prüft die Regeln beider Hosts auf jedem Betriebssystem.
- Gesamte Testsuite grün unter Linux (Python 3.13), `shellcheck` ohne Befund für alle neuen Shell-Skripte.
- Probelauf `scripts/start.sh` in einer Linux-Umgebung ohne GPU: Preflight meldet `net:offline FEHLER` und fehlendes Ollama wie vorgesehen und startet nichts.

Hypothesen (Spike S1 auf Jans Hardware):
- Der vDisk-Start klappt und übersteht Kernel-Updates.
- Debian 13 liefert einen NVIDIA-Treiber ab Serie 570 für die RTX 5060 Ti; sonst braucht das NVIDIA-Repository eine Prüfung nach Verbot 8.
- Freier VRAM nahe 15,5 GB.
- `systemd-run --user --scope` mit Speicher-Delegation funktioniert in der Xfce-Sitzung.

Belegte Einschränkung (korrigiert am 2026-11-03): Colibri unterstützt CUDA unter Linux, aber nur als eigener Build aus dem Quelltext (`make deepseek-v4 CUDA=1`, linkt `libcudart`); ein fertiges Linux-CUDA-Archiv gibt es für v2.1.0 nicht (404). Das gepinnte Linux-Archiv ist für CUDA ein CPU-Build, enthält aber ein Vulkan-Backend (`COLI_VULKAN=1`, 69 SPIR-V-Shader, lädt `libvulkan.so.1`); belegt durch Inhaltsliste und Zeichenketten der Binärdateien. `colibri_settings` nutzt unter Linux bisher weder Vulkan noch CUDA und setzt die CPU. Welcher GPU-Weg kommt, entscheidet Jan. `tests/bench/colibri_gate.py` misst Speicher und Verbindungen noch über PowerShell und läuft nur unter Windows.

Risiken: Der Analyserechner ist Jans Alltagsrechner mit Windows-Platte; deshalb Freigabe nur auf Anforderung und Aushängen vor Läufen mit echten Proben. Mitglieder der Gruppe `docker` haben faktisch Root-Rechte. Eine VM-Flucht bleibt Restrisiko wie bisher.
