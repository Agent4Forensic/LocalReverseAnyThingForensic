# Plan: Umstieg auf Linux, Start als Live-System über Ventoy

Stand: 2026-11-03 · Status: **freigegeben („Go“ von Jan), S2 bis S4 und S6 umgesetzt**; S1 (Hardware), S5 (erster echter Lauf) und S7 (KVM-VM) offen. ADR-0013 ist angenommen, Standards für F1 bis F8 dort. Schritt-für-Schritt: `docs/runbooks/linux-ventoy.md`.

Abweichungen bei der Umsetzung: Der Launcher ist ein Python-Modul (`src/sw_analyst/launcher.py`) mit dünnen `.sh`-Hüllen statt reiner Shell-Skripte, weil er so testbar ist. Statt `--update`/`--build-tools` gibt es `start.sh --setup` (einmalig online). `nvidia-container-toolkit` entfällt, weil kein Werkzeug-Container die GPU braucht. Colibri läuft unter Linux vorerst auf der CPU: v2.1.0 hat kein fertiges Linux-CUDA-Archiv; GPU geht über das Vulkan-Backend des gepinnten Archivs oder einen CUDA-Eigenbau (`make deepseek-v4 CUDA=1`).

Ziel: sw-analyst läuft vollständig unter Linux, gestartet von einer externen SSD über Ventoy, ohne Windows darunter. Damit stehen fast der ganze RAM (31 GB) und der ganze VRAM (16 GB) zur Verfügung. Alles, was die Plattform braucht (System, Werkzeuge, Modelle, Docker-Images, Fälle, Audit-Log), liegt auf der SSD. Die interne Festplatte des Rechners wird nur als Austauschordner eingebunden.

Legende: **belegt** (im Repo oder in der Doku geprüft) · **Annahme** (im Spike zu prüfen) · **offen** (Frage an Jan).

---

## 1. Warum das etwas bringt (belegt aus `docs/STATUS.md`)

| Engpass heute (Windows) | Unter Linux-Live |
|---|---|
| B2: 12,3 von 16,3 GB VRAM durch Desktop-Apps belegt | Kein Browser, Steam, Zotero im Hintergrund. Freier VRAM nahe 15,5 GB (Annahme, Messung in S1). |
| B1/B4: 24-GB-Limit für WSL, Docker und Modelle; Windows behält 7 GB; frei waren 3,7 GB | Kein WSL, kein Docker Desktop. Das Hostsystem braucht mit schlanker Oberfläche etwa 1 bis 2 GB. |
| B3: Hyper-V braucht Admin-Rechte, VM fehlt noch | Root auf dem eigenen Live-System; KVM ist im Kernel. |
| Docker Desktop als VM-Schicht | Docker Engine nativ, Container ohne Zwischen-VM. |

---

## 2. Empfohlener Aufbau: Ventoy mit Linux-vDisk statt Live-ISO

Es gibt zwei Wege, Linux über Ventoy zu starten. **Empfehlung: Weg A.**

### Weg A (empfohlen): Installiertes Debian als Image-Datei (Ventoy „Linux vDisk“, Endung `.vtoy`)
Ventoy startet eine Image-Datei, in die ein normales Debian installiert wurde. Das System verhält sich wie eine normale Installation, liegt aber als eine Datei auf dem Ventoy-Stick.

- Alles bleibt erhalten (persistent), ohne Overlay-Tricks.
- Kernel-Updates, DKMS (NVIDIA-Treiber) und Docker mit `overlay2` funktionieren wie auf einer normalen Installation.
- Das Image lässt sich als Datei sichern, versionieren (`debian-sw-2026-11-03.vtoy`) und per SHA-256 festhalten. Das hilft bei der Nachvollziehbarkeit.

### Weg B (nur Rückfall): Live-ISO plus Ventoy-Persistenz (`persistence.dat`)
- Docker `overlay2` auf einem Overlay-Root funktioniert nicht zuverlässig; `/var/lib/docker` müsste ohnehin auf eine eigene ext4-Partition.
- Der NVIDIA-Treiber muss gegen den Kernel der ISO gebaut werden; ein neues ISO bricht den Treiber.
- Kernel-Updates sind nicht möglich.
- Deshalb nur, falls Weg A auf der Hardware nicht startet.

### Distribution
**Debian 13 (trixie), Netinstall, ohne Desktop-Task**, danach nur das Nötige. Begründung: kein Snap, kein Hintergrunddienst-Ballast, lange Pflege, apt-Pakete sind signiert und versionierbar.
- Oberfläche: **Xfce minimal** (`xfce4`, `xfce4-terminal`, `thunar`, `firefox-esr`, `--no-install-recommends`). Etwa 0,5 GB RAM, kaum VRAM. Wer weniger will: `sway` + `foot` (Annahme: unter 0,2 GB). Ohne Oberfläche geht es auch, aber das Dashboard braucht einen Browser.
- **Annahme (Spike S1):** RTX 5060 Ti (Blackwell) braucht den NVIDIA-Treiber ab Serie 570 mit offenen Kernelmodulen. Liefert Debian 13 diese Version nicht, kommt der Treiber aus dem NVIDIA-CUDA-Repository für Debian (`nvidia-open`), gepinnt auf Version. Rückfall: Ubuntu Server LTS minimal, dort `ubuntu-drivers`.

---

## 3. Datenträger-Layout (externe SSD)

Empfohlen: externe **NVMe-SSD im USB-3.2/USB4-Gehäuse**, mindestens 512 GB. Ein USB-Stick ist zu langsam (Docker-Images, Modelle, Colibri liest Experten von der Platte; ADR-0012 misst 450 MB/s am USB).

Ventoy wird mit „Preserve some space at the end of the disk“ installiert. Der reservierte Bereich wird danach eine eigene ext4-Partition.

| Partition | Dateisystem | Inhalt | Größe (Vorschlag) |
|---|---|---|---|
| 1 `Ventoy` | exFAT | `debian-sw.vtoy` (System, feste Größe), Rettungs-ISOs (Debian-Live, Installer) | 80 GB |
| 2 `VTOYEFI` | FAT | Ventoy-Bootloader (von Ventoy angelegt) | 32 MB |
| 3 `SWDATA` | **LUKS2 + ext4** (offen: Verschlüsselung) | alles Persistente der Plattform, siehe unten | Rest |

Inhalt von `SWDATA`, eingehängt unter `/srv/sw-analyst`:

```
/srv/sw-analyst/
├─ repo/          Git-Checkout von sw-analyst
├─ venv/          Python-Umgebung aus requirements.lock (--require-hashes)
├─ tools/         ollama-<ver>/, colibri-<ver>/ (aus infra/manifest.json, Hash-geprüft)
├─ models/ollama/ OLLAMA_MODELS
├─ models/colibri/ DeepSeek V4 Flash (ersetzt oder spiegelt ki_data, siehe 8.)
├─ docker/        data-root der Docker Engine (/etc/docker/daemon.json)
├─ data/          Aufträge, Berichte, Audit-Log, run/, logs/
├─ vendor/        Offline-Wheelhouse
└─ share -> /mnt/host-share (Austauschordner der internen Platte, Abschnitt 4)
```

Warum Daten getrennt vom System-Image: Das System-Image lässt sich neu bauen oder zurückrollen, ohne Fälle, Modelle und Images zu verlieren. Das System-Image enthält keine Fall- oder Probendaten.

`/etc/fstab` (Kennung über UUID, nie über `/dev/sdX`, damit der Start auf einem anderen Rechner nicht hängt):

```
# SWDATA (bei LUKS: /etc/crypttab mit luks,discard, Passwort beim Start)
UUID=<swdata>  /srv/sw-analyst  ext4  defaults,noatime,nodev,nofail,x-systemd.device-timeout=10s  0 2
```

---

## 4. Austausch mit der internen Festplatte (Windows-Laufwerk)

Ziel: Proben und Berichte zwischen Windows und dem Live-System tauschen, ohne Windows zu gefährden und ohne dass eine Probe auf dem Host ausführbar wird.

**Voraussetzungen unter Windows (einmalig, von Jan):**
1. Schnellstart ausschalten und Ruhezustand aus: `powercfg /h off` (Admin). Sonst ist NTFS „dirty“ und `ntfs3` hängt nur lesend ein; Schreiben in diesem Zustand kann Windows-Daten beschädigen.
2. Ordner anlegen: `D:\sw-analyst-share\in` (Proben hinein), `D:\sw-analyst-share\out` (Berichte heraus).
3. **Offen:** Ist `D:` mit BitLocker verschlüsselt? Dann braucht Linux den Wiederherstellungsschlüssel (`cryptsetup open --type bitlk`). Der Schlüssel wird nie auf der SSD gespeichert.

**Einbinden unter Linux** (Kernel-Treiber `ntfs3`, kein FUSE):

```
# /etc/fstab – Windows-D: nur auf Anforderung, nie automatisch beim Start
UUID=<ntfs-d>  /mnt/host-d  ntfs3  noauto,nofail,nodev,nosuid,noexec,uid=analyst,gid=analyst,umask=077,prealloc  0 0
```

- `noauto`: Eingehängt wird nur über das Skript `sw-share mount` (neu, Abschnitt 6). Startet die SSD auf einem fremden Rechner, wird dort nichts angefasst.
- `noexec,nosuid,nodev`: Eine Probe auf der Freigabe ist nie direkt ausführbar.
- Danach Bind-Mount nur des Austauschordners: `/mnt/host-d/sw-analyst-share` → `/mnt/host-share`. Der Rest von `D:` ist für die Plattform nicht sichtbar (`/mnt/host-d` ist `0700 root`).
- Die Plattform liest Proben aus `in/`, **kopiert sie in den Fallspeicher und hasht sie beim Import** (bestehende Chain-of-Custody). Sie arbeitet nie direkt auf der Freigabe.
- `sw-share mount --ro` hängt `D:` nur lesend ein, wenn nur Proben geholt werden.
- `sw-share umount` vor dem Herunterfahren (auch im `stop`-Skript).

---

## 5. Isolation und Netzwerk (betrifft Verbot 3, nur mit ADR-0013 und Freigabe)

Heute festgelegt (ADR-0000, PROJEKTPLAN 2/6.1): echte Proben nur in einer Hyper-V-VM ohne NIC, Kanal über Hyper-V-Sockets. Ohne Windows gibt es kein Hyper-V. Vorschlag für das Gegenstück unter Linux:

| Ebene | Vorschlag |
|---|---|
| Host-Netz | Zwei Modi über `sw-mode`: **`online`** nur für Einrichtung und Updates (apt, Pins aus `infra/manifest.json`, Docker-Images bauen). **`offline`** für jede Analyse: NetworkManager aus, `rfkill block all`, nftables-Regel „ausgehend alles verwerfen außer Loopback“. Der Preflight prüft den Modus und startet keine Analyse im Online-Modus. |
| Analyse mit harmlosen Proben (Entwicklung) | wie heute: Docker-Container `--network none`, read-only, `--cap-drop ALL`, Limits (`container_runner.py`), jetzt mit nativer Docker Engine; zusätzlich AppArmor-Profil `docker-default` und Seccomp-Standardprofil (bei Docker Engine unter Debian aktiv, Annahme, Prüfung in S3). |
| Echte Proben (I8, ersetzt Hyper-V) | **KVM/QEMU-VM ohne NIC** (`-nic none`), Kanal Host↔VM über **virtio-vsock** (Gegenstück zu AF_HYPERV, ebenfalls ohne IP-Stack). Gateway und Werkzeug-Container laufen in der VM, Modell und Orchestrator auf dem Host mit GPU. Proben gelangen nur als Read-only-Image in die VM, nicht über eine geteilte Host-Freigabe. |
| GPU | bleibt beim Host (Ollama). Kein GPU-Passthrough in die Analyse-VM. |

Restrisiko (gleich wie heute): Eine VM-Flucht lässt sich nie ganz ausschließen. Neu: Der Analyserechner ist jetzt Jans Alltagsrechner mit eingehängter Windows-Platte. Deshalb hängt `sw-share` `D:` vor jedem Lauf mit echten Proben aus (Preflight-Regel), und im Offline-Modus ist kein Netz aktiv.

---

## 6. Code- und Repo-Änderungen („vollständige Änderung auf Linux“)

Linux wird Zielsystem. Ob die Windows-Skripte danach entfallen oder eingefroren bleiben, entscheidet Jan (offen, Frage F5). Bis zur Abnahme bleiben sie unverändert, damit nichts kaputtgeht.

### 6.1 Startskripte (Branch `feat/launcher`)
| Heute | Neu | Hinweis |
|---|---|---|
| `scripts/start.ps1` (525 Zeilen) | `scripts/start.sh` | gleiche Stufen CHECK, INSTALL, OLLAMA, APP; gleiche Schalter (`--offline`, `--update`, `--build-tools`, `--llm colibri`, `--enable-colibri` …). Logik, die in Python schon steht (`preflight.py`, `colibri_settings.py`), bleibt dort; das Shell-Skript bleibt dünn. |
| `scripts/stop.ps1` | `scripts/stop.sh` | PID-Dateien wie heute; beendet Ollama, App, Container mit Label `sw-analyst`, hängt Freigabe aus. |
| `scripts/cleanup.ps1` | `scripts/cleanup.sh` | |
| `infra/start-ollama.ps1` | systemd-Unit `infra/linux/sw-ollama.service` **oder** Start aus `start.sh` | Bindung nur `127.0.0.1:11435`, `OLLAMA_MODELS=/srv/sw-analyst/models/ollama`, Flash Attention, KV-Cache q8_0, `MAX_LOADED_MODELS=1` wie heute. |
| `infra/select-model.ps1` | in `preflight.py`/Python | freier VRAM über `nvidia-smi`, gleiche Stufen A/B/C. |
| `infra/verify-prereqs.ps1` | `python -m sw_analyst --check` | schon vorhanden, nur Linux-Prüfungen ergänzen. |
| `infra/tools/build-images.ps1` | `infra/tools/build-images.sh` | 16 Zeilen, direkte Übersetzung. |
| neu | `infra/linux/sw-share`, `infra/linux/sw-mode` | Freigabe ein/aus, Online/Offline. Keine generischen Befehle (Verbot 4): feste Aktionen, feste Pfade aus einer Konfigurationsdatei. |
| neu | `infra/linux/provision.sh` | Einrichtung des frischen Debian (Pakete mit Version, Docker Engine, NVIDIA-Treiber, nvidia-container-toolkit, Benutzer `analyst`, fstab, nftables). Läuft einmal im Modus `online`. |

### 6.2 Python (Branch `feat/core-chain`)
| Datei | Änderung |
|---|---|
| `src/sw_analyst/preflight.py` | `check_platform`: Linux ist Zielsystem. `_ram_gb`: Linux-Zweig über `/proc/meminfo` (`MemTotal`, `MemAvailable`). `check_ram`: statt `.wslconfig` die Grenze der Plattform prüfen (cgroup/systemd-Slice, siehe 6.3). `port_owner_pid`: Linux über `/proc/net/tcp` + `/proc/<pid>/fd` oder `ss -ltnp`. `process_path`: `/proc/<pid>/exe`. Docker-Hinweis: Docker Engine statt Docker Desktop. Neue Prüfungen: Netzmodus offline, `/srv/sw-analyst` eingehängt und ext4, Freigabe `noexec`, NVIDIA-Treiber geladen. |
| `src/sw_analyst/colibri_settings.py` | `WINDOWS_MIN_GB` → `HOST_MIN_GB` je Plattform; `os.name != "nt"`-Zweig (Zeile 118) für Linux (Datenträger-Erkennung über `/sys/block`, Label statt Laufwerksbuchstabe). |
| `src/sw_analyst/common/hostguard.py` | Kommentar und Grenzen auf die neue Ressourcenregel (6.3). |
| `src/sw_analyst/webui/app.py` | Texte „Docker Desktop“, `scripts\start.ps1` → plattformneutral. |
| `src/sw_analyst/__main__.py`, `gateway/container_runner.py` | nur Doku-Strings; Docker-Aufruf bleibt gleich. Prüfen, ob `--gpus` nirgends für Werkzeug-Container gesetzt wird. |
| `infra/manifest.json` | Linux-Artefakte: `ollama-linux-amd64.tgz` mit SHA-256, Colibri-Linux-Build (Annahme: existiert für v2.1.0, prüfen), Ziele unter `/srv/sw-analyst/tools`. Pfade nicht mehr `D:\…`, sondern relativ zu `SW_ROOT`. |
| Pfade allgemein | Neue Variable `SW_ROOT` (Standard `/srv/sw-analyst`), keine fest verdrahteten Laufwerksbuchstaben. |

### 6.3 Ressourcenregel (Änderung von Jans Entscheidung vom 2026-10-31, braucht Freigabe)
Heute: 24 GB für WSL, Docker und Modelle zusammen, Windows behält 7 GB.
Vorschlag Linux: Das Hostsystem behält **3 GB**; Plattform, Container und Modelle zusammen höchstens **RAM gesamt minus 3 GB** (bei 31 GB also 28 GB). Erzwungen über einen systemd-Slice `sw-analyst.slice` mit `MemoryMax=` für App und Ollama; Docker-Container zusätzlich mit eigenem `--memory` wie heute. HostGuard pausiert weiter unter 3 GB frei. Swap: nur zram klein (2 GB), damit ein Modell nie auf die USB-SSD auslagert.

### 6.4 Tests
- Die Testsuite läuft unter Linux (Entwicklung lief bisher mit `.venv\Scripts\python.exe`). Erster Schritt: `pytest` unter Linux ausführen und die Windows-Annahmen in `tests/unit/test_preflight.py`, `test_colibri_settings.py`, `tests/security/test_host_safety.py` finden.
- Neue Tests: `/proc/meminfo`-Parser, `/proc/net/tcp`-Parser, Mount-Prüfung (`noexec`), Netzmodus-Prüfung, `sw-share` ohne generische Befehle.
- `shellcheck` für alle neuen `.sh`-Dateien.

### 6.5 Doku
`docs/runbooks/betrieb.md` (neuer Abschnitt Linux), neues Runbook `docs/runbooks/linux-ventoy.md` (Schritt-für-Schritt aus Abschnitt 7), `docs/security/sicherheitsmodell.md` (Isolation Linux), `docs/dev-environment.md` (Ventoy-Version mit SHA-256, Debian-ISO mit SHA-256, NVIDIA-Treiberversion), `README.md`, `docs/STATUS.md`.

---

## 7. Einrichtung Schritt für Schritt (Runbook-Entwurf)

### 7.1 Ventoy-SSD vorbereiten (unter Windows, einmalig)
1. Ventoy herunterladen, Version und SHA-256 in `docs/dev-environment.md` festhalten (Verbot 8: vorher prüfen).
2. `Ventoy2Disk.exe` → Ziel: externe SSD (**nicht** die interne Platte, Laufwerk doppelt prüfen) → Option → Partition Style **GPT**, „Preserve some space at the end of the disk“ = Größe für `SWDATA` → Install.
3. Secure Boot (offen, Frage F3): Entweder im BIOS aus, oder beim ersten Start „Enroll key from disk“ (Ventoy-Schlüssel in MokManager). Der NVIDIA-DKMS-Treiber braucht dann ebenfalls einen MOK-Schlüssel.

### 7.2 System-Image bauen (`debian-sw.vtoy`)
1. Debian-13-Netinstall-ISO laden, SHA-256 gegen die signierte `SHA256SUMS` prüfen.
2. In einer VM mit **UEFI** und **fester Größe** (z. B. 60 GB) installieren. Möglichkeiten: Hyper-V Gen 2 auf fester VHDX und danach `qemu-img convert -O raw … debian-sw.vtoy`, oder VirtualBox mit EFI und fester VDI. (Annahme: Ventoy vDisk braucht UEFI-Installation für UEFI-Start; Prüfung in S1.)
3. Bei der Installation: nur „SSH server“ abwählen, „Standard-Systemwerkzeuge“ an, keine Desktop-Task. Partitionierung: eine ext4-Root plus EFI-Partition, keine Swap-Partition.
4. Im installierten System `vtoyboot` aus dem Ventoy-Paket ausführen (`sudo sh vtoyboot.sh`), danach herunterfahren.
5. Image als `debian-sw.vtoy` auf die Ventoy-Partition kopieren. Die Datei muss zusammenhängend liegen; auf eine frisch formatierte exFAT-Partition kopiert ist das der Normalfall (Ventoy meldet sonst einen Fehler).
6. SHA-256 des Images festhalten (`docs/dev-environment.md`).

### 7.3 Erster Start und Einrichtung (im Linux-Live-System, Modus `online`)
1. Im BIOS/UEFI von der SSD starten → Ventoy-Menü → `debian-sw.vtoy`.
2. Partition 3 als `SWDATA` formatieren (LUKS2 + ext4), unter `/srv/sw-analyst` einhängen (fstab/crypttab).
3. Repo klonen nach `/srv/sw-analyst/repo`, `infra/linux/provision.sh` ausführen: Docker Engine (data-root auf `SWDATA`), NVIDIA-Treiber + nvidia-container-toolkit, Xfce minimal, Firefox ESR, nftables, Benutzer `analyst` in Gruppe `docker`.
   **Hinweis Sicherheit:** Mitglieder der Gruppe `docker` haben faktisch Root-Rechte. Alternative ist Docker rootless (offen, Frage F6).
4. Neustart, `nvidia-smi` prüfen.
5. `scripts/start.sh --update --build-tools`: venv aus `requirements.lock`, Ollama aus dem Manifest, Tool-Images, Modell ziehen.
6. `sw-mode offline`. Ab hier keine Netzverbindung.

### 7.4 Alltag
```
# einschalten: SSD anstecken, im Boot-Menü SSD wählen, Ventoy → debian-sw.vtoy
sw-mode offline                 # Standard nach dem Start
sw-share mount                  # D:\sw-analyst-share einbinden (nur wenn gebraucht)
scripts/start.sh                # Plattform starten, Firefox öffnet das Dashboard
scripts/stop.sh                 # beendet alles und hängt die Freigabe aus
```

---

## 8. Offene Punkte zu Colibri und `ki_data`
- `ki_data` ist exFAT über USB. Unter Linux lesbar (Kernel-exFAT). Zwei SSDs am USB teilen sich womöglich die Bandbreite. Vorschlag: Modell nach `SWDATA` kopieren (nach Hash-Prüfung gegen `infra/colibri-model.files.json`) und `ki_data` als Spiegel nutzen. Entscheidet Jan (F7).
- Linux-Build von Colibri 2.1.0 mit CUDA: Annahme, im Spike prüfen und mit SHA-256 ins Manifest.

---

## 9. Reihenfolge, Spikes und Abnahme

| # | Schritt | Abnahme | Branch |
|---|---|---|---|
| S0 | Freigabe von Jan für ADR-0013 und Antworten F1 bis F7 | ADR-0013 „angenommen“ | `docs/blueprint` |
| S1 | Spike Hardware: vDisk startet von der SSD, NVIDIA-Treiber lädt, `nvidia-smi` zeigt 16 GB, Ollama läuft auf GPU, Messung freier RAM und VRAM, Kernel-Update überlebt den vDisk-Start | Messwerte in STATUS.md | – (nur Doku) |
| S2 | Tests unter Linux grün machen (ohne Funktionsänderung) | `pytest` grün unter Linux | `feat/core-chain` |
| S3 | Linux-Zweige in `preflight.py`, `colibri_settings.py`, `hostguard.py`, `SW_ROOT`, Manifest | Tests grün, `--check` unter Linux ohne FEHLER | `feat/core-chain` |
| S4 | `start.sh`, `stop.sh`, `cleanup.sh`, `build-images.sh`, `sw-share`, `sw-mode`, `provision.sh` | shellcheck sauber; R6-Kriterien von Windows gelten gleich | `feat/launcher` |
| S5 | Erster Lauf R5 unter Linux (CTF-Probe über den Browser) | belegte Antwort, Messwerte im Vergleich zu Windows | – |
| S6 | Runbook und Doku, Security-Review (`/security-review`, `/claude-security`) mit Fokus Mount-Optionen, Docker-Gruppe, nftables, `sw-share` | Review ohne offene Befunde | – |
| S7 | I8 unter Linux: KVM-VM ohne NIC, vsock-Kanal | eigener Plan nach S6 | `feat/i8-kvm` |
| S8 | Merge per `--no-ff`, Tag | `main` lauffähig unter Linux | `main` |

---

## 10. Fragen an Jan (nicht raten, CLAUDE.md Verbot 7)
- **F1** Isolation: Ersetzt KVM/QEMU-VM ohne NIC mit vsock die Hyper-V-VM für echte Proben (ADR-0013)?
- **F2** Ressourcen: Host behält 3 GB, Rest für Plattform und Modelle, statt 24-GB-Regel?
- **F3** Secure Boot: aus, oder Ventoy- und NVIDIA-Schlüssel per MOK eintragen?
- **F4** `SWDATA` mit LUKS2 verschlüsseln (Passwort bei jedem Start)? Empfehlung: ja, weil Falldaten und Proben auf einem tragbaren Datenträger liegen.
- **F5** Windows-Skripte nach Abnahme entfernen oder als eingefrorene Variante behalten?
- **F6** Docker als Root-Dienst mit Gruppe `docker` oder Docker rootless?
- **F7** Colibri-Modell nach `SWDATA` kopieren oder weiter von `ki_data` lesen? Ist `D:` mit BitLocker verschlüsselt?
- **F8** Welche SSD (Größe, Anschluss USB 3.2/USB4)? Davon hängt das Layout in Abschnitt 3 ab.
