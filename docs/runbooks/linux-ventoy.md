# Runbook: Linux-Live-Host über Ventoy (ADR-0013)

Stand: 2026-11-03. Gilt für den Linux-Betrieb. Den Windows-Betrieb beschreibt `betrieb.md`. Plan und Begründung stehen in `docs/tasks/linux-live-ventoy.md`.

Legende: **geprüft** (in diesem Repository getestet), **ungeprüft** (muss auf der echten Hardware bestätigt werden, Spike S1).

## Überblick

```
Externe SSD (Ventoy, GPT)
├─ Partition 1 "Ventoy" (exFAT): debian-sw.vtoy (System, feste Größe), Rettungs-ISOs
├─ Partition 2 "VTOYEFI": Ventoy-Bootloader
└─ Partition 3 "SWDATA" (LUKS2 + ext4) → /srv/sw-analyst
     repo/  tools/  models/ollama/  models/colibri/  docker/  vendor/
Interne Platte (Windows D:) → nur D:\sw-analyst-share, über sudo sw-share mount → /mnt/host-share (noexec)
```

Alltag:

```
sudo sw-mode status        # nach dem Start: OFFLINE (Standard beim Booten)
sudo sw-share mount        # nur wenn Proben geholt oder Berichte abgelegt werden; --ro nur lesend
scripts/start.sh           # Plattform starten, Firefox öffnet das Dashboard; Strg+C beendet alles
sudo sw-share umount       # vor dem Herunterfahren und vor Läufen mit echten Proben
```

## 1. Ventoy-SSD vorbereiten (unter Windows, einmalig)

1. Ventoy herunterladen. Version und SHA-256 vor der Nutzung in `docs/dev-environment.md` eintragen (CLAUDE.md, Verbot 8).
2. `Ventoy2Disk.exe` starten. Als Ziel die **externe SSD** wählen. Bitte zweimal prüfen: Ventoy löscht den gewählten Datenträger vollständig.
3. Unter Option: Partition Style **GPT**. Bei „Partition Configuration“ den Platz für `SWDATA` am Ende freihalten (zum Beispiel alles außer 80 GB).
4. Install.
5. Secure Boot: Entweder im UEFI ausschalten oder beim ersten Start im Ventoy-Menü „Enroll key from disk“ wählen und den Ventoy-Schlüssel im MokManager eintragen. Der NVIDIA-Treiber braucht dann ebenfalls einen eingetragenen Schlüssel (DKMS fragt beim Bau danach). Standard in diesem Projekt: Secure Boot aus (Plan F3), weil sonst jedes Kernel-Update einen zweiten MOK-Schritt braucht. **Ungeprüft** auf Jans Mainboard.

## 2. System-Image `debian-sw.vtoy` bauen

1. Debian-13-Netinstall-ISO laden. `SHA256SUMS` und dessen Signatur prüfen (`gpg --verify SHA256SUMS.sign SHA256SUMS`, Debian-CD-Schlüssel), dann die ISO gegen `SHA256SUMS` prüfen.
2. Eine VM mit **UEFI** und einer Platte **fester Größe** (60 GB) anlegen:
   - Hyper-V: Generation 2, feste VHDX, Secure Boot der VM aus.
   - oder VirtualBox: EFI an, feste VDI.
3. Debian installieren:
   - Rechnername `sw-analyst`, Benutzer `analyst`.
   - Partitionierung: EFI-Partition und eine ext4-Root, **keine Swap-Partition** (zram übernimmt das).
   - Softwareauswahl: nur „Standard-Systemwerkzeuge“. Keine Desktop-Umgebung und kein SSH-Server, die Oberfläche installiert `provision.sh`.
4. Im installierten System als root: Ventoy-Paket in die VM kopieren, `sh vtoyboot.sh` ausführen, VM herunterfahren.
5. Image umwandeln (in WSL oder unter Linux): `qemu-img convert -O raw debian-sw.vhdx debian-sw.vtoy` (bei VirtualBox: `VBoxManage clonemedium debian-sw.vdi debian-sw.vtoy --format RAW`).
6. `debian-sw.vtoy` auf die Ventoy-Partition kopieren. Die Datei muss zusammenhängend liegen; auf eine frisch angelegte exFAT-Partition kopiert ist das der Normalfall. Ventoy meldet beim Start sonst einen Fehler.
7. SHA-256 des Images in `docs/dev-environment.md` festhalten (`sha256sum debian-sw.vtoy`).

**Ungeprüft:** Start des vDisk-Images auf Jans Rechner, Verhalten nach einem Kernel-Update (vtoyboot legt einen initramfs-Hook an; nach `apt upgrade` mit neuem Kernel einmal neu starten und prüfen).

## 3. Erster Start und Einrichtung (Modus online)

Im UEFI-Bootmenü die SSD wählen → Ventoy-Menü → `debian-sw.vtoy`.

### 3.1 SWDATA anlegen (einmalig, löscht Partition 3)

```
lsblk -o NAME,SIZE,FSTYPE,LABEL,MODEL     # Partition 3 der Ventoy-SSD finden, z. B. /dev/sdb3; GENAU prüfen
sudo cryptsetup luksFormat --type luks2 /dev/sdX3
sudo cryptsetup open /dev/sdX3 swdata
sudo mkfs.ext4 -L SWDATA /dev/mapper/swdata
sudo mkdir -p /srv/sw-analyst
```

`/etc/crypttab` und `/etc/fstab` (UUIDs mit `sudo blkid` ermitteln; nie `/dev/sdX` eintragen, sonst hängt der Start auf einem anderen Rechner):

```
# /etc/crypttab
swdata  UUID=<uuid-der-luks-partition>  none  luks,discard,nofail
# /etc/fstab
/dev/mapper/swdata  /srv/sw-analyst  ext4  defaults,noatime,nodev,nofail,x-systemd.device-timeout=30s  0 2
```

Ohne Verschlüsselung (nur wenn Jan F4 verneint): `mkfs.ext4 -L SWDATA /dev/sdX3` und in die fstab `UUID=<uuid>` statt `/dev/mapper/swdata`.

```
sudo systemctl daemon-reload && sudo mount /srv/sw-analyst
sudo install -d -o analyst -g analyst /srv/sw-analyst/repo /srv/sw-analyst/tools /srv/sw-analyst/models
```

### 3.2 Repository und Provisionierung

```
git clone https://github.com/Agent4Forensic/LocalReverseAnyThingForensic.git /srv/sw-analyst/repo
cd /srv/sw-analyst/repo
sudo infra/linux/provision.sh          # Pakete, Docker, NVIDIA, zram, Xfce, sw-mode, sw-share, offline beim Booten
sudo reboot
```

Was `provision.sh` installiert, steht im Kopf des Skripts. Es nutzt nur Debian-Pakete und formatiert nichts.

### 3.3 NVIDIA-Treiber prüfen

```
nvidia-smi --query-gpu=name,driver_version,memory.total,memory.used --format=csv
```

Die RTX 5060 Ti (Blackwell) braucht die Treiberserie 570 oder neuer mit offenen Kernelmodulen. **Ungeprüft**, ob Debian 13 diese Version in `non-free` liefert. Falls nicht: nichts auf eigene Faust einbinden. Das NVIDIA-CUDA-Repository für Debian (`nvidia-open`) ist eine neue Quelle und braucht nach CLAUDE.md, Verbot 8, eine Prüfung und einen Eintrag mit Version in `docs/dev-environment.md`. Rückfall nach Plan: Ubuntu Server LTS minimal.

### 3.4 Plattform einrichten (online, als `analyst`)

```
sudo sw-mode online
cd /srv/sw-analyst/repo
scripts/start.sh --setup        # venv aus requirements.lock, Ollama aus dem Manifest (SHA-256), Modell, Tool-Images
sudo sw-mode offline
```

`--setup` lädt nur aus den Pins in `infra/manifest.json` und `requirements.lock`, zieht das Modell passend zum freien VRAM (`--model` setzt es fest) und baut fehlende Tool-Images. Danach hält es alles wieder an.

### 3.5 Austauschordner der internen Platte

Unter Windows (einmalig):
1. Als Administrator `powercfg /h off` (Schnellstart und Ruhezustand aus). Windows danach immer vollständig herunterfahren, bevor Linux startet.
2. Ordner `D:\sw-analyst-share\in` und `D:\sw-analyst-share\out` anlegen.

Unter Linux:
```
lsblk -f                                   # UUID der Windows-Datenpartition (ntfs oder BitLocker)
sudoedit /etc/sw-analyst/share.conf        # SHARE_UUID=..., SHARE_DIR=sw-analyst-share
sudo sw-share mount                        # rw, noexec,nosuid,nodev; nur der Ordner ist sichtbar
sudo sw-share mount --ro                   # nur lesend, zum Holen von Proben
sudo sw-share umount
```

`D:` selbst hängt unter `/run/sw-analyst/hostd`; der Ordner `/run/sw-analyst` gehört root mit Rechten 0700, der Benutzer `analyst` sieht vom Rest der Platte nichts. Bei BitLocker fragt `sw-share` nach dem Wiederherstellungsschlüssel und speichert ihn nicht.

Proben aus `/mnt/host-share/in` werden im Dashboard hochgeladen. Die Plattform kopiert und hasht sie beim Import und arbeitet nie auf der Freigabe. Berichte und Exporte legt man nach `/mnt/host-share/out`.

## 4. Starten und Stoppen

```
scripts/start.sh                       # Standard: Ollama, Modell nach freiem VRAM
scripts/start.sh --model qwen3:14b     # Modell fest
scripts/start.sh --llm colibri         # nur dieser Lauf mit Colibri (ADR-0012), auf Linux derzeit nur CPU
scripts/start.sh --enable-colibri      # dauerhaft, wenn die Hardware es trägt; --disable-colibri zurück
scripts/stop.sh                        # wartet auf einen laufenden Auftrag
scripts/stop.sh --force                # bricht ihn ab und markiert ihn als abgebrochen
scripts/cleanup.sh --phase post --dry-run
```

Der Start verweigert sich, solange der Host online ist (Prüfung `net:offline`). `--allow-online` erlaubt das nur für harmlose Proben und schreibt eine Warnung ins Log.

App, Ollama und Colibri laufen in der systemd-Benutzer-Slice `sw-analyst.slice`. Der Launcher schreibt sie nach `~/.config/systemd/user/sw-analyst.slice` mit `MemoryMax` = RAM gesamt minus 3 GB und `MemorySwapMax=0`. Die Prüfung `ram:limit` zeigt, ob die Grenze greift.

Logs: `data/logs/start-<datum>.log` (Stufenzeilen), `data/logs/app-*.out`, `data/logs/ollama-*.log`.

## 5. Fehlerbehebung

| Meldung | Ursache und Abhilfe |
|---|---|
| `net:offline FEHLER` | Host ist online. `sudo sw-mode offline`, `sw-mode status` muss `OFFLINE` zeigen. |
| `sw-root FEHLER` | SWDATA nicht eingehängt. `sudo systemctl status systemd-cryptsetup@swdata`, Passwort beim Booten vergessen? `sudo cryptsetup open … swdata && sudo mount /srv/sw-analyst`. |
| `ollama 0.40.13 missing` | Einmal online `scripts/start.sh --setup`. |
| `ram:limit WARN` | Kein systemd-Benutzer-Manager (Start ohne grafische Anmeldung). Als `analyst` anmelden; `provision.sh` schaltet `linger` ein. |
| `sw-share: mount failed` | Windows im Ruhezustand oder Schnellstart an: Windows starten, `powercfg /h off`, vollständig herunterfahren. |
| `share:mount FEHLER` | Freigabe ohne `noexec`: `sudo sw-share umount && sudo sw-share mount`. |
| Docker `WARN` | `sudo systemctl start docker`; Daten liegen in `/srv/sw-analyst/docker`, der Dienst wartet auf SWDATA. |

## 6. Sicherheitshinweise

- Der Analyserechner ist Jans Alltagsrechner mit eingehängter Windows-Platte. Vor Läufen mit echten Proben deshalb immer `sudo sw-share umount`; der Preflight meldet eine eingehängte Freigabe als Warnung.
- Mitglieder der Gruppe `docker` haben auf diesem Host faktisch Root-Rechte (Plan F6). Auf dem Live-System gibt es nur den Benutzer `analyst`.
- Echte Proben gehören bis zur Umsetzung von I8 (KVM-VM ohne Netzwerkkarte) nicht auf dieses System. Die Container mit `--network none` sind für harmlose Proben gedacht.
- `sw-mode online` und `sw-share mount` fragen nach dem Passwort; `sw-mode offline` und `sw-share umount` gehen ohne, damit der sichere Zustand nie an einer Passwortabfrage scheitert.
