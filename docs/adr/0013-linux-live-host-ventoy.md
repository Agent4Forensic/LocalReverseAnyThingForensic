# ADR-0013: Linux-Live-Host über Ventoy statt Windows mit WSL und Hyper-V

Status: **vorgeschlagen am 2026-11-03, wartet auf Freigabe durch Jan.** Betrifft VM-Isolation und die Ressourcenregel; nach CLAUDE.md Verbot 3 erst nach ausdrücklicher Freigabe umsetzbar. Plan: `docs/tasks/linux-live-ventoy.md`.

## Kontext
Jan will die Plattform unter Linux als Live-System von einer externen SSD (Ventoy) betreiben, um RAM und GPU voll zu nutzen. Unter Windows belegen Desktop-Apps rund 12 GB VRAM (B2), WSL und Docker sind auf 24 GB begrenzt und Windows behält 7 GB (B1, B4), Hyper-V scheitert an fehlenden Admin-Rechten (B3).

## Optionen
1. **Ventoy mit Linux-vDisk (`.vtoy`, installiertes Debian 13 als Image) plus eigene ext4-Datenpartition:** normale Installation mit Kernel-Updates, DKMS und Docker `overlay2`; System-Image und Daten getrennt.
2. **Ventoy mit Live-ISO und `persistence.dat`:** einfach, aber Docker auf Overlay-Root, NVIDIA-Treiber an die ISO gebunden, keine Kernel-Updates.
3. **Feste Installation auf der SSD ohne Ventoy:** robust, verliert aber das Ventoy-Menü (Rettungs-ISOs, mehrere Images).
4. **Bei Windows bleiben:** Engpässe B1 bis B4 bleiben.

## Vorgeschlagene Entscheidung
- Option 1. Distribution Debian 13 minimal mit Xfce, NVIDIA-Treiber ab Serie 570 (offene Module), Docker Engine nativ.
- Isolation für echte Proben: KVM/QEMU-VM ohne NIC, Kanal über virtio-vsock (ersetzt Hyper-V und AF_HYPERV). Entwicklung mit harmlosen Proben weiter in Containern mit `--network none`.
- Netzmodi `online` (nur Einrichtung) und `offline` (jede Analyse, nftables verwirft alles außer Loopback); der Preflight erzwingt `offline`.
- Austausch mit der internen Platte nur über einen Ordner (`D:\sw-analyst-share`), eingehängt mit `ntfs3`, `noauto,noexec,nosuid,nodev`, nur auf Anforderung; Proben werden beim Import kopiert und gehasht.
- Ressourcen: Host behält 3 GB, Plattform und Modelle bekommen den Rest, erzwungen über einen systemd-Slice.

## Folgen
Belegt: `preflight.py`, `colibri_settings.py`, `hostguard.py`, `infra/manifest.json`, `scripts/*.ps1` und `infra/*.ps1` sind auf Windows ausgelegt und brauchen Linux-Gegenstücke (Plan, Abschnitt 6).

Hypothesen (Spike S1): freier VRAM nahe 15,5 GB; vDisk-Start übersteht Kernel-Updates; NVIDIA-Treiber für Blackwell unter Debian 13 verfügbar; Colibri 2.1.0 hat einen Linux-CUDA-Build.

Risiken: Der Analyserechner ist Jans Alltagsrechner mit Windows-Platte; deshalb Freigabe nur auf Anforderung und Aushängen vor Läufen mit echten Proben. Mitglieder der Gruppe `docker` haben faktisch Root-Rechte. Eine VM-Flucht bleibt Restrisiko wie bisher.

Offene Fragen: F1 bis F8 im Plan, Abschnitt 10.
