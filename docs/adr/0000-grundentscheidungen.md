# ADR-0000: Grundentscheidungen vor Beginn von Phase 0

Status: akzeptiert (Jan, 2026-10-31)

## Kontext
Der Projektplan lässt vier Fragen offen, die vor der Einrichtung der Umgebung geklärt werden mussten: Isolationsart, Ressourcenlimit, Einbindung von REA und Entwicklungs-Vault. Außerdem wünscht Jan Docker, eine hohe Ressourcennutzung (bis 90 % RAM, GPU) und größtmögliche Sicherheit für die Hardware.

## Entscheidungen

### 1. Isolation: Hyper-V-VM plus Docker darin
- Echte Proben werden ausschließlich in einer Hyper-V-VM ohne Netzwerkkarte verarbeitet.
- Innerhalb der VM laufen die Analysewerkzeuge in Docker-Containern mit `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, Speicher-, CPU- und PID-Limits, ohne Host-Mounts außer dem schreibgeschützten Sample-Verzeichnis.
- Entwicklung und Tests mit harmlosen Proben laufen auf dem Dev-Rechner in Docker/WSL2 mit derselben Container-Härtung.
- Folgen: Zwei Schichten (VM-Grenze, Container-Grenze). Für die VM-Anlage sind Administratorrechte nötig. Claude Code hat sie nicht, Jan führt ein erzeugtes Skript selbst aus (Phase 1).

### 2. Ressourcen: hartes Limit 24 GB RAM
- Die Obergrenze von 90 % (ca. 28 GB) wurde bewusst nicht gewählt. Der Host hat 31 GB, Windows benötigt Reserve, frühere Läufe führten bereits zu Speichermangel (Kommentar in `.wslconfig`).
- WSL2/Docker/Modelle zusammen höchstens 24 GB. Jeder Container hat ein eigenes Limit. Windows behält mindestens 7 GB.
- Die GPU wird von Ollama genutzt. Aktuell sind durch Desktop-Anwendungen nur etwa 4,5 GB VRAM frei. Das ist ein Blocker für die Modellwahl (siehe `docs/STATUS.md`, B2).

### 3. REA nur statisch und hinter dem Gateway
- Quelle: `morluto/rea` (MIT). REA enthält auch dynamische Funktionen (Programmstart, Netzwerk-Capture), die Plan-Regel "Sample wird nie gestartet" widersprechen.
- REA läuft nur im Analyse-Container. Das Gateway exponiert per Allowlist ausschließlich statische Funktionen. Die KI erhält nie direkten Zugriff auf den REA-MCP-Server.
- Kein `npx rea-agents setup`. Manuelle Registrierung, Version und Commit gepinnt, Lieferkette per Hash geprüft.

### 4. Entwicklungs-Vault ohne mnemo
- mnemo installiert vier Hooks (auch vor jedem Bash-, Read-, Edit- und Write-Aufruf), lädt ein Binary nach und hat einen optionalen Drittanbieter-Endpunkt. Die Eingriffstiefe steht in keinem Verhältnis zum Nutzen.
- Stattdessen: Markdown-Vault unter `docs/dev-vault/` und graphify-Graph. Der Analyse-Vault bleibt davon getrennt und wird nur von der Plattform geschrieben.

## Folgen
- ADR-0001 bis ADR-0003 bauen darauf auf. Der Kanal Host-VM (ADR-0002) bleibt offen und wird per Spike entschieden.
- Änderungen an diesen Entscheidungen erfordern ein neues ADR und die Freigabe von Jan.
