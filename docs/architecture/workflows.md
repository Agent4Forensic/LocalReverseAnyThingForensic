# Workflows auf einen Blick

Vier Diagramme auf hoher Ebene. Sie zeigen nur, was im Code vorhanden ist (Quellen: `scripts/start.ps1`, `scripts/stop.ps1`, `docs/architecture/chain.md`, `orchestrator/*`, `guard/*`, `gateway/*`). Nicht Umgesetztes ist gestrichelt und als **offen** beschriftet. Die Details der Analysekette stehen in [`chain.md`](chain.md), die geplante Methodik je Phase in [`../roadmap.html`](../roadmap.html).

## 1. Start und Stopp

```mermaid
flowchart TD
    S([scripts\start.ps1]) --> CLEAN[CLEAN<br/>Reste eigener Prozesse, Scratch, Logs > 14 Tage, gelabelte Container]
    CLEAN --> CHECK[CHECK<br/>Preflight: Python, venv, Ports, Platz, GPU, Modell]
    CHECK -->|fehlt etwas| INST[INSTALL<br/>nur aus infra/manifest.json und requirements.lock<br/>SHA-256 geprüft, Abweichung = Abbruch]
    CHECK -->|alles da| UPD
    INST --> UPD[UPDATE<br/>neue Versionen nur melden, nicht einspielen]
    UPD --> OLL[OLLAMA<br/>Port 11435, nur Loopback]
    OLL --> MOD[MODEL<br/>Wahl nach freiem VRAM, Pull bei Bedarf]
    MOD --> APP[APP<br/>FastAPI + Worker, Dashboard im Browser]
    APP --> LOOP[Statusschleife]
    LOOP --> X([scripts\stop.ps1])
    X --> JOBS{läuft ein Job?}
    JOBS -->|ja, ohne -Force| WAIT[warten, bis der Job fertig ist]
    JOBS -->|ja, mit -Force| CANCEL[Job per API abbrechen]
    WAIT --> STOP
    CANCEL --> STOP
    JOBS -->|nein| STOP[STOP<br/>nur eigene Prozesse, Fremde bleiben unberührt]
    STOP --> POST[CLEAN post<br/>PID-Dateien, Caches, gelabelte Container, Netze, Volumes]
```

## 2. Lebenszyklus eines Jobs

```mermaid
flowchart TD
    A([Auftrag: Sample, Beschreibung, Zielfragen]) --> B[Sample ablegen, SHA-256, schreibgeschützt]
    B --> C[Eingaben DE→EN übersetzen]
    C --> D[Triage ohne KI<br/>sample_info, hash_file, identify_type]
    D --> E{Rezept}
    E --> E1[exe] & E2[apk] & E3[script] & E4[generic]
    E1 & E2 & E3 & E4 --> F[Plan: Rezeptschritte mit done_when,<br/>Synthese, je Zielfrage eine Aufgabe]
    F --> Q[(Queue, SQLite)]
    Q --> H{HostGuard<br/>RAM, Platz, GPU-Temperatur}
    H -->|Grenze verletzt| PAUSE[Pause, nach 15 min partial]
    H -->|frei| PLAN{Nächste Aufgabe ist<br/>Synthese oder Zielfrage?}
    PLAN -->|ja, einmal je Job,<br/>unter 75 % Budget| GOAL[Planer: höchstens 4 Aufgaben<br/>aus dem Job-Ziel]
    GOAL --> Q
    PLAN -->|nein| R[Task-Runner<br/>Werkzeug-Schleife, max. 10 Züge]
    R --> V[Prüfer: Zitat wörtlich in Evidence?<br/>Indikatoren der Aussage im Zitat?]
    V --> EV[Evaluator: Ziel erreicht? Lücken?<br/>Lücken werden open-Findings]
    EV -->|Folgeaufgaben, nach der Synthese<br/>nur eine Lückenrunde| Q
    EV --> ART{neues derived/-Artefakt?}
    ART -->|ja| TRI[Typ und Hashes ohne KI, Aufgabe mit passendem Rezept]
    TRI --> Q
    ART -->|nein| PR[Priorisierer: nur wenn neue Aufgaben<br/>dazukamen]
    PR --> NEXT{Queue leer oder Budget erschöpft?}
    NEXT -->|nein| Q
    NEXT -->|Queue leer| RE{Offene Zielfrage und<br/>neue confirmed Findings?}
    RE -->|ja, einmal je Frage| Q
    RE -->|nein| TR[Übersetzung EN→DE]
    NEXT -->|Budget erschöpft| TR
    TR --> REP[Bericht + Defanging]
    REP --> ST{Status}
    ST -->|alles beantwortet| DONE([done])
    ST -->|Lücken oder Budget| PART([partial mit Grund])
    ST -->|keine Aufgabe fertig| FAIL([failed])
```

Synthese und Zielfragen sind normale Aufgaben der Queue mit hoher Prioritätszahl und laufen deshalb zuletzt. Hypothesen und offene Punkte erreichen spätere Analyseaufgaben, Evaluator und Planer als Datenblock, aber keine Zielfrage. Die Regeln stehen in [ADR-0007](../adr/0007-iterativer-analyseprozess.md).

## 3. Schutzschichten um das Modell

```mermaid
flowchart LR
    SM[(Sample<br/>nur Daten)] --> GW{{Gateway<br/>Allowlist, Pfad-Jail, Limits}}
    GW --> TOOLS[Statische Werkzeuge<br/>nur lesend]
    TOOLS --> SC[Scanner + Sanitizer<br/>Anweisungsmuster schwärzen,<br/>Inhalt in untrusted_data]
    SC --> LLM[Modell<br/>lokal, Loopback]
    LLM --> AV[Aktionsprüfung<br/>Schema, Allowlist, Argumente]
    AV -->|zulässig| GW
    AV -->|unzulässig| WD[Wächter<br/>Task blocked, Vorfall als Befund]
    LLM --> VF[Prüfer<br/>Zitat gegen gespeicherte Evidence]
    VF --> ST[(Store: Evidence, Findings)]
    GW -.-> AUD[(Audit-Kette<br/>SHA-256 je Zeile)]
    AV -.-> AUD
    WD -.-> AUD
    VM[[Hyper-V-VM ohne NIC<br/>Docker --network none, read-only<br/>OFFEN]]:::open -.-> GW
    classDef open stroke-dasharray:4 3,fill:#fff,stroke:#999,color:#555
```

## 4. Datenfluss vom Sample zum Bericht

```mermaid
flowchart TD
    S[Sample] --> H[SHA-256 und Typ]
    H --> T[Werkzeugaufruf über das Gateway]
    T --> E[Evidence EV-… mit Ergebnis-Hash]
    E --> F[Finding mit Zitat]
    F --> C{Zitat steht<br/>wörtlich in der Evidence?}
    C -->|ja| OK[confirmed]
    C -->|nein, Beleg vorhanden| HY[hypothesis]
    C -->|nein, kein Beleg| RJ[rejected mit Grund]
    OK --> A[Antwort auf Zielfrage]
    HY -.nur als Hypothese.-> R
    RJ -.nie als Tatsache.-> R
    A --> R[Bericht: Übergabe, Hashes, Evidence-Tabelle, Guard-Ereignisse]
    R --> D[Defanging der IOCs]
    D --> O([Bericht DE + EN])
    E -.-> AU[(Audit-Kette)]
    R -.-> AU
```

## Nicht Teil dieser Diagramme (offen)

Ghidra und Disassembler-Werkzeuge, Docker-Werkzeug-Images, Wissensdatenbank, Obsidian-Vault, Hyper-V-Isolation und die dynamische Analyse ([ADR-0005](../adr/0005-dynamische-analyse.md), Entwurf, braucht Freigabe).