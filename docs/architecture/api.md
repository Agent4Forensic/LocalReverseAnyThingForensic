# Dashboard-API (Vertrag zwischen Backend und Frontend)

Basis: `http://127.0.0.1:8765`. Alle Pfade unter `/api`. JSON, UTF-8. Zeitstempel ISO-8601 UTC (`2026-10-31T17:40:00Z`). Fehler: HTTP-Status plus `{"error":{"code":"…","message":"…"}}`. POST-Anfragen verlangen `Origin` = `http://127.0.0.1:8765` oder `http://localhost:8765`.

Inhalte aus dem Sample (Zeilen, Strings, Zitate) sind unvertrauenswürdig und müssen im Frontend ausschließlich als Text (`textContent`) angezeigt werden, nie als HTML.

Sicherheitsregeln für alle `/api`-Routen: nur `Host` 127.0.0.1/localhost; Anfragen mit `Sec-Fetch-Site` außer `same-origin`/`none` oder mit fremdem `Origin` erhalten 403 (auch GET, wegen Export und Ghidra-Start); POST braucht den eigenen `Origin`; Upload-Routen brauchen `Content-Length` (sonst 411).

## System
- `GET /api/system` → `{version, worker:{state:"idle"|"running", job_id|null}, llm:{reachable:bool, model, base_url}, guard:{active:true, rules:int, version}, gateway:{kind:"dev", tools:int, ghidra:bool, container_tools:[…]}, storage:{data_dir, inside_project:bool}, queue_length:int}`

## Jobs
- `GET /api/jobs` → `[JobSummary]`, neueste zuerst, eigene und importierte Analysen. `JobSummary` enthält zusätzlich `sample_size` (Byte oder `null`), `imported:bool`, bei Importen `original_id`, bei gestarteten Beispielen `example_id`. Status `uploading` gilt, bis das Sample geschrieben ist; der Worker nimmt nur `queued`.
- `POST /api/jobs` (multipart/form-data): Feld `spec` = JSON `{title, description, context_info, focus, target_questions:[{id?, text, expected?}], emulation_opt_in:false, budget_max_tasks?, budget_max_steps?, budget_max_minutes?}`, Feld `sample` = Datei (max. 64 MiB). → `JobSummary`. Läuft schon ein Job, wird der neue `queued`.
- `GET /api/jobs/{id}` → `{summary:JobSummary, spec:{…inkl. text_orig/text_en je Frage}, progress:{tasks_total,done,pending,running,failed,blocked,percent}, totals:{steps,tool_calls,llm_calls,duration_ms}}`
- `POST /api/jobs/{id}/cancel` → `JobSummary`; bei importierten Analysen 409 `read_only`.
- Uploads über dem Limit (64 MiB Sample, 256 MiB Import) lehnt der Server schon am `Content-Length` mit 413 ab.
- `JobSummary` = `{id, title, status:"queued|running|done|partial|failed|cancelled", sample_name, sample_sha256, detected_type, recipe, created_at, started_at, finished_at, duration_ms}`

## Aufgabenbaum, Queue, Aufgabe
- `GET /api/jobs/{id}/tree` → `[TaskNode]` (Wurzeln, verschachtelt in `children`).
  `TaskNode` = `{id, parent_id, seq, title, kind, origin:"triage|recipe|question|split|evaluator|prioritizer|user", status:"pending|running|done|failed|skipped|blocked", priority:int, reason, started_at, finished_at, duration_ms, summary_en, summary_de, children:[TaskNode]}`
- `GET /api/jobs/{id}/queue` → `[{task_id, title, origin, status, priority, reason, position}]` in Ausführungsreihenfolge, laufende Aufgabe zuerst.
- `GET /api/jobs/{id}/tasks/{task_id}` → `{task:TaskNode, prompt:{id, version, sha256, text}, steps:[Step], finding_ids:[…], evidence_ids:[…]}`
  `Step` = `{id, task_id, idx, kind:"prompt|tool|guard|verify|evaluate|prioritize|translate|system", what, how, why, status:"ok|error|blocked", started_at, duration_ms, tool, input_preview, output_preview, evidence_id|null}`

## Ergebnisse
- `GET /api/jobs/{id}/findings` → `[{id, task_id, statement_en, statement_de, status:"confirmed|hypothesis|open|rejected", reject_reason, evidence_ids:[…], quotes:[{evidence_id, quote}], created_at}]`
- `GET /api/jobs/{id}/answers` → `[{question_id, text_orig, text_en, answer_en, answer_de, status:"answered|unresolved|pending", finding_ids:[…], expected|null, match:true|false|null, evaluation_en, evaluation_de}]`
- `GET /api/jobs/{id}/evidence` → `[{id, task_id, tool, tool_version, result_sha256, size, created_at}]`
- `GET /api/jobs/{id}/evidence/{eid}` → `{id, task_id, tool, tool_version, params, result_sha256, text, source_ref, injection_flags:[…], created_at}`

## Code-Viewer
- `GET /api/jobs/{id}/files` → `[{path, kind:"sample|derived", size, sha256}]`
- `GET /api/jobs/{id}/files/content?path=…&start=1&end=400` → `{path, total_lines, start, end, binary:bool, lines:[{n, text}], annotations:[{id, line_start, line_end, text_en, text_de, finding_id|null, evidence_id|null, kind:"finding|note|ioc|warning"}]}`
  Binärdateien kommen als Hexdump-Zeilen (`binary:true`), Zeile n deckt Offset (n-1)·16 ab.
- `GET /api/jobs/{id}/functions`, `GET /api/jobs/{id}/walkthroughs` → `[]`, bis das Modell Lernpfade liefert (dashboard-v2.md).

## Datei-Ansicht (ADR-0008)
- `GET /api/jobs/{id}/inspect?path=sample` → `{path, size, sha256, kind:{kind:"pe|elf|macho|dex|zip|gzip|text|binary", label, machine_code}, location, is_sample, code:{available, reason, tool}, files:[{path, size}]}`
- `GET /api/jobs/{id}/inspect/hex?path=&offset=0&length=1024` → `{path, size, offset, length, rows:[{offset, hex, ascii}]}`, höchstens 64 KiB je Abfrage.
- `GET /api/jobs/{id}/inspect/functions?path=` → `{program:{format, language, compiler, image_base, entry}, functions:[{name, entry, size, signature, thunk, instructions, decompiled}], total, truncated, tool_version}`. 409 `no_ghidra` ohne Ghidra-Image. Der erste Aufruf je Datei startet Ghidra (Minuten), danach Cache.
- `GET /api/jobs/{id}/inspect/function?path=&function=<Name oder Einstiegsadresse>` → `{name, entry, size, signature, disasm:[{address, bytes, text, mnemonic, explain}], disasm_truncated, decompiled, blocks, findings:[…]}`. `explain` stammt aus einer festen Tabelle (`webui/inspect.py`), nicht vom Modell.

## Beispiele (ADR-0008)
- `GET /api/examples` → `{available, folder, items:[{id, title, level, level_rank, description, goal, tests, questions, sample:{name, builder, size, sha256}, paths:{folder, challenge, builder_file, builder_line, runner, stored_as}, runs:[{job_id, status, created_at, flag_found|null}]}]}`, sortiert nach Stufe. Ohne Flagge.
- `GET /api/examples/{id}` → wie ein Listeneintrag plus `flag`, `builder_source`, `challenge_json`, `preview:{kind, hex, text?}`.
- Listeneinträge enthalten zusätzlich `budget_minutes` und `requires` (aus `challenge.json`), `ready`, `missing:[{key:"llm|ghidra", text}]` und `active_job`; die Liste selbst `queue_length` und `worker_busy`.
- `POST /api/examples/{id}/job` (JSON `{budget_max_minutes?, force?}`) → `JobSummary`. Ohne Angabe gilt `budget_minutes` des Beispiels, Aufgaben 20 und Schritte 200 wie `example/run_eval.py`. 409 `not_ready` (Modell oder benötigtes Werkzeug fehlt) und 409 `already_running` (Lauf dieses Beispiels noch aktiv), beides mit `force: true` übergehbar.
- `POST /api/examples-batch` (JSON `{ids?, force?}`) → `{started:[JobSummary], skipped:[{id, reason}]}`. Reiht alle startbereiten Beispiele nach Schwierigkeit ein; der Worker arbeitet sie nacheinander ab.
- `GET /api/jobs/{id}` enthält bei Beispiel-Aufträgen `example:{id, title, level, flag_found}`.

## Export und Import (ADR-0008)
- `GET /api/jobs/{id}/export?include_files=0|1` → ZIP (`application/zip`), Header `X-Bundle-SHA256` und `X-Export-Copy` (Kopie unter `data/exports/`). 409 für laufende Jobs.
- `POST /api/imports` (multipart, Feld `bundle`) → `{job_id:"I0001-J-0003", import_id, checks:{…, audit_valid, events_checked, report_reproducible}, duplicate}`. Fehler: `bad_bundle`, `wrong_format`, `checksum_mismatch`, `audit_invalid`, `too_large`.
- `GET /api/imports/{job_id}` → Manifest, Prüfergebnisse, `imported_at`, `bundle_sha256`. Importierte Analysen sind über alle `/api/jobs/{id}/…`-Routen lesbar, aber schreibgeschützt.

## Log, Zeitverlauf, Schutz, Audit
- `GET /api/jobs/{id}/log?after=0&level=info` → `{events:[{seq, ts, level:"debug|info|warn|error", type, message, data}], last_seq}`
- `GET /api/jobs/{id}/timeline` → `[{task_id, title, status, started_at, duration_ms}]`
- `GET /api/jobs/{id}/guard` → `[{id, ts, task_id, stage:"input|output", rule, severity:"low|medium|high", action:"flagged|redacted|blocked", snippet}]`
- `GET /api/jobs/{id}/audit` → `{valid:bool, entries:int, head_hash, broken_at|null}`

## Live-Stream (Server-Sent Events)
- `GET /api/jobs/{id}/stream?after=0` → `text/event-stream`. Jedes Ereignis: `id: <seq>`, `event: <type>`, `data: {"seq":n,"ts":"…","type":"…","level":"…","message":"…","data":{…}}` (Stufe und Text stehen im Umschlag). Typen: `job`, `task`, `step`, `finding`, `answer`, `annotation`, `guard`, `log`. Daten enthalten die vollständigen, geänderten Objekte im Format der jeweiligen GET-Endpunkte. Nach Verbindungsabbruch mit `Last-Event-ID` fortsetzen. Alle 15 s ein Kommentar-Heartbeat (`: ping`).
- Zusätzlich `GET /api/stream` (global): nur `job`-Ereignisse und Worker-Status.

## Bericht und Prompts
- `GET /api/jobs/{id}/report?lang=de|en&format=md|json` → Markdown (`text/markdown`) oder JSON. Während der Laufzeit liefert der Endpunkt den Live-Bericht des Zwischenstands (`"live": true` im JSON).
- `GET /api/prompts` → `[{id, version, sha256, purpose}]`, `GET /api/prompts/{id}` → `{id, version, sha256, purpose, text}`
