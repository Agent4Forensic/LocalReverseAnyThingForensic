# start.ps1 - one-stop start of sw-analyst: CHECK, INSTALL, UPDATE, OLLAMA, MODEL, APP, then a quiet status loop.
# Design: docs/architecture/dashboard-v2.md section 4. Every line: [HH:mm:ss] [STAGE] message (terminal colored, also data\logs\start-<date>.log).
# Installs only from infra\manifest.json (URL + SHA-256, hash mismatch = hard error) and requirements.lock (--require-hashes).
# Never touches foreign processes (e.g. the Ollama on 11434, other WSL/Docker projects). No admin rights needed.
# Pure ASCII on purpose (Windows PowerShell 5.1 encoding).
param(
    [string]$Model = '',
    [int]$Port = 8765,
    [int]$OllamaPort = 11435,
    [switch]$SkipUpdateCheck,
    [switch]$Update,
    [switch]$Offline,
    [switch]$NoBrowser
)
$ErrorActionPreference = 'Stop'

$Root      = Split-Path -Parent $PSScriptRoot
$Data      = Join-Path $Root 'data'
$RunDir    = Join-Path $Data 'run'
$LogDir    = Join-Path $Data 'logs'
$Py        = Join-Path $Root '.venv\Scripts\python.exe'
$ToolsRoot = 'D:\Tools\sw-analyst'
$Base      = "http://127.0.0.1:$Port"
$OllamaUrl = "http://127.0.0.1:$OllamaPort"
New-Item -ItemType Directory -Force -Path $RunDir, $LogDir | Out-Null
$LogFile   = Join-Path $LogDir ("start-{0:yyyy-MM-dd}.log" -f (Get-Date))
$Utf8      = New-Object System.Text.UTF8Encoding($false)

# ---- logging ---------------------------------------------------------------------------------------------
function Write-Stage([string]$Stage, [string]$Msg, [string]$Level = 'INFO') {
    $prefix = if ($Level -in 'OK', 'WARN', 'FEHLER') { "${Level}: " } else { '' }
    $line = '[{0:HH:mm:ss}] [{1}] {2}{3}' -f (Get-Date), $Stage, $prefix, $Msg
    $color = switch ($Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'FEHLER' { 'Red' } default { 'Gray' } }
    Write-Host $line -ForegroundColor $color
    for ($i = 0; $i -lt 5; $i++) {
        try { [IO.File]::AppendAllText($LogFile, $line + "`r`n", $Utf8); return } catch { Start-Sleep -Milliseconds 50 }
    }
}
function Exit-Fail([string]$Stage, [string]$Msg) { Write-Stage $Stage $Msg 'FEHLER'; exit 1 }

# ---- helpers ---------------------------------------------------------------------------------------------
function Assert-Hash([string]$File, [string]$Expected) {
    if ($Expected -notmatch '^[0-9a-fA-F]{64}$') { Remove-Item -LiteralPath $File -Force; throw "no valid sha256 pin ('$Expected'); file deleted" }
    $got = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $Expected.ToLower()) { Remove-Item -LiteralPath $File -Force; throw "HASH MISMATCH: expected $Expected, got $got; file deleted, nothing installed" }
}
function Test-UnderTools([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    return $full.StartsWith($ToolsRoot + '\', [StringComparison]::OrdinalIgnoreCase)
}
function Get-OllamaVersions {
    if (-not (Test-Path $ToolsRoot)) { return @() }
    return @(Get-ChildItem $ToolsRoot -Directory | Where-Object { $_.Name -match '^ollama-\d+\.\d+\.\d+$' -and (Test-Path (Join-Path $_.FullName 'ollama.exe')) } |
        Sort-Object { [version]($_.Name -replace '^ollama-', '') } -Descending)
}
function Invoke-Native([string]$Exe, [string[]]$CmdArgs) {
    & $Exe @CmdArgs
    if ($LASTEXITCODE -ne 0) { throw "$Exe failed with exit code $LASTEXITCODE" }
}
function Get-Json([string]$Url, [int]$TimeoutSec = 3) { Invoke-RestMethod -Uri $Url -TimeoutSec $TimeoutSec }

function Resolve-Model {
    if ($Model) {
        if ($Model -notmatch '^[A-Za-z0-9._:/-]+$') { Exit-Fail 'MODEL' "invalid model tag '$Model'" }
        return $Model
    }
    try {
        $txt = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'infra\select-model.ps1') | Out-String
        if ($LASTEXITCODE -ne 0) { throw 'select-model.ps1 failed' }
        $sel = $txt | ConvertFrom-Json
        Write-Stage 'MODEL' ("auto: tier {0}, {1} MiB VRAM free -> {2}" -f $sel.tier, $sel.free_vram_mib, $sel.chat_model)
        if ($sel.note) { Write-Stage 'MODEL' $sel.note 'WARN' }
        return [string]$sel.chat_model
    } catch {
        $fallback = $script:Manifest.models.chat_tiers.C
        Write-Stage 'MODEL' "automatic choice failed ($($_.Exception.Message)); using smallest tier $fallback" 'WARN'
        return $fallback
    }
}

# Runs the python preflight; returns the parsed result list (or $null if python is not usable yet).
function Invoke-Check([string]$ModelTag) {
    if (-not (Test-Path $Py)) { return $null }
    $env:PYTHONPATH = Join-Path $Root 'src'
    $a = @('-m', 'sw_analyst', '--check', '--json', '--port', "$Port", '--ollama-url', $OllamaUrl, '--data-dir', $Data)
    if ($ModelTag) { $a += @('--model', $ModelTag) }
    $txt = (& $Py @a | Out-String)
    try { return ($txt | ConvertFrom-Json).results } catch { return @([pscustomobject]@{ name = 'preflight'; status = 'FEHLER'; detail = 'python check produced no result'; fix = 'run: python -m sw_analyst --check' }) }
}
function Show-Results($Results) {
    foreach ($r in $Results) {
        $fix = if ($r.fix -and $r.status -ne 'OK') { "  -> $($r.fix)" } else { '' }
        Write-Stage 'CHECK' ("{0,-18} {1}{2}" -f $r.name, $r.detail, $fix) $r.status
    }
}

function Install-Venv {
    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if (-not (Test-Path $Py)) {
        Write-Stage 'INSTALL' 'creating .venv'
        if ($uv) { Invoke-Native 'uv' @('venv', (Join-Path $Root '.venv')) }
        else { Invoke-Native 'python' @('-m', 'venv', (Join-Path $Root '.venv')) }
    }
    Install-Lock
}
function Install-Lock {
    $lock = Join-Path $Root 'requirements.lock'
    $extra = @()
    if ($Offline) {
        if (-not (Get-ChildItem (Join-Path $Root 'vendor') -Filter *.whl -ErrorAction SilentlyContinue)) {
            throw 'offline: vendor\ has no wheelhouse (*.whl); run once online or fill vendor\'
        }
        $extra = @('--no-index', '--find-links', (Join-Path $Root 'vendor'))
    }
    Write-Stage 'INSTALL' 'installing requirements.lock with --require-hashes'
    if (Get-Command uv -ErrorAction SilentlyContinue) { Invoke-Native 'uv' (@('pip', 'install', '--python', $Py, '--require-hashes', '-r', $lock) + $extra) }
    else { Invoke-Native $Py (@('-m', 'pip', 'install', '--require-hashes', '-r', $lock) + $extra) }
}
function Install-Ollama($c) {
    if ($Offline) { throw 'offline: Ollama is missing and cannot be downloaded' }
    if ($c.url -notmatch '^https://github\.com/' -or $c.sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'manifest entry for ollama is not pinned (https://github.com URL + sha256 required)' }
    if (-not (Test-UnderTools $c.target)) { throw "target $($c.target) is outside $ToolsRoot" }
    $dl = Join-Path $ToolsRoot 'dl'
    New-Item -ItemType Directory -Force -Path $dl | Out-Null
    $zip = Join-Path $dl ("ollama-{0}.zip" -f $c.version)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Stage 'INSTALL' "downloading ollama $($c.version) from the pinned URL"
    Invoke-WebRequest -UseBasicParsing -Uri $c.url -OutFile $zip
    Assert-Hash $zip $c.sha256
    Write-Stage 'INSTALL' 'sha256 matches the manifest' 'OK'
    $tmp = $c.target + '.partial'
    if (Test-Path $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
    Expand-Archive -LiteralPath $zip -DestinationPath $tmp
    if (-not (Test-Path (Join-Path $tmp $c.exe))) { Remove-Item -LiteralPath $tmp -Recurse -Force; throw "$($c.exe) not found in the archive" }
    Move-Item -LiteralPath $tmp -Destination $c.target
    Write-Stage 'INSTALL' "ollama $($c.version) installed in $($c.target)" 'OK'
}

# ===== main ==============================================================================================
try {
    $Manifest = Get-Content (Join-Path $Root 'infra\manifest.json') -Raw | ConvertFrom-Json
    $ol = $Manifest.components.ollama
    $OllamaExe = Join-Path $ol.target $ol.exe

    # ---- 1. CHECK ----
    Write-Stage 'CHECK' ("PowerShell {0}, {1}, repo {2}" -f $PSVersionTable.PSVersion, [Environment]::OSVersion.VersionString, $Root)
    if ($Offline) { Write-Stage 'CHECK' 'offline mode: no network access, local checks and vendor\ only' 'WARN' }
    $ModelTag = Resolve-Model
    $results = Invoke-Check $ModelTag
    if ($null -eq $results) { Write-Stage 'CHECK' '.venv missing; python checks follow after INSTALL' 'WARN' }
    else { Show-Results $results }

    # ---- 2. INSTALL (missing parts only) ----
    $needLock = (-not $results) -or [bool]($results | Where-Object { $_.name -eq 'lock:missing' -and $_.status -eq 'FEHLER' })
    if ($needLock) { Install-Venv } else { Write-Stage 'INSTALL' 'python packages complete' 'OK' }
    $older = Get-OllamaVersions
    if (Test-Path $OllamaExe) { Write-Stage 'INSTALL' "ollama $($ol.version) present" 'OK' }
    elseif ($older.Count -gt 0) { Write-Stage 'INSTALL' "ollama $($ol.version) missing, older $($older[0].Name) present; see UPDATE" 'WARN' }
    else { Install-Ollama $ol }

    # ---- 3. UPDATE (report; apply only with -Update, only pinned versions) ----
    if ($SkipUpdateCheck) { Write-Stage 'UPDATE' 'skipped (-SkipUpdateCheck)' }
    else {
        $drift = $false
        if (Test-Path $Py) {
            $chk = Invoke-Check $ModelTag
            $drift = [bool]($chk | Where-Object { $_.name -eq 'lock:drift' -and $_.status -ne 'OK' })
        }
        $olOld = (-not (Test-Path $OllamaExe)) -and ($older.Count -gt 0)
        if ($drift) {
            if ($Update) { Install-Lock } else { Write-Stage 'UPDATE' 'installed packages differ from requirements.lock; apply with -Update' 'WARN' }
        }
        if ($olOld) {
            if ($Update) { Install-Ollama $ol } else { Write-Stage 'UPDATE' "manifest pins ollama $($ol.version), installed $($older[0].Name); apply with -Update" 'WARN' }
        }
        if (-not $drift -and -not $olOld) { Write-Stage 'UPDATE' 'installed versions match the manifest and lockfile' 'OK' }
        $pending = @($Manifest.components.PSObject.Properties | Where-Object { $_.Value.url -eq 'pending' -or $_.Value.sha256 -eq 'pending' } | ForEach-Object { $_.Name })
        if ($pending.Count -gt 0) { Write-Stage 'UPDATE' ("not pinned yet (needs review before use): " + ($pending -join ', ')) }
        Write-Stage 'UPDATE' 'newer upstream versions are never fetched automatically: a pin update in infra\manifest.json (review) is required first'
    }

    # ---- re-check: abort on real errors ----
    $OllamaDir = if (Test-Path $OllamaExe) { $ol.target } elseif ((Get-OllamaVersions).Count -gt 0) { (Get-OllamaVersions)[0].FullName } else { $null }
    $results = Invoke-Check $ModelTag
    $fatal = @($results | Where-Object { $_.status -eq 'FEHLER' -and -not ($_.name -eq 'ollama:binary' -and $OllamaDir) })
    Write-Stage 'CHECK' ("re-check: {0} checks, {1} errors, {2} warnings" -f $results.Count, $fatal.Count, @($results | Where-Object { $_.status -eq 'WARN' }).Count)
    if ($fatal.Count -gt 0) { Show-Results $fatal; Exit-Fail 'CHECK' 'errors remain; nothing was started' }
    if (-not $OllamaDir) { Exit-Fail 'OLLAMA' 'no ollama installation available' }
    $OllamaExe = Join-Path $OllamaDir 'ollama.exe'

    # ---- 4. OLLAMA + MODEL ----
    # Own process with a time limit and file output (no pipe): the daemon it starts must not be able to block this script.
    $olOut = Join-Path $RunDir 'ollama-start.out'
    Remove-Item -LiteralPath $olOut, ($olOut + '.err') -Force -ErrorAction SilentlyContinue
    $olArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $Root 'infra\start-ollama.ps1')`"", '-OllamaDir', "`"$OllamaDir`"", '-Port', "$OllamaPort")
    $olp = Start-Process -FilePath 'powershell.exe' -ArgumentList $olArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput $olOut -RedirectStandardError ($olOut + '.err')
    $null = $olp.Handle   # keep the handle so ExitCode is readable after exit
    Write-Stage 'OLLAMA' "starting ollama on port $OllamaPort (limit 90 s)"
    if (-not $olp.WaitForExit(90000)) {
        try { $olp.Kill() } catch { }
        Exit-Fail 'OLLAMA' "start-ollama.ps1 did not finish within 90 s; see $olOut"
    }
    foreach ($l in @(Get-Content -LiteralPath $olOut -ErrorAction SilentlyContinue)) { if ("$l".Trim()) { Write-Stage 'OLLAMA' "$l" } }
    if ($olp.ExitCode -ne 0) {
        $err = @(Get-Content -LiteralPath ($olOut + '.err') -ErrorAction SilentlyContinue) -join ' '
        Exit-Fail 'OLLAMA' "start-ollama.ps1 failed (exit $($olp.ExitCode)): $err"
    }
    $conn = Get-NetTCPConnection -LocalPort $OllamaPort -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $conn) { Exit-Fail 'OLLAMA' "nothing listens on port $OllamaPort" }
    $op = Get-Process -Id $conn.OwningProcess
    if (-not $op.Path -or -not (Test-UnderTools $op.Path)) { Exit-Fail 'OLLAMA' "port $OllamaPort is held by a foreign process ($($op.Name), pid $($op.Id)); not touching it" }
    @{ pid = $op.Id; name = $op.Name; started = (Get-Date).ToString('s') } | ConvertTo-Json -Compress | Set-Content (Join-Path $RunDir 'ollama.pid') -Encoding ASCII
    Write-Stage 'OLLAMA' "ollama pid $($op.Id) on $OllamaUrl (loopback only)" 'OK'

    $tags = (Get-Json "$OllamaUrl/api/tags").models | ForEach-Object { $_.name }
    if ($tags -notcontains $ModelTag -and $tags -notcontains "${ModelTag}:latest") {
        if ($Offline) { Exit-Fail 'MODEL' "model $ModelTag missing and -Offline is set" }
        Write-Stage 'MODEL' "model $ModelTag missing: one-time download from the Ollama registry (network, several GB; Ollama verifies the digests)" 'WARN'
        $env:OLLAMA_HOST = "127.0.0.1:$OllamaPort"
        try { Invoke-Native $OllamaExe @('pull', $ModelTag) } finally { Remove-Item Env:OLLAMA_HOST -ErrorAction SilentlyContinue }
        Write-Stage 'MODEL' "$ModelTag pulled" 'OK'
    } else { Write-Stage 'MODEL' "$ModelTag present" 'OK' }
    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $body = @{ model = $ModelTag; prompt = ''; stream = $false; keep_alive = '10m' } | ConvertTo-Json -Compress
        Invoke-RestMethod -Uri "$OllamaUrl/api/generate" -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 600 | Out-Null
        Write-Stage 'MODEL' ("warm-up done in {0:N1}s" -f $sw.Elapsed.TotalSeconds) 'OK'
    } catch { Write-Stage 'MODEL' "warm-up failed: $($_.Exception.Message)" 'WARN' }

    # ---- 5. APP ----
    $appPidFile = Join-Path $RunDir 'app.pid'
    $appProc = $null
    $prev = if (Test-Path $appPidFile) { Get-Content $appPidFile -Raw | ConvertFrom-Json } else { $null }
    if ($prev -and (Get-Process -Id $prev.pid -ErrorAction SilentlyContinue)) {
        Write-Stage 'APP' "already running (pid $($prev.pid)); attaching to it" 'WARN'
        $appProc = Get-Process -Id $prev.pid
    } else {
        $env:PYTHONPATH = Join-Path $Root 'src'; $env:SW_LOG_FILE = $LogFile; $env:PYTHONUNBUFFERED = '1'; $env:PYTHONUTF8 = '1'
        $a = @('-m', 'sw_analyst', '--model', $ModelTag, '--ollama-url', $OllamaUrl, '--data-dir', "`"$Data`"", '--port', "$Port")
        $out = Join-Path $LogDir ("app-{0:yyyy-MM-dd}.out" -f (Get-Date))
        $appProc = Start-Process -FilePath $Py -ArgumentList $a -WorkingDirectory $Root -WindowStyle Hidden -PassThru -RedirectStandardOutput $out -RedirectStandardError ($out + '.err')
        @{ pid = $appProc.Id; name = 'python'; started = (Get-Date).ToString('s') } | ConvertTo-Json -Compress | Set-Content $appPidFile -Encoding ASCII
        Write-Stage 'APP' "started pid $($appProc.Id), waiting for $Base/api/system"
    }
    $ready = $false
    for ($i = 0; $i -lt 90 -and -not $ready; $i++) {
        if ($appProc.HasExited) { Exit-Fail 'APP' "process exited early (exit $($appProc.ExitCode)); see $LogDir\app-*.out.err" }
        try { Get-Json "$Base/api/system" 2 | Out-Null; $ready = $true } catch { Start-Sleep -Seconds 1 }
    }
    if (-not $ready) { Exit-Fail 'APP' "no answer from $Base/api/system after 90 s" }
    Write-Stage 'APP' "ready: $Base/   (Ctrl+C stops everything cleanly)" 'OK'
    if (-not $NoBrowser) { Start-Process "$Base/" }

    # ---- 6. status loop (prints only on change) ----
    $lastW = ''; $lastJ = ''; $lastJob = $null
    try {
        while ($true) {
            Start-Sleep -Seconds 2
            if ($appProc.HasExited) { Exit-Fail 'APP' "application stopped unexpectedly (exit $($appProc.ExitCode))" }
            try { $s = Get-Json "$Base/api/system" } catch { continue }
            $w = "worker={0} queue={1} llm={2}" -f $s.worker.state, $s.queue_length, $(if ($s.llm.reachable) { 'ok' } else { 'down' })
            if ($w -ne $lastW) { Write-Stage 'WORKER' $w $(if ($s.llm.reachable) { 'INFO' } else { 'WARN' }); $lastW = $w }
            $jid = $s.worker.job_id
            if ($jid) {
                $j = "job=$jid"
                try {
                    $act = Get-Json "$Base/api/jobs/$jid/activity"
                    $j += " phase=$($act.phase)"
                    if ($act.task) { $j += " task='$($act.task.title)'" }
                    if ($act.step) { $j += " step='$($act.step.what)'" }
                } catch { }  # activity endpoint may not exist yet
                if ($j -ne $lastJ) { Write-Stage 'JOB' $j; $lastJ = $j }
            } elseif ($lastJob) {
                $fin = try { (Get-Json "$Base/api/jobs/$lastJob").summary.status } catch { 'unknown' }
                Write-Stage 'JOB' "job=$lastJob finished, status=$fin" $(if ($fin -in 'done', 'partial') { 'OK' } else { 'WARN' }); $lastJ = ''
            }
            $lastJob = $jid
        }
    } finally {
        Write-Stage 'STOP' 'shutting down (waits for a running job; Ctrl+C again aborts the wait)'
        & (Join-Path $PSScriptRoot 'stop.ps1') -Port $Port -OllamaPort $OllamaPort
    }
} catch {
    Write-Stage 'CHECK' "aborted: $($_.Exception.Message)" 'FEHLER'
    exit 1
}
