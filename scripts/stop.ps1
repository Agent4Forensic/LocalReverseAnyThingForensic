# stop.ps1 - stops only the own sw-analyst processes (PID files in data\run, then port/process-name cross-check).
# Waits for a running job; -Force cancels it (job is marked cancelled) and stops right away.
# Foreign processes (Ollama on 11434, other WSL/Docker projects) are never touched. No admin rights needed.
# Pure ASCII on purpose (Windows PowerShell 5.1 encoding).
param(
    [int]$Port = 8765,
    [int]$OllamaPort = 11435,
    [switch]$Force,
    [switch]$NoCleanup,     # skip the cleanup after stopping
    [switch]$DockerDeep     # also prune the shared Docker build cache older than 7 days (affects other projects)
)
$ErrorActionPreference = 'Stop'

$Root      = Split-Path -Parent $PSScriptRoot
$Data      = Join-Path $Root 'data'
$RunDir    = Join-Path $Data 'run'
$LogDir    = Join-Path $Data 'logs'
$Py        = Join-Path $Root '.venv\Scripts\python.exe'
$ToolsRoot = 'D:\Tools\sw-analyst'
$Base      = "http://127.0.0.1:$Port"
New-Item -ItemType Directory -Force -Path $RunDir, $LogDir | Out-Null
$LogFile   = Join-Path $LogDir ("start-{0:yyyy-MM-dd}.log" -f (Get-Date))
$Utf8      = New-Object System.Text.UTF8Encoding($false)

function Write-Stage([string]$Stage, [string]$Msg, [string]$Level = 'INFO') {
    $prefix = if ($Level -in 'OK', 'WARN', 'FEHLER') { "${Level}: " } else { '' }
    $line = '[{0:HH:mm:ss}] [{1}] {2}{3}' -f (Get-Date), $Stage, $prefix, $Msg
    $color = switch ($Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'FEHLER' { 'Red' } default { 'Gray' } }
    Write-Host $line -ForegroundColor $color
    for ($i = 0; $i -lt 5; $i++) {
        try { [IO.File]::AppendAllText($LogFile, $line + "`r`n", $Utf8); return } catch { Start-Sleep -Milliseconds 50 }
    }
}

function Read-PidFile([string]$Name) {
    $f = Join-Path $RunDir "$Name.pid"
    if (-not (Test-Path $f)) { return $null }
    try { return (Get-Content $f -Raw | ConvertFrom-Json) } catch { return $null }
}
function Get-CmdLine([int]$ProcId) { (Get-CimInstance Win32_Process -Filter "ProcessId=$ProcId" -ErrorAction SilentlyContinue).CommandLine }

# Own-process tests: app = python running sw_analyst; ollama = ollama.exe below the sw-analyst tools folder.
function Test-OwnApp([int]$ProcId) {
    $p = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
    return [bool]($p -and $p.Name -like 'python*' -and (Get-CmdLine $ProcId) -match 'sw_analyst')
}
function Test-OwnOllama([int]$ProcId) {
    $p = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
    return [bool]($p -and $p.Name -eq 'ollama' -and $p.Path -and $p.Path.StartsWith($ToolsRoot + '\', [StringComparison]::OrdinalIgnoreCase))
}
function Stop-Tree([int]$ProcId) { & cmd.exe /c "taskkill /PID $ProcId /T /F >nul 2>&1" }
function Get-PortOwner([int]$P) {
    # Locale-independent (no state words). Any row whose LOCAL port is $P belongs to the server side: clients use
    # ephemeral ports. The LISTEN row itself is sometimes missing from netstat in hidden sessions, so connected rows count too.
    # Get-NetTCPConnection proved unreliable in detached/hidden sessions, so netstat is parsed instead.
    foreach ($l in (& netstat.exe -ano -p TCP)) {
        $f = @(($l -split '\s+') | Where-Object { $_ })
        if ($f.Count -ge 5 -and $f[0] -eq 'TCP' -and $f[1].EndsWith(":$P") -and [int]$f[-1] -gt 0) { return [int]$f[-1] }
    }
    return 0
}

# Stops "name" (app|ollama): PID file first, then whatever still listens on the port if (and only if) it is ours.
function Stop-Own([string]$Name, [int]$P, [scriptblock]$IsOwn) {
    $d = Read-PidFile $Name
    if ($d) {
        if (& $IsOwn ([int]$d.pid)) { Stop-Tree ([int]$d.pid); Write-Stage 'STOP' "$Name pid $($d.pid) stopped" 'OK' }
        elseif (Get-Process -Id $d.pid -ErrorAction SilentlyContinue) { Write-Stage 'STOP' "pid $($d.pid) from $Name.pid is not our $Name process (pid reused?); left alone" 'WARN' }
        else { Write-Stage 'STOP' "$Name.pid was stale (process already gone)" }
    }
    Start-Sleep -Milliseconds 500
    $o = Get-PortOwner $P
    if ($o -ne 0) {
        if (& $IsOwn $o) { Stop-Tree $o; Write-Stage 'STOP' "$Name still listened on port $P (pid $o); stopped" 'OK' }
        else { Write-Stage 'STOP' "port $P is held by a foreign process (pid $o); not touching it" 'WARN' }
    }
    Remove-Item (Join-Path $RunDir "$Name.pid") -ErrorAction SilentlyContinue
}

try {
    Write-Stage 'STOP' ("stop requested{0}" -f $(if ($Force) { ' (-Force)' } else { '' }))

    # ---- running job ----
    $sys = $null
    try { $sys = Invoke-RestMethod -Uri "$Base/api/system" -TimeoutSec 3 } catch { Write-Stage 'STOP' "application does not answer on $Base (already stopped?)" }
    if ($sys -and $sys.worker.job_id) {
        $jid = $sys.worker.job_id
        if ($Force) {
            Write-Stage 'JOB' "-Force: cancelling job $jid" 'WARN'
            try { Invoke-RestMethod -Uri "$Base/api/jobs/$jid/cancel" -Method Post -Headers @{ Origin = $Base } -Body '' -TimeoutSec 5 | Out-Null }
            catch { Write-Stage 'JOB' "cancel request failed: $($_.Exception.Message)" 'WARN' }
            for ($i = 0; $i -lt 20; $i++) {
                Start-Sleep -Seconds 1
                try { if (-not (Invoke-RestMethod -Uri "$Base/api/system" -TimeoutSec 3).worker.job_id) { break } } catch { break }
            }
        } else {
            Write-Stage 'JOB' "job $jid is running; waiting for it to finish (stop.ps1 -Force cancels it)" 'WARN'
            $n = 0
            while ($true) {
                Start-Sleep -Seconds 5
                try { $cur = (Invoke-RestMethod -Uri "$Base/api/system" -TimeoutSec 3).worker.job_id } catch { break }
                if (-not $cur) { break }
                if ((++$n) % 6 -eq 0) { Write-Stage 'JOB' "still waiting for job $cur" }
            }
            Write-Stage 'JOB' "job $jid finished" 'OK'
        }
    }

    # ---- app, then ollama ----
    Stop-Own 'app' $Port { param($i) Test-OwnApp $i }
    if ($Force -and (Test-Path $Py) -and (Test-Path (Join-Path $Data 'sw_analyst.db'))) {
        # A job that was running when the process was killed must not stay 'running'.
        $env:PYTHONPATH = Join-Path $Root 'src'
        $code = "import sys; from sw_analyst.common.store import Store; from sw_analyst.common.util import utcnow; s=Store(sys.argv[1]+'/sw_analyst.db', sys.argv[1]+'/logs'); print(*[s.update_job(j['id'], status='cancelled', cancel_requested=1, finished_at=utcnow())['id'] for j in [s.running_job()] if j])"
        $m = (& $Py -c $code $Data | Out-String).Trim()
        if ($m) { Write-Stage 'JOB' "job $m marked cancelled" 'WARN' }
    }
    Stop-Own 'ollama' $OllamaPort { param($i) Test-OwnOllama $i }
    if (-not $NoCleanup) {
        $ca = @{ Phase = 'post'; Port = $Port; OllamaPort = $OllamaPort }
        if ($DockerDeep) { $ca.DockerDeep = $true }
        & (Join-Path $PSScriptRoot 'cleanup.ps1') @ca
    }
    Write-Stage 'STOP' 'done, PID files removed' 'OK'
} catch {
    Write-Stage 'STOP' "failed: $($_.Exception.Message)" 'FEHLER'
    exit 1
}
