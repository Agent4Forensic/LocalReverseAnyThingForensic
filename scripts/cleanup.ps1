# cleanup.ps1 - removes what sw-analyst no longer needs. Called by start.ps1 (-Phase pre) and stop.ps1 (-Phase post).
# Scope: ONLY own things. Own = PID files in data\run, processes started from this repo's .venv / D:\Tools\sw-analyst,
# files below data\ and D:\Tools\sw-analyst, Docker objects carrying the label "sw-analyst".
# Foreign processes, foreign Docker objects (other projects), ~/.ollama and the Ollama on 11434 are never touched.
# Cleanup never blocks start or stop: every step catches its own error and reports WARN.
# Pure ASCII on purpose (Windows PowerShell 5.1 encoding).
param(
    [ValidateSet('pre', 'post')][string]$Phase = 'pre',
    [switch]$DryRun,        # only report what would be removed
    [switch]$DockerDeep,    # also prune the shared Docker build cache older than 7 days (unlabeled, affects other projects too)
    [int]$KeepDays = 14,    # log retention
    [int]$Port = 8765,
    [int]$OllamaPort = 11435
)
$ErrorActionPreference = 'Stop'

$Root      = Split-Path -Parent $PSScriptRoot
$Data      = Join-Path $Root 'data'
$RunDir    = Join-Path $Data 'run'
$LogDir    = Join-Path $Data 'logs'
$ToolsRoot = 'D:\Tools\sw-analyst'
$ToolsLogs = Join-Path $ToolsRoot 'logs'
$Label     = 'sw-analyst'
$LogFile   = Join-Path $LogDir ("start-{0:yyyy-MM-dd}.log" -f (Get-Date))
$Utf8      = New-Object System.Text.UTF8Encoding($false)
New-Item -ItemType Directory -Force -Path $RunDir, $LogDir | Out-Null
$script:Freed = [long]0
$script:Items = 0

function Write-Stage([string]$Msg, [string]$Level = 'INFO') {
    $prefix = if ($Level -in 'OK', 'WARN', 'FEHLER') { "${Level}: " } else { '' }
    $line = '[{0:HH:mm:ss}] [CLEAN] {1}{2}' -f (Get-Date), $prefix, $Msg
    $color = switch ($Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'FEHLER' { 'Red' } default { 'Gray' } }
    Write-Host $line -ForegroundColor $color
    for ($i = 0; $i -lt 5; $i++) {
        try { [IO.File]::AppendAllText($LogFile, $line + "`r`n", $Utf8); return } catch { Start-Sleep -Milliseconds 50 }
    }
}
function Step([string]$Name, [scriptblock]$Body) {
    try { & $Body } catch { Write-Stage "$Name failed: $($_.Exception.Message)" 'WARN' }
}

# ---- safety: only paths below these roots may ever be deleted ----
function Test-Deletable([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    foreach ($r in $Data, $ToolsRoot) {
        if ($full.StartsWith($r.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    foreach ($r in (Join-Path $Root 'src'), (Join-Path $Root 'tests'), $Root) {
        # only caches directly named __pycache__ / .pytest_cache below the repo
        if ($full.StartsWith($r.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -and ((Split-Path -Leaf $full) -in '__pycache__', '.pytest_cache')) { return $true }
    }
    return $false
}
function Remove-Own([string]$Path, [string]$Why) {
    if (-not (Test-Deletable $Path)) { Write-Stage "refused to delete outside own folders: $Path" 'WARN'; return }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $size = if ($item.PSIsContainer) { [long](Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum } else { [long]$item.Length }
    if ($DryRun) { Write-Stage "would remove $Path ($Why)"; }
    else { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop }
    $script:Freed += $size; $script:Items++
}
function Remove-Aged([string]$Dir, [string]$Filter, [int]$Days, [string]$Why) {
    if (-not (Test-Path -LiteralPath $Dir)) { return }
    $limit = (Get-Date).AddDays(-$Days)
    foreach ($f in @(Get-ChildItem -LiteralPath $Dir -Filter $Filter -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $limit })) {
        try { Remove-Own $f.FullName $Why } catch { Write-Stage "cannot remove $($f.Name) (in use?)" 'WARN' }
    }
}

# ---- processes ----
function Get-Procs { @(Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='ollama.exe' OR Name='deepseek_v4.exe'" -ErrorAction SilentlyContinue) }
# The venv python.exe is a launcher that starts the base python as a child: match on the command line (module + own data dir) too.
function Test-OwnPython($p) {
    if ($p.Name -ne 'python.exe' -or $p.CommandLine -notmatch '-m\s+"?sw_analyst\b') { return $false }
    $inVenv = $p.ExecutablePath -and $p.ExecutablePath.StartsWith((Join-Path $Root '.venv'), [StringComparison]::OrdinalIgnoreCase)
    return [bool]($inVenv -or $p.CommandLine.IndexOf($Data, [StringComparison]::OrdinalIgnoreCase) -ge 0)
}
function Test-OwnOllama($p) { $p.Name -eq 'ollama.exe' -and $p.ExecutablePath -and $p.ExecutablePath.StartsWith($ToolsRoot + '\', [StringComparison]::OrdinalIgnoreCase) }
function Test-OwnColibri($p) {
    if ($p.Name -eq 'python.exe') { return [bool]($p.CommandLine -match ([regex]::Escape($ToolsRoot) + '\\colibri-[\d.]+\\coli"?\s')) }
    return [bool]($p.ExecutablePath -and $p.ExecutablePath.StartsWith((Join-Path $ToolsRoot 'colibri-'), [StringComparison]::OrdinalIgnoreCase))
}
function Stop-Own($p, [string]$Why) {
    if ($p.ProcessId -eq $PID) { return }
    if ($DryRun) { Write-Stage "would stop $($p.Name) pid $($p.ProcessId) ($Why)"; $script:Items++; return }
    & cmd.exe /c "taskkill /PID $($p.ProcessId) /T /F >nul 2>&1"
    Write-Stage "stopped $($p.Name) pid $($p.ProcessId) ($Why)" 'OK'; $script:Items++
}
function Read-PidFile([string]$Name) {
    $f = Join-Path $RunDir "$Name.pid"
    if (-not (Test-Path $f)) { return $null }
    try { return (Get-Content $f -Raw | ConvertFrom-Json) } catch { return $null }
}
function Get-PortOwner([int]$P) {
    foreach ($l in (& netstat.exe -ano -p TCP)) {
        $f = @(($l -split '\s+') | Where-Object { $_ })
        if ($f.Count -ge 5 -and $f[0] -eq 'TCP' -and $f[1].EndsWith(":$P") -and [int]$f[-1] -gt 0) { return [int]$f[-1] }
    }
    return 0
}

# ---- docker (own label only, bounded run time) ----
function Invoke-Docker([string[]]$DockerArgs, [int]$LimitSec = 30) {
    $out = Join-Path $RunDir 'docker-clean.out'
    $p = Start-Process -FilePath 'docker' -ArgumentList $DockerArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput $out -RedirectStandardError ($out + '.err')
    $null = $p.Handle
    if (-not $p.WaitForExit($LimitSec * 1000)) { try { $p.Kill() } catch { }; throw "docker $($DockerArgs[0]) did not finish within $LimitSec s" }
    $txt = (Get-Content -LiteralPath $out -ErrorAction SilentlyContinue) -join "`n"
    Remove-Item -LiteralPath $out, ($out + '.err') -Force -ErrorAction SilentlyContinue
    if ($p.ExitCode -ne 0) { throw "docker $($DockerArgs -join ' ') exit $($p.ExitCode)" }
    return $txt
}

Write-Stage ("{0} cleanup{1}" -f $Phase, $(if ($DryRun) { ' (dry run, nothing is removed)' } else { '' }))

# 1. PID files: drop stale ones (process gone, or the PID now belongs to something else)
Step 'pid files' {
    foreach ($n in 'app', 'ollama', 'colibri') {
        $d = Read-PidFile $n
        if (-not $d) { if (Test-Path (Join-Path $RunDir "$n.pid")) { Remove-Own (Join-Path $RunDir "$n.pid") 'unreadable pid file' }; continue }
        $proc = Get-Procs | Where-Object { $_.ProcessId -eq [int]$d.pid }
        $own = $proc -and ((Test-OwnPython $proc) -or (Test-OwnOllama $proc) -or (Test-OwnColibri $proc))
        if (-not $own -and $Phase -eq 'pre') { Remove-Own (Join-Path $RunDir "$n.pid") "stale $n.pid" }
    }
}

# 2. processes
Step 'processes' {
    $appPid = $null; $d = Read-PidFile 'app'; if ($d) { $appPid = [int]$d.pid }
    $all = Get-Procs
    $alive = @{}; foreach ($p in $all) { $alive[[int]$p.ProcessId] = $true }
    if ($Phase -eq 'pre') {
        # orphans only: an app that is not in app.pid, ollama runner children whose parent is gone. A reusable ollama server stays.
        foreach ($p in ($all | Where-Object { Test-OwnPython $_ })) {
            if ($p.ProcessId -ne $appPid -and $p.ParentProcessId -ne $appPid) { Stop-Own $p 'orphan app, not in app.pid' }
        }
        if (-not (Read-PidFile 'colibri')) { foreach ($p in ($all | Where-Object { Test-OwnColibri $_ })) { Stop-Own $p 'orphan colibri, not in colibri.pid' } }
        foreach ($p in ($all | Where-Object { (Test-OwnOllama $_) -and $_.CommandLine -match 'runner' })) {
            $parent = Get-Process -Id $p.ParentProcessId -ErrorAction SilentlyContinue
            if (-not $parent) { Stop-Own $p 'orphan model runner (parent gone)' }
        }
    } else {
        # post: everything own that still runs (stop.ps1 has already stopped the PID-file processes)
        foreach ($p in ($all | Where-Object { (Test-OwnPython $_) -or (Test-OwnOllama $_) -or (Test-OwnColibri $_) })) { Stop-Own $p 'left over after stop' }
        foreach ($pn in @{ n = 'app'; p = $Port }, @{ n = 'ollama'; p = $OllamaPort }) {
            $o = Get-PortOwner $pn.p
            if ($o -ne 0) { Write-Stage "port $($pn.p) is still held by pid $o (not ours or not stoppable); left alone" 'WARN' }
        }
        Remove-Own (Join-Path $RunDir 'app.pid') 'stopped' ; Remove-Own (Join-Path $RunDir 'ollama.pid') 'stopped' ; Remove-Own (Join-Path $RunDir 'colibri.pid') 'stopped'
    }
}

# 3. temp files and leftovers
Step 'temp files' {
    foreach ($f in @(Get-ChildItem -LiteralPath $RunDir -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -ne '.pid' })) { Remove-Own $f.FullName 'run-time scratch' }
    if (Test-Path (Join-Path $Data 'tmp')) { foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $Data 'tmp') -Force)) { Remove-Own $f.FullName 'data\tmp' } }
    if (Test-Path $ToolsRoot) {
        foreach ($d in @(Get-ChildItem -LiteralPath $ToolsRoot -Directory -Filter '*.partial' -Force -ErrorAction SilentlyContinue)) { Remove-Own $d.FullName 'unfinished install' }
    }
}

# 4. logs: keep $KeepDays days
Step 'old logs' {
    foreach ($pat in '*.log', '*.out', '*.err') {
        Remove-Aged $LogDir $pat $KeepDays "log older than $KeepDays days"
        Remove-Aged $ToolsLogs $pat $KeepDays "log older than $KeepDays days"
    }
}

if ($Phase -eq 'post') {
    # 5. caches (stale .pyc once hid a code fix) and verified download archives
    Step 'caches' {
        foreach ($sub in 'src', 'tests') {
            $d = Join-Path $Root $sub
            if (Test-Path $d) { foreach ($c in @(Get-ChildItem -LiteralPath $d -Directory -Recurse -Force -Filter '__pycache__' -ErrorAction SilentlyContinue)) { Remove-Own $c.FullName 'python cache' } }
        }
        Remove-Own (Join-Path $Root '.pytest_cache') 'pytest cache'
        Remove-Aged (Join-Path $ToolsRoot 'dl') '*.zip' 1 'install archive (hash is checked again on the next download)'
    }
    # 6. interrupted model downloads: only when no Ollama runs, only older than 3 days (younger ones can still be resumed)
    Step 'partial model blobs' {
        $running = @(Get-Procs | Where-Object { Test-OwnOllama $_ })
        $blobs = Join-Path $ToolsRoot 'ollama-models\blobs'
        if ($running.Count -eq 0) { Remove-Aged $blobs '*-partial*' 3 'interrupted model download older than 3 days' }
    }
}

# 7. docker: own label only. Foreign containers, networks, volumes and images stay.
Step 'docker' {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Write-Stage 'docker not installed; skipped'; return }
    try { Invoke-Docker @('info', '--format', '{{.ServerVersion}}') 15 | Out-Null } catch { Write-Stage 'docker daemon not reachable; skipped'; return }
    $filter = "label=$Label"
    $ids = @((Invoke-Docker @('ps', '-aq', '--filter', $filter)) -split "`n" | Where-Object { $_.Trim() })
    if ($Phase -eq 'pre') { $ids = @((Invoke-Docker @('ps', '-aq', '--filter', $filter, '--filter', 'status=exited', '--filter', 'status=created', '--filter', 'status=dead')) -split "`n" | Where-Object { $_.Trim() }) }
    if ($ids.Count -gt 0) {
        if ($DryRun) { Write-Stage "would remove $($ids.Count) container(s) with label $Label" }
        else {
            if ($Phase -eq 'post') { Invoke-Docker (@('stop', '-t', '10') + $ids) 90 | Out-Null }
            Invoke-Docker (@('rm', '-f', '-v') + $ids) 60 | Out-Null
            Write-Stage "removed $($ids.Count) container(s) with label $Label (and their anonymous volumes)" 'OK'
        }
        $script:Items += $ids.Count
    }
    if (-not $DryRun) {
        foreach ($c in @(@('network', 'prune', '-f', '--filter', $filter), @('volume', 'prune', '-f', '--filter', $filter), @('image', 'prune', '-f', '--filter', $filter))) {
            $txt = Invoke-Docker $c 60
            $rec = ($txt -split "`n" | Where-Object { $_ -match 'reclaimed' } | Select-Object -First 1)
            if ($rec) { Write-Stage ("docker {0} {1}: {2}" -f $c[0], $c[1], $rec.Trim()) }
        }
        if ($DockerDeep) {
            $txt = Invoke-Docker @('builder', 'prune', '-f', '--filter', 'until=168h') 120
            $rec = ($txt -split "`n" | Where-Object { $_ -match 'reclaimed' } | Select-Object -First 1)
            Write-Stage ("docker build cache (shared, older than 7 days): {0}" -f $(if ($rec) { $rec.Trim() } else { 'nothing' })) 'WARN'
        } elseif ($Phase -eq 'post') {
            Write-Stage 'docker build cache is shared with other projects and left alone (stop.ps1 -DockerDeep prunes entries older than 7 days)'
        }
    }
}

Write-Stage ("{0}: {1} item(s), {2:N1} MB {3}" -f $Phase, $script:Items, ($script:Freed / 1MB), $(if ($DryRun) { 'would be freed' } else { 'freed' })) 'OK'
exit 0
