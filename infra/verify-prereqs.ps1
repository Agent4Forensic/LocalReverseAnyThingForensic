# verify-prereqs.ps1
# Checks all prerequisites for sw-analyst on the development host and prints a PASS/WARN/FAIL table.
# Read-only: changes nothing. Pure ASCII on purpose (Windows PowerShell 5.1 encoding).
$ErrorActionPreference = 'Continue'
$results = New-Object System.Collections.Generic.List[object]

function Add-Result([string]$Name, [string]$State, [string]$Detail) {
    $results.Add([pscustomobject]@{ Check = $Name; State = $State; Detail = $Detail })
}

function Test-Cmd([string]$Name) { return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

# --- Tools
foreach ($c in 'git', 'python', 'node', 'docker', 'ollama', 'java', 'uv', 'graphify', 'claude') {
    if (Test-Cmd $c) { Add-Result "tool:$c" 'PASS' (Get-Command $c).Source } else { Add-Result "tool:$c" 'FAIL' 'not found in PATH' }
}

# --- Hardware
try {
    $gpu = (& nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv,noheader,nounits) -split ','
    $total = [int]$gpu[1].Trim(); $used = [int]$gpu[2].Trim(); $free = $total - $used
    $state = if ($free -ge 12000) { 'PASS' } elseif ($free -ge 6000) { 'WARN' } else { 'FAIL' }
    Add-Result 'gpu:free-vram' $state ("{0} MiB free of {1} MiB ({2})" -f $free, $total, $gpu[0].Trim())
} catch { Add-Result 'gpu:free-vram' 'FAIL' 'nvidia-smi not available' }

$ramTotal = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
$ramFree = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 1)
Add-Result 'ram:free' $(if ($ramFree -ge 10) { 'PASS' } else { 'WARN' }) ("{0} GB free of {1} GB" -f $ramFree, $ramTotal)

# --- WSL memory limit (target 24 GB)
$wslcfg = Join-Path $env:USERPROFILE '.wslconfig'
if (Test-Path $wslcfg) {
    $m = Select-String -Path $wslcfg -Pattern '^\s*memory\s*=\s*(\d+)\s*GB' | Select-Object -First 1
    if ($m) {
        $gb = [int]$m.Matches[0].Groups[1].Value
        Add-Result 'wsl:memory-limit' $(if ($gb -le 24) { 'PASS' } else { 'FAIL' }) ("{0} GB (hard cap 24 GB; target 24)" -f $gb)
    } else { Add-Result 'wsl:memory-limit' 'WARN' 'no memory= line' }
} else { Add-Result 'wsl:memory-limit' 'WARN' '.wslconfig missing' }

# --- Docker
docker info --format '{{.ServerVersion}}' 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    Add-Result 'docker:daemon' 'PASS' 'reachable'
    $rt = docker info --format '{{json .Runtimes}}' 2>$null
    Add-Result 'docker:nvidia-runtime' $(if ($rt -match 'nvidia') { 'PASS' } else { 'FAIL' }) 'runtime list checked'
} else { Add-Result 'docker:daemon' 'FAIL' 'daemon not reachable' }

# --- Ollama
try {
    $v = Invoke-RestMethod -Uri 'http://127.0.0.1:11435/api/version' -TimeoutSec 3
    Add-Result 'ollama:server' 'PASS' ("version {0}" -f $v.version)
} catch { Add-Result 'ollama:server' 'FAIL' 'server not reachable on 127.0.0.1:11435' }

# --- Hyper-V (needs admin to inspect features; service state is enough here)
$vmms = Get-Service vmms -ErrorAction SilentlyContinue
Add-Result 'hyperv:vmms' $(if ($vmms -and $vmms.Status -eq 'Running') { 'PASS' } else { 'FAIL' }) $(if ($vmms) { [string]$vmms.Status } else { 'service missing' })

# --- Claude plugins
$instFile = Join-Path $env:USERPROFILE '.claude\plugins\installed_plugins.json'
if (Test-Path $instFile) {
    $inst = Get-Content $instFile -Raw | ConvertFrom-Json
    foreach ($p in 'caveman@caveman', 'ponytail@ponytail', 'claude-security@claude-plugins-official', 'feature-dev@claude-plugins-official', 'pr-review-toolkit@claude-plugins-official', 'mcp-server-dev@claude-plugins-official') {
        $has = $inst.plugins.PSObject.Properties.Name -contains $p
        Add-Result "plugin:$p" $(if ($has) { 'PASS' } else { 'FAIL' }) ''
    }
    foreach ($p in 'mnemo@mnemo-marketplace', 'security-guidance@claude-plugins-official') {
        $has = $inst.plugins.PSObject.Properties.Name -contains $p
        Add-Result "plugin-absent:$p" $(if ($has) { 'FAIL' } else { 'PASS' }) 'must stay uninstalled (ADR-0000)'
    }
} else { Add-Result 'plugins' 'FAIL' 'installed_plugins.json not found' }

# --- Repo guards
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
$hp = git config core.hooksPath
Add-Result 'git:hooksPath' $(if ($hp -eq '.githooks') { 'PASS' } else { 'FAIL' }) ([string]$hp)
Add-Result 'repo:pre-commit-hook' $(if (Test-Path '.githooks\pre-commit') { 'PASS' } else { 'FAIL' }) ''
Add-Result 'repo:autocompact-setting' $(if ((Test-Path '.claude\settings.json') -and ((Get-Content '.claude\settings.json' -Raw) -match 'AUTOCOMPACT')) { 'PASS' } else { 'FAIL' }) ''
Add-Result 'repo:graphify-out' $(if (Test-Path 'graphify-out\graph.json') { 'PASS' } else { 'WARN' }) 'run /graphify . after changes'
Pop-Location

$results | Format-Table -AutoSize | Out-String -Width 200
$fail = ($results | Where-Object State -eq 'FAIL').Count
$warn = ($results | Where-Object State -eq 'WARN').Count
"SUMMARY: FAIL=$fail WARN=$warn PASS=$(($results | Where-Object State -eq 'PASS').Count)"
if ($fail -gt 0) { exit 1 } else { exit 0 }
