# start_eval.ps1 - pick example challenges and run them end to end with the local model.
# Builds a harmless sample per challenge, runs the full chain, then greps the final report for the flag (PASS/FAIL).
# Reports land in data\eval\<timestamp>\ (git-ignored). The application database is not touched.
#   example\start_eval.ps1                      interactive menu
#   example\start_eval.ps1 -Challenge all       no menu (all)    |  -Challenge 01-layered-flag,04-prompt-injection
# Pure ASCII on purpose (Windows PowerShell 5.1 encoding).
param(
    [string]$Challenge = '',      # 'all' or comma separated ids; empty = interactive menu
    [string]$Model = '',          # empty = chosen by free VRAM (infra\select-model.ps1)
    [int]$Minutes = 0,            # time budget per challenge; 0 = budget_minutes from challenge.json
    [int]$OllamaPort = 11435
)
$ErrorActionPreference = 'Stop'

$Here = $PSScriptRoot
$Root = Split-Path -Parent $Here
$Py   = Join-Path $Root '.venv\Scripts\python.exe'
$Url  = "http://127.0.0.1:$OllamaPort"
if (-not (Test-Path $Py)) { Write-Host "FEHLER: $Py missing. Run scripts\start.ps1 once (installs the venv)." -ForegroundColor Red; exit 1 }

# ---- load challenges -------------------------------------------------------------------------------------
$all = @(Get-ChildItem (Join-Path $Here 'challenges') -Directory | Sort-Object Name | ForEach-Object {
    Get-Content (Join-Path $_.FullName 'challenge.json') -Raw -Encoding UTF8 | ConvertFrom-Json })
if ($all.Count -eq 0) { Write-Host 'FEHLER: no challenges found in example\challenges' -ForegroundColor Red; exit 1 }

# ---- selection -------------------------------------------------------------------------------------------
if (-not $Challenge) {
    Write-Host ''
    Write-Host 'Challenges' -ForegroundColor Cyan
    for ($i = 0; $i -lt $all.Count; $i++) {
        $c = $all[$i]
        Write-Host ('  [{0}] {1}  ({2})' -f ($i + 1), $c.title, $c.level) -ForegroundColor White
        Write-Host ('      Beschreibung: {0}' -f $c.description) -ForegroundColor Gray
        Write-Host ('      Ziel:         {0}' -f $c.goal) -ForegroundColor Gray
    }
    Write-Host '  [a] alle    [q] beenden'
    $in = (Read-Host 'Auswahl (Nummern mit Komma, z.B. 1,3)').Trim().ToLower()
    if ($in -eq 'q' -or $in -eq '') { exit 0 }
    if ($in -eq 'a') { $Challenge = 'all' }
    else {
        $ids = foreach ($n in ($in -split '[,\s]+' | Where-Object { $_ })) {
            if ($n -notmatch '^\d+$' -or [int]$n -lt 1 -or [int]$n -gt $all.Count) { Write-Host "FEHLER: ungueltige Auswahl '$n'" -ForegroundColor Red; exit 1 }
            $all[[int]$n - 1].id
        }
        $Challenge = $ids -join ','
    }
}

# ---- Ollama + model --------------------------------------------------------------------------------------
function Test-Ollama { try { $null = Invoke-RestMethod -Uri "$Url/api/version" -TimeoutSec 2; $true } catch { $false } }
if (-not (Test-Ollama)) {
    Write-Host "Ollama on port $OllamaPort not running, starting infra\start-ollama.ps1 ..." -ForegroundColor Yellow
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'infra\start-ollama.ps1') -Port $OllamaPort
    if (-not (Test-Ollama)) { Write-Host 'FEHLER: Ollama does not answer.' -ForegroundColor Red; exit 1 }
}
if (-not $Model) {
    try { $Model = [string]((& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'infra\select-model.ps1') | Out-String | ConvertFrom-Json).chat_model) }
    catch { $Model = 'qwen3:8b'; Write-Host "model auto-select failed, using $Model" -ForegroundColor Yellow }
}
if ($Model -notmatch '^[A-Za-z0-9._:/-]+$') { Write-Host "FEHLER: invalid model tag '$Model'" -ForegroundColor Red; exit 1 }
$have = @((Invoke-RestMethod -Uri "$Url/api/tags" -TimeoutSec 5).models | ForEach-Object { $_.name })
if ($have -notcontains $Model) { Write-Host "FEHLER: model $Model not installed. Installed: $($have -join ', ')" -ForegroundColor Red; exit 1 }

# ---- run -------------------------------------------------------------------------------------------------
Write-Host ("`nModel {0}, challenges: {1}, {2}`n" -f $Model, $Challenge, $(if ($Minutes -gt 0) { "$Minutes min each" } else { "budget per challenge.json" })) -ForegroundColor Cyan
$env:PYTHONPATH = Join-Path $Root 'src'
& $Py (Join-Path $Here 'run_eval.py') --challenge $Challenge --model $Model --url $Url --minutes $Minutes
exit $LASTEXITCODE
