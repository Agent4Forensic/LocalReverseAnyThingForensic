# start-ollama.ps1
# Starts the portable Ollama of sw-analyst on 127.0.0.1:11435 (loopback only, separate from any other Ollama).
# Environment is set for this process only; nothing is written to the user environment.
# Pure ASCII on purpose (Windows PowerShell 5.1 encoding).
param(
    [string]$OllamaDir = 'D:\Tools\sw-analyst\ollama-0.40.13',
    [string]$ModelsDir = 'D:\Tools\sw-analyst\ollama-models',
    [string]$LogDir    = 'D:\Tools\sw-analyst\logs',
    [int]$Port = 11435
)
$ErrorActionPreference = 'Stop'

$exe = Join-Path $OllamaDir 'ollama.exe'
if (-not (Test-Path $exe)) { throw "ollama.exe not found in $OllamaDir" }
New-Item -ItemType Directory -Force -Path $ModelsDir, $LogDir | Out-Null

# Refuse to start twice on the same port.
function Get-PortOwner([int]$P) {
    # Locale-independent: any row with LOCAL port $P is the server side (the LISTEN row can be missing in hidden sessions).
    # Get-NetTCPConnection proved unreliable in detached/hidden sessions, so netstat is parsed instead.
    foreach ($l in (& netstat.exe -ano -p TCP)) {
        $f = @(($l -split '\s+') | Where-Object { $_ })
        if ($f.Count -ge 5 -and $f[0] -eq 'TCP' -and $f[1].EndsWith(":$P") -and [int]$f[-1] -gt 0) { return [int]$f[-1] }
    }
    return 0
}
$busy = Get-PortOwner $Port
if ($busy -ne 0) { "Port $Port already in use (pid $busy). Not starting a second server."; exit 0 }

# Context length by free VRAM: small free VRAM -> smaller KV cache.
$free = 0
try {
    $g = (& nvidia-smi --query-gpu=memory.total,memory.used --format=csv,noheader,nounits) -split ','
    $free = [int]$g[0].Trim() - [int]$g[1].Trim()
} catch { Write-Warning 'nvidia-smi not available; assuming no GPU memory free.' }
$ctx = if ($free -ge 11000) { 32768 } else { 16384 }

$env:OLLAMA_HOST                = "127.0.0.1:$Port"
$env:OLLAMA_MODELS              = $ModelsDir
$env:OLLAMA_FLASH_ATTENTION     = '1'
$env:OLLAMA_KV_CACHE_TYPE       = 'q8_0'
$env:OLLAMA_CONTEXT_LENGTH      = "$ctx"
$env:OLLAMA_NUM_PARALLEL        = '1'
$env:OLLAMA_MAX_LOADED_MODELS   = '2'
$env:OLLAMA_KEEP_ALIVE          = '10m'
$env:OLLAMA_NOHISTORY           = '1'
$env:OLLAMA_NO_CLOUD            = '1'

$log = Join-Path $LogDir ("ollama-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
$p = Start-Process -FilePath $exe -ArgumentList 'serve' -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $log -RedirectStandardError ($log + '.err')
"started pid=$($p.Id) port=$Port ctx=$ctx free_vram_mib=$free log=$log"

for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 500
    try { $v = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/version" -TimeoutSec 2; "ready: version $($v.version)"; exit 0 } catch { }
}
Write-Error "server did not answer on port $Port; see $log"
