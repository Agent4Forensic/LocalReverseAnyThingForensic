# select-model.ps1
# Picks a model tier from the currently free VRAM and prints it as JSON. With -Pull it also pulls the models.
# Tier names come from docs/adr/0001-modellwahl.md. Tags are verified by "ollama pull" (unknown tag -> error).
# Pure ASCII on purpose.
param(
    [switch]$Pull,
    [string]$OllamaExe = 'D:\Tools\sw-analyst\ollama-0.40.13\ollama.exe',
    [int]$Port = 11435
)
$ErrorActionPreference = 'Stop'

$g = (& nvidia-smi --query-gpu=memory.total,memory.used --format=csv,noheader,nounits) -split ','
$free = [int]$g[0].Trim() - [int]$g[1].Trim()

if     ($free -ge 11000) { $tier = 'A'; $chat = 'qwen3:14b' }
elseif ($free -ge 7000)  { $tier = 'B'; $chat = 'qwen3:8b' }
else                     { $tier = 'C'; $chat = 'qwen3:4b' }
$embed = 'qwen3-embedding:0.6b'

$result = [pscustomobject]@{
    free_vram_mib = $free; tier = $tier; chat_model = $chat; embedding_model = $embed
    note = $(if ($tier -eq 'C') { 'Less than 7 GB VRAM free: partial CPU offload, slow and crash-prone on Blackwell (ADR-0001). Close GPU-heavy apps.' } else { '' })
}
$result | ConvertTo-Json

if ($Pull) {
    $env:OLLAMA_HOST = "127.0.0.1:$Port"
    foreach ($m in $chat, $embed) {
        "pulling $m"
        & $OllamaExe pull $m
        if ($LASTEXITCODE -ne 0) { throw "pull failed for $m (tag may not exist)" }
    }
}
