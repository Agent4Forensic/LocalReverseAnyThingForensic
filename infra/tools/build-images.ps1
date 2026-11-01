# build-images.ps1 - builds the pinned tool images of ADR-0006 package B. Needs network once and a running Docker daemon.
# Only this build uses the network; the containers themselves run with --network none. Tags are read by the gateway
# (src/sw_analyst/gateway/container_runner.py IMAGES). Images carry no sw-analyst label, so cleanup.ps1 keeps them.
# Pure ASCII on purpose.
param([string[]]$Only = @('ghidra', 'triage', 'jadx'))
$ErrorActionPreference = 'Stop'
$context = $PSScriptRoot
$manifest = Get-Content (Join-Path (Split-Path -Parent $context) 'manifest.json') -Raw | ConvertFrom-Json
foreach ($target in $Only) {
    $tag = $manifest.tool_images.$target
    if (-not $tag) { throw "unknown image '$target'; known: ghidra, triage, jadx" }
    "building $tag"
    & docker build --target $target -t $tag $context
    if ($LASTEXITCODE -ne 0) { throw "docker build failed for $tag (is Docker Desktop running?)" }
    "$tag -> $(& docker image inspect --format '{{.Id}}' $tag)"
}
