# Test-DetonationIsolation.ps1 - the acceptance of ADR-0005 before the first real sample. Run as admin on the detonation host.
# The packages hold only the harmless probe isolation_probe.ps1; make them on the dev machine with
#   python -m sw_analyst --acceptance-packages <folder>
# and pass that folder. Each package works once: make fresh ones for a repeat. Passing writes <VM>.acceptance.json, which
# Invoke-DetonationRun.ps1 demands for every real run. Pure ASCII on purpose.
param(
    [Parameter(Mandatory)][string]$PackageRoot,
    [Parameter(Mandatory)][string]$DataRoot,
    [string]$Name = 'sw-detonation'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-Admin
Assert-DataRoot $DataRoot
$seal = Get-Content -LiteralPath (Join-Path $DataRoot "$Name.seal.json") -Raw | ConvertFrom-Json
Assert-VmIsolation $Name $seal.platform
$results = [ordered]@{}
function Add-Result([string]$Key, [bool]$Ok, [string]$Detail) { $results[$Key] = @{ ok = $Ok; detail = $Detail } }

function Invoke-Probe([string]$RunId) {
    $folder = Join-Path $PackageRoot $RunId
    & (Join-Path $PSScriptRoot 'Invoke-DetonationRun.ps1') -RunFolder $folder -DataRoot $DataRoot -Name $Name -Acceptance | Out-Host
    $log = Get-Content -LiteralPath (Join-Path $folder 'run-log.json') -Raw | ConvertFrom-Json
    $out = Read-OutputDisk (Join-Path $folder 'output.vhd')
    $probe = $null
    if ($out -and $out.notes) { foreach ($n in $out.notes) { if ($n -like 'probe:*') { $probe = ($n -replace '^probe:', '') | ConvertFrom-Json } } }
    return @{ log = $log; output = $out; probe = $probe }
}

# 1-3: network, host paths, disk and memory, from inside the guest. The probe writes a marker for the next run.
$full = Invoke-Probe 'A-full'
if (-not $full.probe) { Add-Result 'probe_reported' $false 'the probe left no result on the output disk' }
else {
    Add-Result 'probe_reported' $true 'result read'
    Add-Result 'no_network' (-not $full.probe.network_reached) "adapters: $($full.probe.adapters); reached: $($full.probe.network_reached)"
    Add-Result 'no_host_paths' (-not $full.probe.host_paths_reached) "reached: $($full.probe.host_paths_reached)"
    Add-Result 'disk_fill_stays_inside' ($full.probe.disk_full_mb -gt 0) "wrote $($full.probe.disk_full_mb) MiB until the limit"
    Add-Result 'memory_stays_inside' ($full.probe.memory_mb -gt 0) "allocated $($full.probe.memory_mb) MiB until the limit"
}
Add-Result 'host_still_usable' ([bool](Get-VM -Name $Name)) 'this script is still running after the fill test'

# 4: after the revert the marker is gone and the checkpoint hash is unchanged.
$revert = Invoke-Probe 'A-revert'
Add-Result 'revert_removes_marker' ($revert.probe -and -not $revert.probe.marker_found) "marker found: $($revert.probe.marker_found)"
Add-Result 'checkpoint_hash_stable' ($revert.log.checkpoint_sha256_before -eq $revert.log.checkpoint_sha256_after) $revert.log.checkpoint_sha256_after

# 5: a guest that hangs is switched off by the host timer.
$hang = Invoke-Probe 'A-hang'
Add-Result 'host_timer_stops_hang' ($hang.log.stop_reason -eq 'timer') "stop reason: $($hang.log.stop_reason)"

$passed = -not ($results.Values | Where-Object { -not $_.ok })
@{ passed = $passed; vm = $Name; config = (Get-VmConfigFingerprint $Name); base_disk_sha256 = $seal.base_disk_sha256
   tested_utc = (Get-Date).ToUniversalTime().ToString('o'); results = $results } |
    ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $DataRoot "$Name.acceptance.json") -Encoding ASCII
$results.GetEnumerator() | ForEach-Object { "{0,-26} {1,-5} {2}" -f $_.Key, $_.Value.ok, $_.Value.detail }
if (-not $passed) { throw 'Acceptance FAILED: no real sample on this VM' }
'Acceptance passed.'
