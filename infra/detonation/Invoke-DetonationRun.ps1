# Invoke-DetonationRun.ps1 - one approved run on the separate detonation host (ADR-0005 stage 3). Run as admin.
# The folder comes from the dashboard: input.vhd and run.json. Afterwards the folder also holds output.vhd and run-log.json;
# carry those two back and read them in on the dashboard. The host decides when the run ends, never the guest.
# Output disks are copied as files and never mounted. Pure ASCII on purpose.
param(
    [Parameter(Mandatory)][string]$RunFolder,
    [Parameter(Mandatory)][string]$DataRoot,
    [string]$Name = 'sw-detonation',
    [int]$GraceSeconds = 600,         # guest time for booting, baseline and collecting, on top of the sample's time
    [switch]$Acceptance               # only Test-DetonationIsolation.ps1 sets this: the acceptance does not exist yet
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-Admin
Assert-DataRoot $DataRoot
$seal = Get-Content -LiteralPath (Join-Path $DataRoot "$Name.seal.json") -Raw | ConvertFrom-Json
Assert-VmIsolation $Name $seal.platform

$info = Get-Content -LiteralPath (Join-Path $RunFolder 'run.json') -Raw | ConvertFrom-Json
$input_vhd = Join-Path $RunFolder 'input.vhd'
$output_vhd = Join-Path $RunFolder 'output.vhd'
$log_file = Join-Path $RunFolder 'run-log.json'
foreach ($old in $output_vhd, $log_file) { if (Test-Path -LiteralPath $old) { throw "$old exists: this run already happened" } }
$input_sha = (Get-FileHash -LiteralPath $input_vhd -Algorithm SHA256).Hash.ToLowerInvariant()
if ($input_sha -ne $info.input_vhd_sha256) { throw 'input.vhd does not match run.json' }
if ([int]$info.max_seconds -le 0 -or [int]$info.max_seconds -gt 3600) { throw 'run.json has an impossible run time' }

if ($info.platform -ne $seal.platform) { throw "This VM is sealed for $($seal.platform), the run needs $($info.platform)" }
$acceptance_sha = ''
$acceptance_file = Join-Path $DataRoot "$Name.acceptance.json"
if (-not $Acceptance) {
    if (-not (Test-Path -LiteralPath $acceptance_file)) { throw 'No isolation acceptance: run Test-DetonationIsolation.ps1 first' }
    $accepted = Get-Content -LiteralPath $acceptance_file -Raw | ConvertFrom-Json
    if ($accepted.passed -ne $true -or $accepted.config -ne (Get-VmConfigFingerprint $Name) -or $accepted.base_disk_sha256 -ne $seal.base_disk_sha256) {
        throw 'The isolation acceptance does not match this VM any more: repeat Test-DetonationIsolation.ps1'
    }
    $acceptance_sha = (Get-FileHash -LiteralPath $acceptance_file -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-CleanHash { (Get-FileHash -LiteralPath (Get-CheckpointBaseDisk $Name) -Algorithm SHA256).Hash.ToLowerInvariant() }

if ((Get-VM -Name $Name).State -ne 'Off') { throw 'The VM must be off before a run' }
Restore-VMCheckpoint -VMName $Name -Name $CleanCheckpoint -Confirm:$false
$before = Get-CleanHash
if ($before -ne $seal.base_disk_sha256) { throw 'Checkpoint hash differs from the seal: rebuild the VM' }

New-VHD -Path $output_vhd -SizeBytes $OutputDiskBytes -Fixed | Out-Null
# The guest gets a copy, so what it might write to its input disk never reaches the package.
$attached = Join-Path $RunFolder 'input-attached.vhd'
Copy-Item -LiteralPath $input_vhd -Destination $attached
$stop_reason = 'timer'
$start = (Get-Date).ToUniversalTime()
try {
    Add-VMHardDiskDrive -VMName $Name -Path $attached
    Add-VMHardDiskDrive -VMName $Name -Path $output_vhd
    Start-VM -Name $Name
    $deadline = $start.AddSeconds([int]$info.max_seconds + $GraceSeconds)
    while ((Get-Date).ToUniversalTime() -lt $deadline) {
        if ((Get-VM -Name $Name).State -eq 'Off') { $stop_reason = 'guest_shutdown'; break }
        Start-Sleep -Seconds 2
    }
} finally {
    # Hard off whatever happened above. The guest has no say in this.
    if ((Get-VM -Name $Name).State -ne 'Off') { Stop-VM -Name $Name -TurnOff -Force }
    $stop = (Get-Date).ToUniversalTime()
    Get-VMHardDiskDrive -VMName $Name | Where-Object { $_.Path -in @($attached, $output_vhd) } | Remove-VMHardDiskDrive
    Restore-VMCheckpoint -VMName $Name -Name $CleanCheckpoint -Confirm:$false
    Remove-Item -LiteralPath $attached -Force
}
$after = Get-CleanHash
@{ run_id = $info.run_id; vm_name = $Name; host_name = $env:COMPUTERNAME; profile = $info.profile; input_sha256 = $input_sha
   export_sha256 = (Get-FileHash -LiteralPath $output_vhd -Algorithm SHA256).Hash.ToLowerInvariant()
   checkpoint_sha256_before = $before; checkpoint_sha256_after = $after; acceptance_sha256 = $acceptance_sha
   host_start_utc = $start.ToString('o'); host_stop_utc = $stop.ToString('o'); stop_reason = $stop_reason; script_version = $ScriptVersion } |
    ConvertTo-Json | Set-Content -LiteralPath $log_file -Encoding ASCII
if ($before -ne $after) { throw 'Checkpoint hash changed during the run: rebuild the VM, this run is not evidence' }
"Run $($info.run_id) ended: $stop_reason. Carry output.vhd and run-log.json back to the dashboard."
