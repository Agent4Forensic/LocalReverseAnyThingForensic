# common.ps1 - shared checks of the detonation host scripts (ADR-0005 stage 3). Pure ASCII on purpose.
$CleanCheckpoint = 'clean'
$ScriptVersion = '1'
$OutputDiskBytes = 64MB          # src/sw_analyst/detonation.py OUTPUT_DISK_BYTES

function Assert-Admin {
    $id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this as administrator' }
}

function Assert-DataRoot([string]$DataRoot) {
    if (-not (Test-Path -LiteralPath $DataRoot)) { throw "DataRoot does not exist: $DataRoot" }
    $drive = (Resolve-Path -LiteralPath $DataRoot).Drive.Name + ':'
    if ($drive -ieq $env:SystemDrive) { throw 'DataRoot must not be on the system drive: a guest filling its disk must not stop the host (ADR-0005)' }
}

function Assert-AndroidPinned([string]$ManifestPath) {
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    foreach ($name in 'android-sdk-tools', 'android-system-image') {
        if ($manifest.components.$name.sha256 -notmatch '^[0-9a-f]{64}$') { throw "Component $name is not pinned in infra\manifest.json: no Android guest before pin and review" }
    }
}

# Throws on anything that would give the guest a way out. Called when sealing, before each run and by the acceptance test.
function Assert-VmIsolation([string]$Name, [string]$Platform) {
    $problems = @()
    if (Get-VMNetworkAdapter -VMName $Name) { $problems += 'has a network adapter' }
    if (Get-VMIntegrationService -VMName $Name | Where-Object { $_.Enabled }) { $problems += 'has enabled integration services' }
    if ((Get-VMHost).EnableEnhancedSessionMode) { $problems += 'host allows enhanced session' }
    if ((Get-VMMemory -VMName $Name).DynamicMemoryEnabled) { $problems += 'uses dynamic memory' }
    if ((Get-VM -Name $Name).AutomaticCheckpointsEnabled) { $problems += 'takes automatic checkpoints' }
    if (Get-VMGpuPartitionAdapter -VMName $Name -ErrorAction SilentlyContinue) { $problems += 'has a GPU partition' }
    if (Get-VMAssignableDevice -VMName $Name -ErrorAction SilentlyContinue) { $problems += 'has an assigned device' }
    if (Get-VMDvdDrive -VMName $Name) { $problems += 'has a DVD drive' }
    if ((Get-VMProcessor -VMName $Name).ExposeVirtualizationExtensions -and $Platform -ne 'android') { $problems += 'exposes nested virtualization' }
    if ((Get-VMProcessor -VMName $Name).Maximum -ge 100) { $problems += 'has no CPU cap' }
    if ($problems) { throw "VM $Name is not isolated: $($problems -join '; ')" }
}

function Get-VmConfigFingerprint([string]$Name) {
    $vm = Get-VM -Name $Name
    $text = @($vm.VMId, $vm.ProcessorCount, (Get-VMMemory -VMName $Name).Startup, (Get-VMProcessor -VMName $Name).Maximum,
              (Get-VMProcessor -VMName $Name).ExposeVirtualizationExtensions) -join '|'
    $bytes = [Text.Encoding]::ASCII.GetBytes($text)
    ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
}

function Get-CheckpointBaseDisk([string]$Name) {
    $current = (Get-VMHardDiskDrive -VMName $Name | Select-Object -First 1).Path
    while ($true) {
        $parent = (Get-VHD -Path $current).ParentPath
        if (-not $parent) { return $current }
        $current = $parent
    }
}

# Reads the output disk as plain bytes. It is never mounted, because the guest controls its contents (ADR-0005).
function Read-OutputDisk([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        $head = New-Object byte[] 512
        [void]$stream.Read($head, 0, 512)
        if ([Text.Encoding]::ASCII.GetString($head, 0, 8) -ne 'SWDETOUT') { return $null }
        $length = [BitConverter]::ToInt64($head, 8)
        if ($length -le 0 -or $length -gt 32MB) { return $null }
        $body = New-Object byte[] $length
        [void]$stream.Read($body, 0, $length)
        return ([Text.Encoding]::UTF8.GetString($body) | ConvertFrom-Json)
    } finally { $stream.Dispose() }
}
