# New-DetonationVm.ps1 - builds the detonation VM (ADR-0005 stage 3). Run as admin ON THE SEPARATE DETONATION HOST ONLY.
# Steps, in this order (docs/runbooks/detonation.md):
#   -Step Create    VM without network adapter, fixed disk on a data drive, install ISO attached
#   -Step ToolsDisk disk with the guest files, attached once for provisioning, before any sample exists
#   -Step Seal      removes ISO and tools disk, hardens the VM, takes the clean checkpoint and records its hash
# Never add a network adapter, a shared folder or a GPU to this VM. Pure ASCII on purpose.
param(
    [Parameter(Mandatory)][ValidateSet('Create', 'ToolsDisk', 'Seal')][string]$Step,
    [Parameter(Mandatory)][string]$DataRoot,                 # folder on a data drive, not the system drive
    [string]$Name = 'sw-detonation',
    [string]$IsoPath = '',                                   # Create: Windows install ISO, provided by Jan
    [ValidateSet('windows', 'android')][string]$Platform = 'windows',
    [int64]$DiskGB = 80,
    [int64]$MemoryGB = 8,
    [int]$Cpus = 4,
    [int]$CpuMaxPercent = 80
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-Admin
Assert-DataRoot $DataRoot
$vhdx = Join-Path $DataRoot "$Name.vhdx"
$tools = Join-Path $DataRoot "$Name-tools.vhdx"

switch ($Step) {
    'Create' {
        if (-not (Test-Path -LiteralPath $IsoPath)) { throw 'IsoPath is required: the Windows install ISO' }
        if ($Platform -eq 'android') { Assert-AndroidPinned (Join-Path $PSScriptRoot '..\manifest.json') }
        if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { throw "VM $Name exists already" }
        New-VHD -Path $vhdx -SizeBytes ($DiskGB * 1GB) -Fixed | Out-Null
        New-VM -Name $Name -Generation 2 -VHDPath $vhdx | Out-Null
        Get-VMNetworkAdapter -VMName $Name | Remove-VMNetworkAdapter
        Set-VMMemory -VMName $Name -DynamicMemoryEnabled $false -StartupBytes ($MemoryGB * 1GB)
        Set-VMProcessor -VMName $Name -Count $Cpus -Maximum $CpuMaxPercent
        # Android needs nested virtualization for its emulator. That widens the guest's reach into the hypervisor (ADR-0005).
        Set-VMProcessor -VMName $Name -ExposeVirtualizationExtensions ($Platform -eq 'android')
        Set-VM -Name $Name -AutomaticCheckpointsEnabled $false -CheckpointType Standard -AutomaticStartAction Nothing -AutomaticStopAction TurnOff
        Add-VMDvdDrive -VMName $Name -Path $IsoPath
        Set-VMFirmware -VMName $Name -FirstBootDevice (Get-VMDvdDrive -VMName $Name)
        "VM $Name created. Install Windows through the VM console, without any account online. Then run -Step ToolsDisk."
    }
    'ToolsDisk' {
        # A disk made here and mounted here BEFORE any sample exists. Output disks of a run are never mounted (ADR-0005).
        New-VHD -Path $tools -SizeBytes 2GB -Dynamic | Out-Null
        $disk = Mount-VHD -Path $tools -Passthru | Get-Disk
        Initialize-Disk -Number $disk.Number -PartitionStyle GPT
        $volume = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'SWTOOLS' -Confirm:$false
        Copy-Item -Recurse -Force (Join-Path $PSScriptRoot 'guest\*') "$($volume.DriveLetter):\"
        Dismount-VHD -Path $tools
        Add-VMHardDiskDrive -VMName $Name -Path $tools
        "Tools disk attached. In the guest run, as admin: <disk>:\Install-GuestAgent.ps1 -Platform $Platform. Shut the guest down, then run -Step Seal."
    }
    'Seal' {
        if ((Get-VM -Name $Name).State -ne 'Off') { throw 'Shut the VM down first' }
        Get-VMHardDiskDrive -VMName $Name | Where-Object { $_.Path -eq $tools } | Remove-VMHardDiskDrive
        Get-VMDvdDrive -VMName $Name | Remove-VMDvdDrive
        if (Test-Path -LiteralPath $tools) { Remove-Item -LiteralPath $tools }
        Get-VMIntegrationService -VMName $Name | Disable-VMIntegrationService
        Set-VMHost -EnableEnhancedSessionMode $false
        Get-VMNetworkAdapter -VMName $Name | Remove-VMNetworkAdapter
        Get-VMCheckpoint -VMName $Name | Remove-VMCheckpoint
        Assert-VmIsolation $Name $Platform
        Checkpoint-VM -Name $Name -SnapshotName $CleanCheckpoint
        $parent = Get-CheckpointBaseDisk $Name
        $sha = (Get-FileHash -LiteralPath $parent -Algorithm SHA256).Hash.ToLowerInvariant()
        @{ vm = $Name; checkpoint = $CleanCheckpoint; base_disk_sha256 = $sha; platform = $Platform; sealed_utc = (Get-Date).ToUniversalTime().ToString('o') } |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $DataRoot "$Name.seal.json") -Encoding ASCII
        "Sealed. Checkpoint hash $sha. Next: Test-DetonationIsolation.ps1"
    }
}
