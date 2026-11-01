# agent.ps1 - runs at every boot of the detonation guest as SYSTEM (ADR-0005 stage 3). Pure ASCII on purpose.
# Finds the raw input disk, baselines the guest, starts the sample as the low-rights user, waits, collects the differences,
# writes them to the raw output disk and shuts down. Disks hold no file system (src/sw_analyst/detonation.py describes the
# layout). The host timer ends the run anyway if this script never finishes. Results are text only: no binary leaves the guest.
$ErrorActionPreference = 'Continue'
$AgentVersion = 'guest-agent-1'
$Work = 'C:\sw-agent\run'
$Sector = 512

function Get-RawDisks { Get-CimInstance Win32_DiskDrive | Where-Object { $_.Index -ne (Get-Partition -DriveLetter C).DiskNumber } }

function Read-Sectors([string]$Device, [int64]$Offset, [int]$Count) {
    $stream = New-Object IO.FileStream($Device, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        [void]$stream.Seek($Offset, [IO.SeekOrigin]::Begin)
        $buffer = New-Object byte[] ($Count * $Sector)
        [void]$stream.Read($buffer, 0, $buffer.Length)
        return ,$buffer
    } finally { $stream.Dispose() }
}

function Find-Disks {
    $found = @{ input = $null; output = $null }
    foreach ($disk in Get-RawDisks) {
        Set-Disk -Number $disk.Index -IsOffline $false -ErrorAction SilentlyContinue
        $head = Read-Sectors $disk.DeviceID 0 1
        if ([Text.Encoding]::ASCII.GetString($head, 0, 8) -eq 'SWDETIN1') { $found.input = $disk.DeviceID }
        elseif (-not ($head | Where-Object { $_ -ne 0 })) {
            Set-Disk -Number $disk.Index -IsReadOnly $false -ErrorAction SilentlyContinue
            $found.output = $disk.DeviceID
        }
    }
    return $found
}

function Read-Input([string]$Device) {
    $head = Read-Sectors $Device 0 8
    $sampleLength = [BitConverter]::ToInt64($head, 8)
    $sampleHash = ([BitConverter]::ToString($head, 16, 32) -replace '-', '').ToLowerInvariant()
    $manifestLength = [BitConverter]::ToInt32($head, 48)
    if ($sampleLength -le 0 -or $sampleLength -gt 67108864 -or $manifestLength -le 0 -or $manifestLength -gt 3584) { throw 'input disk header is invalid' }
    $manifest = [Text.Encoding]::ASCII.GetString($head, $Sector, $manifestLength) | ConvertFrom-Json
    $sectors = [int][Math]::Ceiling($sampleLength / $Sector)
    $raw = Read-Sectors $Device (8 * $Sector) $sectors
    $bytes = New-Object byte[] $sampleLength
    [Array]::Copy($raw, $bytes, $sampleLength)
    $actual = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    if ($actual -ne $sampleHash) { throw 'sample on the input disk failed its hash check' }
    return @{ manifest = $manifest; bytes = $bytes }
}

function Write-Output-Disk([string]$Device, [string]$Json) {
    $body = [Text.Encoding]::UTF8.GetBytes($Json)
    if ($body.Length -gt 32MB) { throw 'result too large' }
    $head = New-Object byte[] $Sector
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('SWDETOUT'), $head, 8)
    [Array]::Copy([BitConverter]::GetBytes([int64]$body.Length), 0, $head, 8, 8)
    [Array]::Copy([Security.Cryptography.SHA256]::Create().ComputeHash($body), 0, $head, 16, 32)
    $padded = New-Object byte[] ([int][Math]::Ceiling($body.Length / $Sector) * $Sector)
    [Array]::Copy($body, $padded, $body.Length)
    $stream = New-Object IO.FileStream($Device, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    try {
        [void]$stream.Seek($Sector, [IO.SeekOrigin]::Begin)
        $stream.Write($padded, 0, $padded.Length)
        $stream.Flush()
        # The header comes last: a run cut off while writing leaves an empty disk, not half a result.
        [void]$stream.Seek(0, [IO.SeekOrigin]::Begin)
        $stream.Write($head, 0, $Sector)
        $stream.Flush()
    } finally { $stream.Dispose() }
}

$WatchedFolders = 'C:\Users', 'C:\ProgramData', 'C:\Windows\Temp', 'C:\Windows\Tasks'
$AutostartKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                 'Registry::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                 'Registry::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'

function Get-FileState {
    $state = @{}
    foreach ($folder in $WatchedFolders) {
        Get-ChildItem -LiteralPath $folder -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object { $state[$_.FullName] = @{ size = $_.Length; time = $_.LastWriteTimeUtc.Ticks } }
    }
    return $state
}

function Get-RegistryState {
    $state = @{}
    foreach ($key in $AutostartKeys) {
        Get-Item -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
            $item = $_
            foreach ($value in $item.GetValueNames()) { $state["$($item.Name)|$value"] = [string]$item.GetValue($value) }
        }
    }
    return $state
}

function Get-ServiceState {
    $state = @{}
    Get-CimInstance Win32_Service | ForEach-Object { $state[$_.Name] = "$($_.State)|$($_.PathName)" }
    Get-ScheduledTask | ForEach-Object { $state["task:$($_.TaskPath)$($_.TaskName)"] = [string]($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) }
    return $state
}

function Compare-State($Before, $After) {
    $rows = @()
    foreach ($k in $After.Keys) {
        if (-not $Before.ContainsKey($k)) { $rows += @{ op = 'created'; key = $k; now = $After[$k] } }
        elseif (($Before[$k] | ConvertTo-Json -Compress) -ne ($After[$k] | ConvertTo-Json -Compress)) { $rows += @{ op = 'changed'; key = $k; now = $After[$k] } }
    }
    foreach ($k in $Before.Keys) { if (-not $After.ContainsKey($k)) { $rows += @{ op = 'deleted'; key = $k; now = $null } } }
    return ,$rows
}

function Get-ProcessEvents([datetime]$Since) {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $Since } -ErrorAction SilentlyContinue
    return @($events | Select-Object -First 5000 | ForEach-Object {
        $x = [xml]$_.ToXml()
        $d = @{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        @{ pid = $d['NewProcessId']; ppid = $d['ProcessId']; image = $d['NewProcessName']; command_line = $d['CommandLine']; time = $_.TimeCreated.ToUniversalTime().ToString('o') }
    })
}

function Start-AsAnalyst([string]$Path, [string]$Extension, [string]$RunProfile) {
    $commands = @{ '.exe' = @($Path, ''); '.ps1' = @('powershell.exe', "-NoProfile -ExecutionPolicy Bypass -File `"$Path`""); '.bat' = @('cmd.exe', "/c `"$Path`"")
                   '.vbs' = @('wscript.exe', "`"$Path`""); '.js' = @('wscript.exe', "`"$Path`"") }
    if (-not $commands.ContainsKey($Extension)) { throw "no way to start $Extension" }
    $exe, $arguments = $commands[$Extension]
    if ($RunProfile -like 'acceptance-*') { $arguments = "$arguments $RunProfile" }
    $task = if ($arguments) { New-ScheduledTaskAction -Execute $exe -Argument $arguments } else { New-ScheduledTaskAction -Execute $exe }
    $principal = New-ScheduledTaskPrincipal -UserId 'analyst' -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName 'sw-sample' -Action $task -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName 'sw-sample'
}

function Invoke-WindowsRun($Manifest, [byte[]]$Sample, $Out) {
    New-Item -ItemType Directory -Force -Path 'C:\Users\Public\run' | Out-Null
    $path = 'C:\Users\Public\run\sample' + $Manifest.sample_ext
    [IO.File]::WriteAllBytes($path, $Sample)
    $files0, $reg0, $svc0 = (Get-FileState), (Get-RegistryState), (Get-ServiceState)
    $since = Get-Date
    # The logged-on desktop of the low-rights user must exist before the sample starts.
    for ($i = 0; $i -lt 60 -and -not (Get-Process explorer -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Seconds 2 }
    Start-AsAnalyst $path $Manifest.sample_ext $Manifest.profile
    $Out.sample_started = $true
    Start-Sleep -Seconds ([int]$Manifest.max_seconds)
    $state = (Get-ScheduledTask -TaskName 'sw-sample').State
    $Out.notes += "sample task state at the end: $state"
    Get-Process | Where-Object { $_.SessionId -ne 0 -and $_.Name -notin 'explorer', 'dwm', 'winlogon', 'csrss', 'fontdrvhost', 'sihost', 'ctfmon', 'taskhostw' } | ForEach-Object { $Out.notes += "still running: $($_.Name)" }
    $Out.processes = Get-ProcessEvents $since
    foreach ($r in Compare-State $files0 (Get-FileState)) {
        $sha = ''
        if ($r.op -ne 'deleted' -and $r.now.size -le 67108864) { $sha = (Get-FileHash -LiteralPath $r.key -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash }
        $Out.files += @{ op = $r.op; path = $r.key; size = if ($r.now) { $r.now.size } else { '' }; sha256 = $sha }
    }
    foreach ($r in Compare-State $reg0 (Get-RegistryState)) { $k, $v = $r.key -split '\|', 2; $Out.registry += @{ op = $r.op; key = $k; value = $v; data = $r.now } }
    foreach ($r in Compare-State $svc0 (Get-ServiceState)) { $Out.services += @{ op = $r.op; name = $r.key; detail = $r.now } }
    if ($Manifest.profile -like 'acceptance-*' -and (Test-Path -LiteralPath 'C:\Users\Public\sw-probe.json')) {
        $Out.notes += 'probe:' + (Get-Content -LiteralPath 'C:\Users\Public\sw-probe.json' -Raw)
    }
}

function Invoke-AndroidRun($Manifest, [byte[]]$Sample, $Out) {
    # Emulator inside this VM (nested virtualization, no network). Versions are pinned in infra\manifest.json. Frida is planned, not built.
    $sdk = 'C:\sw-agent\android'
    $adb = Join-Path $sdk 'platform-tools\adb.exe'
    $path = Join-Path $Work 'sample.apk'
    [IO.File]::WriteAllBytes($path, $Sample)
    $emulator = Start-Process -FilePath (Join-Path $sdk 'emulator\emulator.exe') -ArgumentList '-avd', 'sw', '-no-window', '-no-audio', '-no-snapshot', '-wipe-data', '-no-boot-anim' -PassThru
    & $adb wait-for-device
    for ($i = 0; $i -lt 120 -and (& $adb shell getprop sys.boot_completed).Trim() -ne '1'; $i++) { Start-Sleep -Seconds 5 }
    $packagesBefore = & $adb shell pm list packages
    $Out.logs += @{ source = 'adb install'; line = [string](& $adb install -g $path 2>&1) }
    $package = (Compare-Object $packagesBefore (& $adb shell pm list packages) | Select-Object -First 1).InputObject
    $Out.notes += "package: $package"
    if ($package) {
        $name = ($package -replace '^package:', '').Trim()
        & $adb shell monkey -p $name -c android.intent.category.LAUNCHER 1 | Out-Null
        $Out.sample_started = $true
    }
    Start-Sleep -Seconds ([int]$Manifest.max_seconds)
    @(& $adb logcat -d -v time) | Select-Object -Last 4000 | ForEach-Object { $Out.logs += @{ source = 'logcat'; line = [string]$_ } }
    @(& $adb shell ps -A) | ForEach-Object { $Out.logs += @{ source = 'ps'; line = [string]$_ } }
    Stop-Process -Id $emulator.Id -Force -ErrorAction SilentlyContinue
}

New-Item -ItemType Directory -Force -Path $Work | Out-Null
$disks = Find-Disks
if (-not $disks.input -or -not $disks.output) { Stop-Computer -Force; exit 1 }     # started without a run: nothing to do
$result = [ordered]@{ schema = 1; run_id = ''; agent_version = $AgentVersion; guest_start_utc = (Get-Date).ToUniversalTime().ToString('o'); guest_end_utc = ''
                      platform = ''; sample_started = $false; exit_code = $null; processes = @(); files = @(); registry = @(); services = @(); logs = @(); notes = @() }
try {
    $run = Read-Input $disks.input
    $result.run_id = $run.manifest.run_id
    $result.platform = $run.manifest.platform
    if ($run.manifest.platform -eq 'android') { Invoke-AndroidRun $run.manifest $run.bytes $result } else { Invoke-WindowsRun $run.manifest $run.bytes $result }
} catch { $result.notes += "agent error: $($_.Exception.Message)" }
# Acceptance point 5: this run plays a hung guest, so that the host timer has to end it.
if ($run -and $run.manifest.profile -eq 'acceptance-hang') { while ($true) { Start-Sleep -Seconds 60 } }
$result.guest_end_utc = (Get-Date).ToUniversalTime().ToString('o')
Write-Output-Disk $disks.output ($result | ConvertTo-Json -Depth 5 -Compress)
Stop-Computer -Force
