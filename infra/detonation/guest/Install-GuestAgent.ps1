# Install-GuestAgent.ps1 - run once as admin INSIDE the detonation guest, from the tools disk (ADR-0005). Pure ASCII on purpose.
# Puts the agent in place, creates the low-rights user the sample runs as, and starts the agent at every boot as SYSTEM.
# The guest holds no accounts, credentials or real data. The random password below exists only here.
param([ValidateSet('windows', 'android')][string]$Platform = 'windows', [string]$AndroidBundle = '')
$ErrorActionPreference = 'Stop'
$home_dir = 'C:\sw-agent'
New-Item -ItemType Directory -Force -Path $home_dir | Out-Null
Copy-Item -Force (Join-Path $PSScriptRoot 'agent.ps1') $home_dir
# Only SYSTEM and admins may touch the agent; the sample's user cannot read its results before they are written.
& icacls.exe $home_dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'icacls failed' }

$bytes = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$password = [Convert]::ToBase64String($bytes)
$secure = ConvertTo-SecureString $password -AsPlainText -Force
if (-not (Get-LocalUser -Name 'analyst' -ErrorAction SilentlyContinue)) { New-LocalUser -Name 'analyst' -Password $secure -PasswordNeverExpires | Out-Null }
Add-LocalGroupMember -Group 'Users' -Member 'analyst' -ErrorAction SilentlyContinue
# Interactive session for the sample: some samples need a desktop. Autologon is fine here, the password protects nothing.
$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty -Path $winlogon -Name AutoAdminLogon -Value '1'
Set-ItemProperty -Path $winlogon -Name DefaultUserName -Value 'analyst'
Set-ItemProperty -Path $winlogon -Name DefaultPassword -Value $password

# What the agent later reads: process creation events with command lines.
& auditpol.exe /set /subcategory:'Process Creation' /success:enable | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'auditpol failed' }
New-Item -Force -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
& wevtutil.exe sl Security /ms:209715200 | Out-Null
# Raw disks of a run must come online without a mount.
Set-StorageSetting -NewDiskPolicy OnlineAll

if ($Platform -eq 'android') {
    if (-not (Test-Path -LiteralPath $AndroidBundle)) { throw 'AndroidBundle: folder with the pinned SDK tools and system image (infra\manifest.json) is required' }
    Copy-Item -Recurse -Force $AndroidBundle (Join-Path $home_dir 'android')
}

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File $home_dir\agent.ps1"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
Register-ScheduledTask -TaskName 'sw-agent' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
'Agent installed. Remove nothing else, shut down, then run New-DetonationVm.ps1 -Step Seal on the host.'
