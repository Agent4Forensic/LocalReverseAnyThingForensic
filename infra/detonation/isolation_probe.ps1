# isolation_probe.ps1 - harmless self-written test sample for the ADR-0005 acceptance. It checks its own isolation, nothing else.
# It runs as the low-rights guest user and writes its findings to C:\Users\Public\sw-probe.json, which the guest agent reports
# for acceptance profiles only. Its only side effects stay inside the guest: one marker file, one fill file, memory.
# The mode comes from the profile name the agent passes as the first argument. Pure ASCII on purpose.
param([string]$Mode = 'acceptance-full')
$ErrorActionPreference = 'SilentlyContinue'
$result = [ordered]@{ mode = $Mode; adapters = 0; network_reached = @(); host_paths_reached = @(); disk_full_mb = 0; memory_mb = 0; marker_found = $false }
$marker = 'C:\Users\Public\sw-marker.txt'
function Save { $result | ConvertTo-Json -Compress | Set-Content -LiteralPath 'C:\Users\Public\sw-probe.json' -Encoding ASCII }

$result.marker_found = Test-Path -LiteralPath $marker
Save
if ($Mode -ne 'acceptance-full') { exit 0 }     # revert: only the marker check above. hang: the agent itself plays the hung guest.

$result.adapters = @(Get-NetAdapter).Count
foreach ($name in 'example.com', 'www.microsoft.com') {
    if (Resolve-DnsName $name -DnsOnly -QuickTimeout) { $result.network_reached += "dns:$name" }
}
foreach ($url in 'http://1.1.1.1/', 'http://192.168.0.1/', 'http://172.17.0.1/', 'http://10.0.0.1/') {
    try { $null = Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 5; $result.network_reached += "http:$url" } catch { }
}
foreach ($path in '\\tsclient\c', '\\host\c$', '\\wsl$', '\\10.0.0.1\c$') {
    if (Test-Path -LiteralPath $path) { $result.host_paths_reached += $path }
}
Save

# Fill and memory tests stop at their own limit or at the VM's limit, whichever comes first.
Set-Content -LiteralPath $marker -Value 'written by the isolation probe' -Encoding ASCII
$fill = 'C:\Users\Public\sw-fill.bin'
$chunk = New-Object byte[] (16MB)
([Random]::new()).NextBytes($chunk)             # zeros might never reach the disk
try {
    $stream = [IO.File]::OpenWrite($fill)
    for ($i = 0; $i -lt 6400; $i++) { $stream.Write($chunk, 0, $chunk.Length); $result.disk_full_mb += 16; if ($i % 32 -eq 0) { Save } }
} catch { } finally { if ($stream) { $stream.Dispose() } }
Remove-Item -LiteralPath $fill -Force
Save
$hold = New-Object Collections.ArrayList
try {
    for ($i = 0; $i -lt 2048; $i++) {
        $block = New-Object byte[] (16MB)
        [Array]::Clear($block, 0, $block.Length)
        [void]$hold.Add($block)
        $result.memory_mb += 16
        if ($i % 32 -eq 0) { Save }
    }
} catch { }
$hold.Clear()
Save
