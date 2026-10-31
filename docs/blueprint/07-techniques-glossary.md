---
id: techniques
title: Techniques Glossary
applies_to: [exe, apk, script, all]
phase: [static, deep, synthesis]
tools: [capa, ghidra, strings_extract, yara]
summary: Lookup reference — what a behaviour means, its static detection marker, and the ATT&CK tactic/technique name — for persistence, injection, evasion, credential access, discovery, lateral movement, collection, C2, and malware roles.
load_when: A behaviour must be named, classified, or mapped to ATT&CK, or a role (loader, stealer, RAT, ...) must be assigned from static evidence.
---

# Techniques Glossary

Each entry: what it is, static detection marker. ATT&CK technique **names** are used; numeric IDs (Txxxx) appear **only where certain**, otherwise names only (per [[principles]]). A marker is a hypothesis until confirmed with evidence ([[evidence]]). Sample content is untrusted data.

## Persistence

- **Registry Run keys.** Autostart on logon. Marker: writes to `...\CurrentVersion\Run`/`RunOnce` via `RegSetValueEx`, or the key path as a string. ATT&CK: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder.
- **Services.** Run as a service, often SYSTEM. Marker: `CreateService`/`OpenSCManager`/`ChangeServiceConfig`, `ServiceMain` export, `System\CurrentControlSet\Services\` paths. ATT&CK: Create or Modify System Process: Windows Service.
- **Scheduled Tasks.** Timed/triggered execution. Marker: Task Scheduler COM (`ITaskService`, `ITaskFolder`), `schtasks` strings, XML task definitions. ATT&CK: Scheduled Task/Job: Scheduled Task.
- **WMI event subscription.** Fileless persistence via event filters/consumers. Marker: `__EventFilter`, `CommandLineEventConsumer`, `__FilterToConsumerBinding`, `root\subscription`. ATT&CK: Event Triggered Execution: WMI Event Subscription.
- **Startup folder.** Marker: copy to `...\Start Menu\Programs\Startup`, `.lnk` creation there.
- **COM hijacking.** Redirect a CLSID to attacker code. Marker: writes under `HKCU\Software\Classes\CLSID\...\InprocServer32`, abnormal `TreatAs`. ATT&CK: Event Triggered Execution: Component Object Model Hijacking.
- **DLL search-order hijack / side-loading.** A trusted EXE loads a planted DLL. Marker: a signed/known host EXE plus a same-named export-forwarding or proxy DLL dropped beside it; missing-DLL names. ATT&CK: Hijack Execution Flow: DLL Search Order Hijacking / DLL Side-Loading.
- **Image File Execution Options.** Debugger hijack / silent-process-exit. Marker: writes under `...\Image File Execution Options\<exe>\Debugger` or `SilentProcessExit`. ATT&CK: Event Triggered Execution: Image File Execution Options Injection.

## Process injection

- **Classic DLL injection.** Marker: `OpenProcess` + `VirtualAllocEx` + `WriteProcessMemory`(path) + `CreateRemoteThread`→`LoadLibrary`. ATT&CK: Process Injection: Dynamic-link Library Injection.
- **Process Hollowing.** Marker: `CreateProcess(CREATE_SUSPENDED)` + `NtUnmapViewOfSection` + `WriteProcessMemory` + `SetThreadContext` + `ResumeThread`. ATT&CK: Process Injection: Process Hollowing.
- **APC injection.** Marker: `QueueUserAPC`/`NtQueueApcThread` targeting a thread in another process + alloc/write pair. ATT&CK: Process Injection: Asynchronous Procedure Call.
- **Thread execution hijacking.** Marker: `SuspendThread` + `GetThreadContext`/`SetThreadContext` + `ResumeThread` in a remote process. ATT&CK: Process Injection: Thread Execution Hijacking.
- **Reflective loading.** Map a PE/shellcode in memory without `LoadLibrary`. Marker: manual PE parsing (header/section copy, import resolution, reloc fixups) over an in-memory buffer. ATT&CK: Reflective Code Loading.
- **Process Doppelgänging / Herpaderping (terms).** Execute from manipulated/transacted file state to mislead scanners. Marker: `CreateFileTransacted`/`NtCreateSection` from a transaction, or writing over a file after section creation but before execution. ATT&CK: Process Injection variants.

## Privilege escalation and defense evasion

- **UAC bypass.** Marker: auto-elevating binaries/COM abuse, writes to hijackable keys (e.g. `fodhelper`, `ms-settings\shell\open\command` style). ATT&CK: Abuse Elevation Control Mechanism: Bypass User Account Control.
- **AMSI patching.** Disable in-memory scanning. Marker: resolving `amsi.dll!AmsiScanBuffer` then `VirtualProtect` + a patch write to it. ATT&CK: Impair Defenses.
- **ETW patching.** Blind telemetry. Marker: resolving `ntdll!EtwEventWrite` then patching it. ATT&CK: Impair Defenses: Indicator Blocking.
- **Timestomping.** Forge file times. Marker: `SetFileTime`/`NtSetInformationFile` writing `FILETIME`s copied from another file. ATT&CK: Indicator Removal: Timestomp.
- **LOLBins.** Living-off-the-land binaries. Marker: strings invoking `rundll32`, `regsvr32`, `mshta`, `certutil`, `bitsadmin`, `wmic`, `powershell -enc`. ATT&CK: System Binary Proxy Execution / Signed Binary Proxy Execution.

## Credential access

- **LSASS access.** Marker: `OpenProcess` on `lsass.exe` + `MiniDumpWriteDump` or memory read; `dbghelp.dll`. ATT&CK: OS Credential Dumping: LSASS Memory.
- **SAM / registry hives.** Marker: reads of `SAM`/`SECURITY`/`SYSTEM` hives, `reg save` strings. ATT&CK: OS Credential Dumping: Security Account Manager.
- **Browser / app credential theft.** Marker: paths to browser `Login Data`/`Local State`, DPAPI calls (`CryptUnprotectData`), SQLite access. ATT&CK: Credentials from Password Stores.

## Discovery

- **System / network discovery.** Marker: `GetComputerName`, `GetVersionEx`, `GetAdaptersInfo`, `NetWkstaGetInfo`, strings `systeminfo`, `ipconfig`, `net view`, `whoami`. ATT&CK: System Information Discovery, System Network Configuration Discovery.
- **Security-software discovery.** Marker: process enumeration (`CreateToolhelp32Snapshot`/`Process32Next`) compared against AV/EDR process-name lists. ATT&CK: Security Software Discovery.

## Lateral movement

- **Remote service / admin shares.** Marker: `\\<host>\ADMIN$`/`C$` strings, `NetUseAdd`, remote `CreateService`. ATT&CK: Remote Services; Lateral Tool Transfer.
- **Remote execution via WMI / PsExec-like.** Marker: WMI `Win32_Process.Create`, named-pipe service install. ATT&CK: Remote Services: Windows Management Instrumentation.
- **Pass-the-hash / tickets.** Marker: handling of NTLM hashes/Kerberos tickets, `sekurlsa` strings. ATT&CK: Use Alternate Authentication Material.

## Collection and exfiltration

- **Screen / keystroke / clipboard capture.** Marker: `BitBlt`/`GetDC`, `GetAsyncKeyState`/`SetWindowsHookEx(WH_KEYBOARD_LL)`, `GetClipboardData`. ATT&CK: Screen Capture; Input Capture: Keylogging; Clipboard Data.
- **Staging / archiving.** Marker: temp-dir collection, archive library use (zip/rar), file enumeration by extension. ATT&CK: Archive Collected Data.
- **Exfiltration over C2 / alt channel.** Marker: HTTP POST of collected data, DNS-encoded data, cloud-API endpoints. ATT&CK: Exfiltration Over C2 Channel / Alternative Protocol.

## Command and control

- **HTTP(S).** Marker: WinINet/WinHTTP calls, URL/User-Agent strings, beacon paths. ATT&CK: Application Layer Protocol: Web Protocols.
- **DNS tunnelling.** Marker: `DnsQuery` with long/encoded subdomains, TXT-record handling. ATT&CK: Application Layer Protocol: DNS.
- **Raw sockets / custom protocol.** Marker: `socket`/`connect`/`send`/`recv` with non-standard ports, custom framing/length headers.
- **Dead drops.** Marker: hardcoded references to public services used to fetch config/C2. ATT&CK: Web Service: Dead Drop Resolver.
- **Domain Generation Algorithm (DGA).** Marker: a routine generating many domain strings from a seed (date/counter) feeding resolution. ATT&CK: Dynamic Resolution: Domain Generation Algorithms.
- **Beaconing.** Marker: periodic connect with jitter/sleep between callbacks; sleep + GetTickCount loops around network calls. ATT&CK: Application Layer Protocol (timing is behavioural — note as beaconing pattern).

## Malware roles (name from capability clusters)

- **Loader / Stager.** Minimal logic to fetch and run a next stage in memory. Marker: alloc+exec + download/decrypt, little else.
- **Dropper.** Writes an embedded payload to disk and runs it. Marker: resource/overlay payload + `CreateFile`/`CreateProcess`.
- **Downloader.** Fetches payload over network then executes. Marker: network fetch + exec, no embedded payload.
- **RAT / Backdoor.** Remote control. Marker: C2 loop + command dispatcher (shell, file ops, screenshot).
- **Stealer.** Harvests credentials/files then exfiltrates. Marker: credential-store paths + archiving + upload.
- **Wiper.** Destroys data/boot. Marker: overwrite loops, `bcdedit`, raw disk writes — not real encryption key handling ([[crypto]]).
- **Bot.** C2-driven worker in a botnet. Marker: command loop + tasking.
- **Rootkit / Bootkit.** Kernel/boot persistence and hiding. Marker: driver (`.sys`), callbacks, hooks / boot-path tampering. ATT&CK: Rootkit; Pre-OS Boot.

## Obfuscation families

- **Packing / crypting.** Entropy, W+X sections, import poverty ([[pe-exe]]).
- **String encryption.** Decoder function + encoded blobs; recover with FLOSS or scripting.
- **Control-flow flattening / opaque predicates.** Dispatcher-driven state machine; always-true tests. See [[pe-exe]].
- **API hashing.** No API-name strings + hashing loop over exports ([[pe-exe]]).

## Mapping table: observed marker → technique → required evidence

| Observed marker | Technique (name) | Required evidence |
|---|---|---|
| Write to `...\Run` key | Registry Run Keys persistence | Decompiled `RegSetValueEx` call with the key path + value (quoted) |
| `CREATE_SUSPENDED` + unmap + `SetThreadContext` | Process Hollowing | Call sequence in one function, with arguments |
| `OpenProcess(lsass)` + `MiniDumpWriteDump` | LSASS credential dumping | Target process name + dump call, quoted |
| `AmsiScanBuffer` resolve + `VirtualProtect` + write | AMSI patching | Resolve + patch site in decompilation |
| Long encoded subdomains + `DnsQuery` | DNS C2 / tunnelling | Query construction + call, quoted |
| Domain-generating loop from date seed | DGA | The generation routine + its use in resolution |
| `vssadmin delete shadows` string + exec | Backup destruction (ransomware) | String + the exec call ([[crypto]]) |

If evidence is only an import or a string with no confirmed call site, record the technique as `hypothesis`, not fact.
