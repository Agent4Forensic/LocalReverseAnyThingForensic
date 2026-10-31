---
id: workflow
title: Master workflow from intake to report
applies_to: [exe, apk, script, all]
phase: [triage, static, deep, dynamic, synthesis, report]
tools: [ghidra, jadx, apktool, capa, yara, floss, binwalk, pefile, androguard]
summary: Phase model of a complete static analysis, with ordered actions, outputs and exit criteria per phase, path decision trees, prioritization under budget, function ranking in Ghidra, decomposition, recursion, coverage, target questions, ransomware and multi-stage handling.
load_when: Load when planning a job, choosing the next phase or path, deciding whether to split or stop, or handling extracted payloads.
---

# Master workflow from intake to report

## Phase model overview

| # | Phase | Goal | Main file |
|---|---|---|---|
| 0 | Intake / chain of custody | Fix identity and provenance of the sample | this file, [[report]] |
| 1 | Triage | Know what the file is and pick the path | [[triage]] |
| 2 | Static baseline | Collect cheap, broad indicators | [[triage]], [[pe-exe]], [[apk]], [[scripts]] |
| 3 | Deep analysis (code) | Understand relevant code paths | [[pe-exe]], [[apk]], [[scripts]] |
| 4 | Unlayering / unpacking | Reach the real payload statically | [[pe-exe]], [[apk]], [[scripts]], [[fallbacks]] |
| 5 | Behavior reconstruction | Turn code facts into capabilities | [[techniques]], [[crypto]] |
| - | Dynamic (backlog) | Not enabled | [[dynamic]] |
| 6 | Synthesis | Resolve contradictions, check coverage, answer questions | [[evidence]] |
| 7 | Report | Produce the evidenced report | [[report]] |

Phases 3 to 5 iterate: unpacking produces new code (back to 1 for the artifact), behavior reconstruction raises questions (back to 3). Rule for every phase: evidence first, interpretation second ([[principles]]).

## Phase 0: Intake and chain of custody

- **Goal:** unambiguous identity of the analyzed object.
- **Inputs:** sample (read-only, never executable), job description, context information, target questions.
- **Actions (in order):** 1. `hash_file` (SHA-256, SHA-1, MD5). 2. `sample_info` (size, name as submitted). 3. Record tool versions and recipe (done by the platform). 4. Note what the user claims about origin in context, as claim, not fact.
- **Outputs:** hash evidence; custody fields for the report.
- **Exit:** hashes stored as evidence.
- **Mistakes:** treating the submitted file name or user description as evidence of what the file is; re-hashing artifacts under the parent's hash (each artifact has its own).

## Phase 1: Triage

- **Goal:** determine real type, packing/obfuscation state, and the analysis path.
- **Inputs:** sample, Phase 0 evidence.
- **Actions:** 1. `identify_type` (magic and structure, ignore the extension). 2. `entropy_map` (whole file and per region). 3. Type-specific header view: `pe_headers` for PE; `zip_list` for APK/JAR/OOXML; `script_detect` for text. 4. Quick `strings_extract` with a filter (`grep` for `http`, `\\`, `.dll`, `MZ`) instead of full output. 5. Choose the path with the decision tree below.
- **Tools:** DevGateway tools, pefile, exiftool/file ([[tools]]).
- **Outputs:** type finding, entropy observations, first hypotheses (each with trigger evidence), selected path.
- **Exit:** type confirmed; path chosen; packer/layer suspicion recorded as `hypothesis` or rejected.
- **Mistakes:** concluding "packed" from entropy alone (compressed resources and embedded images are also high entropy); trusting the extension; skipping triage for extracted artifacts.

## Path decision tree

| Observation (with evidence) | Path | Next action |
|---|---|---|
| PE, section entropy > ~7.2 on large raw size, few imports (`LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`/`VirtualProtect` only), entry point outside first code section, odd section names (`UPX0`, raw size 0 with large virtual size) | Packer path | Identify packer and stub statically ([[pe-exe]]), Phase 4 |
| PE with CLR data directory (COM descriptor, index 14) and import `mscoree.dll!_CorExeMain`/`_CorDllMain` | Managed (.NET) path | .NET section in [[pe-exe]]; capa and YARA support .NET; native Ghidra view shows only the stub |
| PE, normal entropy, rich imports | Native path | Phase 2, then function ranking (Phase 3) |
| PE with large overlay or high-entropy resource plus resource APIs (`FindResource`, `LoadResource`, `LockResource`, `SizeofResource`) | Dropper/loader path | Extract artifact, recurse; analyze loader logic |
| Script with long Base64/hex/char-code blob, or `eval`/`IEX`/`Invoke-Expression`/`ExecuteGlobal` | Layer path | [[scripts]]: `decode_layer` per layer, each layer is evidence |
| APK with `lib/<abi>/*.so` plus `DexClassLoader`/`InMemoryDexClassLoader` or encrypted files in `assets/` | Multi-stage APK path | Manifest, Application class, loader code, then native lib in Ghidra |
| APK without native code or loaders | Standard APK path | [[apk]] manifest, components, jadx |
| Archive or container (ZIP, OOXML, ISO) | Container path | `zip_list`, extract members as artifacts, recurse |
| Unidentified type | Generic path | [[fallbacks]] (unknown formats), `hexdump` of header, binwalk signatures |

Several rows can apply. Order: container first, then layers, then packer, then code.

## Phase 2: Static baseline

- **Goal:** broad, cheap indicator set that guides deep analysis.
- **Actions (EXE):** 1. Imports and exports (pefile/`pe_headers`). 2. Sections, resources, overlay, timestamps, version info, signature presence. 3. `capa` (capability overview with addresses). 4. YARA with the bundled rule set. 5. FLOSS (static plus decoded strings) or filtered `strings_extract`. 6. Group imports by category (network, crypto, process, registry, file, service).
- **Actions (APK):** 1. Manifest (package, permissions, components, exported flags, `android:name` of Application). 2. Certificate. 3. DEX list, native libs, assets. 4. YARA. 5. Filtered strings over DEX.
- **Actions (script):** 1. Language and encoding. 2. Visible URLs, paths, commands. 3. Layer count estimate.
- **Outputs:** indicator findings (mostly `confirmed` observations, `hypothesis` interpretations), list of candidate functions/classes for Phase 3.
- **Exit:** every mandatory recipe baseline step has evidence or a recorded failure.
- **Mistakes:** reporting capa or YARA rule names as proven behavior; dumping all strings into context; ignoring the overlay.

## Phase 3: Deep analysis of code

- **Goal:** understand the code paths that implement relevant behavior.
- **Inputs:** ranked candidate list (see function ranking), baseline findings.
- **Actions:** 1. Run or reuse the Ghidra analysis (native) or jadx output (DEX). 2. Start at the entry point and the top-ranked functions. 3. Per function: decompile, list callees, constants, strings, xrefs; summarize in 3 to 6 lines; annotate. 4. Follow callers/callees only if they raise the relevance score. 5. Cross-check suspicious decompiler output with disassembly.
- **Outputs:** per-function summaries, annotations, findings with quotes from decompiled or disassembled code.
- **Exit:** coverage target for relevant functions reached, or remaining functions handed off as subtasks.
- **Mistakes:** reading CRT/library code; trusting decompiler types; describing callees never decompiled; skipping indirect calls (`(**(code **)(...))()`) that hide resolved APIs.

## Function relevance ranking in Ghidra

Score candidates, review in descending order. Exclude functions identified as library code (Function ID/FLIRT-style matches, CRT startup) unless they are hooked or modified.

| Signal | Weight | How to find |
|---|---|---|
| Program entry, `main`/`WinMain` reached from CRT start, `DllMain`, exports, TLS callbacks | high | Entry point, export list, TLS directory |
| Calls to sensitive imports (process injection, crypto, network, registry Run keys, service creation, file enumeration) | high | Xrefs to import entries |
| References to interesting strings (URLs, paths, commands, ransom note text, mutex names) | high | Xrefs from string addresses |
| Crypto constants (AES S-box bytes `63 7c 77 7b`, SHA-256 `0x428a2f98`, MD5/SHA-1 init `0x67452301`, CRC32 `0xEDB88320`, ChaCha/Salsa `expand 32-byte k`, 256-iteration swap loops for RC4) | high | capa, YARA crypto rules, byte search |
| Dynamic API resolution (hash loops, `GetProcAddress` with computed names, PEB walking) | high | capa, loops with rotate/XOR over export names |
| Large functions with a switch/dispatch over a command ID | medium-high | Function size, many cases; typical C2 handler |
| Loops with XOR/add/rotate over buffers | medium | Decoding routines |
| High cyclomatic complexity or many callees | medium | Function metrics in Ghidra |
| Cycles in the call graph (retry, beacon loops with `Sleep`) | medium | Call graph |
| Small wrappers with one call | low | Only to name them |

Ties: prefer functions that answer a pending target question.

## Phase 4: Unlayering and unpacking

- **Goal:** reach the innermost meaningful code statically, or document why not.
- **Actions:** 1. Identify the layer mechanism (packer stub, encoded script layer, encrypted asset, embedded resource). 2. Locate key, algorithm and data (offset, size). 3. Decode with an allowed static tool (`decode_layer` for script encodings, artifact extraction for embedded files). 4. Hash and store each artifact; it enters triage (recursion). 5. If decoding is not possible with the toolset, document stub behavior, algorithm hypothesis, data location and the blocking reason.
- **Fallback:** emulation of single routines is off; mark such ideas `[DYNAMIC: requires dynamic-analysis capability, not enabled]` and see [[dynamic]] and [[fallbacks]].
- **Exit:** every detected layer is either decoded (artifact with hash) or documented as unresolved with reason.
- **Mistakes:** claiming payload behavior from the stub; decoding with a guessed key without confirming it in code; losing the link between artifact and parent offset.

## Phase 5: Behavior reconstruction from static evidence

- **Goal:** convert code facts into capabilities: persistence, communication, injection, credential access, encryption, destruction, anti-analysis, spreading.
- **Actions:** 1. For each capability candidate, collect the chain: trigger (entry or command) to API call with arguments. 2. Look up meaning in [[techniques]] and [[crypto]]. 3. Write one finding per capability with the strongest evidence (decompiled call with constant arguments beats import presence). 4. Derive IOCs only from confirmed findings (paths, registry keys, mutexes, URLs, file extensions).
- **Exit:** each capability claimed in a finding has a reachable code path or is labeled hypothesis with the missing link.
- **Mistakes:** "imports InternetOpenA, therefore C2"; mixing behavior of different stages; assuming execution order without control-flow evidence.

## Dynamic analysis (backlog block)

`[DYNAMIC: requires dynamic-analysis capability, not enabled]`

The platform never executes samples. Static substitutes always come first: decode routines by reading them, extract configs from data sections, reconstruct API sequences from code. Dynamic methods (sandbox run, debugger, API tracing, memory dumping after unpacking, network capture) are described as methodology in [[dynamic]]. In this workflow, record a dynamic need as an `open` finding: "Static analysis could not determine X; resolution would require dynamic analysis (not enabled)."

## Phase 6: Synthesis

- **Actions:** 1. List all findings by status. 2. Resolve contradictions ([[evidence]]). 3. Run the coverage check (below). 4. Answer each target question from confirmed findings only; otherwise `unresolved` with reason. 5. Collect open questions with reason (budget, tool failure, packed, dynamic needed). 6. Build the stage map for multi-stage samples.
- **Exit:** every target question has an answer or `unresolved`; no unresolved contradiction is silently dropped.
- **Mistakes:** upgrading hypotheses to facts in the summary; answering from blueprint knowledge instead of evidence.

## Phase 7: Report

Follow [[report]]: summary, metadata and custody, assignment, answers with status, findings with evidence IDs and quotes, defanged IOCs, open questions, methodology and timeline. The report generator uses stored data; your part is precise finding statements and summaries. Never include payload bytes.

## Prioritization under a tight budget

Order by information gain per step:

1. Hashes, type, entropy, headers (cheap, decide the path).
2. Imports/exports and capa (broad capability map with addresses).
3. Targeted strings (filtered for URLs, paths, registry, commands).
4. Steps needed for mandatory target questions.
5. Entry point plus top 5 ranked functions.
6. Layer decoding if a layer blocks the questions.
7. Remaining ranked functions, IOC completion, optional questions.

Budget guideline (adjust per job): triage and baseline up to about 15 %, deep analysis and unlayering about 55 %, target questions about 20 %, synthesis reserve about 10 %. If the reserve would be consumed, stop deep work.

## When to stop

Stop a task when: its goal is reached with evidence; or two different approaches failed (finish with `open` finding and what was tried); or about two thirds of the turns are used and the rest can be split.

Stop the job (handled by the orchestrator) when all target questions are answered and coverage is reached, or the budget is exhausted (`partial`), or the user cancels. Do not continue depth on optional topics while a mandatory question is unresolved and reachable.

## Decomposition rules for subtasks

Split when a task would need more turns or context than available, or when parts have different inputs. Each subtask needs a narrower goal, a concrete input and a reason tied to a finding or gap.

| Situation | Good split |
|---|---|
| 40 relevant functions ranked | One subtask per cluster of 3 to 5 related functions (by callee set or string topic), highest scores first |
| Config blob found, decryption unknown | (a) find routines referencing blob address, (b) identify algorithm and key, (c) decode and extract fields |
| APK with loader and native lib | (a) Java loader logic, (b) native lib exports and `JNI_OnLoad`, (c) asset decryption |
| Script with 4 layers | One subtask per layer only if a layer needs research; otherwise decode sequentially in one task |
| Target question "how does it persist?" | (a) registry/service/task APIs xrefs, (b) dropped file paths, (c) startup folder strings |

Bad splits: restating the parent goal; "analyze everything else"; subtasks without input address, class or artifact.

## Recursion on extracted payloads

- Every extracted artifact gets a hash, a parent reference (parent hash, offset, size, method) and its own triage.
- Choose the recipe by the artifact's real type, not by the parent.
- Keep findings separated per artifact; label the stage in statements ("Stage 2 (SHA-256 `...`) creates ...").
- Limit depth: if the same mechanism repeats (layer N decodes to a structurally identical layer N+1), decode in a loop within one task and report the count.
- Stop recursion when the artifact is data (image, config, decoy document) and record what it is.

## Coverage

Coverage is reached when:

1. All mandatory recipe steps have evidence or a recorded failure reason.
2. Relevant functions (ranked set, library code excluded) are reviewed to the recipe threshold (example in the EXE recipe: `functions_reviewed_min: 0.9`). Reviewed means decompiled or disassembled and summarized with a finding or a "no relevant behavior" note.
3. Every detected layer or artifact is decoded and triaged, or documented as unresolved with reason.
4. Every target question is answered or `unresolved` with reason.

Report coverage numbers honestly; never claim completeness beyond them.

## Handling target questions

- Read all target questions at job start. Map each to the phase and evidence that can answer it.
- Mandatory questions first: secure a confirmed basis before optional exploration.
- Answer narrowly: what was asked, with finding references; state scope limits ("in the reviewed functions").
- If the question presupposes something false ("Which server does it exfiltrate to?" but no network code exists), say what was found and that the premise is not supported.
- Questions with an expected answer (CTF mode, see [[ctf]]) are still answered only from evidence.

## Ransomware additional questions

When encryption plus file enumeration indicators appear, add these questions (details in [[crypto]]):

1. Algorithm and mode (symmetric file cipher, asymmetric key wrap), with constants or API calls as evidence.
2. Key generation: CSPRNG (`BCryptGenRandom`, `CryptGenRandom`, `RtlGenRandom`) or weak source (`rand`/`srand(time)`).
3. Key protection: embedded public key, per-file or global key, key stored where.
4. File selection: extension lists, excluded paths/extensions, size thresholds, partial encryption.
5. Recovery inhibition: shadow copy or backup deletion commands, boot configuration changes.
6. Process/service termination lists, network share enumeration.
7. Ransom note name and content location, appended extension, mutex.
8. Kill switch or language/locale checks.
9. Weaknesses: key reuse, nonce reuse, key in recoverable location, flawed randomness.

Each answer needs code-level evidence; strings alone give hypothesis at most.

## Multi-stage families: loaders and droppers

- **Dropper:** carries the payload inside (resource, overlay, appended data, encrypted section). Static goal: extract and recurse.
- **Downloader:** fetches the payload (`URLDownloadToFileW`, WinHTTP/WinINet calls, `HttpClient`, Java `URLConnection`). Static goal: URL, storage path, execution method; the payload itself is unavailable offline, record as `open`.
- **Loader:** decrypts/maps a payload in memory (`VirtualAlloc` plus copy plus `VirtualProtect`, `Assembly.Load(byte[])`, `InMemoryDexClassLoader`, reflective loading). Static goal: key, algorithm, payload location.

Build a stage map: stage, hash, type, how obtained (offset/method or URL), what it does, evidence IDs. Never attribute behavior of one stage to another. If a stage is missing (downloaded at runtime), the report states the gap explicitly.
