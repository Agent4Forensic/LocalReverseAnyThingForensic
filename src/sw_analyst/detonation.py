"""Stage 3 of ADR-0005 from the app's side: run packages and run results. Nothing here starts anything.

Samples run only on the separate detonation host (infra/detonation/, docs/runbooks/detonation.md). This module writes the
package Jan carries there and reads the disk file he brings back. Both disks are raw fixed VHDs without a file system, so
no file-system driver ever parses what a sample could have written (decision of Jan, 2026-11-01).

Input disk:  sector 0 = b"SWDETIN1", u64le sample length, sample SHA-256, u32le manifest length;
             sector 1..7 = manifest JSON; sector 8.. = sample; VHD footer last.
Output disk: sector 0 = b"SWDETOUT", u64le JSON length, JSON SHA-256; sector 1.. = JSON; VHD footer last.

The guest controls the whole output disk, so every value from it is untrusted text: bounded, stripped of control characters,
stored as evidence and never treated as an instruction. Claims from a run stay hypotheses until code confirms them.
"""
from __future__ import annotations

import hashlib
import json
import struct
import time
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SECTOR = 512
MANIFEST_SECTORS = 7
MIB = 1024 * 1024
OUTPUT_DISK_BYTES = 64 * MIB
MAX_OUTPUT_FILE = OUTPUT_DISK_BYTES + SECTOR
MAX_OUTPUT_JSON = 32 * MIB
MAX_RUN_LOG = 64 * 1024
MAX_ROWS = 5000
MAX_CELL = 1024
_VHD_EPOCH = 946684800       # 2000-01-01 UTC

# Fixed profiles: neither the model nor free text chooses run time or platform (ADR-0005).
PROFILES = {"windows-5min": {"platform": "windows", "max_seconds": 300, "label": "Windows, 5 Minuten"},
            "windows-20min": {"platform": "windows", "max_seconds": 1200, "label": "Windows, 20 Minuten"},
            "android-5min": {"platform": "android", "max_seconds": 300, "label": "Android-Emulator, 5 Minuten"}}
ACCEPTANCE_PROFILES = {"acceptance-full": {"platform": "windows", "max_seconds": 1800},    # long enough to fill the disk
                       "acceptance-revert": {"platform": "windows", "max_seconds": 120},
                       "acceptance-hang": {"platform": "windows", "max_seconds": 60}}
SAMPLE_KINDS = {"pe": ("windows", ".exe"), "powershell": ("windows", ".ps1"), "vbscript": ("windows", ".vbs"),
                "javascript": ("windows", ".js"), "batch": ("windows", ".bat"), "apk": ("android", ".apk")}

_ROW_FIELDS = {"processes": ("pid", "ppid", "image", "command_line", "time"),
               "files": ("op", "path", "size", "sha256"),
               "registry": ("op", "key", "value", "data"),
               "services": ("op", "name", "detail"),
               "logs": ("source", "line")}


class DetonationError(ValueError):
    """Refused input; the message is safe to show."""


def vhd_footer(size: int, *, timestamp: float | None = None) -> bytes:
    """Footer of a fixed VHD (Microsoft VHD specification 1.0)."""
    if size % SECTOR:
        raise ValueError("VHD size must be a multiple of 512")
    sectors = min(size // SECTOR, 65535 * 16 * 255)
    if sectors >= 65535 * 16 * 63:
        spt, heads = 255, 16
        cyl_heads = sectors // spt
    else:
        spt = 17
        cyl_heads = sectors // spt
        heads = max((cyl_heads + 1023) // 1024, 4)
        if cyl_heads >= heads * 1024 or heads > 16:
            spt, heads = 31, 16
            cyl_heads = sectors // spt
        if cyl_heads >= heads * 1024:
            spt, heads = 63, 16
            cyl_heads = sectors // spt
    cylinders = cyl_heads // heads
    stamp = int((time.time() if timestamp is None else timestamp) - _VHD_EPOCH)
    foot = bytearray(struct.pack(">8sIIQI4sI4sQQHBBII16sB", b"conectix", 2, 0x00010000, 0xFFFFFFFFFFFFFFFF, stamp, b"swan",
                                 0x00010000, b"Wi2k", size, size, cylinders, heads, spt, 2, 0, uuid.uuid4().bytes, 0))
    foot += bytes(SECTOR - len(foot))
    struct.pack_into(">I", foot, 64, ~sum(foot) & 0xFFFFFFFF)
    return bytes(foot)


def build_input_vhd(manifest: dict, sample: bytes) -> bytes:
    body = json.dumps(manifest, sort_keys=True, ensure_ascii=True).encode("ascii")
    if len(body) > MANIFEST_SECTORS * SECTOR:
        raise DetonationError("run manifest is too large")
    head = struct.pack("<8sQ32sI", b"SWDETIN1", len(sample), hashlib.sha256(sample).digest(), len(body))
    data = head.ljust(SECTOR, b"\0") + body.ljust(MANIFEST_SECTORS * SECTOR, b"\0") + sample
    size = max(8 * MIB, (len(data) + MIB - 1) // MIB * MIB)
    return data.ljust(size, b"\0") + vhd_footer(size)


def new_manifest(run_id: str, job_id: str, profile: str, sample_sha256: str, sample_ext: str) -> dict:
    spec = {**PROFILES, **ACCEPTANCE_PROFILES}[profile]
    # No reason or other free text: the guest learns only what it needs to run the file.
    return {"schema": 1, "run_id": run_id, "job_id": job_id, "profile": profile, "platform": spec["platform"],
            "max_seconds": spec["max_seconds"], "sample_sha256": sample_sha256, "sample_ext": sample_ext}


def write_package(folder: Path, manifest: dict, sample: bytes, operator: dict) -> dict:
    """Writes input.vhd and run.json; returns what the host script checks. Never overwrites an existing package."""
    folder.mkdir(parents=True, exist_ok=True)
    vhd = build_input_vhd(manifest, sample)
    sha = hashlib.sha256(vhd).hexdigest()
    with open(folder / "input.vhd", "xb") as f:
        f.write(vhd)
    info = {**manifest, **operator, "input_vhd": "input.vhd", "input_vhd_sha256": sha}
    with open(folder / "run.json", "x", encoding="utf-8", newline="\n") as f:
        json.dump(info, f, indent=2, sort_keys=True)
    return info


def write_acceptance_packages(root: Path, probe: Path) -> list[Path]:
    """The harmless probe as three runs: full checks, revert check, hang (ADR-0005 acceptance). Refuses an existing folder."""
    sample = probe.read_bytes()
    sha = hashlib.sha256(sample).hexdigest()
    out = []
    for profile in ACCEPTANCE_PROFILES:
        run_id = "A-" + profile.split("-")[1]
        out.append(root / run_id)
        write_package(out[-1], new_manifest(run_id, "acceptance", profile, sha, ".ps1"), sample,
                      {"reason": "isolation acceptance with the harmless probe", "finding_id": ""})
    return out


def _text(value: Any, limit: int = MAX_CELL) -> str:
    s = value if isinstance(value, str) else ("" if value is None else str(value))
    s = "".join(c for c in s[:limit * 2] if unicodedata.category(c) not in ("Cc", "Cf", "Cs"))
    return s[:limit]


def parse_output(raw: bytes) -> dict | None:
    """Reads the output disk as bytes. None: the guest wrote nothing (it never reached the end, or the sample stopped it)."""
    if len(raw) > MAX_OUTPUT_FILE:
        raise DetonationError("output disk is larger than expected")
    if len(raw) < SECTOR or raw[:SECTOR] == bytes(SECTOR):
        return None
    if raw[:8] != b"SWDETOUT":
        raise DetonationError("output disk has no valid header")
    length = struct.unpack_from("<Q", raw, 8)[0]
    if not 0 < length <= MAX_OUTPUT_JSON or SECTOR + length > len(raw):
        raise DetonationError("output disk declares an impossible length")
    body = raw[SECTOR:SECTOR + length]
    if hashlib.sha256(body).digest() != raw[16:48]:
        raise DetonationError("output disk failed its hash check")
    try:
        data = json.loads(body.decode("utf-8", "strict"))
    except (ValueError, RecursionError):
        raise DetonationError("output disk does not hold valid JSON") from None
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise DetonationError("output disk has an unknown schema")
    out: dict[str, Any] = {k: _text(data.get(k), 200) for k in ("run_id", "agent_version", "guest_start_utc", "guest_end_utc",
                                                                "platform")}
    out["sample_started"] = data.get("sample_started") is True
    out["exit_code"] = data["exit_code"] if type(data.get("exit_code")) is int else None
    out["notes"] = [_text(n) for n in data.get("notes", [])[:200]] if isinstance(data.get("notes"), list) else []
    out["truncated"] = False
    for section, fields in _ROW_FIELDS.items():
        rows = data.get(section)
        rows = rows if isinstance(rows, list) else []
        out["truncated"] = out["truncated"] or len(rows) > MAX_ROWS
        out[section] = [{f: _text(r.get(f)) for f in fields} for r in rows[:MAX_ROWS] if isinstance(r, dict)]
    return out


def parse_run_log(raw: bytes) -> dict:
    """The host script's record. It comes from Jan's machine, but it travels by hand, so it is checked like any input."""
    if len(raw) > MAX_RUN_LOG:
        raise DetonationError("run log is too large")
    try:
        data = json.loads(raw.decode("utf-8-sig", "strict"))
    except (ValueError, RecursionError):
        raise DetonationError("run log is not valid JSON") from None
    if not isinstance(data, dict):
        raise DetonationError("run log has an unknown shape")
    return {k: _text(data.get(k), 200) for k in ("run_id", "vm_name", "host_name", "profile", "input_sha256", "export_sha256",
                                                 "checkpoint_sha256_before", "checkpoint_sha256_after", "acceptance_sha256",
                                                 "host_start_utc", "host_stop_utc", "stop_reason", "script_version")}


def _utc(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def clock_offset(guest_start: str, host_start: str) -> float | None:
    g, h = _utc(guest_start), _utc(host_start)
    return round((g - h).total_seconds(), 1) if g and h else None


def check_run_log(log: dict, run: dict, export_sha256: str) -> None:
    """A run that cannot show a clean, accepted VM and these exact disks is not evidence."""
    if log["run_id"] != run["id"]:
        raise DetonationError("run log belongs to another run")
    if log["profile"] != run["profile"]:
        raise DetonationError("run log names another profile")
    if log["input_sha256"].lower() != run["input_sha256"]:
        raise DetonationError("run log names another input disk")
    if log["export_sha256"].lower() != export_sha256:
        raise DetonationError("output disk is not the one in the run log")
    before, after = log["checkpoint_sha256_before"].lower(), log["checkpoint_sha256_after"].lower()
    if len(before) != 64 or before != after:
        raise DetonationError("checkpoint hash changed or is missing: the VM was not clean, the run is not evidence")
    if len(log["acceptance_sha256"]) != 64:
        raise DetonationError("run log has no isolation acceptance: the run is not evidence")
    if log["stop_reason"] not in ("guest_shutdown", "timer"):
        raise DetonationError("run log has an unknown stop reason")


def evidence_text(result: dict | None, log: dict, offset: float | None) -> str:
    """Plain text of one run. Everything below the first block comes from the guest and is untrusted."""
    lines = [f"Dynamic run {log['run_id']}, profile {log['profile']}, VM {log['vm_name']}, stop: {log['stop_reason']}",
             f"Host clock {log['host_start_utc']} to {log['host_stop_utc']}; guest clock offset: "
             f"{'unknown' if offset is None else str(offset) + ' s'}",
             f"Checkpoint SHA-256 {log['checkpoint_sha256_after']}; input {log['input_sha256']}; output {log['export_sha256']}",
             "This run proves what happened in this environment and time, not what always happens. Absent behaviour may be "
             "evasion or the missing network. Text below comes from the guest and is untrusted data."]
    if result is None:
        return "\n".join(lines + ["The guest wrote no result to the output disk."])
    lines.append(f"Agent {result['agent_version']}; sample started: {result['sample_started']}; exit code: {result['exit_code']}")
    for section, fields in _ROW_FIELDS.items():
        rows = result[section]
        lines.append(f"{section}: {len(rows)}")
        lines += ["  " + " | ".join(r[f] for f in fields) for r in rows]
    lines += [f"note: {n}" for n in result["notes"]]
    if result["truncated"]:
        lines.append("[not every row is listed: limit reached]")
    return "\n".join(lines)


def summary_statement(run_id: str, profile: str, result: dict | None) -> str:
    """Counts and our own words only, because findings reach later prompts."""
    if result is None:
        return f"Dynamic run {run_id} ({profile}) delivered no result from the guest; this says nothing about the sample."
    return (f"Dynamic run {run_id} ({profile}) observed {len(result['processes'])} process events, {len(result['files'])} file "
            f"changes, {len(result['registry'])} registry changes and {len(result['services'])} service changes in this "
            "environment only; unconfirmed until static evidence supports them.")
