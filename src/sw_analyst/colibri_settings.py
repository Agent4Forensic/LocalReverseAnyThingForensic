"""Chooses the colibri settings from this machine's hardware (ADR-0012).

    python -m sw_analyst.colibri_settings          # readable, needs the volume for the disk measurement
    python -m sw_analyst.colibri_settings --json   # what the launcher (start.sh / start.ps1) applies
    python -m sw_analyst.colibri_settings --check  # may this machine use colibri at all? exit 1 with the reasons if not

The rules are the VRAM table in colibri docs/deepseek-v4.md and the limits of this project (CLAUDE.md, HostGuard). `coli tune`
measures on top of this and saves a profile that `coli serve` reads; this script sets what must be right before the first run.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import random
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from sw_analyst.common import linuxhost
from sw_analyst.preflight import FEHLER, IS_WIN, _ram_gb, _run, _volume_root, check_colibri, component

HARD_LIMIT_GB = 24    # Windows: WSL, Docker and models together (decision of Jan, 2026-10-31)
DOCKER_SHARE_GB = 4   # kept for the tool containers that run during a job
WINDOWS_MIN_GB = 7    # Windows keeps at least this much
LINUX_MIN_GB = linuxhost.HOST_RESERVE_GB   # Linux live host keeps this much (ADR-0013); no separate hard limit
HEADROOM_GB = 4       # HostGuard pauses a job below 3 GB free
FLOOR_GB = 12         # measured with coli plan: 5.8 GB dense + 5.9 GB runtime, nothing left for warm experts
WANTED_GB = 16        # the setup catalog's minimum for this model
CTX = 16384           # what the runner's prompts are sized for (CONTEXT_CHAR_BUDGET, REPLY_TOKENS_MAX)
EXPERT_MB = 12.6      # one routed expert (docs/deepseek-v4.md)
MISSES_PER_TOKEN = 230  # routed-expert reads per token at 6 % VRAM hit rate (docs/deepseek-v4.md, Performance)
MIN_TOK_S = 0.5       # below this one reply of 2000 tokens takes more than an hour: not usable for a job


@dataclass
class Hardware:
    ram_total_gb: float = 0.0
    ram_free_gb: float = 0.0
    gpu_name: str = ""
    compute_cap: float = 0.0
    vram_total_mib: int = 0
    vram_free_mib: int = 0
    disk_bus: str = ""
    disk_read_mb_s: float = 0.0


def host_limits(hw: Hardware, windows: bool = IS_WIN) -> tuple[int, int, str]:
    """(cap for the engine in GB, GB the host keeps, host name). Windows: 24-GB rule; Linux: total minus the reserve."""
    if windows:
        return int(min(HARD_LIMIT_GB - DOCKER_SHARE_GB, hw.ram_total_gb - WINDOWS_MIN_GB)), WINDOWS_MIN_GB, "Windows"
    return int(hw.ram_total_gb - LINUX_MIN_GB - DOCKER_SHARE_GB), LINUX_MIN_GB, "the Linux host"


def _gpu_env(hw: Hardware, cuda_build: bool = True) -> tuple[str, dict, str]:
    """The VRAM table of the docs, by what is free now. Rows are named for cards; a card also holds other programs."""
    if not cuda_build:
        return "cpu", {"DSV4_CUDA": "0"}, "CPU only: no pinned CUDA build of colibri for this platform (manifest, ADR-0013)"
    base = {"COLI_CUDA": "1", "COLI_GPU": "0", "V4_LOADER_LANES": "3", "COLI_CUDA_PIPE": "2"}
    free = hw.vram_free_mib
    if hw.compute_cap < 8 or free < 4500:
        return "cpu", {"DSV4_CUDA": "0"}, f"CPU only: {free} MiB VRAM free, compute capability {hw.compute_cap}"
    if free >= 11000:
        return "cuda", {**base, "CUDA_DENSE": "1", "COLI_CUDA_ATTN_BATCH": "1", "COLI_CUDA_MOE_BATCH": "1",
                        "V4_MOE_REFILL_GROUP": "12"}, f"full GPU tier: {free} MiB VRAM free"
    if free >= 7000:
        return "cuda", {**base, "CUDA_DENSE": "1", "COLI_CUDA_ATTN_BATCH": "1", "COLI_CUDA_MOE_BATCH": "0"}, \
            f"no prefill bank on the GPU: {free} MiB VRAM free, it needs about 11 GB"
    return "cuda", {**base, "CUDA_DENSE": "0", "COLI_CUDA_ATTN_BATCH": "0", "COLI_CUDA_MOE_BATCH": "1"}, \
        f"no dense mirrors on the GPU: {free} MiB VRAM free, they need about 7 GB"


def choose(hw: Hardware, ram_override: int = 0, windows: bool = IS_WIN, cuda_build: bool | None = None) -> dict:
    notes: list[str] = []
    warnings: list[str] = []
    if hw.ram_total_gb <= 0:
        raise ValueError("the RAM of this machine could not be read; no budget is guessed")
    cap, host_min, host = host_limits(hw, windows)   # the limits beat every other wish
    if cap <= 0:
        raise ValueError(f"{hw.ram_total_gb:.1f} GB RAM leave nothing beside the {host_min} GB {host} keeps")
    ram = min(cap, ram_override if ram_override > 0 else max(FLOOR_GB, int(hw.ram_free_gb - HEADROOM_GB)))
    notes.append(f"--ram {ram}: {hw.ram_free_gb:.1f} GB free of {hw.ram_total_gb:.1f} GB, cap {cap} GB"
                 + (" (set by hand)" if ram_override > 0 else ""))
    if ram_override > cap:
        rule = "24 GB rule, " if windows else ""
        warnings.append(f"--ram {ram_override} asked for, {cap} GB is the limit here ({rule}{host} keeps {host_min} GB)")
    if ram < FLOOR_GB:
        warnings.append(f"--ram {ram} is below the {FLOOR_GB} GB the engine was measured to need: it may refuse to start")
    elif ram < WANTED_GB:
        warnings.append(f"--ram {ram} is below the {WANTED_GB} GB this model wants: every GB freed by closing programs adds speed")
    if not ram_override and hw.ram_free_gb < ram + 3:
        warnings.append(f"only {hw.ram_free_gb:.1f} GB RAM free: HostGuard pauses a job below 3 GB free")
    backend, env, why = _gpu_env(hw, windows if cuda_build is None else cuda_build)
    notes.append(why)
    if backend == "cuda" and hw.compute_cap >= 12:
        notes.append(f"{hw.gpu_name}: compute capability {hw.compute_cap}, the engine picks its DeepGEMM kernels")
    if backend == "cuda" and hw.vram_free_mib < hw.vram_total_mib - 3000:
        warnings.append(f"{hw.vram_total_mib - hw.vram_free_mib} MiB VRAM are in use by other programs: closing them helps")
    env["COLI_QUEUE_TIMEOUT"] = "36000"  # a translation waits behind a long reply; the default of 300 s would fail it
    estimate = 0.0
    if hw.disk_read_mb_s:
        estimate = round(hw.disk_read_mb_s / (MISSES_PER_TOKEN * EXPERT_MB), 2)
        notes.append(f"model disk: {hw.disk_bus or 'unknown bus'}, {hw.disk_read_mb_s:.0f} MB/s; about {estimate} tok/s if disk "
                     "reads alone limit it (derived from the docs, not measured)")
    if hw.disk_bus.upper() == "USB":
        warnings.append("the model is on USB: a second copy on another drive (--colibri-mirror / -ColibriMirror) would split the reads")
    return {"backend": backend, "ram_gb": ram, "ctx": CTX, "env": env, "notes": notes, "warnings": warnings,
            "estimate_tok_s": estimate, "hardware": asdict(hw)}


def eligible(hw: Hardware, model_problem: str = "", windows: bool = IS_WIN) -> list[str]:
    """Why this machine should stay on Ollama and a smaller model; empty means colibri may be switched on (ADR-0012)."""
    why = [model_problem] if model_problem else []
    host_min = WINDOWS_MIN_GB if windows else LINUX_MIN_GB
    host = "Windows" if windows else "the Linux host"
    if hw.ram_total_gb < WANTED_GB + host_min:
        why.append(f"{hw.ram_total_gb:.1f} GB RAM in total, {WANTED_GB + host_min} GB needed ({WANTED_GB} GB for the model, {host_min} GB for {host})")
    if hw.ram_free_gb < WANTED_GB + HEADROOM_GB:
        why.append(f"{hw.ram_free_gb:.1f} GB RAM free, {WANTED_GB + HEADROOM_GB} GB needed")
    rate = hw.disk_read_mb_s / (MISSES_PER_TOKEN * EXPERT_MB)
    if rate < MIN_TOK_S:
        why.append(f"model disk reads {hw.disk_read_mb_s:.0f} MB/s ({hw.disk_bus or 'unknown bus'}), about {rate:.2f} tok/s; "
                   f"{MIN_TOK_S} tok/s need {MIN_TOK_S * MISSES_PER_TOKEN * EXPERT_MB:.0f} MB/s")
    return why


def _measure_read_linux(shard: Path, seconds: float) -> float:
    """O_DIRECT reads (no page cache) of one expert's size at random 128-KiB-aligned offsets."""
    import mmap
    size = 12_582_912
    try:
        fd = os.open(shard, os.O_RDONLY | getattr(os, "O_DIRECT", 0))
    except OSError:
        return 0.0
    try:
        buf = mmap.mmap(-1, size)   # page aligned, as O_DIRECT requires
        steps = (shard.stat().st_size - size) // 131072
        got, t0 = 0, time.monotonic()
        while time.monotonic() - t0 < seconds:
            n = os.preadv(fd, [buf], random.randrange(steps) * 131072)
            if n <= 0:
                return 0.0
            got += n
        return got / 1e6 / (time.monotonic() - t0)
    except OSError:
        return 0.0
    finally:
        os.close(fd)


def _disk_bus_linux(root: Path) -> str:
    """'USB' if the block device under <root> hangs on a USB bus (sysfs path), else 'internal'; '' if unknown."""
    m = linuxhost.mount_of(root, linuxhost.mounts())
    if not m or not m["source"].startswith("/dev/"):
        return ""
    dev = os.path.basename(os.path.realpath(m["source"]))
    p = Path("/sys/class/block", dev)
    try:
        return "USB" if "/usb" in os.path.realpath(p) else "internal"
    except OSError:
        return ""


def _measure_read(folder: Path, seconds: float = 5.0) -> float:
    """Unbuffered reads of one expert's size at random offsets of the largest shard: what the engine does on a cache miss."""
    shards = sorted(folder.glob("*.safetensors"), key=lambda p: p.stat().st_size)
    if not shards or shards[-1].stat().st_size < 1 << 28:
        return 0.0
    if os.name != "nt":
        return _measure_read_linux(shards[-1], seconds)
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.restype = ctypes.c_void_p
    k.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
    k.VirtualAlloc.restype = ctypes.c_void_p
    k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    k.SetFilePointerEx.argtypes = [ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p, ctypes.c_ulong]
    k.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    k.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
    size = 12_582_912           # a multiple of the sector size, as FILE_FLAG_NO_BUFFERING requires
    buf = None
    h = k.CreateFileW(str(shards[-1]), 0x80000000, 1, None, 3, 0x20000000, None)
    if h in (None, ctypes.c_void_p(-1).value):
        return 0.0
    try:
        buf, got, t0 = k.VirtualAlloc(None, size, 0x3000, 0x04), 0, time.monotonic()
        if not buf:
            return 0.0
        steps = (shards[-1].stat().st_size - size) // 131072
        while time.monotonic() - t0 < seconds:
            if not k.SetFilePointerEx(h, random.randrange(steps) * 131072, None, 0):
                return 0.0   # no measurement beats one of sequential reads
            n = ctypes.c_ulong()
            if not k.ReadFile(h, buf, size, ctypes.byref(n), None):
                return 0.0
            got += n.value
        return got / 1e6 / (time.monotonic() - t0)
    finally:
        if buf:
            k.VirtualFree(buf, 0, 0x8000)
        k.CloseHandle(h)


def detect(model: dict) -> Hardware:
    hw = Hardware()
    ram = _ram_gb()
    if ram:
        hw.ram_total_gb, hw.ram_free_gb = ram
    # shortcut: the first card only, COLI_GPU=0 means the same one on a single-GPU machine; upgrade for several cards
    r = _run(["nvidia-smi", "--query-gpu=name,compute_cap,memory.total,memory.free", "--format=csv,noheader,nounits"])
    if r and r.returncode == 0 and r.stdout.strip():
        f = [x.strip() for x in r.stdout.splitlines()[0].split(",")]
        try:
            hw.gpu_name, hw.compute_cap, hw.vram_total_mib, hw.vram_free_mib = f[0], float(f[1]), int(f[2]), int(f[3])
        except (IndexError, ValueError):
            pass   # an unreadable answer counts as no GPU, the CPU path always works
    root = _volume_root(model["volume_label"])
    if root:
        if IS_WIN:
            letter = str(root)[0]
            b = _run(["powershell", "-NoProfile", "-Command", f"(Get-Partition -DriveLetter {letter} | Get-Disk).BusType"], 30)
            hw.disk_bus = b.stdout.strip() if b and b.returncode == 0 else ""
        else:
            hw.disk_bus = _disk_bus_linux(root)
        hw.disk_read_mb_s = round(_measure_read(root / Path(*model["dir"].replace("\\", "/").split("/"))), 1)
    return hw


def main() -> int:
    ap = argparse.ArgumentParser(prog="colibri_settings")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--ram", type=int, default=0, help="expert cache budget in GB, 0 = from the free RAM")
    ap.add_argument("--check", action="store_true", help="exit 1 and name the reasons if this machine should stay on Ollama")
    a = ap.parse_args()
    manifest = Path(__file__).resolve().parents[2] / "infra" / "manifest.json"
    if a.check:
        m = json.loads(manifest.read_text(encoding="utf-8"))
        pins = json.loads((manifest.parent / "colibri-model.files.json").read_text(encoding="utf-8"))["files"]
        bad = [r["detail"] for r in check_colibri(m, pins) if r["status"] == FEHLER]
        why = eligible(detect(component(m, "colibri", "models")), "; ".join(bad))
        print(json.dumps({"eligible": not why, "reasons": why}))
        return 1 if why else 0
    try:
        m = json.loads(manifest.read_text(encoding="utf-8"))
        s = choose(detect(component(m, "colibri", "models")), a.ram, cuda_build=IS_WIN or bool(component(m, "colibri").get("url_cuda")))
    except ValueError as e:
        print(f"colibri_settings: {e}", file=sys.stderr)
        return 1
    if a.json:
        print(json.dumps(s))
        return 0
    print(f"backend {s['backend']}, --ram {s['ram_gb']}, --ctx {s['ctx']}")
    for line in s["notes"]:
        print("  " + line)
    for line in s["warnings"]:
        print("  WARN " + line)
    for k, v in s["env"].items():
        print(f"  {k}={v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
