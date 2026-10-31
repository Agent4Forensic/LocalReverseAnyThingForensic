"""Preflight checks, stage logging, manifest hash check and PID files for scripts\\start.ps1 / stop.ps1.

Stdlib only on purpose: the check must run before anything else is installed.
Every check returns {"name", "status", "detail", "fix"} with status OK | WARN | FEHLER.
Messages are ASCII (German without umlauts) so the PowerShell console never garbles them.
No network access except loopback to the own Ollama (port from the caller).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime
from importlib import metadata
from pathlib import Path

OK, WARN, FEHLER = "OK", "WARN", "FEHLER"
STAGES = ("CHECK", "INSTALL", "UPDATE", "OLLAMA", "MODEL", "APP", "WORKER", "JOB", "GUARD", "STOP")
RAM_LIMIT_GB = 24
MIN_FREE_VRAM_MIB = 7000
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


# ---- logging --------------------------------------------------------------------------------------------
def fmt_line(stage: str, msg: str, level: str = "INFO", now: datetime | None = None) -> str:
    """'[HH:mm:ss] [STAGE] Meldung'; OK/WARN/FEHLER get a text prefix so the log file keeps the severity."""
    if stage not in STAGES:
        raise ValueError(f"unknown stage {stage!r}")
    prefix = f"{level}: " if level in (OK, WARN, FEHLER) else ""
    return f"[{(now or datetime.now()):%H:%M:%S}] [{stage}] {prefix}{msg}"


def log(stage: str, msg: str, level: str = "INFO", logfile: str | Path | None = None) -> str:
    """Print the line and append it to logfile (default: env SW_LOG_FILE, written by start.ps1)."""
    line = fmt_line(stage, msg, level)
    print(line, flush=True)
    target = logfile or os.environ.get("SW_LOG_FILE")
    if target:
        try:
            with open(target, "a", encoding="utf-8", newline="\n") as f:
                f.write(line + "\n")
        except OSError:
            pass  # logging must never break the platform
    return line


# ---- manifest / hash ------------------------------------------------------------------------------------
class HashMismatch(Exception):
    pass


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_hash(path: str | Path, expected: str) -> str:
    """Return the digest if it equals the pinned one; otherwise raise (no pin, bad pin or mismatch are all hard errors)."""
    exp = (expected or "").strip().lower()
    if not _HEX64.match(exp):
        raise HashMismatch(f"no valid sha256 pin ({expected!r}); refusing to use {path}")
    got = sha256_file(path)
    if got != exp:
        raise HashMismatch(f"sha256 mismatch for {path}: expected {exp}, got {got}")
    return got


def load_manifest(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ---- PID files ------------------------------------------------------------------------------------------
def write_pid(path: str | Path, pid: int, name: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"pid": int(pid), "name": name, "started": datetime.now().isoformat(timespec="seconds")}),
                 encoding="utf-8")


def read_pid(path: str | Path) -> dict | None:
    """None for a missing or corrupt file; corrupt content never raises."""
    try:
        d = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        return d if isinstance(d, dict) and int(d["pid"]) > 0 else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def pid_alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        code = ctypes.c_ulong()
        ok = k32.GetExitCodeProcess(h, ctypes.byref(code))
        k32.CloseHandle(h)
        return bool(ok) and code.value == 259  # STILL_ACTIVE
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def clean_stale_pid(path: str | Path) -> bool:
    """Delete the PID file if it is unreadable or the process is gone. True if the file was removed."""
    p = Path(path)
    if not p.exists():
        return False
    d = read_pid(p)
    if d is None or not pid_alive(d["pid"]):
        p.unlink(missing_ok=True)
        return True
    return False


# ---- aggregation / rendering ----------------------------------------------------------------------------
def result(name: str, status: str, detail: str, fix: str = "") -> dict:
    return {"name": name, "status": status, "detail": detail, "fix": fix}


def aggregate(results: list[dict]) -> str:
    sts = {r["status"] for r in results}
    return FEHLER if FEHLER in sts else WARN if WARN in sts else OK


def render_table(results: list[dict]) -> str:
    w = max([len(r["name"]) for r in results] + [5])
    rows = [f"{r['status']:<6} {r['name']:<{w}}  {r['detail']}" + (f"  -> {r['fix']}" if r["fix"] and r["status"] != OK else "")
            for r in results]
    return "\n".join(rows + [f"GESAMT: {aggregate(results)}"])


# ---- individual checks ----------------------------------------------------------------------------------
def _run(cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def check_platform() -> list[dict]:
    out = [result("os", OK if sys.platform == "win32" else WARN, sys.platform, "Zielsystem ist Windows 11")]
    v = sys.version_info
    out.append(result("python", OK if v >= (3, 11) else FEHLER, f"{v.major}.{v.minor}.{v.micro}", "Python >= 3.11 noetig"))
    out.append(result("venv", OK if sys.prefix != sys.base_prefix else WARN, sys.prefix, "start.ps1 legt .venv an"))
    return out


def _norm(n: str) -> str:
    return re.sub(r"[-_.]+", "-", n).lower()


def parse_lock(text: str) -> dict[str, str]:
    return {_norm(m.group(1)): m.group(2) for m in re.finditer(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)", text, re.M)}


def check_lock(lock_path: str | Path) -> list[dict]:
    p = Path(lock_path)
    if not p.exists():
        return [result("lock:missing", FEHLER, f"{p} fehlt", "Lockfile aus dem Repo wiederherstellen")]
    missing, drift = [], []
    for name, ver in parse_lock(p.read_text(encoding="utf-8")).items():
        try:
            have = metadata.version(name)
        except metadata.PackageNotFoundError:
            missing.append(name)
            continue
        if have != ver:
            drift.append(f"{name} {have}->{ver}")
    return [
        result("lock:missing", FEHLER if missing else OK, ", ".join(missing[:8]) or "alle Pakete installiert",
               "start.ps1 installiert mit --require-hashes"),
        result("lock:drift", WARN if drift else OK, ", ".join(drift[:8]) or "Versionen entsprechen dem Lockfile",
               "start.ps1 -Update gleicht mit dem Lockfile ab"),
    ]


def check_docker() -> dict:
    if not shutil.which("docker"):
        return result("docker", WARN, "nicht gefunden (optional)", "nur fuer Container-Werkzeuge noetig")
    r = _run(["docker", "info", "--format", "{{.ServerVersion}}"], 15)
    if r and r.returncode == 0:
        return result("docker", OK, f"Daemon {r.stdout.strip()}")
    return result("docker", WARN, "Daemon nicht erreichbar (optional)", "Docker Desktop starten, falls Container gebraucht werden")


def gpu_free_mib() -> tuple[int, int, str] | None:
    r = _run(["nvidia-smi", "--query-gpu=name,memory.total,memory.used", "--format=csv,noheader,nounits"])
    if not r or r.returncode != 0 or not r.stdout.strip():
        return None
    name, total, used = [x.strip() for x in r.stdout.splitlines()[0].split(",")]
    return int(total) - int(used), int(total), name


def check_gpu() -> dict:
    g = gpu_free_mib()
    if not g:
        return result("gpu:vram", WARN, "nvidia-smi nicht verfuegbar", "ohne GPU laeuft das Modell sehr langsam")
    free, total, name = g
    st = OK if free >= MIN_FREE_VRAM_MIB else WARN
    return result("gpu:vram", st, f"{free} MiB frei von {total} MiB ({name})",
                  "GPU-lastige Programme schliessen (ADR-0001: unter 7 GB frei ist instabil)")


def _ram_gb() -> tuple[float, float] | None:
    if os.name != "nt":
        return None
    import ctypes

    class MS(ctypes.Structure):
        _fields_ = [("l", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [(n, ctypes.c_ulonglong) for n in
                    ("total", "avail", "tpf", "apf", "tv", "av", "ae")]
    ms = MS()
    ms.l = ctypes.sizeof(MS)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms)):
        return None
    return ms.total / 2**30, ms.avail / 2**30


def check_ram(wslconfig: str | Path | None = None) -> list[dict]:
    out = []
    ram = _ram_gb()
    if ram:
        total, free = ram
        out.append(result("ram:free", OK if free >= 10 else WARN, f"{free:.1f} GB frei von {total:.1f} GB",
                          "Programme schliessen; Windows behaelt mindestens 7 GB"))
    else:
        out.append(result("ram:free", WARN, "nicht ermittelbar"))
    cfg = Path(wslconfig) if wslconfig else Path.home() / ".wslconfig"
    m = re.search(r"^\s*memory\s*=\s*(\d+)\s*GB", cfg.read_text(encoding="utf-8", errors="ignore"), re.I | re.M) if cfg.exists() else None
    if m and int(m.group(1)) <= RAM_LIMIT_GB:
        out.append(result("wsl:memory-limit", OK, f"{m.group(1)} GB (Limit {RAM_LIMIT_GB} GB)"))
    else:
        out.append(result("wsl:memory-limit", WARN, f".wslconfig ohne memory<={RAM_LIMIT_GB}GB", f"memory={RAM_LIMIT_GB}GB in .wslconfig setzen"))
    return out


def port_free(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def check_ports(ports: dict[str, int], run_dir: str | Path) -> list[dict]:
    """ports: {'app': 8765, 'ollama': 11435}. A busy port is fine only if our own live PID file explains it."""
    out = []
    for key, port in ports.items():
        pid = read_pid(Path(run_dir) / f"{key}.pid")
        if port_free(port):
            out.append(result(f"port:{port}", OK, f"frei ({key})"))
        elif pid and pid_alive(pid["pid"]):
            out.append(result(f"port:{port}", OK, f"belegt durch eigenen Prozess pid {pid['pid']} ({key})"))
        else:
            out.append(result(f"port:{port}", FEHLER, f"belegt durch fremden Prozess ({key})",
                              "Fremde Prozesse werden nie beendet; -Port / -OllamaPort aendern"))
    return out


def check_ollama_binary(manifest: dict) -> dict:
    c = manifest.get("components", {}).get("ollama", {})
    exe = Path(c.get("target", "")) / c.get("exe", "ollama.exe")
    if exe.exists():
        return result("ollama:binary", OK, f"{c.get('version')} in {exe.parent}")
    return result("ollama:binary", FEHLER, f"{exe} fehlt", "start.ps1 installiert aus dem gepinnten Manifest (Hash-Pruefung)")


def _loopback_get(url: str, timeout: float = 3.0) -> dict:
    host = re.match(r"^http://([^:/]+)", url)
    if not host or host.group(1) not in ("127.0.0.1", "localhost"):
        raise ValueError("only loopback URLs are allowed")
    with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 (loopback checked above)
        return json.loads(r.read())


def check_models(ollama_port: int, model: str | None, embedding: str | None) -> list[dict]:
    try:
        have = {m["name"] for m in _loopback_get(f"http://127.0.0.1:{ollama_port}/api/tags")["models"]}
    except Exception:  # server down is normal before OLLAMA stage
        return [result("model:chat", WARN, "Ollama laeuft nicht, Modellliste unbekannt (wird nach dem Start geprueft)")]
    out = []
    for key, tag in (("chat", model), ("embedding", embedding)):
        if not tag:
            continue
        ok = tag in have or f"{tag}:latest" in have
        out.append(result(f"model:{key}", OK if ok else WARN, f"{tag} {'vorhanden' if ok else 'fehlt'}",
                          f"ollama pull {tag} (nur online, durch start.ps1 mit Hinweis)"))
    return out


def check_gateway() -> dict:
    try:
        from sw_analyst.gateway.dev_gateway import DevGateway
        with tempfile.TemporaryDirectory() as d:
            n = len(DevGateway(d).list_tools())
        return result("gateway:selftest", OK if n > 0 else FEHLER, f"{n} Werkzeuge registriert")
    except Exception as e:  # any failure here is a platform error, report it
        return result("gateway:selftest", FEHLER, f"{type(e).__name__}: {e}", "Lockfile-Pakete pruefen")


def check_audit_chain(data_dir: str | Path) -> dict:
    try:
        from sw_analyst.common.audit import verify_file
    except ImportError as e:
        return result("audit:chain", FEHLER, f"Import fehlgeschlagen: {e}")
    files = sorted(Path(data_dir, "logs").glob("*/audit.jsonl"))
    bad = [f"{f.parent.name}@{v.broken_at}" for f in files if not (v := verify_file(f)).valid]
    if bad:
        return result("audit:chain", FEHLER, "Kette gebrochen: " + ", ".join(bad), "Log nicht aendern; Vorfall an Jan melden")
    return result("audit:chain", OK, f"{len(files)} Log(s) geprueft")


def run_checks(root: str | Path, data_dir: str | Path, app_port: int = 8765, ollama_port: int = 11435,
               model: str | None = None) -> list[dict]:
    root, data_dir = Path(root), Path(data_dir)
    manifest = load_manifest(root / "infra" / "manifest.json")
    res = check_platform()
    res += check_lock(root / "requirements.lock")
    res.append(check_docker())
    res.append(check_gpu())
    res += check_ram()
    res += check_ports({"app": app_port, "ollama": ollama_port}, data_dir / "run")
    res.append(check_ollama_binary(manifest))
    res += check_models(ollama_port, model, manifest.get("models", {}).get("embedding"))
    res.append(check_gateway())
    res.append(check_audit_chain(data_dir))
    return res


def main_check(root: str | Path, data_dir: str | Path, app_port: int, ollama_port: int, model: str | None,
               as_json: bool = False) -> int:
    t0 = time.time()
    res = run_checks(root, data_dir, app_port, ollama_port, model)
    print(json.dumps({"status": aggregate(res), "results": res}) if as_json else render_table(res))
    if not as_json:
        log("CHECK", f"{len(res)} Pruefungen in {time.time() - t0:.1f}s: {aggregate(res)}")
    return 1 if aggregate(res) == FEHLER else 0
