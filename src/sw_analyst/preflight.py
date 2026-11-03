"""Preflight checks, stage logging, manifest hash check and PID files for the launchers.

Launchers: scripts/start.sh and stop.sh on Linux (ADR-0013, sw_analyst.launcher), scripts\\start.ps1 and stop.ps1 on Windows.

Stdlib only on purpose: the check must run before anything else is installed.
Every check returns {"name", "status", "detail", "fix"} with status OK | WARN | FEHLER.
Messages are ASCII (German without umlauts) so the PowerShell console never garbles them.
Platform facts on Linux come from common/linuxhost.py (read-only /proc and /sys).
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

from sw_analyst.common import linuxhost

OK, WARN, FEHLER = "OK", "WARN", "FEHLER"
STAGES = ("CHECK", "INSTALL", "UPDATE", "OLLAMA", "MODEL", "APP", "WORKER", "JOB", "GUARD", "DATA", "STOP",
          "SETUP", "DOCKER", "COLIBRI", "GATE", "CLEAN")
RAM_LIMIT_GB = 24          # Windows: WSL, Docker and models together (decision of Jan, 2026-10-31)
IS_WIN = os.name == "nt"
DEFAULT_SW_ROOT = "/srv/sw-analyst"   # Linux: the SWDATA volume on the Ventoy SSD (ADR-0013)
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


def platform_key() -> str:
    return "windows" if IS_WIN else "linux"


def sw_root() -> Path:
    """Linux: root of tools, models and Docker data (env SW_ROOT, default /srv/sw-analyst). Windows keeps D:\\Tools."""
    return Path(os.environ.get("SW_ROOT") or DEFAULT_SW_ROOT)


def _expand(v):
    return v.replace("${SW_ROOT}", str(sw_root())) if isinstance(v, str) else v


def component(manifest: dict, name: str, section: str = "components") -> dict:
    """Manifest entry with the overrides of this platform (key "linux") merged in and ${SW_ROOT} expanded.
    The Windows values are the top level, so the PowerShell scripts read the same file unchanged."""
    c = dict(manifest.get(section, {}).get(name) or {})
    over = c.pop("linux", None)
    if not IS_WIN and isinstance(over, dict):
        c.update(over)
    return {k: _expand(v) for k, v in c.items()}


def tools_root(manifest: dict) -> Path:
    t = component(manifest, "ollama").get("target", "")
    return Path(t).parent if t else (Path("D:/Tools/sw-analyst") if IS_WIN else sw_root() / "tools")


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
    ok = sys.platform == "win32" or linuxhost.is_linux()
    out = [result("os", OK if ok else WARN, sys.platform, "Zielsysteme: Linux (ADR-0013) oder Windows 11")]
    v = sys.version_info
    out.append(result("python", OK if v >= (3, 11) else FEHLER, f"{v.major}.{v.minor}.{v.micro}", "Python >= 3.11 noetig"))
    out.append(result("venv", OK if sys.prefix != sys.base_prefix else WARN, sys.prefix, "start.sh / start.ps1 legt .venv an"))
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
               "start installiert mit --require-hashes"),
        result("lock:drift", WARN if drift else OK, ", ".join(drift[:8]) or "Versionen entsprechen dem Lockfile",
               "start --update (Linux) / start.ps1 -Update gleicht mit dem Lockfile ab"),
    ]


def check_docker() -> dict:
    if not shutil.which("docker"):
        return result("docker", WARN, "nicht gefunden (optional)", "nur fuer Container-Werkzeuge noetig")
    r = _run(["docker", "info", "--format", "{{.ServerVersion}}"], 15)
    if r and r.returncode == 0:
        return result("docker", OK, f"Daemon {r.stdout.strip()}")
    fix = "Docker Desktop starten" if IS_WIN else "sudo systemctl start docker (Benutzer in Gruppe docker, ADR-0013)"
    return result("docker", WARN, "Daemon nicht erreichbar (optional)", fix + ", falls Container gebraucht werden")


def check_tool_images(manifest: dict) -> list[dict]:
    """Optional images of ADR-0006 package B. Without Docker there is nothing to ask; check_docker already says so."""
    probe = _run(["docker", "info", "--format", "{{.ServerVersion}}"], 15) if shutil.which("docker") else None
    if not probe or probe.returncode != 0:
        return []
    out = []
    for key, tag in manifest.get("tool_images", {}).items():
        r = _run(["docker", "image", "inspect", "--format", "{{.Id}}", tag], 15)
        ok = bool(r and r.returncode == 0)
        out.append(result(f"image:{key}", OK if ok else WARN, f"{tag} {'vorhanden' if ok else 'fehlt (Werkzeuge bleiben aus)'}",
                          "powershell -File infra\\tools\\build-images.ps1 (einmalig online)" if IS_WIN
                          else "scripts/start.sh --setup baut fehlende Images (einmalig online)"))
    return out


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
    if not IS_WIN:
        return linuxhost.ram_gb()
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
    if not IS_WIN:
        return check_ram_linux()
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


def check_ram_linux(ram: tuple[float, float] | None = None, cg_limit: float | None = None) -> list[dict]:
    """ADR-0013: the host keeps HOST_RESERVE_GB; platform, containers and models together at most the rest, enforced by
    the systemd user slice sw-analyst.slice (MemoryMax) that the launcher starts the app and the engine in."""
    ram = ram if ram is not None else _ram_gb()
    if not ram:
        return [result("ram:free", WARN, "nicht ermittelbar")]
    total, free = ram
    reserve = linuxhost.HOST_RESERVE_GB
    out = [result("ram:free", OK if free >= 10 else WARN, f"{free:.1f} GB frei von {total:.1f} GB",
                  f"andere Programme schliessen; der Host behaelt {reserve} GB")]
    cap = total - reserve
    lim = cg_limit if cg_limit is not None else linuxhost.cgroup_memory_limit_gb()
    if lim is not None and lim <= cap + 0.01:
        out.append(result("ram:limit", OK, f"cgroup-Grenze {lim:.1f} GB (hoechstens {cap:.1f} GB, Host behaelt {reserve} GB)"))
    else:
        out.append(result("ram:limit", WARN, "keine cgroup-Grenze fuer diesen Prozess" if lim is None else f"cgroup-Grenze {lim:.1f} GB > {cap:.1f} GB",
                          "ueber scripts/start.sh starten (systemd-run --user --slice=sw-analyst.slice, MemoryMax)"))
    return out


def port_free(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def port_owner_pid(port: int) -> int | None:
    """PID that listens on 127.0.0.1:<port> (Windows: parsed from netstat; Linux: /proc; no admin rights needed)."""
    if not IS_WIN:
        return linuxhost.listen_pid(port)
    try:
        txt = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True, errors="replace", timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in txt.splitlines():
        parts = line.split()
        # State words are localised ("LISTENING"/"ABHOEREN"), so they are not used. Any row with this LOCAL port is
        # the server side (clients use ephemeral ports); the LISTEN row itself can be missing in hidden sessions.
        if len(parts) >= 5 and parts[0] == "TCP" and parts[1].endswith(f":{port}"):
            try:
                if int(parts[-1]) > 0:
                    return int(parts[-1])
            except ValueError:
                return None
    return None


def process_path(pid: int) -> str | None:
    """Executable path of a process (Windows via QueryFullProcessImageNameW, Linux via /proc/<pid>/exe)."""
    if not IS_WIN:
        return linuxhost.exe_path(pid)
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return None
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = ctypes.c_ulong(len(buf))
            return buf.value if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)) else None
        finally:
            k32.CloseHandle(h)
    except (AttributeError, OSError):
        return None


def path_under(path: str | None, roots: list[str]) -> bool:
    if not path:
        return False
    p = os.path.normcase(os.path.abspath(path))
    return any(p.startswith(os.path.normcase(os.path.abspath(r)) + os.sep) for r in roots)


def check_ports(ports: dict[str, int], run_dir: str | Path, own_roots: list[str] | None = None) -> list[dict]:
    """ports: {'app': 8765, 'ollama': 11435}. A busy port is fine if our own live PID file explains it, or if the
    listener is a program installed under one of own_roots (e.g. a leftover of our own earlier start)."""
    out = []
    for key, port in ports.items():
        pid = read_pid(Path(run_dir) / f"{key}.pid")
        if port_free(port):
            out.append(result(f"port:{port}", OK, f"frei ({key})"))
            continue
        if pid and pid_alive(pid["pid"]):
            out.append(result(f"port:{port}", OK, f"belegt durch eigenen Prozess pid {pid['pid']} ({key})"))
            continue
        owner = port_owner_pid(port)
        exe = process_path(owner) if owner else None
        if os.environ.get("SW_DEBUG_PREFLIGHT"):
            print(f"[debug] port={port} owner={owner} exe={exe} roots={own_roots}", file=sys.stderr)
        if own_roots and path_under(exe, own_roots):
            out.append(result(f"port:{port}", OK, f"belegt durch eigene Instanz pid {owner} ({key}), wird weiterverwendet"))
        else:
            who = f" ({os.path.basename(exe)}, pid {owner})" if exe else ""
            out.append(result(f"port:{port}", FEHLER, f"belegt durch fremden Prozess{who} ({key})",
                              "Fremde Prozesse werden nie beendet; Port aendern (--port / --ollama-port)"))
    return out


def check_ollama_binary(manifest: dict) -> dict:
    c = component(manifest, "ollama")
    exe = Path(c.get("target", "")) / c.get("exe", "ollama.exe")
    if exe.exists():
        return result("ollama:binary", OK, f"{c.get('version')} in {c.get('target')}")
    return result("ollama:binary", FEHLER, f"{exe} fehlt", "start installiert aus dem gepinnten Manifest (Hash-Pruefung)")


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
                          f"ollama pull {tag} (nur online: start.sh --setup / start.ps1)"))
    return out


def _volume_root(label: str) -> Path | None:
    """Root of the one mounted volume with this label. A USB drive letter can change, the label does not."""
    if not IS_WIN:
        return linuxhost.volume_root(label)
    r = _run(["powershell", "-NoProfile", "-Command", f"@(Get-Volume | Where-Object FileSystemLabel -ceq '{label}').DriveLetter"], 30)
    letters = r.stdout.split() if r and r.returncode == 0 else []
    return Path(f"{letters[0]}:/") if len(letters) == 1 else None


def check_colibri(manifest: dict, pins: list[dict]) -> list[dict]:
    """Engine present, model volume mounted, every model file has its pinned size (ADR-0012). The list comes from the repository,
    never from the removable drive. This catches a truncated shard; start.ps1 checks the hashes, which takes minutes."""
    c = component(manifest, "colibri")
    m = component(manifest, "colibri", "models")
    if not m:
        return [result("colibri:model", FEHLER, "kein Eintrag models.colibri im Manifest")]
    exe = Path(c.get("target", "")) / c.get("exe", "coli")
    out = [result("colibri:binary", OK if exe.exists() else FEHLER, f"{c.get('version')} in {exe.parent}",
                  "start mit --llm colibri (Linux) / -Llm colibri (Windows) installiert die gepinnte Version")]
    root = _volume_root(m["volume_label"])
    if root is None:
        return out + [result("colibri:volume", FEHLER, f"Datenträger {m['volume_label']} nicht eindeutig gefunden", "SSD anschließen")]
    folder = root / Path(*re.split(r"[\\/]", m["dir"]))
    if not pins:
        return out + [result("colibri:model", FEHLER, "keine gepinnten Dateien (infra/colibri-model.files.json)")]
    bad = [f["file"] for f in pins if not (folder / f["file"]).is_file() or (folder / f["file"]).stat().st_size != f["size"]]
    if bad:
        return out + [result("colibri:model", FEHLER, f"{len(bad)} von {len(pins)} Dateien fehlen oder haben die falsche Größe, z. B. {bad[0]}",
                             "python infra/fetch-colibri-model.py, siehe docs/runbooks/betrieb.md")]
    return out + [result("colibri:model", OK, f"{m['id']}: {len(pins)} Dateien auf {root} (Revision {m['revision'][:7]}, Größen geprüft)")]


def check_network(allow_online: bool = False, routes: list[str] | None = None, links: list[str] | None = None) -> dict:
    """ADR-0013: analysis only in offline mode (infra/linux/sw-mode offline): no default route, no physical link up."""
    routes = linuxhost.default_routes() if routes is None else routes
    links = linuxhost.active_interfaces() if links is None else links
    if not routes and not links:
        return result("net:offline", OK, "keine Standardroute, keine aktive Netzwerkverbindung")
    detail = f"online: Standardroute {', '.join(routes) or '-'}, aktiv {', '.join(links) or '-'}"
    if allow_online:
        return result("net:offline", WARN, detail + " (--allow-online gesetzt)", "nur harmlose Proben; vor echten Proben sudo sw-mode offline")
    return result("net:offline", FEHLER, detail, "sudo sw-mode offline (Einrichtung und Updates nur mit start.sh --setup)")


def check_share(table: list[dict] | None = None, share: str = linuxhost.SHARE_MOUNT) -> dict:
    """The exchange folder of the internal disk: never mounted with exec, setuid or device files (infra/linux/sw-share)."""
    table = linuxhost.mounts() if table is None else table
    m = next((x for x in table if x["target"] == share), None)
    if m is None:
        return result("share:mount", OK, f"{share} nicht eingehaengt")
    missing = [o for o in linuxhost.SHARE_REQUIRED_OPTS if o not in m["options"]]
    if missing:
        return result("share:mount", FEHLER, f"{share} ohne {','.join(missing)} eingehaengt ({m['fstype']})", "sudo sw-share umount; sudo sw-share mount")
    return result("share:mount", WARN, f"{share} eingehaengt ({m['fstype']}, {'ro' if 'ro' in m['options'] else 'rw'}, noexec)",
                  "vor Laeufen mit echten Proben: sudo sw-share umount")


def check_sw_root(table: list[dict] | None = None, root: Path | None = None) -> dict:
    root = root or sw_root()
    if not root.is_dir():
        return result("sw-root", FEHLER, f"{root} fehlt", "SWDATA einhaengen (docs/runbooks/linux-ventoy.md) oder SW_ROOT setzen")
    m = linuxhost.mount_of(root, linuxhost.mounts() if table is None else table)
    fs = m["fstype"] if m else "?"
    if fs not in ("ext4", "xfs", "btrfs"):
        return result("sw-root", WARN, f"{root} auf {fs}", "SWDATA als ext4 einrichten (Rechte, Docker overlay2)")
    return result("sw-root", OK, f"{root} auf {fs} ({m['source']})")


def check_gateway(scratch_parent: str | Path | None = None) -> dict:
    try:
        from sw_analyst.gateway.dev_gateway import DevGateway
        if scratch_parent:   # inside the project folder, not %TEMP% (virus scanner exception)
            Path(scratch_parent).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_parent) as d:
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
               model: str | None = None, llm: str = "ollama", colibri_port: int = 11436,
               allow_online: bool | None = None) -> list[dict]:
    root, data_dir = Path(root), Path(data_dir)
    manifest = load_manifest(root / "infra" / "manifest.json")
    res = check_platform()
    if not IS_WIN:
        if allow_online is None:
            allow_online = os.environ.get("SW_ALLOW_ONLINE") == "1"
        res += [check_network(allow_online), check_share(), check_sw_root()]
    res += check_lock(root / "requirements.lock")
    res.append(check_docker())
    res += check_tool_images(manifest)
    res.append(check_gpu())
    res += check_ram()
    res += check_ports({"app": app_port, "colibri": colibri_port} if llm == "colibri" else {"app": app_port, "ollama": ollama_port},
                       data_dir / "run",
                       [str(tools_root(manifest))])
    if llm == "colibri":
        res += check_colibri(manifest, load_manifest(root / "infra" / "colibri-model.files.json")["files"])
    else:
        res.append(check_ollama_binary(manifest))
        res += check_models(ollama_port, model, manifest.get("models", {}).get("embedding"))
    res.append(check_gateway(data_dir / "tmp"))
    res.append(check_audit_chain(data_dir))
    return res


def main_check(root: str | Path, data_dir: str | Path, app_port: int, ollama_port: int, model: str | None,
               as_json: bool = False, llm: str = "ollama", colibri_port: int = 11436) -> int:
    t0 = time.time()
    res = run_checks(root, data_dir, app_port, ollama_port, model, llm, colibri_port)
    print(json.dumps({"status": aggregate(res), "results": res}) if as_json else render_table(res))
    if not as_json:
        log("CHECK", f"{len(res)} Pruefungen in {time.time() - t0:.1f}s: {aggregate(res)}")
    return 1 if aggregate(res) == FEHLER else 0
