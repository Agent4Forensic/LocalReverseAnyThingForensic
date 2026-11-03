"""Linux launcher of sw-analyst (ADR-0013): the counterpart of scripts\\start.ps1, stop.ps1 and cleanup.ps1.

    scripts/start.sh --setup      once, online (sudo sw-mode online): venv, Ollama, model, tool images from the pins
    scripts/start.sh              every day, offline: CHECK, OLLAMA, MODEL, APP, then a quiet status loop (Ctrl+C stops)
    scripts/stop.sh [--force]     stops only the own processes; --force cancels a running job
    scripts/cleanup.sh --phase post [--dry-run]

Rules (the same as on Windows):
- Installs only from infra/manifest.json (https://github.com URL + SHA-256, a mismatch is a hard error) and requirements.lock
  (--require-hashes). Only --setup downloads anything; a normal start never touches the network.
- Never touches foreign processes: a process is ours only if its PID file, its executable below the tools folder or its
  command line (this repo's venv, this data folder) says so. No root rights needed; Docker is a system service here.
- App, Ollama and colibri run in the systemd user slice sw-analyst.slice, whose MemoryMax leaves the host its reserve.
Stdlib only: this module runs before the venv exists.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

from sw_analyst import preflight as pf
from sw_analyst.common import linuxhost

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
RUN = DATA / "run"
LOGS = DATA / "logs"
VENV_PY = ROOT / ".venv" / "bin" / "python"
SLICE = "sw-analyst.slice"
LABEL = "sw-analyst"
NAMES = ("app", "ollama", "colibri")
_COLORS = {"OK": "\033[32m", "WARN": "\033[33m", "FEHLER": "\033[31m"}


class Fail(Exception):
    def __init__(self, stage: str, msg: str):
        super().__init__(msg)
        self.stage = stage


# ---- logging ------------------------------------------------------------------------------------------------
def say(stage: str, msg: str, level: str = "INFO") -> None:
    line = pf.fmt_line(stage, msg, level)
    color = _COLORS.get(level, "") if sys.stdout.isatty() else ""
    print(f"{color}{line}\033[0m" if color else line, flush=True)
    target = os.environ.get("SW_LOG_FILE")
    if target:
        try:
            with open(target, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass


def _setup_dirs() -> None:
    RUN.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("SW_LOG_FILE", str(LOGS / f"start-{datetime.now():%Y-%m-%d}.log"))


# ---- small helpers --------------------------------------------------------------------------------------------
def manifest() -> dict:
    return pf.load_manifest(ROOT / "infra" / "manifest.json")


def tools_root(m: dict) -> Path:
    return pf.tools_root(m)


def under(path: str | Path | None, root: Path) -> bool:
    """True if <path> lies strictly below <root> (resolved, no prefix tricks like /srv/x-evil)."""
    if not path:
        return False
    try:
        Path(path).resolve().relative_to(root.resolve())
        return Path(path).resolve() != root.resolve()
    except (ValueError, OSError):
        return False


def get_json(url: str, timeout: float = 3.0) -> dict:
    return pf._loopback_get(url, timeout)


def post_json(url: str, body: dict | None, timeout: float = 10.0, origin: str | None = None) -> dict:
    if not url.startswith("http://127.0.0.1:"):
        raise ValueError("only loopback URLs are allowed")
    req = urllib.request.Request(url, data=json.dumps(body or {}).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **({"Origin": origin} if origin else {})})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # loopback never goes through a proxy
    with opener.open(req, timeout=timeout) as r:
        raw = r.read()
    return json.loads(raw) if raw.strip() else {}


def run(cmd: list[str], env: dict | None = None, timeout: int | None = None) -> None:
    rc = subprocess.run(cmd, env=env, timeout=timeout).returncode
    if rc != 0:
        raise RuntimeError(f"{Path(cmd[0]).name} failed with exit code {rc}")


def gpu_free_mib() -> int:
    g = pf.gpu_free_mib()
    return g[0] if g else 0


# ---- ownership (Linux /proc) ----------------------------------------------------------------------------------
def is_own_app(pid: int) -> bool:
    cl = linuxhost.cmdline(pid)
    if "sw_analyst" not in cl or "-m" not in cl:
        return False
    return bool(cl) and (under(cl[0], ROOT / ".venv") or str(DATA) in cl)


def is_own_ollama(pid: int, troot: Path) -> bool:
    return under(linuxhost.exe_path(pid), troot) and Path(linuxhost.exe_path(pid) or "").name == "ollama"


def is_own_colibri(pid: int, troot: Path) -> bool:
    cl = linuxhost.cmdline(pid)
    if under(linuxhost.exe_path(pid), troot) and "colibri-" in (linuxhost.exe_path(pid) or ""):
        return True   # the engine binary itself
    return any(under(a, troot) and Path(a).name == "coli" and "colibri-" in a for a in cl[1:3])


def own_check(name: str, troot: Path):
    return {"app": is_own_app, "ollama": lambda p: is_own_ollama(p, troot), "colibri": lambda p: is_own_colibri(p, troot)}[name]


def stop_tree(pid: int, grace_s: float = 10.0) -> None:
    """SIGTERM to the process group (started with its own session), SIGKILL after the grace time."""
    try:
        pgid = os.getpgid(pid)
    except OSError:
        return
    target = (lambda s: os.killpg(pgid, s)) if pgid == pid else (lambda s: os.kill(pid, s))
    try:
        target(signal.SIGTERM)
    except OSError:
        return
    t0 = time.monotonic()
    while time.monotonic() - t0 < grace_s:
        if not pf.pid_alive(pid):
            return
        time.sleep(0.2)
    try:
        target(signal.SIGKILL)
    except OSError:
        pass


def own_processes(troot: Path) -> list[tuple[int, str]]:
    """(pid, kind) of every process of ours that runs now; kind app|ollama|colibri."""
    out = []
    for d in Path("/proc").iterdir():
        if not d.name.isdigit() or int(d.name) == os.getpid():
            continue
        pid = int(d.name)
        for kind in NAMES:
            if own_check(kind, troot)(pid):
                out.append((pid, kind))
                break
    return out


# ---- memory slice (ADR-0013) ----------------------------------------------------------------------------------
def slice_unit_text(total_gb: float, reserve_gb: int = linuxhost.HOST_RESERVE_GB) -> str:
    cap_mib = int((total_gb - reserve_gb) * 1024)
    return ("# written by sw_analyst.launcher (ADR-0013): app, Ollama and colibri together, the host keeps "
            f"{reserve_gb} GB\n[Unit]\nDescription=sw-analyst platform\n\n[Slice]\nMemoryMax={cap_mib}M\nMemorySwapMax=0\n")


def ensure_slice() -> list[str]:
    """Writes the user slice with the memory limit and returns the command prefix that starts a process inside it.
    Without a systemd user manager the platform still runs; the preflight then warns (ram:limit)."""
    if not shutil.which("systemd-run") or not os.environ.get("XDG_RUNTIME_DIR"):
        say("CHECK", "no systemd user session: processes run without the memory slice", "WARN")
        return []
    ram = linuxhost.ram_gb()
    if not ram:
        return []
    unit = Path.home() / ".config" / "systemd" / "user" / SLICE
    text = slice_unit_text(ram[0])
    if not unit.exists() or unit.read_text(encoding="utf-8") != text:
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text(text, encoding="utf-8")
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, timeout=30)
    prefix = ["systemd-run", "--user", "--scope", "--quiet", f"--slice={SLICE}", "--"]
    probe = subprocess.run(prefix + ["true"], capture_output=True, text=True, timeout=30)
    if probe.returncode != 0:
        say("CHECK", f"systemd-run --user failed ({probe.stderr.strip()[:120]}): processes run without the memory slice", "WARN")
        return []
    say("CHECK", f"memory slice {SLICE}: {text.split('MemoryMax=')[1].split()[0]} for app and engine together", "OK")
    return prefix


def spawn(cmd: list[str], log: Path, env: dict, cwd: Path, prefix: list[str]) -> subprocess.Popen:
    """Own session (Ctrl+C in the terminal reaches only the launcher, which then stops everything in order)."""
    out = open(log, "ab")
    err = open(str(log) + ".err", "ab")
    try:
        return subprocess.Popen(prefix + cmd, stdout=out, stderr=err, stdin=subprocess.DEVNULL, env=env, cwd=cwd,
                                start_new_session=True)
    finally:
        out.close()
        err.close()


# ---- install (only with --setup; always from the pins) --------------------------------------------------------
def _download(url: str, sha: str, dest: Path) -> Path:
    if not url.startswith("https://github.com/") or len(sha or "") != 64:
        raise RuntimeError(f"manifest entry is not pinned (https://github.com URL + sha256 required): {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    say("INSTALL", f"downloading {url}")
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(url, timeout=60) as r, open(tmp, "wb") as f:   # noqa: S310 (pinned github URL above)
        shutil.copyfileobj(r, f, 1 << 20)
    try:
        pf.verify_hash(tmp, sha)
    except pf.HashMismatch:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, dest)
    say("INSTALL", f"sha256 matches the manifest ({dest.name})", "OK")
    return dest


def extract(archive: Path, dest: Path) -> None:
    """tar.gz / tar.zst with the 'data' filter: no absolute paths, no '..', no links out of dest, no setuid bits."""
    if archive.name.endswith(".tar.zst"):
        if not shutil.which("zstd"):
            raise RuntimeError("zstd is missing (sudo apt install zstd; infra/linux/provision.sh installs it)")
        p = subprocess.Popen(["zstd", "-dc", str(archive)], stdout=subprocess.PIPE)
        try:
            with tarfile.open(fileobj=p.stdout, mode="r|") as t:
                t.extractall(dest, filter="data")
        finally:
            p.stdout.close()
            if p.wait() != 0:
                raise RuntimeError(f"zstd could not read {archive.name}")
    else:
        with tarfile.open(archive, "r:*") as t:
            t.extractall(dest, filter="data")


def install_component(name: str, c: dict, troot: Path) -> None:
    target = Path(c["target"])
    if not under(target, troot):
        raise RuntimeError(f"target {target} is outside {troot}")
    tmp = Path(str(target) + ".partial")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    for url, sha in ((c.get("url"), c.get("sha256")), (c.get("url_cuda"), c.get("sha256_cuda"))):
        if url:
            extract(_download(url, sha, troot / "dl" / url.rsplit("/", 1)[-1]), tmp)
    if not (tmp / c["exe"]).is_file():
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"{c['exe']} not found in the {name} archive")
    shutil.rmtree(target, ignore_errors=True)
    os.replace(tmp, target)
    say("INSTALL", f"{name} {c.get('version')} installed in {target}", "OK")


def install_lock(online: bool) -> None:
    if not VENV_PY.exists():
        say("INSTALL", "creating .venv")
        run([sys.executable, "-m", "venv", str(ROOT / ".venv")])
    wheels = list((ROOT / "vendor").glob("*.whl"))
    extra = ["--no-index", "--find-links", str(ROOT / "vendor")] if (not online and wheels) else []
    if not online and not wheels:
        raise RuntimeError("offline and vendor/ has no wheelhouse: run scripts/start.sh --setup once online")
    say("INSTALL", "installing requirements.lock with --require-hashes" + (" from vendor/" if extra else ""))
    run([str(VENV_PY), "-m", "pip", "install", "--quiet", "--require-hashes", "-r", str(ROOT / "requirements.lock")] + extra)


def build_images(m: dict) -> None:
    if not shutil.which("docker"):
        say("SETUP", "docker not installed; tool images skipped (infra/linux/provision.sh installs Docker Engine)", "WARN")
        return
    if subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, timeout=30).returncode != 0:
        say("SETUP", "docker daemon not reachable (sudo systemctl start docker); tool images skipped", "WARN")
        return
    for target, tag in m.get("tool_images", {}).items():
        if subprocess.run(["docker", "image", "inspect", tag], capture_output=True, timeout=30).returncode == 0:
            say("SETUP", f"image {tag} present", "OK")
            continue
        say("SETUP", f"building {tag} from pinned sources (network, can take minutes)")
        try:
            run(["docker", "build", "--target", target, "-t", tag, str(ROOT / "infra" / "tools")])
            say("SETUP", f"image {tag} built", "OK")
        except RuntimeError as e:
            say("SETUP", f"image {tag} not built: {e}; container tools for it stay unavailable", "WARN")


# ---- model choice -------------------------------------------------------------------------------------------
def resolve_model(m: dict, wanted: str) -> str:
    if wanted:
        if not all(ch.isalnum() or ch in "._:/-" for ch in wanted):
            raise Fail("MODEL", f"invalid model tag '{wanted}'")
        return wanted
    tiers = m["models"]["chat_tiers"]
    free = gpu_free_mib()
    tier = "A" if free >= 11000 else "B" if free >= 7000 else "C"
    say("MODEL", f"auto: tier {tier}, {free} MiB VRAM free -> {tiers[tier]}")
    if tier == "C":
        say("MODEL", "less than 7 GB VRAM free: partial CPU offload, slow and crash-prone on Blackwell (ADR-0001)", "WARN")
    return tiers[tier]


# ---- Ollama ---------------------------------------------------------------------------------------------------
def ollama_env(port: int, free_mib: int) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("OLLAMA_")}
    env.update({
        "OLLAMA_HOST": f"127.0.0.1:{port}",
        "OLLAMA_MODELS": str(pf.sw_root() / "models" / "ollama"),
        "OLLAMA_FLASH_ATTENTION": "1", "OLLAMA_KV_CACHE_TYPE": "q8_0",
        "OLLAMA_CONTEXT_LENGTH": "32768" if free_mib >= 11000 else "16384",
        "OLLAMA_NUM_PARALLEL": "1", "OLLAMA_MAX_LOADED_MODELS": "1", "OLLAMA_KEEP_ALIVE": "10m",
        "OLLAMA_NOHISTORY": "1", "OLLAMA_NO_CLOUD": "1",
    })
    return env


def start_ollama(c: dict, port: int, troot: Path, prefix: list[str]) -> None:
    exe = Path(c["target"]) / c["exe"]
    url = f"http://127.0.0.1:{port}"
    owner = linuxhost.listen_pid(port)
    if owner:
        if is_own_ollama(owner, troot):
            pf.write_pid(RUN / "ollama.pid", owner, "ollama")
            say("OLLAMA", f"own ollama already listens on {port} (pid {owner}); reused", "OK")
            return
        raise Fail("OLLAMA", f"port {port} is held by a foreign process (pid {owner}); not touching it")
    if not pf.port_free(port):
        raise Fail("OLLAMA", f"port {port} is busy and its owner is not visible to this user; not touching it")
    free = gpu_free_mib()
    env = ollama_env(port, free)
    Path(env["OLLAMA_MODELS"]).mkdir(parents=True, exist_ok=True)
    log = LOGS / f"ollama-{datetime.now():%Y%m%d-%H%M%S}.log"
    p = spawn([str(exe), "serve"], log, env, exe.parent, prefix)
    pf.write_pid(RUN / "ollama.pid", p.pid, "ollama")
    say("OLLAMA", f"starting ollama pid {p.pid} on {url} (ctx {env['OLLAMA_CONTEXT_LENGTH']}, {free} MiB VRAM free, limit 90 s)")
    for _ in range(180):
        if p.poll() is not None:
            raise Fail("OLLAMA", f"ollama exited early (exit {p.returncode}); see {log}.err")
        try:
            v = get_json(f"{url}/api/version", 2)
            say("OLLAMA", f"ready: version {v.get('version')} on {url} (loopback only)", "OK")
            return
        except Exception:  # noqa: BLE001 - not up yet
            time.sleep(0.5)
    raise Fail("OLLAMA", f"no answer on {url} after 90 s; see {log}.err")


def ensure_model(c: dict, port: int, tag: str, m: dict, allow_pull: bool) -> None:
    url = f"http://127.0.0.1:{port}"
    tags = {x["name"] for x in get_json(f"{url}/api/tags").get("models", [])}
    if tag not in tags and f"{tag}:latest" not in tags:
        if not allow_pull:
            raise Fail("MODEL", f"model {tag} missing; pull it once online with scripts/start.sh --setup")
        say("MODEL", f"model {tag} missing: one-time download from the Ollama registry (network, several GB)", "WARN")
        run([str(Path(c["target"]) / c["exe"]), "pull", tag], env={**os.environ, "OLLAMA_HOST": f"127.0.0.1:{port}"})
        say("MODEL", f"{tag} pulled", "OK")
    else:
        say("MODEL", f"{tag} present", "OK")
    embed = m["models"].get("embedding")
    if embed and embed not in tags and f"{embed}:latest" not in tags:
        say("MODEL", f"embedding model {embed} missing; only the planned knowledge base needs it")


def warm_up(port: int, tag: str) -> None:
    t0 = time.monotonic()
    try:
        post_json(f"http://127.0.0.1:{port}/api/generate", {"model": tag, "prompt": "", "stream": False, "keep_alive": "10m"}, 600)
        say("MODEL", f"warm-up done in {time.monotonic() - t0:.1f}s", "OK")
    except Exception as e:  # noqa: BLE001 - the app still starts; the dashboard shows the model state
        say("MODEL", f"warm-up failed: {e}", "WARN")


# ---- colibri (ADR-0012) ---------------------------------------------------------------------------------------
def colibri_verdict() -> list[str]:
    if not VENV_PY.exists():
        return ["python environment not installed yet"]
    r = subprocess.run([str(VENV_PY), "-m", "sw_analyst.colibri_settings", "--check"], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": str(ROOT / "src")}, timeout=600)
    try:
        return list(json.loads(r.stdout)["reasons"])
    except (ValueError, KeyError):
        return ["the check gave no result"]


def start_colibri(a, c: dict, cm: dict, tag: str, prefix: list[str]) -> tuple[str, str, Path]:
    root = pf._volume_root(cm["volume_label"])
    if root is None:
        raise Fail("COLIBRI", f"volume {cm['volume_label']} not found exactly once (/dev/disk/by-label)")
    model_dir = root / cm["dir"]
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    fetch = str(ROOT / "infra" / "fetch-colibri-model.py")
    if a.skip_model_hash:
        say("COLIBRI", "model hashes NOT checked (--skip-model-hash); only the sizes were", "WARN")
    else:
        say("COLIBRI", "checking the model against the pinned hashes (167 GB, several minutes)")
        run([str(VENV_PY), fetch, "--verify"], env=env)
        say("COLIBRI", "all model files match the pinned hashes", "OK")
    env.pop("COLI_MODEL_MIRROR", None)
    if a.colibri_mirror:
        if not Path(a.colibri_mirror).is_dir():
            raise Fail("COLIBRI", f"mirror folder {a.colibri_mirror} not found")
        if not a.skip_model_hash:
            run([str(VENV_PY), fetch, "--verify", "--dir", a.colibri_mirror], env=env)
            say("COLIBRI", "mirror matches the pinned hashes", "OK")
        env["COLI_MODEL_MIRROR"] = a.colibri_mirror
    r = subprocess.run([str(VENV_PY), "-m", "sw_analyst.colibri_settings", "--json", "--ram", str(a.ram_gb)],
                       capture_output=True, text=True, env=env, timeout=600)
    try:
        s = json.loads(r.stdout)
    except ValueError:
        raise Fail("COLIBRI", f"colibri_settings gave no result: {r.stderr.strip()[:300]}") from None
    settings_file = RUN / "colibri-settings.json"
    settings_file.write_text(r.stdout, encoding="utf-8")
    env.update(s["env"])
    for n in s["notes"]:
        say("COLIBRI", n)
    for w in s["warnings"]:
        say("COLIBRI", w, "WARN")
    model_tag = f"{tag}-{s['backend']}"
    coli = str(Path(c["target"]) / c["exe"])
    if a.colibri_prepare:
        for sub in ("doctor", "plan", "tune"):
            say("COLIBRI", f"coli {sub} (can take long)")
            run([str(VENV_PY), coli, sub, "--model", str(model_dir), "--ram", str(s["ram_gb"]), "--ctx", str(s["ctx"])], env=env)
    key = uuid.uuid4().hex   # per start, never on disk; only serve and the app get it
    env.update({"COLI_API_KEY": key, "PYTHONUTF8": "1", "PYTHONUNBUFFERED": "1"})
    log = LOGS / f"colibri-{datetime.now():%Y%m%d-%H%M%S}.log"
    p = spawn([str(VENV_PY), coli, "serve", "--model", str(model_dir), "--ram", str(s["ram_gb"]), "--ctx", str(s["ctx"]),
               "--host", "127.0.0.1", "--port", str(a.colibri_port), "--model-id", model_tag], log, env, Path(c["target"]), prefix)
    pf.write_pid(RUN / "colibri.pid", p.pid, "colibri")
    say("COLIBRI", f"serve pid {p.pid}, backend {s['backend']}, --ram {s['ram_gb']}, --ctx {s['ctx']}; loading (limit 30 min), log {log}")
    for i in range(360):
        if p.poll() is not None:
            raise Fail("COLIBRI", f"serve exited early; see {log}.err")
        try:
            get_json(f"http://127.0.0.1:{a.colibri_port}/health", 3)
            say("COLIBRI", f"ready after about {i * 5} s on http://127.0.0.1:{a.colibri_port} (loopback only)", "OK")
            return model_tag, key, settings_file
        except Exception:  # noqa: BLE001 - still loading
            time.sleep(5)
    raise Fail("COLIBRI", f"no answer from /health after 30 min; see {log}.err")


# ---- CHECK ----------------------------------------------------------------------------------------------------
def python_check(a, model_tag: str, llm: str) -> list[dict] | None:
    if not VENV_PY.exists():
        return None
    cmd = [str(VENV_PY), "-m", "sw_analyst", "--check", "--json", "--port", str(a.port),
           "--ollama-url", f"http://127.0.0.1:{a.ollama_port}", "--data-dir", str(DATA)]
    if model_tag:
        cmd += ["--model", model_tag]
    if llm == "colibri":
        cmd += ["--llm", "colibri", "--colibri-url", f"http://127.0.0.1:{a.colibri_port}"]
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "SW_ALLOW_ONLINE": "1" if (a.allow_online or a.setup) else "0"}
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)
    try:
        return json.loads(r.stdout)["results"]
    except (ValueError, KeyError):
        return [pf.result("preflight", pf.FEHLER, "python check produced no result", "run: python -m sw_analyst --check")]


def show(results: list[dict]) -> None:
    for r in results:
        fix = f"  -> {r['fix']}" if r.get("fix") and r["status"] != pf.OK else ""
        say("CHECK", f"{r['name']:<18} {r['detail']}{fix}", r["status"])


# ---- start ----------------------------------------------------------------------------------------------------
def cmd_start(a) -> int:
    _setup_dirs()
    m = manifest()
    troot = tools_root(m)
    ol, cl, cm = pf.component(m, "ollama"), pf.component(m, "colibri"), pf.component(m, "colibri", "models")
    llm = a.llm or "ollama"
    flag = DATA / "colibri.enabled"
    if a.disable_colibri:
        flag.unlink(missing_ok=True)
        say("COLIBRI", "switched off; Ollama from now on", "OK")
    if not a.llm and not a.disable_colibri and (a.enable_colibri or flag.exists()) and not a.setup:
        why = colibri_verdict()
        if not why:
            if a.enable_colibri:
                flag.write_text(datetime.now().isoformat(timespec="seconds"), encoding="ascii")
                say("COLIBRI", "hardware is sufficient: switched on, from now on without this option (--disable-colibri reverts it)", "OK")
            llm = "colibri"
        else:
            for w in why:
                say("COLIBRI", w, "WARN")
            say("COLIBRI", "this machine cannot carry colibri right now: staying on Ollama and the model that fits", "WARN")

    if not a.no_cleanup:
        cleanup("pre", port=a.port, ollama_port=a.ollama_port)

    say("CHECK", f"Python {sys.version.split()[0]}, {os.uname().sysname} {os.uname().release}, repo {ROOT}, SW_ROOT {pf.sw_root()}")
    if a.setup:
        say("SETUP", "setup mode: downloads only from the pins, then stop (switch to offline afterwards: sudo sw-mode offline)", "WARN")
    if not shutil.which("nvidia-smi"):
        say("CHECK", "nvidia-smi not found; install the NVIDIA driver (infra/linux/provision.sh), else the model runs on the CPU", "WARN")
    if llm == "colibri":
        model_tag = f"{cm['id']}@{cm['revision'][:7]}-colibri-{cl['version']}"
    else:
        model_tag = resolve_model(m, a.model)

    # ---- INSTALL (setup only downloads; a normal start may install the venv from vendor/) ----
    results = python_check(a, model_tag, llm)
    if results is not None and not a.setup:
        show(results)
    need_lock = results is None or any(r["name"] == "lock:missing" and r["status"] == pf.FEHLER for r in results)
    drift = bool(results) and any(r["name"] == "lock:drift" and r["status"] != pf.OK for r in results)
    if need_lock or (drift and a.setup):
        install_lock(online=a.setup)
    elif drift:
        say("UPDATE", "installed packages differ from requirements.lock; apply with --setup", "WARN")
    else:
        say("INSTALL", "python packages complete", "OK")
    for name, c in (("colibri", cl) if llm == "colibri" else ("ollama", ol),):
        if (Path(c["target"]) / c["exe"]).is_file():
            say("INSTALL", f"{name} {c.get('version')} present", "OK")
        elif a.setup:
            install_component(name, c, troot)
        else:
            raise Fail("INSTALL", f"{name} {c.get('version')} missing; install it once online with scripts/start.sh --setup")
    pending = [k for k, v in m["components"].items() if v.get("url") == "pending" or v.get("sha256") == "pending"]
    if pending:
        say("UPDATE", "not pinned yet (needs review before use): " + ", ".join(pending))

    prefix = ensure_slice()
    if a.setup:
        if llm == "ollama":
            start_ollama(ol, a.ollama_port, troot, prefix)
            ensure_model(ol, a.ollama_port, model_tag, m, allow_pull=True)
        build_images(m)
        stop(argparse.Namespace(port=a.port, ollama_port=a.ollama_port, colibri_port=a.colibri_port, force=False,
                                no_cleanup=True, docker_deep=False))
        say("SETUP", "setup finished. Next: sudo sw-mode offline, then scripts/start.sh", "OK")
        return 0

    results = python_check(a, model_tag, llm) or []
    fatal = [r for r in results if r["status"] == pf.FEHLER]
    say("CHECK", f"re-check: {len(results)} checks, {len(fatal)} errors, {sum(r['status'] == pf.WARN for r in results)} warnings")
    if fatal:
        show(fatal)
        raise Fail("CHECK", "errors remain; nothing was started")
    if a.allow_online:
        say("CHECK", "--allow-online: the host is online during analysis; only harmless samples (ADR-0013)", "WARN")

    try:
        docker_ok = (not a.no_docker and shutil.which("docker") and
                     subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0)
        say("DOCKER", "daemon running" if docker_ok else "daemon not used or not reachable; container tools stay unavailable",
            "OK" if docker_ok else "WARN")
        key, settings_file = "", None
        if llm == "ollama":
            start_ollama(ol, a.ollama_port, troot, prefix)
            ensure_model(ol, a.ollama_port, model_tag, m, allow_pull=False)
            warm_up(a.ollama_port, model_tag)
        else:
            model_tag, key, settings_file = start_colibri(a, cl, cm, model_tag, prefix)
            if a.colibri_gate or a.colibri_prepare:
                job = ([str(ROOT / "infra" / "colibri-warmup.py"), "--url", f"http://127.0.0.1:{a.colibri_port}", "--model", model_tag]
                       if a.colibri_prepare else
                       [str(ROOT / "tests" / "bench" / "colibri_gate.py"), "--url", f"http://127.0.0.1:{a.colibri_port}",
                        "--model", model_tag, "--settings", str(settings_file)])
                rc = subprocess.run([str(VENV_PY)] + job, env={**os.environ, "PYTHONPATH": str(ROOT / "src"), "SW_COLIBRI_KEY": key}).returncode
                say("GATE", f"finished, exit {rc}", "OK" if rc == 0 else "WARN")
                return rc
        return run_app(a, model_tag, llm, key, prefix)
    finally:   # also on Ctrl+C: nothing (and no GPU memory) is left behind
        say("STOP", "shutting down (waits for a running job; Ctrl+C again aborts the wait)")
        stop(argparse.Namespace(port=a.port, ollama_port=a.ollama_port, colibri_port=a.colibri_port, force=False,
                                no_cleanup=a.no_cleanup, docker_deep=False))


def run_app(a, model_tag: str, llm: str, key: str, prefix: list[str]) -> int:
    base = f"http://127.0.0.1:{a.port}"
    prev = pf.read_pid(RUN / "app.pid")
    if prev and is_own_app(prev["pid"]):
        raise Fail("APP", f"already running (pid {prev['pid']}); stop it first with scripts/stop.sh")
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONUNBUFFERED": "1", "PYTHONUTF8": "1"}
    cmd = [str(VENV_PY), "-m", "sw_analyst", "--model", model_tag, "--ollama-url", f"http://127.0.0.1:{a.ollama_port}",
           "--data-dir", str(DATA), "--port", str(a.port)]
    if llm == "colibri":
        cmd += ["--llm", "colibri", "--colibri-url", f"http://127.0.0.1:{a.colibri_port}", "--num-ctx", "16384"]
        env["SW_COLIBRI_KEY"] = key
    out = LOGS / f"app-{datetime.now():%Y-%m-%d}.out"
    p = spawn(cmd, out, env, ROOT, prefix)
    pf.write_pid(RUN / "app.pid", p.pid, "python")
    say("APP", f"started pid {p.pid}, waiting for {base}/api/system")
    for _ in range(90):
        if p.poll() is not None:
            raise Fail("APP", f"process exited early (exit {p.returncode}); see {out}.err")
        try:
            get_json(f"{base}/api/system", 2)
            break
        except Exception:  # noqa: BLE001 - not up yet
            time.sleep(1)
    else:
        raise Fail("APP", f"no answer from {base}/api/system after 90 s")
    say("APP", f"ready: {base}/   (Ctrl+C stops everything cleanly)", "OK")
    if not a.no_browser and shutil.which("xdg-open") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        subprocess.Popen(["xdg-open", f"{base}/"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    last_w = last_j = ""
    last_job = None
    while True:
        time.sleep(2)
        if p.poll() is not None:
            raise Fail("APP", f"application stopped unexpectedly (exit {p.returncode})")
        try:
            s = get_json(f"{base}/api/system")
        except Exception:  # noqa: BLE001 - a busy app answers late; the next round asks again
            continue
        w = f"worker={s['worker']['state']} queue={s.get('queue_length')} llm={'ok' if s['llm'].get('reachable') else 'down'}"
        if w != last_w:
            say("WORKER", w, "INFO" if s["llm"].get("reachable") else "WARN")
            last_w = w
        jid = s["worker"].get("job_id")
        if jid:
            j = f"job={jid}"
            try:
                act = get_json(f"{base}/api/jobs/{jid}/activity")
                j += f" phase={act.get('phase')}"
                if act.get("task"):
                    j += f" task='{act['task'].get('title')}'"
            except Exception:  # noqa: BLE001
                pass
            if j != last_j:
                say("JOB", j)
                last_j = j
        elif last_job:
            try:
                fin = get_json(f"{base}/api/jobs/{last_job}")["summary"]["status"]
            except Exception:  # noqa: BLE001
                fin = "unknown"
            say("JOB", f"job={last_job} finished, status={fin}", "OK" if fin in ("done", "partial") else "WARN")
            last_j = ""
        last_job = jid


# ---- stop -----------------------------------------------------------------------------------------------------
def _stop_own(name: str, port: int, troot: Path) -> None:
    is_own = own_check(name, troot)
    d = pf.read_pid(RUN / f"{name}.pid")
    if d:
        if is_own(d["pid"]):
            stop_tree(d["pid"])
            say("STOP", f"{name} pid {d['pid']} stopped", "OK")
        elif pf.pid_alive(d["pid"]):
            say("STOP", f"pid {d['pid']} from {name}.pid is not our {name} process (pid reused?); left alone", "WARN")
    time.sleep(0.3)
    o = linuxhost.listen_pid(port)
    if o:
        if is_own(o):
            stop_tree(o)
            say("STOP", f"{name} still listened on port {port} (pid {o}); stopped", "OK")
        else:
            say("STOP", f"port {port} is held by a foreign process (pid {o}); not touching it", "WARN")
    (RUN / f"{name}.pid").unlink(missing_ok=True)


def stop(a) -> int:
    _setup_dirs()
    m = manifest()
    troot = tools_root(m)
    base = f"http://127.0.0.1:{a.port}"
    say("STOP", "stop requested" + (" (--force)" if a.force else ""))
    try:
        jid = get_json(f"{base}/api/system")["worker"].get("job_id")
    except Exception:  # noqa: BLE001 - app already gone
        jid = None
    if jid:
        if a.force:
            say("JOB", f"--force: cancelling job {jid}", "WARN")
            try:
                post_json(f"{base}/api/jobs/{jid}/cancel", None, 5, origin=base)
            except Exception as e:  # noqa: BLE001
                say("JOB", f"cancel request failed: {e}", "WARN")
            for _ in range(20):
                time.sleep(1)
                try:
                    if not get_json(f"{base}/api/system")["worker"].get("job_id"):
                        break
                except Exception:  # noqa: BLE001
                    break
        else:
            say("JOB", f"job {jid} is running; waiting for it to finish (scripts/stop.sh --force cancels it)", "WARN")
            n = 0
            while True:
                time.sleep(5)
                try:
                    if not get_json(f"{base}/api/system")["worker"].get("job_id"):
                        break
                except Exception:  # noqa: BLE001
                    break
                n += 1
                if n % 6 == 0:
                    say("JOB", f"still waiting for job {jid}")
            say("JOB", f"job {jid} finished", "OK")
    _stop_own("app", a.port, troot)
    if a.force and VENV_PY.exists() and (DATA / "sw_analyst.db").exists():
        code = ("import sys; from sw_analyst.common.store import Store; from sw_analyst.common.util import utcnow; "
                "s=Store(sys.argv[1]+'/sw_analyst.db', sys.argv[1]+'/logs'); "
                "print(*[s.update_job(j['id'], status='cancelled', cancel_requested=1, finished_at=utcnow())['id'] for j in [s.running_job()] if j])")
        r = subprocess.run([str(VENV_PY), "-c", code, str(DATA)], capture_output=True, text=True,
                           env={**os.environ, "PYTHONPATH": str(ROOT / "src")}, timeout=60)
        if r.stdout.strip():
            say("JOB", f"job {r.stdout.strip()} marked cancelled", "WARN")
    _stop_own("colibri", a.colibri_port, troot)
    o = linuxhost.listen_pid(a.ollama_port)
    if o and is_own_ollama(o, troot):
        try:
            for mdl in get_json(f"http://127.0.0.1:{a.ollama_port}/api/ps").get("models", []):
                post_json(f"http://127.0.0.1:{a.ollama_port}/api/generate", {"model": mdl["name"], "keep_alive": 0}, 20)
                say("STOP", f"model {mdl['name']} unloaded from the GPU", "OK")
        except Exception as e:  # noqa: BLE001
            say("STOP", f"model unload failed ({e}); the process is stopped anyway", "WARN")
    _stop_own("ollama", a.ollama_port, troot)
    g = pf.gpu_free_mib()
    if g:
        used = g[1] - g[0]
        say("STOP", f"GPU memory in use: {used} of {g[1]} MiB" + (" (something else still uses the GPU; not touching it)" if used >= 1500 else ""),
            "WARN" if used >= 1500 else "OK")
    if any(x["target"] == linuxhost.SHARE_MOUNT for x in linuxhost.mounts()):
        say("STOP", f"{linuxhost.SHARE_MOUNT} is still mounted; unmount it before shutdown: sudo sw-share umount", "WARN")
    if not a.no_cleanup:
        cleanup("post", port=a.port, ollama_port=a.ollama_port, docker_deep=a.docker_deep)
    say("STOP", "done, PID files removed", "OK")
    return 0


# ---- cleanup ---------------------------------------------------------------------------------------------------
def deletable(path: Path, troot: Path) -> bool:
    if under(path, DATA) or under(path, troot):
        return True
    return under(path, ROOT) and path.name in ("__pycache__", ".pytest_cache")


def cleanup(phase: str = "pre", dry_run: bool = False, keep_days: int = 14, port: int = 8765, ollama_port: int = 11435,
            docker_deep: bool = False) -> int:
    _setup_dirs()
    troot = tools_root(manifest())
    freed, items = 0, 0

    def remove(p: Path, why: str) -> None:
        nonlocal freed, items
        if not deletable(p, troot):
            say("CLEAN", f"refused to delete outside own folders: {p}", "WARN")
            return
        if not p.exists() and not p.is_symlink():
            return
        size = sum(f.stat().st_size for f in p.rglob("*") if f.is_file()) if p.is_dir() else p.lstat().st_size
        if dry_run:
            say("CLEAN", f"would remove {p} ({why})")
        elif p.is_dir() and not p.is_symlink():
            shutil.rmtree(p)
        else:
            p.unlink()
        freed += size
        items += 1

    def aged(d: Path, pattern: str, days: int, why: str) -> None:
        limit = time.time() - days * 86400
        for f in (d.glob(pattern) if d.is_dir() else []):
            if f.is_file() and f.stat().st_mtime < limit:
                remove(f, why)

    def step(name: str, fn) -> None:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - cleanup never blocks start or stop
            say("CLEAN", f"{name} failed: {e}", "WARN")

    say("CLEAN", f"{phase} cleanup" + (" (dry run, nothing is removed)" if dry_run else ""))

    def pids() -> None:
        for n in NAMES:
            f = RUN / f"{n}.pid"
            d = pf.read_pid(f)
            if d is None:
                if f.exists():
                    remove(f, "unreadable pid file")
            elif phase == "pre" and not own_check(n, troot)(d["pid"]):
                remove(f, f"stale {n}.pid")

    def procs() -> None:
        nonlocal items
        known = {d["pid"] for n in NAMES if (d := pf.read_pid(RUN / f"{n}.pid"))}
        for pid, kind in own_processes(troot):
            if phase == "pre" and pid in known:
                continue
            if phase == "pre" and kind == "ollama":
                continue   # a running own Ollama is reused by the start, not killed
            if dry_run:
                say("CLEAN", f"would stop {kind} pid {pid}")
            else:
                stop_tree(pid)
                say("CLEAN", f"stopped {kind} pid {pid} ({'orphan' if phase == 'pre' else 'left over after stop'})", "OK")
            items += 1

    def temp() -> None:
        for f in (RUN.iterdir() if RUN.is_dir() else []):
            if f.is_file() and f.suffix != ".pid":
                remove(f, "run-time scratch")
        for f in ((DATA / "tmp").iterdir() if (DATA / "tmp").is_dir() else []):
            remove(f, "data/tmp")
        for d in (troot.glob("*.partial") if troot.is_dir() else []):
            remove(d, "unfinished install")

    def logs() -> None:
        for pat in ("*.log", "*.out", "*.err"):
            aged(LOGS, pat, keep_days, f"log older than {keep_days} days")

    def caches() -> None:
        for sub in ("src", "tests"):
            for c in (ROOT / sub).rglob("__pycache__"):
                remove(c, "python cache")
        remove(ROOT / ".pytest_cache", "pytest cache")
        aged(troot / "dl", "*.tar.*", 1, "install archive (hash is checked again on the next download)")

    def blobs() -> None:
        if not any(k == "ollama" for _, k in own_processes(troot)):
            aged(pf.sw_root() / "models" / "ollama" / "blobs", "*-partial*", 3, "interrupted model download older than 3 days")

    def docker() -> None:
        nonlocal items
        if not shutil.which("docker"):
            return
        if subprocess.run(["docker", "info"], capture_output=True, timeout=15).returncode != 0:
            say("CLEAN", "docker daemon not reachable; skipped")
            return
        flt = ["--filter", f"label={LABEL}"]
        extra = ["--filter", "status=exited", "--filter", "status=created", "--filter", "status=dead"] if phase == "pre" else []
        ids = subprocess.run(["docker", "ps", "-aq", *flt, *extra], capture_output=True, text=True, timeout=30).stdout.split()
        if ids:
            if dry_run:
                say("CLEAN", f"would remove {len(ids)} container(s) with label {LABEL}")
            else:
                if phase == "post":
                    subprocess.run(["docker", "stop", "-t", "10", *ids], capture_output=True, timeout=90)
                subprocess.run(["docker", "rm", "-f", "-v", *ids], capture_output=True, timeout=60)
                say("CLEAN", f"removed {len(ids)} container(s) with label {LABEL}", "OK")
            items += len(ids)
        if not dry_run:
            for c in (["network", "prune", "-f", *flt], ["volume", "prune", "-f", *flt], ["image", "prune", "-f", *flt]):
                subprocess.run(["docker", *c], capture_output=True, timeout=60)
            if docker_deep:
                subprocess.run(["docker", "builder", "prune", "-f", "--filter", "until=168h"], capture_output=True, timeout=120)
                say("CLEAN", "docker build cache older than 7 days pruned (shared with other projects)", "WARN")

    step("pid files", pids)
    step("processes", procs)
    step("temp files", temp)
    step("old logs", logs)
    if phase == "post":
        step("caches", caches)
        step("partial model blobs", blobs)
    step("docker", docker)
    if phase == "post" and not dry_run:
        for n in NAMES:
            (RUN / f"{n}.pid").unlink(missing_ok=True)
    say("CLEAN", f"{phase}: {items} item(s), {freed / 2**20:.1f} MB {'would be freed' if dry_run else 'freed'}", "OK")
    return 0


# ---- CLI --------------------------------------------------------------------------------------------------------
def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="sw_analyst.launcher", description="Linux launcher (ADR-0013)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start")
    s.add_argument("--setup", action="store_true", help="online once: install from the pins, pull the model, build images, then stop")
    s.add_argument("--model", default="")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--ollama-port", type=int, default=11435)
    s.add_argument("--llm", choices=("ollama", "colibri"), default=None,
                   help='this run only (default="ollama"); colibri here skips the hardware check')
    s.add_argument("--enable-colibri", action="store_true")
    s.add_argument("--disable-colibri", action="store_true")
    s.add_argument("--colibri-port", type=int, default=11436)
    s.add_argument("--ram-gb", type=int, default=0, choices=range(0, 129), metavar="0..128")
    s.add_argument("--colibri-mirror", default="")
    s.add_argument("--colibri-prepare", action="store_true")
    s.add_argument("--colibri-gate", action="store_true")
    s.add_argument("--skip-model-hash", action="store_true")
    s.add_argument("--allow-online", action="store_true", help="start although the host is online (harmless samples only)")
    s.add_argument("--no-browser", action="store_true")
    s.add_argument("--no-cleanup", action="store_true")
    s.add_argument("--no-docker", action="store_true")
    t = sub.add_parser("stop")
    t.add_argument("--port", type=int, default=8765)
    t.add_argument("--ollama-port", type=int, default=11435)
    t.add_argument("--colibri-port", type=int, default=11436)
    t.add_argument("--force", action="store_true")
    t.add_argument("--no-cleanup", action="store_true")
    t.add_argument("--docker-deep", action="store_true")
    c = sub.add_parser("cleanup")
    c.add_argument("--phase", choices=("pre", "post"), default="pre")
    c.add_argument("--dry-run", action="store_true")
    c.add_argument("--keep-days", type=int, default=14)
    c.add_argument("--docker-deep", action="store_true")
    return ap


def main(argv: list[str] | None = None) -> int:
    a = parser().parse_args(argv)
    if not linuxhost.is_linux():
        print("sw_analyst.launcher is the Linux launcher; on Windows use scripts\\start.ps1", file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        if a.cmd == "start":
            return cmd_start(a)
        if a.cmd == "stop":
            return stop(a)
        return cleanup(a.phase, a.dry_run, a.keep_days, docker_deep=a.docker_deep)
    except Fail as e:
        say(e.stage, str(e), "FEHLER")
        return 1
    except KeyboardInterrupt:
        say("STOP", "interrupted; shutting down")
        return 130
    except Exception as e:  # noqa: BLE001 - any other error ends the start with its message, never a silent exit
        say("CHECK", f"aborted: {type(e).__name__}: {e}", "FEHLER")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
