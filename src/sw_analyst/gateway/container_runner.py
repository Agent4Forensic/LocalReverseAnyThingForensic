"""The only place the model-reachable code starts a process: hardened, offline tool containers (ADR-0006, package B).

What keeps this from being a generic command runner:
- the argv is built here from constants; `op` must be in OPS and no model text can reach it
- the image is addressed by its immutable id, which also goes into every result as the tool version
- the sample travels over stdin into a noexec tmpfs, so no host path is mounted into the container
- `tests/security/test_host_safety.py` pins this module as the only one allowed to import subprocess
"""
from __future__ import annotations

import subprocess
import threading
import uuid
from dataclasses import dataclass

TIMEOUT_S = 600
MAX_JSON_OUTPUT = 128 * 1024 * 1024    # parsed in memory; json.loads can need over 20 times the bytes
MAX_TAR_OUTPUT = 256 * 1024 * 1024     # jadx: read without parsing into objects, big apps need the room
LABEL = "sw-analyst"       # scripts/cleanup.ps1 removes leftovers carrying this label
USER = "10001:10001"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# image key -> (tag, version shown in evidence). Tags must match infra/manifest.json tool_images (tested).
IMAGES = {"ghidra": ("sw-analyst/ghidra:12.1.4", "ghidra-12.1.4"),
          "triage": ("sw-analyst/triage:1", "capa-10.0.0+floss-3.2.0+yara-x-1.22.1"),
          "jadx": ("sw-analyst/jadx:1.5.6", "jadx-1.5.6")}


@dataclass(frozen=True)
class Op:
    image: str
    memory: str
    cpus: str
    pids: int
    tmp_size: str
    tmp_exec: bool = False     # PyInstaller binaries unpack and load their libraries from /tmp
    max_output: int = MAX_JSON_OUTPUT


_TRIAGE = dict(image="triage", memory="3g", cpus="2", pids=128, tmp_size="1g", tmp_exec=True)
_JADX = dict(image="jadx", memory="4g", cpus="4", pids=256, tmp_size="2g", max_output=MAX_TAR_OUTPUT)
OPS = {"ghidra": Op("ghidra", "6g", "4", 512, "4g"),
       "capa": Op(**_TRIAGE), "floss": Op(**_TRIAGE), "yara": Op(**_TRIAGE),
       "jadx-apk": Op(**_JADX), "jadx-dex": Op(**_JADX), "jadx-jar": Op(**_JADX)}


class ContainerError(Exception):
    """The tool container failed; the message is safe to show to the model. `final`: the same input would fail the same way."""

    def __init__(self, message: str, final: bool = False):
        super().__init__(message)
        self.final = final


def build_argv(op: str, image_id: str, name: str) -> list[str]:
    spec = OPS[op]
    tmp_flags = "rw,nosuid,nodev," + ("exec" if spec.tmp_exec else "noexec")     # Docker defaults to noexec
    # --pull never: a missing image must fail, not reach for a registry. --log-driver none: stdout is the result, not a log.
    return ["docker", "run", "--rm", "-i", "--pull", "never", "--log-driver", "none", "--name", name, "--label", LABEL,
            "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", USER, "--memory", spec.memory, "--memory-swap", spec.memory, "--cpus", spec.cpus,
            "--pids-limit", str(spec.pids),
            "--tmpfs", "/job:rw,noexec,nosuid,nodev,size=160m,uid=10001,gid=10001,mode=0700",
            "--tmpfs", f"/tmp:{tmp_flags},size={spec.tmp_size},uid=10001,gid=10001,mode=0700",
            image_id, op]


def _docker(*args: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout,  # noqa: S603
                          creationflags=_NO_WINDOW, check=False)


class ContainerRunner:
    def __init__(self, image_ids: dict[str, str]):
        self.image_ids = image_ids

    @classmethod
    def detect(cls) -> "ContainerRunner":
        """Finds the built images. Docker missing or stopped means no container tools, which is a normal state."""
        found: dict[str, str] = {}
        for key, (tag, _version) in IMAGES.items():
            try:
                r = _docker("image", "inspect", "--format", "{{.Id}}", tag)
            except (OSError, subprocess.SubprocessError):
                break
            if r.returncode == 0 and r.stdout.strip().startswith("sha256:"):
                found[key] = r.stdout.strip()
        return cls(found)

    def has(self, op: str) -> bool:
        return OPS[op].image in self.image_ids

    def version(self, op: str) -> str:
        key = OPS[op].image
        return f"{IMAGES[key][1]}@{self.image_ids[key][:19]}"

    def run(self, op: str, data: bytes) -> bytes:
        if op not in OPS or not self.has(op):
            raise ContainerError(f"Tool image for '{op}' is not available")
        name = f"sw-analyst-{uuid.uuid4().hex}"
        limit = OPS[op].max_output
        proc = subprocess.Popen(build_argv(op, self.image_ids[OPS[op].image], name), stdin=subprocess.PIPE,  # noqa: S603
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=_NO_WINDOW)
        out: list[bytes] = []
        err = bytearray()
        too_big = threading.Event()

        def feed():
            try:
                proc.stdin.write(data)
            except OSError:
                pass       # the tool may exit without reading everything
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass

        def read_out():
            total = 0
            while chunk := proc.stdout.read(1 << 20):
                total += len(chunk)
                if total > limit:
                    too_big.set()
                    _kill(proc, name)
                    return
                out.append(chunk)

        def read_err():
            while chunk := proc.stderr.read(4096):
                err[:] = (err + chunk)[-4096:]

        threads = [threading.Thread(target=t, daemon=True) for t in (feed, read_out, read_err)]
        for t in threads:
            t.start()
        try:
            code = proc.wait(timeout=TIMEOUT_S)
        except subprocess.TimeoutExpired:
            _kill(proc, name)
            raise ContainerError(f"Tool '{op}' exceeded the {TIMEOUT_S} s limit and was stopped", final=True) from None
        for t in threads:
            t.join(timeout=10)
        if too_big.is_set():
            raise ContainerError(f"Tool '{op}' exceeded the {limit // (1024 * 1024)} MiB output limit and was stopped", final=True)
        if any(t.is_alive() for t in threads):
            raise ContainerError(f"Tool '{op}' did not finish delivering its output")
        if code in (124, 137):     # entry.sh timeout, or the kernel at the memory limit
            raise ContainerError(f"Tool '{op}' ran out of time or memory and was stopped", final=True)
        if code != 0:
            tail = err.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
            raise ContainerError(f"Tool '{op}' failed with exit code {code}: {tail[0][:300]}")
        return b"".join(out)


def _kill(proc: subprocess.Popen, name: str) -> None:
    try:
        _docker("rm", "-f", name, timeout=30)
    except (OSError, subprocess.SubprocessError):
        pass
    proc.kill()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass
