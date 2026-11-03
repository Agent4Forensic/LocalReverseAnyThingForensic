"""Read-only facts about a Linux host (ADR-0013): memory, listeners, processes, mounts, network, cgroup limits, volumes.

Stdlib only, like preflight.py: it runs before the venv exists. Every function only reads /proc, /sys or /dev/disk;
nothing here changes the system. Parsers take text so the tests need no real host. The proc/sys roots can be moved
for tests (`proc`, `sys_root` arguments).
"""
from __future__ import annotations

import os
import re
from pathlib import Path

HOST_RESERVE_GB = 3   # the Linux host keeps this much; platform, containers and models share the rest (ADR-0013)
SHARE_MOUNT = "/mnt/host-share"   # bind mount of the exchange folder on the internal disk (infra/linux/sw-share)
SHARE_REQUIRED_OPTS = ("noexec", "nosuid", "nodev")


# ---- memory -------------------------------------------------------------------------------------------------
def parse_meminfo(text: str) -> tuple[float, float] | None:
    """(total, available) in GiB from /proc/meminfo; None if a field is missing."""
    vals = {m.group(1): int(m.group(2)) for m in re.finditer(r"^(\w+):\s+(\d+)\s*kB", text, re.M)}
    if "MemTotal" not in vals or "MemAvailable" not in vals:
        return None
    return vals["MemTotal"] / 2**20, vals["MemAvailable"] / 2**20


def ram_gb(proc: str = "/proc") -> tuple[float, float] | None:
    try:
        return parse_meminfo(Path(proc, "meminfo").read_text(encoding="ascii", errors="replace"))
    except OSError:
        return None


def cgroup_memory_limit_gb(proc: str = "/proc", cg_root: str = "/sys/fs/cgroup") -> float | None:
    """Smallest memory.max on the cgroup v2 path of this process and its parents (a slice limit counts for all below)."""
    try:
        line = next(ln for ln in Path(proc, "self", "cgroup").read_text().splitlines() if ln.startswith("0::"))
    except (OSError, StopIteration):
        return None
    rel = line[3:].strip().strip("/")
    best = None
    parts = rel.split("/") if rel else []
    for i in range(len(parts), -1, -1):
        f = Path(cg_root, *parts[:i], "memory.max")
        try:
            v = f.read_text().strip()
        except OSError:
            continue
        if v.isdigit():
            gb = int(v) / 2**30
            best = gb if best is None else min(best, gb)
    return best


# ---- listeners and processes --------------------------------------------------------------------------------
def parse_proc_net_tcp(text: str, port: int) -> set[int]:
    """Socket inodes listening (state 0A) on <port> in /proc/net/tcp or tcp6 text."""
    out = set()
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        try:
            lport = int(f[1].rsplit(":", 1)[1], 16)
        except (IndexError, ValueError):
            continue
        if lport == port and f[3] == "0A" and f[9].isdigit():
            out.add(int(f[9]))
    return out


def listen_pid(port: int, proc: str = "/proc") -> int | None:
    """PID that holds the listening socket on <port>. Only processes this user may inspect are found (no root needed
    for own processes); a foreign listener shows up as None, and check_ports then reports the port as foreign."""
    inodes: set[int] = set()
    for name in ("tcp", "tcp6"):
        try:
            inodes |= parse_proc_net_tcp(Path(proc, "net", name).read_text(), port)
        except OSError:
            pass
    if not inodes:
        return None
    wanted = {f"socket:[{i}]" for i in inodes}
    for d in Path(proc).iterdir():
        if not d.name.isdigit():
            continue
        try:
            for fd in (d / "fd").iterdir():
                if os.readlink(fd) in wanted:
                    return int(d.name)
        except OSError:
            continue
    return None


def exe_path(pid: int, proc: str = "/proc") -> str | None:
    try:
        return os.readlink(Path(proc, str(pid), "exe"))
    except OSError:
        return None


def cmdline(pid: int, proc: str = "/proc") -> list[str]:
    try:
        return [a for a in Path(proc, str(pid), "cmdline").read_bytes().decode("utf-8", "replace").split("\0") if a]
    except OSError:
        return []


# ---- mounts, volumes ----------------------------------------------------------------------------------------
def _unescape(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def parse_mounts(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 4:
            out.append({"source": _unescape(f[0]), "target": _unescape(f[1]), "fstype": f[2], "options": f[3].split(",")})
    return out


def mounts(proc: str = "/proc") -> list[dict]:
    try:
        return parse_mounts(Path(proc, "self", "mounts").read_text())
    except OSError:
        return []


def mount_of(path: str | Path, table: list[dict]) -> dict | None:
    """The mount entry that contains <path> (longest matching target)."""
    p = os.path.abspath(path)
    hits = [m for m in table if p == m["target"] or p.startswith(m["target"].rstrip("/") + "/")]
    return max(hits, key=lambda m: len(m["target"])) if hits else None


def volume_root(label: str, table: list[dict] | None = None, by_label: str = "/dev/disk/by-label") -> Path | None:
    """Mount point of the one volume with this file system label (udev escapes spaces as \\x20)."""
    link = Path(by_label, label.replace(" ", "\\x20"))
    try:
        dev = os.path.realpath(link)
    except OSError:
        return None
    if not os.path.exists(link):
        return None
    hits = {m["target"] for m in (table if table is not None else mounts()) if os.path.realpath(m["source"]) == dev}
    return Path(next(iter(hits))) if len(hits) == 1 else None


# ---- network ------------------------------------------------------------------------------------------------
def active_interfaces(sys_root: str = "/sys") -> list[str]:
    """Physical interfaces (with a device behind them) whose link is up. Virtual bridges such as docker0 do not count:
    they reach nothing outside on their own. Offline mode (infra/linux/sw-mode) leaves none."""
    out = []
    base = Path(sys_root, "class", "net")
    try:
        names = sorted(p.name for p in base.iterdir())
    except OSError:
        return out
    for n in names:
        if n == "lo" or not (base / n / "device").exists():
            continue
        try:
            state = (base / n / "operstate").read_text().strip()
        except OSError:
            continue
        if state in ("up", "unknown") and _has_carrier(base / n):
            out.append(n)
    return out


def parse_default_routes(route_v4: str, route_v6: str = "") -> list[str]:
    """Interfaces that carry a default route (/proc/net/route, /proc/net/ipv6_route)."""
    out = []
    for line in route_v4.splitlines()[1:]:
        f = line.split()
        if len(f) >= 8 and f[1] == "00000000" and f[7] == "00000000":
            out.append(f[0])
    for line in route_v6.splitlines():
        f = line.split()
        if len(f) >= 10 and f[0] == "0" * 32 and f[1] == "00" and f[9] != "lo":
            out.append(f[9])
    return sorted(set(out))


def default_routes(proc: str = "/proc") -> list[str]:
    def rd(name: str) -> str:
        try:
            return Path(proc, "net", name).read_text()
        except OSError:
            return ""
    return parse_default_routes(rd("route"), rd("ipv6_route"))


def _has_carrier(dev: Path) -> bool:
    try:
        return (dev / "carrier").read_text().strip() == "1"
    except OSError:   # reading carrier fails while the link is administratively down
        return False


def is_linux() -> bool:
    return os.name == "posix" and os.uname().sysname == "Linux"
