"""Host protection between tasks: pause the job while RAM, disk or GPU temperature are in the danger zone.

The model cannot reach this module and cannot change the limits. It only reads fixed system values, so a sample
or a prompt injection cannot use it. Thresholds protect the running system; they do not replace the hard
memory limits of WSL and Docker (docs/adr/0000-grundentscheidungen.md).
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from sw_analyst.preflight import _loopback_get, _ram_gb, _run


@dataclass(frozen=True)
class HostLimits:
    min_free_ram_gb: float = 3.0
    min_free_disk_gb: float = 10.0
    max_gpu_temp_c: int = 85
    pause_s: float = 30.0       # wait between two checks while a limit is exceeded
    max_pause_s: float = 900.0  # afterwards the job stops as partial


def _gpu_temp_c() -> int | None:
    r = _run(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"])
    if not r or r.returncode != 0:
        return None
    try:
        return max(int(x) for x in r.stdout.split())
    except ValueError:
        return None


class HostGuard:
    def __init__(self, data_dir: str | Path, limits: HostLimits = HostLimits(),
                 ollama_url: str = "http://127.0.0.1:11435"):
        self.data_dir, self.limits, self.ollama_url = Path(data_dir), limits, ollama_url

    def problems(self) -> list[str]:
        """Limits exceeded right now. A value that cannot be read is no reason to stop (the preflight warns)."""
        out: list[str] = []
        ram = _ram_gb()
        if ram and ram[1] < self.limits.min_free_ram_gb:
            out.append(f"free RAM {ram[1]:.1f} GiB below {self.limits.min_free_ram_gb} GiB")
        free_disk = shutil.disk_usage(self.data_dir).free / 2**30
        if free_disk < self.limits.min_free_disk_gb:
            out.append(f"free disk {free_disk:.1f} GiB below {self.limits.min_free_disk_gb} GiB")
        temp = _gpu_temp_c()
        if temp is not None and temp >= self.limits.max_gpu_temp_c:
            out.append(f"GPU temperature {temp} C at or above {self.limits.max_gpu_temp_c} C")
        return out

    def offload_warning(self) -> str:
        """Partial CPU offload is the known crash source on this GPU generation (ADR-0001)."""
        try:
            for m in _loopback_get(self.ollama_url + "/api/ps").get("models", []):
                if m.get("size_vram", 0) < m.get("size", 0):
                    return f"model {m.get('name')} is only partly in VRAM ({m['size_vram']} of {m['size']} bytes)"
        except Exception:  # noqa: BLE001 - informational check only, the LLM client reports real outages
            pass
        return ""
