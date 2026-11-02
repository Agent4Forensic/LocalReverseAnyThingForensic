"""Fetch or verify the colibri model on its volume, against the hashes pinned in this repository (ADR-0012).

    python infra/fetch-colibri-model.py            # developer machine, needs network: fetch what is missing or wrong
    python infra/fetch-colibri-model.py --verify   # no network: size and hash of every file, exit 1 on any difference

The list of files, sizes and hashes is infra/colibri-model.files.json, not anything on the SSD: a removable drive proves nothing
about itself. A file gets its final name only after it passes. Only weights and metadata; the Python code in the model
repository is left out on purpose, nothing here runs it.
"""
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def volume_by_label(label: str) -> str:
    out = subprocess.run(["powershell", "-NoProfile", "-Command", f"@(Get-Volume | Where-Object FileSystemLabel -ceq '{label}').DriveLetter"],
                         capture_output=True, text=True, check=True).stdout.split()
    if len(out) != 1:
        sys.exit(f"FAIL: expected exactly one mounted volume {label}, found {out}")
    return out[0]


def digest(p: Path, h) -> str:
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def passes(p: Path, entry: dict) -> bool:
    if not p.is_file() or p.stat().st_size != entry["size"]:
        return False
    if entry["sha256"]:
        return digest(p, hashlib.sha256()) == entry["sha256"]
    return digest(p, hashlib.sha1(f"blob {entry['size']}\0".encode())) == entry["git_blob"]  # small files: git blob id


def verify(target: Path, pins: list[dict]) -> list[str]:
    """Names of the files that are missing or differ."""
    return [e["file"] for e in pins if not passes(target / e["file"], e)]


def fetch(target: Path, repo: str, rev: str, pins: list[dict]) -> int:
    total, done, t0 = sum(e["size"] for e in pins), 0, time.monotonic()
    print(f"START {time.strftime('%H:%M:%S')} {len(pins)} files, {total / 1e9:.1f} GB -> {target}", flush=True)
    target.mkdir(parents=True, exist_ok=True)
    for e in sorted(pins, key=lambda x: x["size"]):
        final, part = target / e["file"], target / (e["file"] + ".part")
        if not passes(final, e):
            url = f"https://huggingface.co/{repo}/resolve/{rev}/{e['file']}"
            for attempt in range(1, 6):
                rc = subprocess.run(["curl.exe", "-sS", "-L", "--fail", "-C", "-", "--retry", "20", "--retry-delay", "15",
                                     "--retry-all-errors", "--speed-limit", "1024", "--speed-time", "180", "-o", str(part), url]).returncode
                if rc == 0 and passes(part, e):
                    os.replace(part, final)
                    break
                print(f"RETRY {e['file']}: curl {rc}, attempt {attempt}", flush=True)
                if rc == 0:
                    part.unlink(missing_ok=True)   # wrong size or hash: a resume would keep the bad bytes
            else:
                print(f"FAIL {e['file']}", flush=True)
                return 1
            print(f"{time.strftime('%H:%M:%S')} {(done + e['size']) / 1e9:6.1f}/{total / 1e9:.1f} GB  {e['file']}", flush=True)
        done += e["size"]
    print(f"OK {target} {len(pins)} files verified in {time.monotonic() - t0:.0f} s", flush=True)
    return 0


def main() -> int:
    m = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))["models"]["colibri"]
    pins = json.loads((HERE / "colibri-model.files.json").read_text(encoding="utf-8"))["files"]
    target = Path(f"{volume_by_label(m['volume_label'])}:/") / m["dir"]
    if "--verify" not in sys.argv[1:]:
        return fetch(target, m["repo"], m["revision"], pins)
    t0 = time.monotonic()
    bad = verify(target, pins)
    if bad:
        print(f"FAIL {len(bad)} of {len(pins)} files missing or changed, first: {bad[0]}", flush=True)
        return 1
    print(f"OK {len(pins)} files match the pinned hashes in {time.monotonic() - t0:.0f} s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
