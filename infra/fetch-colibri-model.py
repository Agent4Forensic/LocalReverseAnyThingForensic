"""Fetch the colibri model pinned in infra/manifest.json onto its volume, file by file (ADR-0012, developer machine, needs network).

    python infra/fetch-colibri-model.py

Resumes, then checks size and SHA-256 of every file; a file gets its final name only after it passes. A second run re-checks
what is there and fetches only what is missing, so it also serves as a full verification. Only weights and metadata: the
Python code in the model repository is left out on purpose, nothing here runs it.
"""
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

KEEP = {"LICENSE", "README.md", "config.json", "generation_config.json", "model.safetensors.index.json", "tokenizer.json"}


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
    if p.stat().st_size != entry["size"]:
        return False
    lfs = (entry.get("lfs") or {}).get("sha256")
    if lfs:
        return digest(p, hashlib.sha256()) == lfs
    return digest(p, hashlib.sha1(f"blob {entry['size']}\0".encode())) == entry["blobId"]  # small files: git blob id


def main() -> int:
    m = json.loads((Path(__file__).resolve().parent / "manifest.json").read_text(encoding="utf-8"))["models"]["colibri"]
    repo, rev = m["repo"], m["revision"]
    target = Path(f"{volume_by_label(m['volume_label'])}:/") / m["dir"]
    target.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(f"https://huggingface.co/api/models/{repo}/revision/{rev}?blobs=true", headers={"User-Agent": "curl/8"})
    meta = json.load(urllib.request.urlopen(req, timeout=60))
    files = [s for s in meta["siblings"] if s["rfilename"].endswith(".safetensors") or s["rfilename"] in KEEP]
    total = sum(s["size"] for s in files)
    print(f"START {time.strftime('%H:%M:%S')} {len(files)} files, {total / 1e9:.1f} GB -> {target}", flush=True)
    done, t0, record = 0, time.monotonic(), []
    for s in sorted(files, key=lambda x: x["size"]):
        name, size = s["rfilename"], s["size"]
        final, part = target / name, target / (name + ".part")
        if not (final.exists() and passes(final, s)):
            url = f"https://huggingface.co/{repo}/resolve/{rev}/{name}"
            for attempt in range(1, 6):
                rc = subprocess.run(["curl.exe", "-sS", "-L", "--fail", "-C", "-", "--retry", "20", "--retry-delay", "15",
                                     "--retry-all-errors", "--speed-limit", "1024", "--speed-time", "180", "-o", str(part), url]).returncode
                if rc == 0 and passes(part, s):
                    os.replace(part, final)
                    break
                print(f"RETRY {name}: curl {rc}, attempt {attempt}", flush=True)
                if rc == 0:
                    part.unlink(missing_ok=True)   # wrong size or hash: a resume would keep the bad bytes
            else:
                print(f"FAIL {name}", flush=True)
                return 1
            print(f"{time.strftime('%H:%M:%S')} {(done + size) / 1e9:6.1f}/{total / 1e9:.1f} GB  {done / 1e6 / max(time.monotonic() - t0, 1):5.0f} MB/s  {name}", flush=True)
        done += size
        record.append({"file": name, "size": size, "sha256": (s.get("lfs") or {}).get("sha256") or "", "git_blob": s["blobId"]})
    (target / "provenance.json").write_text(json.dumps({"repo": repo, "revision": rev, "license": m["license"], "files": record,
                                                        "verified_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, indent=1) + "\n", encoding="utf-8")
    print(f"OK {target} {len(files)} files verified", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
