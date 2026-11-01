"""Runtime folders of the platform. Everything the server writes lands inside the project folder.

Why: the virus scanner on the development machine has an exception for the project folder only. Uploads that
Starlette spools to the system temp folder (%TEMP%), job folders created relative to a random working directory
or rules copied elsewhere can be quarantined or deleted there. So relative data paths resolve against the project
root (never against the current working directory), every runtime folder is created at start, and Python's temp
folder (tempfile, upload spooling) is moved to <data>/tmp.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]

# jobs: samples and derived files · logs: audit chains · run: PID files · tmp: temp/upload spool
# imports: imported analyses (read-only) · exports: last exports · eval: example runs (example/run_eval.py)
RUNTIME_DIRS = ("jobs", "logs", "run", "tmp", "imports", "exports", "eval")


def resolve_data_dir(value: str | Path | None) -> Path:
    """Relative paths count from the project root, so the start folder of the process does not matter."""
    p = Path(value) if value else Path("data")
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    return p.resolve()


def inside_project(path: Path) -> bool:
    try:
        path.resolve().relative_to(PROJECT_ROOT)
        return True
    except ValueError:
        return False


def prepare_runtime(data_dir: Path, *, redirect_temp: bool = True) -> dict:
    """Creates every runtime folder and points the temp folder of this process (and its children) at <data>/tmp.

    Returns {"data_dir", "inside_project", "created": [...], "temp_dir"}. Raises OSError if a folder cannot be
    created or written, because the server must not start with half its storage missing.
    """
    created = []
    for name in RUNTIME_DIRS:
        d = data_dir / name
        if not d.is_dir():
            d.mkdir(parents=True, exist_ok=True)
            created.append(name)
    tmp = data_dir / "tmp"
    probe = tmp / ".write-test"
    probe.write_bytes(b"ok")
    probe.unlink()
    if redirect_temp:
        tempfile.tempdir = str(tmp)
        for var in ("TMP", "TEMP", "TMPDIR"):
            os.environ[var] = str(tmp)
    return {"data_dir": str(data_dir), "inside_project": inside_project(data_dir), "created": created,
            "temp_dir": str(tmp)}
