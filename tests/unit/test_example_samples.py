"""Committed example samples (ADR-0009) are exact copies of the builder output and listed in the manifest."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_committed_samples_match_builders_and_manifest():
    r = subprocess.run([sys.executable, "-I", str(ROOT / "example" / "build_samples.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_manifest_lists_every_challenge_and_only_sample_paths():
    files = json.loads((ROOT / "example" / "samples.manifest.json").read_text(encoding="utf-8"))["files"]
    ids = {p.parent.name for p in (ROOT / "example" / "challenges").glob("*/challenge.json")}
    assert {v["challenge"] for v in files.values()} == ids
    for rel, v in files.items():
        assert rel.startswith("example/challenges/") and "/sample/" in rel and ".." not in rel
        assert hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() == v["sha256"]


def test_examples_api_points_to_the_committed_file():
    from sw_analyst.webui.examples import Examples
    for e in Examples().list():
        assert e["paths"]["sample_file"].endswith("/sample/" + e["sample"]["name"]) and e["paths"]["sample_file_ok"] is True
