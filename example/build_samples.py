"""Writes the harmless example samples into the repository and keeps their manifest (ADR-0009).

    python example/build_samples.py           # (re)write example/challenges/<id>/sample/<name> and samples.manifest.json
    python example/build_samples.py --check   # exit 1 if a file or the manifest differs from what the builders produce

Source of truth stays the builder in samples.py (named in challenge.json and in the manifest). The committed file is
only a copy of its output; the pre-commit hook lets a sample through only if its SHA-256 is in the manifest, and the
test suite checks that the manifest matches the builders. Nothing here runs a sample.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from samples import BUILDERS  # noqa: E402

MANIFEST = HERE / "samples.manifest.json"


def expected() -> dict[str, dict]:
    out = {}
    for f in sorted((HERE / "challenges").glob("*/challenge.json")):
        c = json.loads(f.read_text(encoding="utf-8"))
        name, builder = c["sample"]["name"], c["sample"]["builder"]
        if "/" in name or "\\" in name or name.startswith("."):
            sys.exit(f"{f}: sample.name must be a plain file name")
        data = BUILDERS[builder]()
        rel = f"example/challenges/{c['id']}/sample/{name}"
        out[rel] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "challenge": c["id"],
                    "builder": f"example/samples.py:{builder}", "_data": data}
    return out


def main() -> int:
    check = "--check" in sys.argv[1:]
    exp = expected()
    root = HERE.parent
    manifest = {k: {x: v[x] for x in v if x != "_data"} for k, v in exp.items()}
    text = json.dumps({"note": "harmless self-made example samples, see docs/adr/0009-beispielproben-im-repository.md",
                       "files": manifest}, indent=1, sort_keys=True) + "\n"
    bad = []
    for rel, v in exp.items():
        p = root / rel
        if check:
            if not p.is_file() or p.read_bytes() != v["_data"]:
                bad.append(rel)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(v["_data"])
    if check:
        if not MANIFEST.is_file() or MANIFEST.read_text(encoding="utf-8") != text:
            bad.append(str(MANIFEST.relative_to(root)))
        print("ok" if not bad else "differs: " + ", ".join(bad))
        return 1 if bad else 0
    MANIFEST.write_text(text, encoding="utf-8", newline="\n")
    print(f"{len(exp)} sample(s) written, manifest {MANIFEST.relative_to(root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
