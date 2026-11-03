#!/usr/bin/env bash
# stop.sh - Linux launcher of sw-analyst (ADR-0013). All logic is in src/sw_analyst/launcher.py (stdlib only, tested).
# Usage: scripts/stop.sh --help
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "python3 missing: sudo apt install python3 python3-venv (infra/linux/provision.sh)" >&2; exit 1; }
export PYTHONPATH="$ROOT/src"
exec python3 -I -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); from sw_analyst.launcher import main; raise SystemExit(main())' "$ROOT/src" stop "$@"
