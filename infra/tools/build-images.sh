#!/usr/bin/env bash
# build-images.sh - builds the pinned tool images of ADR-0006 package B (Linux counterpart of build-images.ps1).
# Needs network once and a running Docker daemon; the containers themselves run with --network none.
# Usage: infra/tools/build-images.sh [ghidra] [triage] [jadx]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$HERE/../manifest.json"
targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(ghidra triage jadx)
for t in "${targets[@]}"; do
  case "$t" in ghidra|triage|jadx) ;; *) echo "unknown image '$t'; known: ghidra, triage, jadx" >&2; exit 1 ;; esac
  tag="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["tool_images"][sys.argv[2]])' "$MANIFEST" "$t")"
  echo "building $tag"
  docker build --target "$t" -t "$tag" "$HERE"
  echo "$tag -> $(docker image inspect --format '{{.Id}}' "$tag")"
done
