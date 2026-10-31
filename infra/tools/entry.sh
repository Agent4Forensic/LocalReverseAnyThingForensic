#!/bin/sh
# Fixed dispatch inside the tool containers. The sample arrives on stdin and lands in a noexec tmpfs; nothing from the host
# file system is mounted. $1 is one of the fixed operations below, chosen by the gateway; no model text ever reaches this
# script. Results go to stdout, diagnostics to stderr.
set -eu
umask 077
op="${1:-}"
head -c 67108865 > /job/sample
chmod 0444 /job/sample

jadx_run() {
    cp /job/sample "/job/input.$1"
    # jadx exits non-zero when single classes fail; whatever it decompiled is still valid output.
    /opt/jadx/bin/jadx --no-res --show-bad-code -j 2 -d /tmp/out "/job/input.$1" >/tmp/jadx.log 2>&1 || true
    if [ ! -d /tmp/out/sources ]; then tail -n 20 /tmp/jadx.log >&2; exit 1; fi
    exec tar -C /tmp/out/sources -cf - .
}

case "$op" in
    capa)  exec /opt/tools/capa -j -q /job/sample ;;
    floss) exec /opt/tools/floss -j -q /job/sample ;;
    yara)  exec /opt/tools/yr scan --output-format json --print-meta --print-strings=64 /opt/sw/sw_analyst.yar /job/sample ;;
    ghidra)
        mkdir -p /tmp/proj
        if ! /opt/ghidra/support/analyzeHeadless /tmp/proj p -import /job/sample -scriptPath /opt/sw \
                -postScript ExportAll.java /tmp/out.json -deleteProject >/tmp/ghidra.log 2>&1 || [ ! -s /tmp/out.json ]; then
            tail -n 20 /tmp/ghidra.log >&2
            exit 1
        fi
        exec cat /tmp/out.json ;;
    jadx-apk) jadx_run apk ;;
    jadx-dex) jadx_run dex ;;
    jadx-jar) jadx_run jar ;;
    *) echo "unknown operation" >&2; exit 64 ;;
esac
