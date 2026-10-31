#!/bin/sh
# Fixed dispatch inside the tool containers. The sample arrives on stdin and lands in a noexec tmpfs; nothing from the host
# file system is mounted. $1 is one of the fixed operations below, chosen by the gateway; no model text ever reaches this
# script. Results go to stdout, diagnostics to stderr.
set -eu
umask 077
op="${1:-}"
# Below the gateway limit of 600 s, so a container outlives a crashed app by minutes at most.
LIMIT="timeout -k 5 590"
head -c 67108865 > /job/sample
chmod 0444 /job/sample

jadx_run() {
    cp /job/sample "/job/input.$1"
    # jadx exits non-zero when single classes fail; whatever it decompiled is still valid output.
    rc=0
    $LIMIT /opt/jadx/bin/jadx --no-res --show-bad-code -j 2 -d /tmp/out "/job/input.$1" >/tmp/jadx.log 2>&1 || rc=$?
    # A run cut off by the limit must not pass as a complete result.
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then tail -n 20 /tmp/jadx.log >&2; exit "$rc"; fi
    if [ ! -d /tmp/out/sources ]; then tail -n 20 /tmp/jadx.log >&2; exit 1; fi
    exec tar -C /tmp/out/sources -cf - .
}

case "$op" in
    capa)  exec $LIMIT /opt/tools/capa -j -q /job/sample ;;
    floss) exec $LIMIT /opt/tools/floss -j -q /job/sample ;;
    yara)  exec $LIMIT /opt/tools/yr scan --output-format json --print-meta --print-strings=64 /opt/sw/sw_analyst.yar /job/sample ;;
    ghidra)
        mkdir -p /tmp/proj
        rc=0
        $LIMIT /opt/ghidra/support/analyzeHeadless /tmp/proj p -import /job/sample -scriptPath /opt/sw \
                -postScript ExportAll.java /tmp/out.json -deleteProject >/tmp/ghidra.log 2>&1 || rc=$?
        if [ "$rc" -ne 0 ] || [ ! -s /tmp/out.json ]; then
            tail -n 20 /tmp/ghidra.log >&2
            if [ "$rc" -eq 0 ]; then rc=1; fi
            exit "$rc"
        fi
        exec cat /tmp/out.json ;;
    jadx-apk) jadx_run apk ;;
    jadx-dex) jadx_run dex ;;
    jadx-jar) jadx_run jar ;;
    *) echo "unknown operation" >&2; exit 64 ;;
esac
