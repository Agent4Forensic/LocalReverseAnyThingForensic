"""Teach the colibri expert cache this project's work (ADR-0012). Started by scripts\\start.ps1 -Llm colibri -ColibriPrepare.

The engine records in .coli_usage which experts a workload routes to and keeps those in memory first. Harmless self-written
pseudo-C, assembly and script snippets go through it with very short replies: what counts is the routing of the prompts.
The key comes from SW_COLIBRI_KEY. Nothing here runs a sample.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sw_analyst.llm.base import ChatMessage, LLMError  # noqa: E402
from sw_analyst.llm.colibri import ColibriClient  # noqa: E402

SNIPPETS = [
    "undefined8 FUN_00401000(char *param_1,int param_2)\n{\n  int iVar1;\n  iVar1 = 0;\n  while (iVar1 < param_2) {\n"
    "    param_1[iVar1] = param_1[iVar1] ^ 0x5a;\n    iVar1 = iVar1 + 1;\n  }\n  return 0;\n}",
    "push rbp\nmov rbp, rsp\nsub rsp, 0x20\nmov dword ptr [rbp-4], 0\njmp short loc_401030\nloc_401020:\nmov eax, [rbp-4]\n"
    "xor byte ptr [rcx+rax], 0x41\nadd dword ptr [rbp-4], 1\nloc_401030:\ncmp dword ptr [rbp-4], edx\njl short loc_401020\nleave\nret",
    "PE32+ executable, sections .text .rdata .data .rsrc, imports KERNEL32.dll CreateFileW ReadFile VirtualAlloc, entropy of .rsrc 7.8",
    "$b = 'SGVsbG8='\n$d = [Convert]::FromBase64String($b)\n$s = New-Object IO.MemoryStream(,$d)\n"
    "$g = New-Object IO.Compression.GZipStream($s, [IO.Compression.CompressionMode]::Decompress)",
    "import base64, zlib\nblob = base64.b64decode(data)\nkey = blob[:4]\nout = bytes(c ^ key[i % 4] for i, c in enumerate(blob[4:]))\nprint(zlib.decompress(out))",
    "public final class MainActivity extends Activity {\n  protected void onCreate(Bundle b) {\n    super.onCreate(b);\n"
    "    String u = getString(R.string.endpoint);\n    new Thread(new Loader(u)).start();\n  }\n}",
]
QUESTION = "In one short sentence, what does this code or output do?\n\n"


def warm(llm, snippets: list[str] = SNIPPETS, max_tokens: int = 8) -> int:
    """Number of snippets the engine took. A failing one is reported and the rest still run: this only tunes speed."""
    ok = 0
    for i, s in enumerate(snippets, 1):
        t0 = time.monotonic()
        try:
            llm.chat([ChatMessage(role="user", content=QUESTION + s)], think=False, max_tokens=max_tokens)
            ok += 1
            print(f"[{time.strftime('%H:%M:%S')}] warm-up {i}/{len(snippets)}: {time.monotonic() - t0:.0f} s", flush=True)
        except LLMError as e:
            print(f"[{time.strftime('%H:%M:%S')}] warm-up {i}/{len(snippets)} failed: {e}", flush=True)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--model", required=True)
    a = ap.parse_args()
    ok = warm(ColibriClient(a.model, a.url, os.environ.pop("SW_COLIBRI_KEY", "")))
    print(f"warm-up: {ok} of {len(SNIPPETS)} snippets", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
