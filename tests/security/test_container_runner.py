"""What the container boundary can start (ADR-0006 package B). If one of these fails, the model's power over the host changed."""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import sw_analyst
from sw_analyst.gateway import container_runner as cr
from sw_analyst.gateway.base import DYNAMIC_TOOLS
from sw_analyst.gateway.container_runner import IMAGES, OPS, ContainerError, ContainerRunner, build_argv
from sw_analyst.gateway.container_tools import ALL_TOOLS, ContainerTools, attach_container_tools
from sw_analyst.gateway.dev_gateway import DevGateway

ROOT = Path(sw_analyst.__file__).parent
REPO = ROOT.parents[1]
IMAGE_IDS = {k: f"sha256:{k[0] * 64}" for k in IMAGES}


def test_subprocess_is_used_only_here_and_only_for_two_fixed_calls():
    tree = ast.parse((ROOT / "gateway" / "container_runner.py").read_text(encoding="utf-8"))
    used = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and getattr(n.func.value, "id", "") == "subprocess"}
    assert used == {"Popen", "run"}
    assert not [k for n in ast.walk(tree) if isinstance(n, ast.Call) for k in n.keywords if k.arg == "shell"]


@pytest.mark.parametrize("op", sorted(OPS))
def test_every_container_is_offline_read_only_and_limited(op):
    argv = build_argv(op, "sha256:abc", "sw-analyst-x")
    joined = " ".join(argv)
    for flag in ("--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges", "--user 10001:10001",
                 "--memory ", "--memory-swap ", "--cpus ", "--pids-limit ", "--label sw-analyst", "--rm", "--pull never", "--log-driver none"):
        assert flag in joined, flag
    assert argv[:2] == ["docker", "run"] and argv[-2:] == ["sha256:abc", op]
    job = argv[argv.index("--tmpfs") + 1]
    assert job.startswith("/job:") and "noexec" in job
    for forbidden in ("-v", "--volume", "--mount", "--privileged", "--network=host", "--device", "--gpus", "--pid", "--ipc"):
        assert forbidden not in argv


def test_memory_limits_stay_inside_the_host_budget():
    # CLAUDE.md: 24 GB for WSL, Docker and models together; one tool at a time runs (single worker).
    assert max(int(spec.memory.rstrip("g")) for spec in OPS.values()) <= 6


def test_unknown_operation_never_starts_a_process(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not start anything")
    monkeypatch.setattr(cr.subprocess, "Popen", boom)
    for op in ("sh", "ghidra; rm -rf /", "../x", ""):
        with pytest.raises(ContainerError):
            ContainerRunner(IMAGE_IDS).run(op, b"x")


def test_missing_image_never_starts_a_process(monkeypatch):
    monkeypatch.setattr(cr.subprocess, "Popen", lambda *a, **k: pytest.fail("must not start"))
    with pytest.raises(ContainerError):
        ContainerRunner({}).run("capa", b"x")


def test_container_allowlist_is_exactly_this_and_takes_no_command_like_argument(tmp_path):
    assert ALL_TOOLS == {"list_functions", "disassemble", "decompile", "xrefs", "basic_blocks", "capa_scan", "yara_scan",
                         "floss_decode", "jadx_decompile"}
    gw = DevGateway(tmp_path)
    base = {t.name for t in gw.list_tools()}
    added = attach_container_tools(gw, ContainerRunner(IMAGE_IDS))
    tools = gw.list_tools()
    # ADR-0005: emulate_function is attached with its image, but stays hidden until the dashboard switch opens it.
    assert set(added) == ALL_TOOLS | DYNAMIC_TOOLS and {t.name for t in tools} == base | ALL_TOOLS
    gw.dynamic_enabled = lambda: True
    assert {t.name for t in gw.list_tools()} == base | ALL_TOOLS | DYNAMIC_TOOLS
    tools = gw.list_tools()
    assert all(t.read_only for t in tools)
    params = {p for t in tools for p in t.params}
    assert not params & {"cmd", "command", "script", "url", "host", "port", "code", "args", "exec", "rules", "image", "op"}


def test_without_images_the_allowlist_does_not_grow(tmp_path):
    gw = DevGateway(tmp_path)
    assert attach_container_tools(gw, ContainerRunner({})) == []
    assert not {t.name for t in gw.list_tools()} & ALL_TOOLS


def test_detect_treats_missing_docker_as_no_tools(monkeypatch):
    def gone(*a, **k):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(cr.subprocess, "run", gone)
    assert ContainerRunner.detect().image_ids == {}


def test_image_tags_match_the_manifest_and_dockerfile():
    manifest = json.loads((REPO / "infra" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["tool_images"] == {k: v[0] for k, v in IMAGES.items()}
    dockerfile = (REPO / "infra" / "tools" / "Dockerfile").read_text(encoding="utf-8")
    for name in ("ghidra", "capa", "floss", "yara-x", "jadx"):
        comp = manifest["components"][name]
        assert comp["url"] in dockerfile and comp["sha256"] in dockerfile and len(comp["sha256"]) == 64 and comp["license"]
    assert all("@sha256:" in line for line in dockerfile.splitlines() if line.startswith("FROM ") and " fetch" not in line[:11])
    assert manifest["components"]["rea"]["url"] == "pending"      # deferred: no REA in any image


def test_entry_script_runs_only_fixed_operations():
    entry = (REPO / "infra" / "tools" / "entry.sh").read_text(encoding="utf-8")
    assert "\r" not in entry
    assert "eval" not in entry and '$2' not in entry and '$@' not in entry
    # emulate has its own fixed entry: it takes numbers in a frame on stdin, and its argv is checked there.
    assert set(OPS) - {"emulate"} <= {line.strip().split(")")[0] for line in entry.splitlines() if ")" in line}
    emu = (REPO / "infra" / "tools" / "emu" / "emulate.py").read_text(encoding="utf-8")
    assert 'sys.argv[1:] != ["emulate"]' in emu
    for word in ("subprocess", "os.system", "eval(", "exec(", "__import__", "socket", "ctypes"):
        assert word not in emu, word


def test_jadx_tar_is_read_in_memory_and_names_cannot_escape(tmp_path):
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, body in {"../../evil.java": b"x", "./com/A.java": b"class A {}", "notes.txt": b"skip"}.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
        link = tarfile.TarInfo("link.java")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)
    before = set(tmp_path.iterdir())
    files = ContainerTools.parse_jadx_tar(buf.getvalue())["files"]
    assert files["com/A.java"] == "class A {}" and "link.java" not in files and "notes.txt" not in files
    assert set(tmp_path.iterdir()) == before
