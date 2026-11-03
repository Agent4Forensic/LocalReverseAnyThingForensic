"""Linux launcher (ADR-0013): only own processes and folders, pinned installs, safe extraction, the memory slice."""
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from sw_analyst import launcher as ln
from sw_analyst import preflight as pf

ROOT = Path(__file__).resolve().parents[2]
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads the real /proc")


def test_under_refuses_prefix_tricks_and_the_root_itself(tmp_path):
    root = tmp_path / "tools"
    (root / "ollama-1").mkdir(parents=True)
    assert ln.under(root / "ollama-1" / "bin" / "ollama", root)
    assert not ln.under(tmp_path / "tools-evil" / "x", root)
    assert not ln.under(root, root) and not ln.under(None, root)
    assert not ln.under(root / ".." / "elsewhere", root)


def test_deletable_only_own_folders(tmp_path):
    troot = tmp_path / "tools"
    assert ln.deletable(ln.DATA / "tmp" / "x", troot)
    assert ln.deletable(troot / "ollama-1.partial", troot)
    assert ln.deletable(ln.ROOT / "src" / "__pycache__", troot)
    assert not ln.deletable(ln.ROOT / "src" / "sw_analyst", troot)
    assert not ln.deletable(Path("/etc"), troot)


def _tar_gz(path: Path, members: dict) -> Path:
    with tarfile.open(path, "w:gz") as t:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o4755 if name.endswith("suid") else 0o755
            t.addfile(info, io.BytesIO(data))
    return path


def test_extract_strips_setuid_and_refuses_paths_outside(tmp_path):
    good = _tar_gz(tmp_path / "a.tar.gz", {"bin/tool": b"x", "bin/suid": b"y"})
    dest = tmp_path / "out"
    dest.mkdir()
    ln.extract(good, dest)
    assert (dest / "bin" / "tool").read_bytes() == b"x"
    assert not (dest / "bin" / "suid").stat().st_mode & 0o4000
    evil = _tar_gz(tmp_path / "b.tar.gz", {"../escape": b"z"})
    with pytest.raises(tarfile.TarError):
        ln.extract(evil, dest)
    assert not (tmp_path / "escape").exists()


def test_install_refuses_unpinned_urls_and_targets_outside(tmp_path):
    with pytest.raises(RuntimeError, match="not pinned"):
        ln._download("https://example.com/x.tar.gz", "0" * 64, tmp_path / "x")
    with pytest.raises(RuntimeError, match="not pinned"):
        ln._download("https://github.com/x.tar.gz", "pending", tmp_path / "x")
    with pytest.raises(RuntimeError, match="outside"):
        ln.install_component("ollama", {"target": "/usr/local/ollama", "exe": "bin/ollama"}, tmp_path / "tools")


def test_install_from_a_verified_archive(tmp_path, monkeypatch):
    archive = _tar_gz(tmp_path / "ollama.tar.gz", {"bin/ollama": b"#!/bin/sh\n"})
    sha = pf.sha256_file(archive)

    def fake_download(url, s, dest):
        assert s == sha
        return archive
    monkeypatch.setattr(ln, "_download", fake_download)
    troot = tmp_path / "tools"
    c = {"url": "https://github.com/o.tar.gz", "sha256": sha, "target": str(troot / "ollama-1"), "exe": "bin/ollama", "version": "1"}
    ln.install_component("ollama", c, troot)
    assert (troot / "ollama-1" / "bin" / "ollama").is_file() and not (troot / "ollama-1.partial").exists()
    with pytest.raises(RuntimeError, match="not found"):
        ln.install_component("ollama", {**c, "exe": "bin/other"}, troot)


def test_download_deletes_a_file_with_the_wrong_hash(tmp_path, monkeypatch):
    class R(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(ln.urllib.request, "urlopen", lambda url, timeout: R(b"tampered"))
    with pytest.raises(pf.HashMismatch):
        ln._download("https://github.com/a/b.tar.gz", "0" * 64, tmp_path / "dl" / "b.tar.gz")
    assert not any((tmp_path / "dl").iterdir())


def test_slice_leaves_the_host_its_reserve():
    text = ln.slice_unit_text(31.1)
    assert "MemoryMax=28774M" in text and "MemorySwapMax=0" in text and "[Slice]" in text


def test_ollama_env_is_loopback_and_offline(monkeypatch, tmp_path):
    monkeypatch.setenv("OLLAMA_HOST", "0.0.0.0:11434")   # a user setting must never leak into our server
    monkeypatch.setenv("SW_ROOT", str(tmp_path))
    env = ln.ollama_env(11435, 15000)
    assert env["OLLAMA_HOST"] == "127.0.0.1:11435" and env["OLLAMA_NO_CLOUD"] == "1"
    assert env["OLLAMA_MODELS"] == str(tmp_path / "models" / "ollama") and env["OLLAMA_CONTEXT_LENGTH"] == "32768"
    assert ln.ollama_env(11435, 8000)["OLLAMA_CONTEXT_LENGTH"] == "16384"


def test_model_tier_follows_the_free_vram(monkeypatch):
    m = pf.load_manifest(ROOT / "infra" / "manifest.json")
    for free, tier in ((15000, "A"), (8000, "B"), (2000, "C")):
        monkeypatch.setattr(ln, "gpu_free_mib", lambda f=free: f)
        assert ln.resolve_model(m, "") == m["models"]["chat_tiers"][tier]
    assert ln.resolve_model(m, "qwen3:8b") == "qwen3:8b"
    with pytest.raises(ln.Fail):
        ln.resolve_model(m, "qwen3; rm -rf /")


def test_post_json_is_loopback_only():
    with pytest.raises(ValueError):
        ln.post_json("http://example.com/api", {})


@linux_only
def test_ownership_never_claims_a_foreign_process(tmp_path):
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        assert not ln.is_own_app(p.pid) and not ln.is_own_ollama(p.pid, tmp_path) and not ln.is_own_colibri(p.pid, tmp_path)
        assert not ln.is_own_ollama(os.getpid(), Path(sys.executable).parent.parent)   # under the root, but not named ollama
    finally:
        p.kill()
        p.wait()


@linux_only
def test_stop_tree_ends_the_whole_group():
    p = subprocess.Popen([sys.executable, "-c", "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); time.sleep(60)"],
                         start_new_session=True)
    ln.stop_tree(p.pid, grace_s=5)
    assert p.wait(10) is not None


def test_wrappers_call_the_launcher_and_pass_shellcheck_style():
    for name in ("start", "stop", "cleanup"):
        txt = (ROOT / "scripts" / f"{name}.sh").read_text()
        assert txt.startswith("#!/usr/bin/env bash") and "set -euo pipefail" in txt
        assert f'"$ROOT/src" {name} "$@"' in txt and "eval" not in txt
        assert os.access(ROOT / "scripts" / f"{name}.sh", os.X_OK)


def test_host_tools_have_fixed_actions_only():
    for name in ("sw-mode", "sw-share"):
        txt = (ROOT / "infra" / "linux" / name).read_text()
        assert "set -euo pipefail" in txt and "eval " not in txt and "bash -c" not in txt
        assert "*) echo \"usage:" in txt          # unknown action: refused
    share = (ROOT / "infra" / "linux" / "sw-share").read_text()
    assert "noexec,nosuid,nodev" in share and "install -d -m 0700 -o root -g root \"$HIDDEN\"" in share
    sudoers = (ROOT / "infra" / "linux" / "sudoers-sw-analyst").read_text()
    assert "sw-mode online" not in sudoers and "sw-share mount" not in sudoers   # these ask for the password


def test_offline_firewall_drops_everything_but_loopback():
    nft = (ROOT / "infra" / "linux" / "nftables-offline.nft").read_text()
    for chain in ("input", "output", "forward"):
        assert f"hook {chain} priority -300; policy drop;" in nft
    assert 'iif "lo" accept' in nft and 'oif "lo" accept' in nft and nft.count("accept") == 2


def test_cli_help_lists_setup_and_force(capsys):
    with pytest.raises(SystemExit):
        ln.parser().parse_args(["start", "--help"])
    assert "--setup" in capsys.readouterr().out
    a = ln.parser().parse_args(["stop", "--force"])
    assert a.force and a.cmd == "stop"
    assert json.loads(json.dumps(vars(ln.parser().parse_args(["cleanup", "--dry-run"]))))["dry_run"] is True
