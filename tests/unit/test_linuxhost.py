"""Linux host facts and the Linux preflight checks (ADR-0013). Parsers get text, so these run on every OS."""
import os
import socket
import sys

import pytest

from sw_analyst import preflight as pf
from sw_analyst.common import linuxhost as lh

MEMINFO = "MemTotal:       32612345 kB\nMemFree:         1000000 kB\nMemAvailable:   20971520 kB\nSwapTotal: 0 kB\n"


def test_meminfo():
    total, avail = lh.parse_meminfo(MEMINFO)
    assert round(total, 1) == 31.1 and avail == 20.0
    assert lh.parse_meminfo("MemTotal: 1 kB\n") is None


def test_proc_net_tcp_listen_rows_only():
    text = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:2CAB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4711 1\n"
            "   1: 0100007F:2CAB 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 4712 1\n"
            "   2: 0100007F:2CAC 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4713 1\n")
    assert lh.parse_proc_net_tcp(text, 11435) == {4711}
    assert lh.parse_proc_net_tcp(text, 1) == set()


def test_mounts_and_mount_of():
    table = lh.parse_mounts("/dev/sdb3 /srv/sw-analyst ext4 rw,noatime 0 0\n"
                            "/dev/sda2 /mnt/host\\040share ntfs3 rw,nosuid,nodev,noexec 0 0\n/dev/x / ext4 rw 0 0\n")
    assert table[1]["target"] == "/mnt/host share" and "noexec" in table[1]["options"]
    assert lh.mount_of("/srv/sw-analyst/repo/data", table)["fstype"] == "ext4"
    assert lh.mount_of("/srv/sw-analyst-evil", table)["target"] == "/"   # no prefix trick


def test_default_routes_v4_and_v6():
    v4 = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
          "wlp3s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n"
          "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\n")
    v6 = ("00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000000000000000001 "
          "00000400 00000001 00000000 00000003 enp4s0\n"
          "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 "
          "ffffffff 00000001 00000000 00200200 lo\n")
    assert lh.parse_default_routes(v4, v6) == ["enp4s0", "wlp3s0"]
    assert lh.parse_default_routes(v4.splitlines()[0] + "\n") == []


def test_active_interfaces_counts_only_physical_links(tmp_path):
    net = tmp_path / "class" / "net"
    for name, state, carrier, physical in (("lo", "unknown", "1", False), ("docker0", "up", "1", False),
                                           ("enp4s0", "up", "1", True), ("wlp3s0", "down", "0", True)):
        d = net / name
        d.mkdir(parents=True)
        (d / "operstate").write_text(state + "\n")
        (d / "carrier").write_text(carrier + "\n")
        if physical:
            (d / "device").mkdir()
    assert lh.active_interfaces(str(tmp_path)) == ["enp4s0"]


def test_cgroup_limit_takes_the_smallest_on_the_path(tmp_path):
    proc, cg = tmp_path / "proc", tmp_path / "cg"
    (proc / "self").mkdir(parents=True)
    (proc / "self" / "cgroup").write_text("0::/user.slice/user-1000.slice/user@1000.service/sw-analyst.slice/run-1.scope\n")
    base = cg / "user.slice" / "user-1000.slice" / "user@1000.service" / "sw-analyst.slice"
    (base / "run-1.scope").mkdir(parents=True)
    (base / "run-1.scope" / "memory.max").write_text("max\n")
    (base / "memory.max").write_text(str(28 * 2**30) + "\n")
    (cg / "user.slice" / "memory.max").write_text(str(30 * 2**30) + "\n")
    assert lh.cgroup_memory_limit_gb(str(proc), str(cg)) == 28
    (proc / "self" / "cgroup").write_text("0::/\n")
    assert lh.cgroup_memory_limit_gb(str(proc), str(cg)) is None


def test_volume_root_by_label(tmp_path):
    dev = tmp_path / "sdc1"
    dev.write_text("")
    by_label = tmp_path / "by-label"
    by_label.mkdir()
    (by_label / "ki_data").symlink_to(dev)
    table = [{"source": str(dev), "target": "/media/analyst/ki_data", "fstype": "exfat", "options": ["rw"]}]
    assert str(lh.volume_root("ki_data", table, str(by_label))) == "/media/analyst/ki_data"
    assert lh.volume_root("missing", table, str(by_label)) is None
    assert lh.volume_root("ki_data", [], str(by_label)) is None        # not mounted


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads the real /proc")
def test_listen_pid_finds_this_process():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    try:
        assert lh.listen_pid(s.getsockname()[1]) == os.getpid()
        assert lh.exe_path(os.getpid()) and lh.cmdline(os.getpid())
    finally:
        s.close()


# ---- preflight on Linux -------------------------------------------------------------------------------------
def test_offline_check_refuses_an_online_host_unless_allowed():
    assert pf.check_network(routes=[], links=[])["status"] == pf.OK
    r = pf.check_network(routes=["wlp3s0"], links=[])
    assert r["status"] == pf.FEHLER and "sw-mode offline" in r["fix"]
    assert pf.check_network(True, routes=["wlp3s0"], links=["wlp3s0"])["status"] == pf.WARN


def test_share_must_be_noexec_nosuid_nodev():
    ok = [{"source": "/dev/sda2", "target": lh.SHARE_MOUNT, "fstype": "ntfs3", "options": ["rw", "nosuid", "nodev", "noexec"]}]
    bad = [{**ok[0], "options": ["rw", "nosuid"]}]
    assert pf.check_share([])["status"] == pf.OK
    assert pf.check_share(ok)["status"] == pf.WARN          # mounted: reminder to unmount before real samples
    r = pf.check_share(bad)
    assert r["status"] == pf.FEHLER and "noexec" in r["detail"] and "nodev" in r["detail"]


def test_sw_root_wants_a_linux_file_system(tmp_path):
    table = [{"source": "/dev/sdb3", "target": str(tmp_path), "fstype": "ext4", "options": []}]
    assert pf.check_sw_root(table, tmp_path)["status"] == pf.OK
    assert pf.check_sw_root([{**table[0], "fstype": "exfat"}], tmp_path)["status"] == pf.WARN
    assert pf.check_sw_root(table, tmp_path / "missing")["status"] == pf.FEHLER


def test_ram_check_wants_the_slice_limit():
    assert {r["name"]: r["status"] for r in pf.check_ram_linux((31.1, 20.0), 28.0)} == {"ram:free": pf.OK, "ram:limit": pf.OK}
    assert {r["name"]: r["status"] for r in pf.check_ram_linux((31.1, 20.0), 30.0)}["ram:limit"] == pf.WARN
    assert pf.check_ram_linux((31.1, 5.0), 28.0)[0]["status"] == pf.WARN


def test_manifest_has_pinned_linux_overrides(monkeypatch, tmp_path):
    m = pf.load_manifest(pf.Path(__file__).resolve().parents[2] / "infra" / "manifest.json")
    monkeypatch.setattr(pf, "IS_WIN", False)
    monkeypatch.setenv("SW_ROOT", str(tmp_path))
    o = pf.component(m, "ollama")
    assert o["url"].endswith("ollama-linux-amd64.tar.zst") and len(o["sha256"]) == 64
    assert o["target"] == f"{tmp_path}/tools/ollama-0.40.13" and o["exe"] == "bin/ollama"
    c = pf.component(m, "colibri")
    assert "linux" in c["url"] and len(c["sha256"]) == 64 and c["url_cuda"] is None
    assert pf.component(m, "colibri", "models")["dir"] == "sw-analyst/colibri/deepseek-v4-flash-0731"
    assert pf.tools_root(m) == tmp_path / "tools"
    monkeypatch.setattr(pf, "IS_WIN", True)
    assert pf.component(m, "ollama")["exe"] == "ollama.exe" and "linux" not in pf.component(m, "ollama")
