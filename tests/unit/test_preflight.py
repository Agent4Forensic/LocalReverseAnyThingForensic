import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path

import pytest

from sw_analyst import preflight as pf

ROOT = Path(__file__).resolve().parents[2]


def test_hash_good_and_bad(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello")
    good = hashlib.sha256(b"hello").hexdigest()
    assert pf.verify_hash(f, good) == good
    assert pf.verify_hash(f, good.upper()) == good  # pin case does not matter
    with pytest.raises(pf.HashMismatch):
        pf.verify_hash(f, "0" * 64)


@pytest.mark.parametrize("pin", ["pending", "", "abc", None])
def test_unpinned_is_hard_error(tmp_path, pin):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    with pytest.raises(pf.HashMismatch):
        pf.verify_hash(f, pin)


def test_real_manifest_ollama_pinned():
    m = pf.load_manifest(ROOT / "infra" / "manifest.json")
    o = m["components"]["ollama"]
    assert o["url"].startswith("https://github.com/ollama/ollama/releases/download/v0.40.13/")
    assert re.fullmatch(r"[0-9a-f]{64}", o["sha256"])
    assert "latest" not in o["url"]
    assert m["components"]["rea"]["sha256"] == "pending"  # not pinned -> verify_hash would refuse it


def test_aggregate():
    r = pf.result
    assert pf.aggregate([]) == pf.OK
    assert pf.aggregate([r("a", pf.OK, ""), r("b", pf.WARN, "")]) == pf.WARN
    assert pf.aggregate([r("a", pf.WARN, ""), r("b", pf.FEHLER, ""), r("c", pf.OK, "")]) == pf.FEHLER
    table = pf.render_table([r("a", pf.FEHLER, "kaputt", "reparieren")])
    assert "FEHLER" in table and "reparieren" in table and table.endswith("GESAMT: FEHLER")


def test_log_format_and_file(tmp_path, capsys):
    line = pf.fmt_line("CHECK", "hallo", now=datetime(2026, 1, 2, 3, 4, 5))
    assert line == "[03:04:05] [CHECK] hallo"
    assert re.fullmatch(r"\[\d\d:\d\d:\d\d\] \[STOP\] WARN: x", pf.fmt_line("STOP", "x", "WARN"))
    assert "[DATA]" in pf.fmt_line("DATA", "x")  # __main__ logs the data folder under this stage
    with pytest.raises(ValueError):
        pf.fmt_line("BOGUS", "x")
    logfile = tmp_path / "logs" / "start.log"
    logfile.parent.mkdir()
    pf.log("APP", "up", logfile=logfile)
    assert re.fullmatch(r"\[\d\d:\d\d:\d\d\] \[APP\] up\n", logfile.read_text())
    assert "[APP] up" in capsys.readouterr().out


def test_pid_file_logic(tmp_path):
    p = tmp_path / "run" / "app.pid"
    assert pf.read_pid(p) is None
    pf.write_pid(p, os.getpid(), "python")
    d = pf.read_pid(p)
    assert d["pid"] == os.getpid() and d["name"] == "python"
    assert pf.pid_alive(os.getpid())
    assert not pf.clean_stale_pid(p) and p.exists()  # live process: keep
    pf.write_pid(p, 2**22 + 12345, "python")  # no such process
    assert pf.clean_stale_pid(p) and not p.exists()
    p.write_text("{not json")
    assert pf.read_pid(p) is None
    assert pf.clean_stale_pid(p) and not p.exists()


def test_parse_lock_and_check_lock(tmp_path):
    lock = tmp_path / "l.lock"
    lock.write_text("pytest==999.0.0 \\\n    --hash=sha256:aa\nnot_a_real_pkg_xyz==1.0 \\\n    --hash=sha256:bb\n", encoding="utf-8")
    assert pf.parse_lock(lock.read_text())["pytest"] == "999.0.0"
    res = {r["name"]: r for r in pf.check_lock(lock)}
    assert res["lock:missing"]["status"] == pf.FEHLER and "not-a-real-pkg-xyz" in res["lock:missing"]["detail"]
    assert res["lock:drift"]["status"] == pf.WARN
    assert pf.check_lock(tmp_path / "none.lock")[0]["status"] == pf.FEHLER


def test_ports_own_pid_is_ok(tmp_path):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    port = s.getsockname()[1]
    try:
        assert pf.check_ports({"app": port}, tmp_path)[0]["status"] == pf.FEHLER  # foreign owner
        pf.write_pid(tmp_path / "app.pid", os.getpid(), "python")
        assert pf.check_ports({"app": port}, tmp_path)[0]["status"] == pf.OK  # explained by own live pid
    finally:
        s.close()


def test_loopback_only():
    with pytest.raises(ValueError):
        pf._loopback_get("http://example.com/api/tags")


def test_audit_chain_check(tmp_path):
    from sw_analyst.common.audit import AuditLog
    a = AuditLog(tmp_path / "logs" / "J-0001" / "audit.jsonl")
    a.append({"x": 1})
    a.append({"x": 2})
    assert pf.check_audit_chain(tmp_path)["status"] == pf.OK
    path = tmp_path / "logs" / "J-0001" / "audit.jsonl"
    path.write_text(path.read_text().replace('"x":1', '"x":9'), encoding="utf-8")
    assert pf.check_audit_chain(tmp_path)["status"] == pf.FEHLER


def test_main_check_json_exit_code(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(pf, "run_checks", lambda *a, **k: [pf.result("x", pf.FEHLER, "d", "f")])
    assert pf.main_check(ROOT, tmp_path, 8765, 11435, None, as_json=True) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "FEHLER" and out["results"][0]["name"] == "x"
    monkeypatch.setattr(pf, "run_checks", lambda *a, **k: [pf.result("x", pf.WARN, "d")])
    assert pf.main_check(ROOT, tmp_path, 8765, 11435, None, as_json=True) == 0


@pytest.mark.skipif(os.name != "nt", reason="Windows paths; path_under follows the host OS")
def test_path_under_recognises_own_install_root():
    from sw_analyst.preflight import path_under
    roots = [r"D:\Tools\sw-analyst"]
    assert path_under(r"D:\Tools\sw-analyst\ollama-0.40.13\ollama.exe", roots)
    assert not path_under(r"C:\Users\x\AppData\Local\Programs\Ollama\ollama.exe", roots)
    assert not path_under(r"D:\Tools\sw-analyst-evil\ollama.exe", roots)  # prefix trick
    assert not path_under(None, roots)
