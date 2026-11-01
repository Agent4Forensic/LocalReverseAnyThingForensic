"""Hex view of the dashboard: whole-file paging in base64, format structure and analysis ranges. Harmless samples only."""
from __future__ import annotations

import base64
import io
import sys
import zipfile
from pathlib import Path

from tests.unit.test_dashboard_api import ORIGIN, _app, _job  # noqa: F401  (shared fixtures)

from sw_analyst.common.paths import PROJECT_ROOT

sys.path.insert(0, str(PROJECT_ROOT))
from example import samples  # noqa: E402


def _labels(d):
    return [r["label"] for r in d["regions"]]


def test_hex_b64_pages_cover_the_whole_file(tmp_path: Path):
    client, store, gw = _app(tmp_path)
    data = bytes(range(256)) * 600          # 153600 bytes: more than two 64 KiB pages
    jid = _job(store, gw, data)
    got = b""
    off = 0
    while off < len(data):
        d = client.get(f"/api/jobs/{jid}/inspect/hex", params={"offset": off, "length": 65536, "format": "b64"}).json()
        got += base64.b64decode(d["data_b64"])
        off += d["length"]
    assert got == data and d["size"] == len(data)
    assert client.get(f"/api/jobs/{jid}/inspect/hex", params={"format": "evil"}).status_code == 422


def test_pe_structure_names_headers_sections_and_overlay(tmp_path: Path):
    client, store, gw = _app(tmp_path)
    jid = _job(store, gw, samples.pe_appended_config(), "a.exe")
    d = client.get(f"/api/jobs/{jid}/inspect/structure").json()
    labels = _labels(d)
    assert d["kind"] == "pe"
    for want in ("DOS-Kopf (MZ)", "e_lfanew", "PE-Signatur", "COFF-Kopf", "Sektionstabelle", "Overlay"):
        assert want in labels, (want, labels)
    assert any(lb.startswith("Sektion ") for lb in labels)
    assert all(r["offset"] + r["length"] <= d["size"] for r in d["regions"])


def test_zip_structure_lists_members(tmp_path: Path):
    client, store, gw = _app(tmp_path)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>" * 20)
        z.writestr("readme.txt", b"harmless")
    jid = _job(store, gw, buf.getvalue(), "a.zip")
    d = client.get(f"/api/jobs/{jid}/inspect/structure").json()
    labels = _labels(d)
    assert "Zentralverzeichnis" in labels and "Daten: AndroidManifest.xml" in labels and "Daten: readme.txt" in labels


def test_hostile_or_truncated_files_give_notes_not_errors(tmp_path: Path):
    client, store, gw = _app(tmp_path)
    for data in (b"MZ" + b"\xff" * 100, b"PK\x03\x04" + b"\x00" * 40, b"\x7fELF" + b"\x02\x01" * 3):
        jid = _job(store, gw, data)
        r = client.get(f"/api/jobs/{jid}/inspect/structure")
        assert r.status_code == 200, r.text


def test_finding_quote_and_evidence_range_are_located_in_the_file(tmp_path: Path):
    client, store, gw = _app(tmp_path)
    data = b"\x00" * 100 + b"set url = https://example.invalid/a\n" + "wide text here".encode("utf-16-le")
    jid = _job(store, gw, data)
    ev = store.add_evidence(jid, None, "hexdump", "1", {"path": "sample", "offset": 100, "length": 36},
                            "hexdump text", source_ref={"source_ref": {"file": "sample", "offset": 100, "length": 36}})
    store.add_finding(jid, "T-1", "The sample sets a URL.", "confirmed", [ev["id"]],
                      [{"evidence_id": ev["id"], "quote": "set url = https://example.invalid/a"}])
    store.add_finding(jid, "T-1", "Wide text found.", "hypothesis", [ev["id"]],
                      [{"evidence_id": ev["id"], "quote": "wide text here"}])
    d = client.get(f"/api/jobs/{jid}/inspect/structure").json()
    fnd = [r for r in d["regions"] if r["source"] == "finding"]
    assert any(r["offset"] == 100 and r["status"] == "confirmed" for r in fnd)
    assert any(r["offset"] == 136 and "UTF-16" in r["label"] for r in fnd)
    evr = [r for r in d["regions"] if r["source"] == "evidence"]
    assert evr and evr[0]["offset"] == 100 and evr[0]["status"] == "confirmed"


def test_structure_refuses_paths_outside_the_job(tmp_path: Path):
    client, store, gw = _app(tmp_path)
    jid = _job(store, gw, b"harmless")
    assert client.get(f"/api/jobs/{jid}/inspect/structure", params={"path": "../../etc/passwd"}).status_code == 404
