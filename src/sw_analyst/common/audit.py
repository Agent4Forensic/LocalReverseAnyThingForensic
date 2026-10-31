"""Tamper-evident audit log: JSON lines, every line carries the hash of the previous line.

entry_hash = sha256(prev_hash + canonical_json(entry_without_hashes))
Editing, deleting or reordering any line breaks the chain and verify() reports where.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path

from sw_analyst.common.util import canonical_json, sha256_hex

GENESIS = "0" * 64


@dataclass
class AuditVerdict:
    valid: bool
    entries: int
    head_hash: str
    broken_at: int | None = None


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._head = GENESIS
        self._count = 0
        if self.path.exists():
            v = verify_file(self.path)
            if not v.valid:
                raise ValueError(f"existing audit log is corrupt at entry {v.broken_at}: {self.path}")
            self._head, self._count = v.head_hash, v.entries

    @property
    def head_hash(self) -> str:
        return self._head

    def append(self, entry: dict) -> str:
        with self._lock:
            body = dict(entry)
            body["n"] = self._count + 1
            body["prev"] = self._head
            h = sha256_hex(self._head + canonical_json(body))
            line = canonical_json({**body, "hash": h})
            with self.path.open("a", encoding="utf-8", newline="\n") as f:
                f.write(line + "\n")
            self._head, self._count = h, self._count + 1
            return h


def verify_file(path: str | Path) -> AuditVerdict:
    path = Path(path)
    if not path.exists():
        return AuditVerdict(True, 0, GENESIS)
    head, n = GENESIS, 0
    with path.open("r", encoding="utf-8") as f:
        for i, raw in enumerate(f, start=1):
            raw = raw.rstrip("\n")
            if not raw:
                continue
            try:
                obj = json.loads(raw)
                claimed = obj.pop("hash")
            except (ValueError, KeyError):
                return AuditVerdict(False, n, head, i)
            if obj.get("prev") != head or obj.get("n") != n + 1:
                return AuditVerdict(False, n, head, i)
            if sha256_hex(head + canonical_json(obj)) != claimed:
                return AuditVerdict(False, n, head, i)
            head, n = claimed, n + 1
    return AuditVerdict(True, n, head)
