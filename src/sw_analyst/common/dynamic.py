"""The dashboard switch for dynamic analysis (ADR-0005). Off unless the last entry of its own audit chain says on.

The chain is the state, so no change can happen without a record. A broken chain reads as off and refuses changes.
Only the dashboard API can flip this; the model has no tool for it.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from sw_analyst.common.audit import AuditLog
from sw_analyst.common.util import utcnow

FILE_NAME = "dynamic_audit.jsonl"


class DynamicSwitch:
    def __init__(self, data_dir: str | Path):
        self.path = Path(data_dir) / FILE_NAME
        self._lock = threading.Lock()
        self._on = False
        self._reason = ""
        self._changed_at = None
        self.error = ""
        try:
            self._audit = AuditLog(self.path)
        except (ValueError, OSError) as exc:
            self._audit = None
            self.error = str(exc)
            return
        if self.path.exists():
            with self.path.open("r", encoding="utf-8") as f:
                for raw in f:
                    if raw.strip():
                        entry = json.loads(raw)
                        self._on, self._reason, self._changed_at = entry["enabled"] is True, entry["reason"], entry["ts"]

    def is_on(self) -> bool:
        return self._on

    def set(self, enabled: bool, reason: str) -> dict:
        """Raises ValueError when the chain is broken or switching on has no reason."""
        reason = " ".join(reason.split())
        if self._audit is None:
            raise ValueError(f"audit chain of the switch is broken: {self.error}")
        if enabled and not reason:
            raise ValueError("switching on needs a reason")
        with self._lock:
            if enabled != self._on:
                ts = utcnow()
                self._audit.append({"ts": ts, "type": "dynamic_switch", "enabled": enabled, "reason": reason})
                self._on, self._reason, self._changed_at = enabled, reason, ts
        return self.state()

    def state(self) -> dict:
        return {"enabled": self._on, "reason": self._reason, "changed_at": self._changed_at, "error": self.error,
                "audit_head": self._audit.head_hash if self._audit else None}
