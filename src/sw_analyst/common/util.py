"""Small shared helpers."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


def utcnow() -> str:
    """ISO-8601 UTC timestamp with second precision, e.g. 2026-10-31T17:40:00Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> str:
    """Deterministic JSON used for hashing and the audit chain."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def preview(text: str, limit: int = 400) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + f"... [+{len(text) - limit} chars]"
