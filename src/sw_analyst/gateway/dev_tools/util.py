"""Small byte/text helpers shared by the DevGateway tools (static, no side effects)."""
from __future__ import annotations

import math
from collections import Counter
from typing import Iterable, Optional

_PRINT = bytes(range(0x20, 0x7F)) + b"\t\n\r"
_ALNUM_SPACE = (
    b" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)


def entropy_from_counts(counts: Iterable[int], n: int) -> float:
    if n <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def shannon_entropy(data: bytes) -> float:
    n = len(data)
    if n == 0:
        return 0.0
    h = entropy_from_counts(Counter(data).values(), n)
    return h if h > 0 else 0.0


def printable_ratio(data: bytes) -> float:
    """Share of printable ASCII (plus tab/CR/LF) bytes."""
    if not data:
        return 0.0
    return 1.0 - len(data.translate(None, _PRINT)) / len(data)


def alnum_space_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return 1.0 - len(data.translate(None, _ALNUM_SPACE)) / len(data)


def hex_bytes(data: bytes, limit: int = 32) -> str:
    s = " ".join(f"{b:02x}" for b in data[:limit])
    return s + (" ..." if len(data) > limit else "")


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        left = " ".join(f"{b:02x}" for b in chunk[:8])
        right = " ".join(f"{b:02x}" for b in chunk[8:])
        hexpart = (left + "  " + right).ljust(width * 3)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:08x}  {hexpart} |{asc}|")
    return "\n".join(lines)


def looks_utf16le(data: bytes) -> bool:
    """Heuristic: ASCII-range text stored as UTF-16LE (NUL at every odd position)."""
    head = data[:4096]
    if len(head) < 4:
        return False
    pairs = len(head) // 2
    odd_nul = head[1:2 * pairs:2].count(0)
    even_nul = head[0:2 * pairs:2].count(0)
    return odd_nul >= 0.4 * pairs and even_nul <= 0.05 * pairs


def decode_text_bytes(data: bytes) -> Optional[tuple[str, str]]:
    """Return (text, encoding) when data is text, None when it looks binary."""
    head = data[:8192]
    if not head:
        return "", "utf-8"
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16le", errors="replace"), "utf-16le"
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16be", errors="replace"), "utf-16be"
    if b"\x00" in head:
        if looks_utf16le(data):
            return data.decode("utf-16le", errors="replace"), "utf-16le"
        return None
    # control characters other than tab, LF, CR, FF, BS, ESC count as binary
    ctrl = len(head.translate(None, bytes(range(0x20, 0x100)) + b"\t\n\r\x0c\x08\x1b"))
    if ctrl > 0.05 * len(head):
        return None
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace"), "utf-8"
    return data.decode("utf-8", errors="replace"), "utf-8"


def split_lines(text: str) -> list[str]:
    """Deterministic line split on LF (CR stripped); same rule for every tool."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [ln[:-1] if ln.endswith("\r") else ln for ln in lines]


def clip(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[:n] + f"...[+{len(s) - n} chars]"
