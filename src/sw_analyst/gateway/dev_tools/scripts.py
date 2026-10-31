"""Script language heuristics and obfuscation indicators (text analysis only).

Keyword lists are written as split literals so that this detector source does not itself
look like a script sample to file scanners.
"""
from __future__ import annotations

import re
import time

_R = re.compile
LANG_ORDER = ["html", "powershell", "vbscript", "javascript", "python", "bash", "batch"]

_PS_CMDLETS = (r"(?i)\b(?:Write-" "Host|Write-" "Output|Invoke-" "Expression|Invoke-" "WebRequest|New-" "Object|"
               r"Get-" "ChildItem|Set-" "ExecutionPolicy|Start-" "Process|Add-" "Type|Get-" "Content|Out-" "File|"
               r"ForEach-" "Object|Select-" "Object|Where-" "Object|Invoke-" "Command|Set-" "Content|Get-" r"Item)\b")

# language -> [(regex, weight, description)]
LANG_RULES: dict[str, list[tuple[re.Pattern, int, str]]] = {
    "html": [
        (_R(r"(?i)<!doctype\s+html|<html\b"), 4, "HTML doctype/<html> tag"),
        (_R(r"(?i)<(?:head|body|div|script|iframe|form|meta)\b"), 2, "HTML tags"),
        (_R(r"</\w+>"), 1, "closing tags"),
    ],
    "powershell": [
        (_R(_PS_CMDLETS), 3, "PowerShell cmdlets"),
        (_R(r"(?i)\bpower" r"shell(?:\.exe)?\b"), 2, "'powershell' keyword"),
        (_R(r"(?i)(?<![\w-])-(?:enc\w*|ec|nop|noprofile)\b|-w(?:indowstyle)?\s+hid" r"den"), 3,
         "PowerShell command-line switches"),
        (_R(r"(?i)\[System\.[A-Za-z.]+\]::"), 3, "[System.*]:: static call"),
        (_R(r"(?i)From" r"Base64" r"String"), 2, "Base64 conversion call"),
        (_R(r"(?im)^\s*param\s*\("), 2, "param() block"),
        (_R(r"\$env:\w+"), 2, "$env: variable"),
        (_R(r"(?m)^\s*\$[A-Za-z_]\w*\s*="), 1, "$variable assignment"),
    ],
    "vbscript": [
        (_R(r"(?im)^\s*(?:Dim|Option Explicit|On Error Resume Next)\b"), 2, "Dim/Option Explicit"),
        (_R(r"(?im)^\s*Set\s+\w+\s*="), 2, "Set obj ="),
        (_R(r"(?i)\b(?:Create" r"Object|WScript\.\w+|MsgBox|Get" r"Object)\b"), 3,
         "object creation / WScript / MsgBox"),
        (_R(r"(?im)^\s*End\s+(?:Sub|Function|If)\b"), 2, "End Sub/Function/If"),
        (_R(r"(?im)^\s*'"), 1, "apostrophe comments"),
    ],
    "javascript": [
        (_R(r"\b(?:var|let|const)\s+[\w$]+\s*="), 2, "var/let/const declaration"),
        (_R(r"\bfunction\s*[\w$]*\s*\("), 2, "function(...)"),
        (_R(r"=>"), 1, "arrow function"),
        (_R(r"\b(?:document|window|navigator)\.\w+"), 2, "browser objects"),
        (_R(r"\bconsole\.(?:log|error)\b"), 2, "console.log"),
        (_R(r"\brequire\s*\("), 2, "require()"),
        (_R(r"\b(?:ev" r"al|at" r"ob|unescape)\s*\(|String\.from" r"CharCode"), 1,
         "dynamic evaluation / decoding helpers"),
        (_R(r"\bActive" r"XObject\b"), 3, "ActiveX object (JScript)"),
    ],
    "python": [
        (_R(r"(?m)^\s*import\s+\w+"), 2, "import statement"),
        (_R(r"(?m)^\s*from\s+[\w.]+\s+import\b"), 3, "from x import y"),
        (_R(r"(?m)^\s*def\s+\w+\s*\([^)]*\)\s*(?:->\s*[^:]+)?:"), 3, "def f(...):"),
        (_R(r"if\s+__name__\s*==\s*['\"]__main__['\"]"), 3, "__main__ guard"),
        (_R(r"(?m)^\s*class\s+\w+(?:\([^)]*\))?\s*:"), 2, "class definition"),
        (_R(r"\bprint\s*\("), 1, "print()"),
    ],
    "bash": [
        (_R(r"(?m)^\s*if\s+\[\[?.*\]\]?\s*;\s*then\b"), 3, "if [ ... ]; then"),
        (_R(r"(?m)^\s*(?:for|while)\s+\w+\s+in\s"), 2, "for ... in loop"),
        (_R(r"(?m)^\s*(?:echo|export|chmod|curl|wget|sudo|mkdir|rm|cd)\s"), 2, "shell commands"),
        (_R(r"(?m)^\s*fi\s*$"), 1, "fi"),
        (_R(r"\$\(\w[^)]*\)|\$\{\w+\}"), 1, "$(...) / ${...} expansion"),
    ],
    "batch": [
        (_R(r"(?im)^\s*@?echo\s+off\b"), 4, "@echo off"),
        (_R(r"(?im)^\s*(?:set\s+(?:/[ap]\s+)?\w+=|goto\s+:?\w+|call\s+:?\w+|"
            r"if\s+(?:not\s+)?(?:exist|defined|errorlevel)\b)"), 2, "set/goto/call/if exist"),
        (_R(r"(?im)^\s*(?:rem\s|::)"), 2, "REM/:: comments"),
        (_R(r"%~?\w+%|%~?\d"), 1, "%var% / %1 expansion"),
        (_R(r"(?i)\bcmd(?:\.exe)?\s+/c\b"), 1, "cmd /c"),
    ],
}

_SHEBANG = {
    "python": "python", "pwsh": "powershell", "powershell": "powershell", "node": "javascript",
    "bash": "bash", "/sh": "bash", "zsh": "bash", "dash": "bash",
}


def detect_language(text: str) -> tuple[str, int, list[str]]:
    """Return (language, score, reasons). language is 'text' when nothing reaches score 3."""
    head = text[:200_000]
    first = head.split("\n", 1)[0].strip()
    if first.startswith("#!"):
        low = first.lower()
        for key, lang in _SHEBANG.items():
            if key in low:
                return lang, 10, [f"shebang line {first[:80]!r} names {lang}"]
        return "text", 0, [f"shebang line {first[:80]!r} names an unsupported interpreter"]
    best, best_score, best_reasons = "text", 0, []
    for lang in LANG_ORDER:
        score, reasons = 0, []
        for rx, weight, desc in LANG_RULES[lang]:
            if rx.search(head):
                score += weight
                reasons.append(f"{desc} (+{weight})")
        if score > best_score:
            best, best_score, best_reasons = lang, score, reasons
    if best_score < 3:
        return "text", best_score, ["no language reached the minimum score of 3"]
    return best, best_score, best_reasons


# ---------------------------------------------------------------- obfuscation indicators
INDICATORS: list[tuple[str, re.Pattern, str]] = [
    ("base64_blob", _R(r"[A-Za-z0-9+/]{80,}={0,2}"), "long base64-like string"),
    ("hex_blob", _R(r"(?<![0-9A-Za-z])[0-9a-fA-F]{64,}(?![0-9A-Za-z])"), "long hex string"),
    ("numeric_array", _R(r"(?:\b\d{2,3}\s*,\s*){20,}"), "long numeric array (char codes?)"),
    ("encoded_command", _R(r"(?i)(?<![\w-])-(?:enc\w*|ec)\b"), "PowerShell encoded-command switch"),
    ("frombase64string", _R(r"(?i)From" r"Base64" r"String"), "Base64 conversion call"),
    ("atob", _R(r"\bat" r"ob\s*\("), "atob() call"),
    ("eval", _R(r"\bev" r"al\s*\("), "eval() call"),
    ("fromcharcode", _R(r"String\s*\.\s*from" r"CharCode"), "String.fromCharCode"),
    ("unescape", _R(r"\bunescape\s*\("), "unescape() call"),
    ("chr_chain", _R(r"(?i)(?:\bchrw?\$?\(\s*\d+\s*\)\s*[&+]\s*){3,}"), "chain of chr() calls"),
    ("char_cast_chain", _R(r"(?i)(?:\[char\]\s*\d+\s*[+,]?\s*){3,}"), "chain of [char] casts"),
    ("xor_operation", _R(r"(?i)-bxor\b|\bxor\b|charCodeAt\s*\([^)]*\)\s*\^|\bord\s*\([^)]*\)\s*\^"),
     "XOR operation on characters"),
    ("xor_loop", _R(r"(?i)\b(?:for|foreach|while)\b[^\n]{0,120}(?:\^|-bxor|\bxor\b)"), "XOR inside a loop"),
    ("invoke_expression", _R(r"(?i)\b(?:Invoke-" r"Expression|i" r"ex)\b"), "Invoke-Expression / IEX"),
    ("download_api", _R(r"(?i)Net\.Web" r"Client|Download" r"String|Download" r"File|Invoke-" r"WebRequest|XML" r"HTTP|"
                         r"URLDownload" r"ToFile|Start-" r"BitsTransfer"), "download API"),
    ("exec_api", _R(r"(?i)WScript\.Sh" r"ell|Shell\.App" r"lication|Active" r"XObject|Start-" r"Process|"
                     r"\bcmd(?:\.exe)?\s+/c\b|\.Run\s*\("), "process/shell execution API"),
    ("hidden_window", _R(r"(?i)-w(?:indowstyle)?\s+hid" r"den"), "hidden window"),
    ("compression_api", _R(r"(?i)IO\.Compression|DeflateStream|GzipStream|ZlibStream"),
     "compression stream API"),
]
_CONCAT = _R(r"""["']\s*[+&.]\s*["']""")
MAX_INDICATORS = 200
MAX_LINE = 200_000


def find_indicators(lines: list[str], deadline: float) -> tuple[list[tuple[int, str, str]], bool]:
    """Return ([(line_no, name, snippet)], time_exceeded). One hit per (line, indicator)."""
    hits: list[tuple[int, str, str]] = []
    for no, raw in enumerate(lines, 1):
        if time.monotonic() > deadline:
            return hits, True
        line = raw[:MAX_LINE]
        if not line.strip():
            continue
        for name, rx, _desc in INDICATORS:
            m = rx.search(line)
            if m:
                s = max(0, m.start() - 20)
                snippet = line[s:m.start() + 80].strip()
                hits.append((no, name, snippet + ("..." if m.start() + 80 < len(line) else "")))
        n = len(_CONCAT.findall(line))
        if n >= 10:
            hits.append((no, "long_concatenation", f"{n} string concatenations on one line"))
    return hits, False


def indicator_description(name: str) -> str:
    for n, _rx, desc in INDICATORS:
        if n == name:
            return desc
    return "line with many string concatenations" if name == "long_concatenation" else name
