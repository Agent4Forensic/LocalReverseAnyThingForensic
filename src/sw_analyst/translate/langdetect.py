"""Tiny stop-word language detector for German vs. English (no dependencies).

Protected spans (code, IDs, hashes, URLs, paths, ...) are masked first and ignored, so code-heavy
snippets do not skew the result.  Returns ``'unknown'`` when there is no or contradictory evidence.
"""
from __future__ import annotations

import re
from typing import Literal

from sw_analyst.translate.protect import PLACEHOLDER_RE, protect

__all__ = ["detect_lang"]

_EN_RAW = """
the and of to is are was were be been being it its that this these those with for on as at by from or not
but have has had will would can could should may might do does did we you they he she i an a which what when
where who how if then than there their our your his her them us me my into over under about after before
between during without within against such more most other some any all each both only own same very just
because while through up out off again once here why via
"""
_DE_RAW = """
der die das den dem des ein eine einen einem einer eines und oder aber nicht ist sind war waren wird werden
wurde wurden hat haben hatte kann können konnte muss müssen soll sollen mit von zu zum zur auf aus bei nach
über unter vor für durch gegen ohne um im am ins vom beim als wie wenn dass ob auch noch nur schon sehr
diese dieser dieses diesem diesen dies es sie er wir ihr ich du sich mir mich uns euch ihnen kein keine
keinen dann denn weil während zwischen bis seit hier dort wo was wer warum wieso welche welcher welches
bitte wurde datei sind zeige zeig analysiere prüfe
"""
_EN = set(_EN_RAW.split())
_DE = set(_DE_RAW.split())
_COMMON = _EN & _DE          # words that exist in both languages carry no information
_EN -= _COMMON
_DE -= _COMMON

_WORD = re.compile(r"[A-Za-zÄÖÜäöüß]+")
_UMLAUT = re.compile(r"[äöüÄÖÜß]")


def detect_lang(text: str) -> Literal["de", "en", "unknown"]:
    """Guess whether ``text`` is German or English."""
    if not text or not text.strip():
        return "unknown"
    masked, _ = protect(text)
    cleaned = PLACEHOLDER_RE.sub(" ", masked)
    words = [w.lower() for w in _WORD.findall(cleaned)]
    if not words:
        return "unknown"
    de = sum(1 for w in words if w in _DE)
    en = sum(1 for w in words if w in _EN)
    de += 2 * len(_UMLAUT.findall(cleaned))
    if de == 0 and en == 0:
        return "unknown"
    if de >= 1.5 * en and de > en:
        return "de"
    if en >= 1.5 * de and en > de:
        return "en"
    return "unknown"
