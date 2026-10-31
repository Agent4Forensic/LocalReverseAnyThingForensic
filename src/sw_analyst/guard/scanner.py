"""Prompt-injection scanner for untrusted sample text.

The scanner normalises text (NFKC, hidden characters, homoglyphs, whitespace,
comment leaders, simple escapes) while keeping an index map back to the original
text, then applies English and German rules. Pure standard library; all regexes
use bounded quantifiers to avoid catastrophic backtracking.

Severity: high = clear instruction to the AI / override / exfiltration / breakout /
encoded; medium = role markers, persona, verdict manipulation; low = keywords.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from array import array
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

GUARD_VERSION = "guard-1.0.0"

_SEV_ORDER = {"low": 1, "medium": 2, "high": 3}

_MAX_PER_RULE = 200
_MAX_TOTAL = 2000
_MAX_BLOBS = 300
_MAX_BLOB_DECODE = 262144       # chars of one blob that are decoded
_MAX_DECODE_BUDGET = 2_000_000  # total decoded chars per scan
_MAX_DEPTH = 2
_SNIPPET_MAX = 200


@dataclass
class Detection:
    rule: str
    category: str
    severity: str  # 'low' | 'medium' | 'high'
    start: int     # offsets in the ORIGINAL text
    end: int
    snippet: str


# --------------------------------------------------------------------------- normalisation

_HOMOGLYPH: dict[str, str] = {}
for _src, _dst in (
    # Cyrillic (lowercase; uppercase is lowered before lookup)
    ("авсеёорхуіїјѕһԁԛԝкмнтгѵ", "abceeopxyiijshdqwkmhtrv"),
    # Greek
    ("αβεηικμνορτυχγω", "abeniukvvoptuxyw"),
    ("ςϲ", "sc"),
    # Latin lookalikes / small caps
    ("ɑɡıᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘʀꜱᴛᴜᴠᴡʏᴢ", "agiabcdefghijklmnoprstuvwyz"),
):
    for _a, _b in zip(_src, _dst):
        _HOMOGLYPH[_a] = _b

_DE = {"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss"}
_EXTRA_HIDDEN = {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D,
                 0x3164, 0xFFA0, 0x2800 * 0}  # 0 entry is harmless
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_WEAK_HIDDEN = {0x200C, 0x200D, 0xFE0E, 0xFE0F, 0x200E, 0x200F, 0xFEFF, 0x00AD}

_ENTITY = {"lt": "<", "gt": ">", "amp": "&", "quot": '"', "apos": "'", "nbsp": " "}

_SPECIAL_RX = re.compile(
    r"([^\x20-\x7e\t\n\r]+)"
    r"|(\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|&#[xX][0-9a-fA-F]{1,6};|&#[0-9]{1,7};"
    r"|&(?:lt|gt|amp|quot|apos|nbsp);)"
)


@lru_cache(maxsize=8192)
def _fold(c: str) -> tuple[int, str]:
    """Return (kind, replacement). kind: 0 keep, 1 hidden char, 2 silently dropped."""
    cp = ord(c)
    if c in "\x0b\x0c":
        return (0, " ")
    if cp < 0x20 or cp == 0x7F:
        return (2, "")
    cat = unicodedata.category(c)
    if (cat == "Cf" or cp in _EXTRA_HIDDEN or 0xFE00 <= cp <= 0xFE0F
            or 0xE0100 <= cp <= 0xE01EF):
        return (1, "")
    if cat in ("Cc", "Cs", "Co", "Cn"):
        return (2, "")
    n = unicodedata.normalize("NFKC", c).lower()
    out: list[str] = []
    for ch in n:
        if ch in _DE:
            out.append(_DE[ch])
            continue
        if ch.isspace():
            out.append(" ")
            continue
        for dc in unicodedata.normalize("NFKD", ch):
            if unicodedata.category(dc) in ("Mn", "Me"):
                continue
            dc = dc.lower()
            for x in dc:
                out.append(_HOMOGLYPH.get(x, x))
    return (0, "".join(out))


class _View:
    __slots__ = ("s", "st", "en")

    def __init__(self, s: str, st: array, en: array):
        self.s, self.st, self.en = s, st, en


_WS_RX = re.compile(r"(?:\\[nrt]|\s){2,}|\\[nrt]|[^\S ]")
_LEAD_RX = re.compile(
    r"\n(?:(?://+|/\*+|\*+/|\*+|#+|--+|;+|<!--|-->|'+|%+|>+|rem\b)[ ]?)+"
)


def _rebuild(v: _View, rx: re.Pattern, fn) -> _View:
    s, st, en = v.s, v.st, v.en
    out: list[str] = []
    nst, nen = array("i"), array("i")
    pos = 0
    found = False
    for m in rx.finditer(s):
        found = True
        a, b = m.span()
        if a > pos:
            out.append(s[pos:a])
            nst.extend(st[pos:a])
            nen.extend(en[pos:a])
        rep = fn(m)
        if rep:
            out.append(rep)
            nst.append(st[a])
            nen.append(en[b - 1])
        pos = b
    if not found:
        return v
    if pos < len(s):
        out.append(s[pos:])
        nst.extend(st[pos:])
        nen.extend(en[pos:])
    return _View("".join(out), nst, nen)


def _ws_rep(m: re.Match) -> str:
    run = m.group()
    if "\n" in run or "\r" in run or "\\n" in run or "\\r" in run:
        return "\n"
    return " "


@dataclass
class _Norm:
    m: _View                 # marker view (newlines kept, comment leaders kept)
    a: _View                 # phrase view (comment leaders after newline removed)
    hidden: list             # (start, end, char)


def _normalize(text: str) -> _Norm:
    out: list[str] = []
    st, en = array("i"), array("i")
    hidden: list = []
    pos = 0

    def put_ascii(a: int, b: int) -> None:
        out.append(text[a:b].lower())
        st.extend(range(a, b))
        en.extend(range(a + 1, b + 1))

    def emit(ch: str, s_: int, e_: int) -> None:
        kind, rep = _fold(ch)
        if kind == 0:
            if rep:
                out.append(rep)
                for _ in rep:
                    st.append(s_)
                    en.append(e_)
        elif kind == 1:
            hidden.append((s_, e_, ch))

    for m in _SPECIAL_RX.finditer(text):
        a, b = m.span()
        if a > pos:
            put_ascii(pos, a)
        if m.lastindex == 1:
            for i in range(a, b):
                emit(text[i], i, i + 1)
        else:
            tok = m.group(2)
            ch: Optional[str] = None
            try:
                if tok.startswith("\\u"):
                    ch = chr(int(tok[2:], 16))
                elif tok.startswith("\\x"):
                    v = int(tok[2:], 16)
                    ch = chr(v) if v < 0x80 else None
                elif tok.startswith("&#x") or tok.startswith("&#X"):
                    ch = chr(int(tok[3:-1], 16))
                elif tok.startswith("&#"):
                    ch = chr(int(tok[2:-1]))
                else:
                    ch = _ENTITY[tok[1:-1]]
            except (ValueError, OverflowError):
                ch = None
            if ch is None:
                put_ascii(a, b)
            elif ord(ch) < 0x80 and ch not in "\t\n\r" and 0x20 <= ord(ch) <= 0x7E:
                out.append(ch.lower())
                st.append(a)
                en.append(b)
            else:
                emit(ch, a, b)
        pos = b
    if pos < len(text):
        put_ascii(pos, len(text))
    v1 = _View("".join(out), st, en)
    vm = _rebuild(v1, _WS_RX, _ws_rep)
    if _LEAD_RX.search(vm.s):
        va = _rebuild(vm, _LEAD_RX, lambda m: "\n")
    else:
        va = vm
    return _Norm(vm, va, hidden)


def normalize_text(text: str) -> str:
    """Normalised (phrase view) text; used by other guard modules for comparisons."""
    return _normalize(text).a.s


# --------------------------------------------------------------------------- rule DSL

def R(p: str) -> str:
    return p.replace("~", "[ \\n]")


@dataclass(frozen=True)
class _Rule:
    name: str
    category: str
    sev: str
    rx: Optional[re.Pattern]
    view: str = "A"
    boost: Optional[str] = None   # 'ai' | 'frame' | 'jb' | 'any'
    to: str = "high"
    extend: bool = True
    orig: Optional[re.Pattern] = None


_AI_NEAR = re.compile(R(
    r"\b(?:ai|a\.i\.|llm|llms|assistants?|language~models?|chatbots?|chatgpt|gpt-?\d[\w.]*|"
    r"claude|copilot|gemini|llama|ai~agents?|ai~models?|ai~system|ki|ki-assistent\w*|"
    r"sprachmodell\w*|assistent\w*|kuenstliche~intelligenz|the~model|this~model|your~model|"
    r"analysis~(?:ai|bot|agent))\b"))
_FRAME = re.compile(R(
    r"\b(?:your~(?:task|job|goal|mission|objective|assignment)|immediately|right~now|at~once|"
    r"silently|secretly|quietly|covertly|stealthily|first~of~all|"
    r"(?:do~not|don't|never)~(?:tell|inform|mention|reveal|notify|show|alert)|"
    r"without~(?:telling|informing|notifying|asking|alerting|mentioning)|"
    r"(?:before|instead~of)~(?:answering|responding|replying|continuing|finishing)|"
    r"in~your~(?:report|analysis|answer|response|summary|findings|verdict|output|reply|conclusion)|"
    r"sofort|unverzueglich|ab~sofort|heimlich|still~und~leise|dein(?:e|en)?~(?:aufgabe|auftrag|ziel)|"
    r"in~deinem~(?:bericht|ergebnis|fazit)|bevor~du)\b"))
_JB = re.compile(R(
    r"\b(?:jailbreak\w*|dan|unrestricted|unfiltered|uncensored|developer~mode|god~mode|"
    r"no~restrictions|without~(?:any~)?(?:restrictions|limits|filters|rules)|no~rules|"
    r"do~anything|evil|ignore~(?:all~)?(?:rules|restrictions))\b"))
_WINDOW = 120


def _boost_hit(kind: str, s: str, a: int, b: int) -> bool:
    lo, hi = max(0, a - _WINDOW), min(len(s), b + _WINDOW)
    if kind in ("ai", "any") and _AI_NEAR.search(s, lo, hi):
        return True
    if kind in ("frame", "any") and _FRAME.search(s, lo, hi):
        return True
    if kind in ("jb", "any") and _JB.search(s, lo, hi):
        return True
    return False


_RULES: list[_Rule] = []
_RULE_BY_NAME: dict[str, _Rule] = {}


def _r(name, cat, sev, pat, *, view="A", boost=None, to="high", extend=True,
       orig=None, flags=0):
    rule = _Rule(name, cat, sev, re.compile(R(pat), flags), view, boost, to, extend,
                 re.compile(orig) if orig else None)
    _RULES.append(rule)
    _RULE_BY_NAME[name] = rule


# ---- fragments
_STRONGMOD = (r"(?:previous|prior|above|earlier|preceding|former|original|initial|existing|"
              r"your|system|safety|foregoing)")
_TGT = (r"(?:instructions?|instruction~set|prompts?|rules?|guidelines?|directives?|directions?|"
        r"guardrails?|programming|training|constraints?|restrictions?|commands?|orders?|"
        r"safeguards?|policies|policy|context|messages?|conversation|settings)")
_FILLER = (r"(?:all|any|every|the|these|those|of|and|or|my|other|what|that|you|were|was|been|have|"
           r"told|said|given|so|far|safety|content|ethical|security|initial|system)")
_AI_ADDR = (r"(?:ai|a\.i\.|llms?|ai~assistants?|assistants?|language~models?|large~language~models?|"
            r"chatbots?|chatgpt|gpt-?\d[\w.]*|gpt|claude|copilot|gemini|llama|ai~agents?|ai~models?|"
            r"ai~systems?|ai~analy\w+|ai~tools?|ai~readers?|ai~reviewers?|ki|ki-assistent\w*|"
            r"ki-modell\w*|ki-system\w*|sprachmodell\w*|assistent\w*|kuenstliche~intelligenz|"
            r"automated~(?:analy\w+|systems?|reviewers?|scanners?|tools?)|"
            r"analysis~(?:ai|bot|agent|assistant)|security~(?:ai|assistant|bot)|"
            r"reverse~engineering~(?:ai|assistant|agent|tool|model))")
_URLISH = (r"(?:https?://|ftp://|www\.|\w[\w.-]{0,40}\.(?:com|net|org|io|ru|cn|xyz|top|tk|info|biz|onion)\b|"
           r"[\w.+-]+@[\w-]+\.\w{2,}|\d{1,3}(?:\.\d{1,3}){3})")
_BENIGN_WORD = (r"(?:benign|harmless|safe|clean|legitimate|non-?malicious|innocuous|trustworthy|trusted|"
                r"not~(?:a~)?(?:malicious|malware|virus|threat|dangerous|harmful|suspicious|trojan|ransomware)|"
                r"no~threat|false~positive|free~of~malware|virus-?free)")
_DE_BENIGN = (r"(?:harmlos|sicher|ungefaehrlich|unbedenklich|legitim|gutartig|sauber|"
              r"vertrauenswuerdig)")

# ---- override
_r("ovr_prev_instructions", "override", "high",
   r"\b(?:(?:ignore|disregard|forget|override|overwrite|discard|abandon|neglect|dismiss|bypass|skip|"
   r"drop|supersede|negate)|(?:do~not|don't|dont|never|stop)~(?:follow|obey|listen~to|heed|adhere~to|"
   r"comply~with)(?:ing)?)~(?:" + _FILLER + r"~){0,4}" + _STRONGMOD + r"~(?:" + _FILLER + r"~){0,3}"
   + _TGT + r"\b")
_r("ovr_everything_above", "override", "high",
   r"\b(?:ignore|disregard|forget)~(?:everything|all|anything)~(?:above|before|prior|previous|"
   r"(?:you|i|we|they)~(?:were|have|had|know|knew|learned|said|told|got)|that~(?:was|came|has|you)|"
   r"so~far|else|until~now|said|written|stated|preceding|up~to~here)\b")
_r("ovr_above_generic", "override", "medium",
   r"\b(?:ignore|disregard|forget)~(?:(?:all|any|the|of|everything|what|that|is|was)~){0,3}"
   r"(?:above|preceding|foregoing|aforementioned|previous(?:ly)?|prior|earlier)\b"
   r"(?!~(?:error|errors|warning|warnings|exception|exceptions|version|versions|line|lines|call|calls|"
   r"result|results|value|values|entry|entries|step|steps|item|items|row|rows|record|records))",
   boost="any")
_r("ovr_de_prev_instructions", "override", "high",
   r"\b(?:ignorier\w*|missacht\w*|vergiss\w*|vergess\w*|ueberschreib\w*|ueberspring\w*|verwirf\w*|"
   r"umgeh\w*|setz\w*~\w+~ausser~kraft|beacht\w*~(?:\w+~)?nicht|befolg\w*~(?:\w+~)?nicht)~"
   r"(?:(?:die|der|das|den|dem|und|oder|bitte|jetzt|einfach|sicherheits|system)~){0,3}"
   r"(?:(?:alle[nrs]?|saemtliche[nrs]?|jegliche[nrs]?|deine[nrs]?|bisherige[nrs]?|vorherige[nrs]?|"
   r"vorige[nrs]?|vorangegangene[nrs]?|vorhergehende[nrs]?|obige[nrs]?|fruehere[nrs]?|"
   r"oben~genannte[nrs]?|ursprueglich\w*|urspruengliche[nrs]?|system|vorab)~)+"
   r"(?:(?:alle|diese|bisherigen|vorherigen|sicherheits|system)~){0,2}"
   r"(?:anweisung\w*|instruktion\w*|regel\w*|vorgabe\w*|befehl\w*|richtlinie\w*|aufforderung\w*|"
   r"prompt\w*|systemprompt\w*|systemanweisung\w*|einschraenkung\w*|vorschrift\w*|direktive\w*|"
   r"leitlinie\w*|kontext\w*|auftraege?|auftrag|nachricht\w*)\b")
_r("ovr_de_everything", "override", "high",
   r"\b(?:ignorier\w*|vergiss\w*|vergess\w*|missacht\w*)~(?:bitte~)?(?:alles|saemtliches)"
   r"~(?:davor|zuvor|vorher|obige\w*|oben\w*|bisherige\w*|bisher|gesagt\w*|geschrieben\w*|bis~jetzt|"
   r"was~(?:du|ich|wir|man|vorher|zuvor|bisher|oben)\b)")
_r("ovr_de_everything_bare", "override", "medium",
   r"\b(?:vergiss|vergess\w*|ignorier\w*)~(?:bitte~)?alles\b", boost="any")
_r("ovr_from_now_on", "override", "medium",
   r"\bfrom~now~on[, ]{0,2}(?:you|always|only|ignore|respond|answer|reply|never|do~not|don't|act|"
   r"behave|treat|use|output|say|call|write|all)\b", boost="ai")
_r("ovr_stop_analysis", "override", "medium",
   r"\b(?:stop|cease|abort|halt|terminate|cancel|discontinue)~(?:(?:your|the|this|any|all|further|"
   r"current)~){0,2}(?:analy[sz]\w+|investigation|task|work|reverse~engineering|processing|"
   r"examination|review|scan(?:ning)?)\b(?:~(?:now|immediately|here|at~once|right~now))?"
   r"|\bdo~not~(?:analy[sz]e|investigate|examine|inspect|decompile|disassemble|continue|proceed)"
   r"~(?:(?:this|the|any|further|more|these|it|file|sample|binary|code|anything|with)~){0,3}\w*",
   boost="any")
_r("ovr_disable_safety", "override", "medium",
   r"\b(?:disable|turn~off|bypass|remove|circumvent|deactivate|lift|switch~off|override|violate)~"
   r"(?:(?:all|the|any|these|those|every|its|of|and|content|ethical|moral)~){0,3}"
   r"(?:safety|ethics|ethical|guardrails?|safeguards?|censorship|alignment|restrictions|limitations|"
   r"content~filters?|safety~filters?|safety~(?:checks?|measures?|rules?|guidelines)|constraints|"
   r"moderation|guidelines|policies)\b", boost="any")
_r("ovr_your_safeguards", "override", "high",
   r"\b(?:disable|bypass|remove|circumvent|deactivate|lift|override|ignore|violate|break|disregard|"
   r"forget|drop|abandon|stop~following)~your~(?:\w+~){0,2}?(?:safety|ethic\w*|guardrails?|safeguards?|"
   r"filters?|restrictions|limitations|programming|constraints|rules|guidelines|policies|instructions|"
   r"training|moderation|alignment|principles|values|boundaries|limits)\b")

# ---- persona
_r("per_you_are_now", "persona", "medium",
   r"\byou(?:'re|~are)~(?:now|no~longer|henceforth)\b", boost="any")
_r("per_act_as", "persona", "medium",
   r"\b(?:please~)?(?:act|behave)~(?:as|like)~(?:if~you~(?:were|are)~)?(?:an?~|the~|my~|our~)?"
   r"(?:\w+~){0,2}?(?:ai|assistant|expert|hacker|admin\w*|developer|unrestricted|unfiltered|jailbroken|"
   r"uncensored|system|root|interpreter|terminal|shell|dan|llm|chatbot|translator|analyst|evil|human|"
   r"person|character|persona|linux|console|oracle|god|devil|pirate|attacker|operator|moderator|"
   r"compiler|debugger|sandbox)\b", boost="any")
_r("per_pretend", "persona", "medium",
   r"\b(?:pretend~(?:to~be|you~are|that~you|you're)|role-?play~as|simulate~being|imagine~you~are|"
   r"assume~the~role~of|take~on~the~role|play~the~role~of|play~the~part)\b", boost="any")
_r("per_dan", "persona", "medium",
   r"\b(?:(?:you~are|you're|act~as|be|become|as|called|named|is|enable|activate|enter|switch~to|"
   r"pretend~to~be|play|roleplay~as|simulate)~(?:now~)?(?:the~)?dan\b(?:~(?:mode|persona|character|"
   r"version|prompt))?|dan~(?:mode|persona|prompt|protocol|jailbreak)\b|dan[:,]~(?:you|from~now))",
   boost="any", orig=r"\bDAN\b")
_r("per_do_anything_now", "persona", "high", r"\bdo~anything~now\b")
_r("per_jailbroken", "persona", "high",
   r"\byou(?:'re|~are|~have~been|~were)~(?:now~)?(?:jailbroken|freed|unleashed|liberated|unlocked|"
   r"unshackled)\b|\bjailbreak(?:ed)?~(?:mode|prompt|persona|protocol|version|activated|enabled|engaged)\b"
   r"|\b(?:enable|activate|enter|enabled|activated|engage)~(?:the~)?jailbreak\b")
_r("per_dev_mode", "persona", "medium",
   r"\b(?:enable|enabled|activate|activated|enter|entered|switch(?:ed)?~to|turn~on|turned~on|entering|"
   r"now~in|you~are~in|engage|unlock)~(?:the~|a~|your~|my~)?(?:developer|dev|god|jailbreak|"
   r"unrestricted|dan|unfiltered|uncensored|sudo)~mode\b", boost="any")
_r("per_new_instructions", "persona", "medium",
   r"\b(?:new|updated|revised|additional|secret|hidden|special|priority|urgent|override|real|actual)~"
   r"(?:system~)?(?:instructions?|directives?|orders?|prompt)\b", boost="any")
_r("per_prompt_extract_your", "persona", "high",
   r"\b(?:reveal|show|print|repeat|output|display|leak|disclose|tell~me|dump|give~me|share|expose|"
   r"reproduce|recite|copy|what~(?:is|are))~(?:me~)?(?:your|you're|ur)~(?:(?:full|entire|complete|hidden|"
   r"secret|initial|original|system|exact)~){0,3}(?:system~prompt|instructions|prompt|initial~prompt|"
   r"rules|guidelines)\b")
_r("per_prompt_extract", "persona", "medium",
   r"\b(?:reveal|show|print|repeat|output|display|leak|disclose|dump|share|expose|reproduce|recite)~"
   r"(?:me~)?(?:the~|this~|all~|above~)?(?:(?:full|entire|complete|hidden|secret|initial|original)~){0,3}"
   r"(?:system~prompt|initial~prompt)\b", boost="any")
_r("per_system_prompt_override", "persona", "medium",
   r"\b(?:new|updated|override|replace|replaced|overwrite|overwritten|change|modify|rewrite)~"
   r"(?:(?:the|your|this|my|all|any|previous|original)~)*system~prompt\b", boost="any")
_r("per_you_are_ai", "persona", "medium",
   r"\byou~are~(?:an?|the)~(?:\w+~){0,3}?(?:assistant|ai|llm|chatbot|language~model)\b")
_r("per_de_du_bist_jetzt", "persona", "medium",
   r"\b(?:du~bist~(?:jetzt|nun|ab~jetzt|ab~sofort|von~nun~an)|ab~(?:jetzt|sofort)~(?:bist|wirst|musst|"
   r"sollst|agierst|verhaeltst)~du|ab~jetzt~(?:musst|sollst|wirst|darfst|antwortest|verhaeltst)|"
   r"von~nun~an~(?:bist|musst|sollst|wirst|antwortest)|verhalte~dich~(?:ab~jetzt~)?(?:wie|als)|"
   r"agiere~(?:ab~jetzt~)?als|handle~(?:ab~jetzt~)?als|tu~so~als~(?:ob|waerst|wuerdest)|"
   r"stell~dir~vor,?~du~(?:bist|waerst)|spiel\w*~(?:die|eine)~rolle|schluepf\w*~in~die~rolle|"
   r"nimm~die~rolle~(?:von|eines|einer)|deine~neue~(?:aufgabe|rolle|anweisung\w*|mission|identitaet|"
   r"persoenlichkeit))\b", boost="any")
_r("per_de_neue_anweisung", "persona", "medium",
   r"\bneue[nr]?~(?:anweisung\w*|instruktion\w*|regel\w*|vorgabe\w*|befehl\w*|systemprompt|"
   r"systemanweisung\w*|aufgabe)\b", boost="any")
_r("per_de_extract", "persona", "high",
   r"\b(?:zeige|nenne|gib|verrate|wiederhole|drucke|offenbare|liste)\b[^\n]{0,30}?"
   r"deine[nrs]?~(?:\w+~){0,2}(?:systemprompt|system-prompt|systemanweisung\w*|anweisungen|prompt|"
   r"instruktionen|regeln)\b")
_r("kw_system_prompt", "persona", "low", r"\bsystem[ -]prompts?\b|\bsystemprompt\b|\bsystemanweisung\w*")
_r("kw_developer_mode", "persona", "low",
   r"\b(?:developer|god|sudo)~mode\b|\bentwickler-?modus\b")
_r("kw_jailbreak", "persona", "low", r"\bjailbreak\w*|\bprompt~injection\b|\bllm~injection\b",
   boost="ai", to="medium")

# ---- chat markers (marker view)
_r("cm_special_tokens", "chat_marker", "high",
   r"<\|(?:im_start|im_end|system|user|assistant|endoftext|eot_id|eom_id|start_header_id|"
   r"end_header_id|begin_of_text|end_of_text|fim_prefix|fim_middle|fim_suffix|tool_call|"
   r"tool_response|python_tag|reserved_special_token_\d+|channel|message|constrain|developer|sep|pad|"
   r"bos|eos|start|end|return|call)\|>", view="M", extend=False)
_r("cm_pipe_generic", "chat_marker", "medium", r"<\|[a-z_][a-z0-9_]{1,30}\|>", view="M", extend=False)
_r("cm_llama", "chat_marker", "high",
   r"\[/?inst\]|<<~?/?~?sys~?>>|\[/?system_prompt\]|\[/?available_tools\]|\[/?tool_calls?\]|"
   r"\[/?tool_results\]", view="M", extend=False)
_r("cm_gemma_turn", "chat_marker", "high", r"<(?:start|end)_of_turn>", view="M", extend=False)
_r("cm_md_header", "chat_marker", "medium",
   r"(?m)^ ?#{3}~(?:system|instructions?|human|assistant|user|response|input|developer)\b",
   view="M", extend=False)
_r("cm_role_prefix", "chat_marker", "medium",
   r"(?m)^ ?(?:system|assistant|human|developer)~?:", view="M", extend=False)
_r("cm_role_bracket", "chat_marker", "medium",
   r"(?m)^ ?\[(?:system|assistant|human|developer|user)\]", view="M", extend=False)
_r("cm_role_json", "chat_marker", "medium",
   r"\\*[\"']role\\*[\"']~?:~?\\*[\"'](?:system|assistant|developer)\\*[\"']", view="M", extend=False)
_r("cm_untrusted_tag", "chat_marker", "high",
   r"<~?/?~?untrusted[_ -]?data\b[^>\n]{0,100}>?", view="M", extend=False)
_r("cm_untrusted_kw", "chat_marker", "medium", r"\buntrusted[_ -]data\b", view="M", boost="any")
_r("cm_xml_tool", "chat_marker", "high",
   r"<~?/?~?(?:function_calls?|function_results?|tool_call|tool_use|tool_result|invoke|antml:\w+|"
   r"system_prompt)\b[^>\n]{0,100}>", view="M", extend=False)
_r("cm_xml_wrapper", "chat_marker", "medium",
   r"<~?/?~?(?:system|assistant|human|instructions?|developer|thinking|scratchpad|admin|"
   r"user_message|assistant_message)\b[^>\n]{0,60}>", view="M", extend=False)

# ---- fake tool / action JSON
_r("fa_action_json", "fake_action", "high",
   r"\\*[\"']action\\*[\"']~?:~?\\*[\"'](?:tool|finish)\\*[\"']", view="M", extend=False)
_r("fa_tool_args", "fake_action", "high",
   r"\\*[\"']tool\\*[\"']~?:~?\\*[\"'][a-z_][a-z0-9_]{1,40}\\*[\"']~?,~?\\*[\"']args\\*[\"']~?:|"
   r"\\*[\"']args\\*[\"']~?:~?\{[^}\n]{0,200}\}~?,~?\\*[\"']why\\*[\"']", view="M", extend=False)
_r("fa_finish_json", "fake_action", "high",
   r"\\*[\"']findings\\*[\"']~?:~?\[~?\{~?\\*[\"']statement\\*[\"']|"
   r"\\*[\"']evidence\\*[\"']~?:~?\[~?\{~?\\*[\"']id\\*[\"']~?:~?\\*[\"']ev-\d{6}|"
   r"\\*[\"']status\\*[\"']~?:~?\\*[\"']confirmed\\*[\"']~?,~?\\*[\"']evidence\\*[\"']",
   view="M", extend=False)
_r("fa_use_tool", "fake_action", "medium",
   r"\b(?:use|call|invoke|run|execute|trigger)~(?:the~)?(?:tool|function)\b[^\n]{0,20}?"
   r"(?:delete|remove|write|send|upload|exec|shell|cmd|command|download)", boost="any")

# ---- exfiltration / execution / concealment
_r("ex_send_url", "exfil_exec", "medium",
   r"\b(?:send|upload|post|transmit|forward|exfiltrate|email|e-mail|leak|submit|transfer|mail|beam|"
   r"push|ship|relay|deliver|dump)\b[^\n]{0,80}?\b(?:to|at|via|towards|into|onto)~"
   r"(?:the~|this~|my~|our~)?(?:(?:remote|external|attacker|c2|server|url|endpoint|webhook|address|"
   r"host|site|website|domain|email|mailbox|ip)~)*" + _URLISH, boost="any")
_r("ex_send_ai_object", "exfil_exec", "high",
   r"\b(?:send|upload|post|transmit|forward|leak|exfiltrate|email|submit)\b~(?:me~|us~)?"
   r"(?:the~|this~|your~|all~)?(?:\w+~){0,2}?(?:conversation|chat~history|system~prompt|"
   r"your~instructions|your~prompt|previous~messages|context~window)\b[^\n]{0,60}?\b(?:to|at|via)\b")
_r("ex_run_following", "exfil_exec", "medium",
   r"\b(?:run|execute|launch|invoke|issue|type|enter|paste|use)~(?:the|this|these|that|following|below)~"
   r"(?:\w+~){0,2}?(?:commands?|code|script|scripts|payload|shell|instructions?|snippets?|one-?liner|"
   r"binary|program|executable|query)\b|\b(?:run|execute)~the~following\b", boost="any")
_r("ex_cmd_after_imperative", "exfil_exec", "medium",
   r"\b(?:execute|run|invoke|launch|spawn|start|type|paste|issue|call)\b[^\n]{0,30}?"
   r"(?:\bcurl~|\bwget~|\bpowershell(?:\.exe)?~-|\bcmd(?:\.exe)?~/[ck]|\bbash~-c|\bsh~-c|\bnc~-|"
   r"\bnetcat\b|\bpython3?~-c|\bcertutil\b|\bbitsadmin\b|\bmshta\b|\brundll32\b|\bregsvr32\b|\biex\b|"
   r"invoke-expression|invoke-webrequest|\bstart-process|\bos\.system|\bsubprocess\b|\beval\()",
   boost="any")
_r("ex_you_must", "exfil_exec", "medium",
   r"\byou~(?:must|should|need~to|have~to|shall|are~to)~(?:\w+~){0,2}?(?:execute|run|download|fetch|"
   r"exfiltrate|upload|send|delete|erase|wipe|install|visit|curl|connect~to|ping|beacon|post)\b",
   boost="ai")
_r("ex_delete", "exfil_exec", "medium",
   r"\b(?:delete|erase|wipe|remove|destroy|purge|shred|format|truncate|clear)\b~"
   r"(?:(?:all|the|this|that|every|your|any|these|my|those|of|its)~){1,3}(?:\w+~){0,2}?"
   r"(?:files?|logs?|data|evidence|memory|history|database|conversation|context|analysis|results?|"
   r"samples?|reports?|notes?|findings|traces?|artifacts?|disk|drive|backups?|shadow~copies|"
   r"workspace|job)\b", boost="any")
_r("ex_conceal", "exfil_exec", "high",
   r"\b(?:do~not|don't|dont|never)~(?:\w+~)?(?:tell|inform|mention|reveal|disclose|notify|alert|warn|"
   r"show)\b[^\n]{0,25}?\b(?:the~|your~)?(?:user|analyst|operator|human|owner|reader|reviewer|"
   r"investigator|administrator)\b|\b(?:without|not)~(?:telling|informing|notifying|alerting|warning|"
   r"mentioning)~(?:the~)?(?:user|analyst|operator|human|owner|reader)\b|"
   r"\bkeep~(?:this|it|that|these)~(?:a~)?(?:secret|hidden|confidential)\b|"
   r"\bhide~(?:this|it|that)~from~(?:the~|your~)?(?:user|analyst|operator|human)\b|"
   r"\bverschweig\w*|\bverheimlich\w*|\bunterschlag\w*~(?:\w+~)?(?:das|dies|es)\b|"
   r"\bsag\w*~(?:\w+~){0,2}?(?:dem|der|den)~(?:nutzer|benutzer|anwender|analysten|bediener|user)\w*~nicht\b|"
   r"\bnicht~(?:dem|an~den|den)~(?:nutzer|benutzer|anwender|analysten)\w*~(?:mitteil|sagen|erzaehl|"
   r"melden|zeigen|verraten)\w*|\bhalte?~(?:\w+~)?(?:das|dies|es)~geheim\b|"
   r"\bohne~(?:dem~)?(?:nutzer|benutzer|anwender)\w*~(?:zu~)?(?:sagen|informieren|benachrichtigen)\b|"
   r"\b(?:erwaehn\w*|verrat\w*)~(?:\w+~){0,2}nicht\b[^\n]{0,30}?(?:nutzer|benutzer|anwender|analyst)")
_r("ex_de_send", "exfil_exec", "medium",
   r"\b(?:sende|schick\w*|sendet|uebertrage\w*|uebermittle\w*|lade|poste|leite|exfiltriere|maile|"
   r"uebersende)\b[^\n]{0,80}?\b(?:an|nach|zu|auf|per)\b[^\n]{0,20}?" + _URLISH, boost="any")
_r("ex_de_exec", "exfil_exec", "medium",
   r"\b(?:fuehr\w*|starte\w*|ruf\w*|nutze|verwende)~(?:\w+~){0,2}?(?:folgende\w*|nachstehende\w*|"
   r"untenstehende\w*|diese\w*|obige\w*)~(?:\w+~){0,2}?(?:befehl\w*|code|skript\w*|script\w*|"
   r"kommando\w*|anweisung\w*|programm|payload|shell\w*|commands?)\b", boost="any")
_r("ex_de_delete", "exfil_exec", "medium",
   r"\bloesch\w*~(?:(?:alle|die|den|das|saemtliche|diese[nrs]?|deine|jede[nrs]?)~){1,3}(?:\w+~){0,2}?"
   r"(?:dateien|datei|logs?|daten|beweise|beweismittel|speicher|verlauf|historie|datenbank|"
   r"konversation|kontext|analyse|ergebnisse|proben?|berichte?|notizen|spuren|artefakte|festplatte|"
   r"laufwerk|backups?|schattenkopien)\b", boost="any")
_r("kw_cmdline", "exfil_exec", "low",
   r"\b(?:curl|wget)~|\bpowershell(?:\.exe)?~-|\bcmd(?:\.exe)?~/[ck]\b", extend=False)

# ---- manipulation of the assessment
_r("vm_report_benign", "verdict_manip", "medium",
   r"\b(?:report|declare|conclude|classify|label|mark|rate|describe|state|characteri[sz]e|portray|"
   r"depict|certify|deem|judge|approve|whitelist|assess|evaluate|summari[sz]e|confirm|verify|claim|"
   r"regard|treat|consider|present|identify)\b[^\n]{0,60}?\b" + _BENIGN_WORD + r"\b", boost="any")
_r("vm_assertion", "verdict_manip", "medium",
   r"\b(?:this|the)~(?:file|sample|binary|program|software|application|app|executable|document|code|"
   r"script|tool|payload|dll|archive)~(?:is|are|was)~(?:completely~|totally~|100%~|absolutely~|"
   r"entirely~|perfectly~|verified~|certified~|known~to~be~|definitely~)?(?:benign|harmless|safe|"
   r"clean|legitimate|non-?malicious|innocuous|trusted|virus-?free|not~malicious|not~malware|"
   r"not~a~virus|not~a~threat|false~positive)\b|\bthis~is~(?:not|no)~(?:a~)?(?:malware|malicious|"
   r"virus|threat|trojan|ransomware|harmful|dangerous)\b", boost="ai")
_r("vm_do_not_flag", "verdict_manip", "medium",
   r"\bdo~not~(?:flag|report|detect|classify|mark|label|treat|consider|identify|regard)~"
   r"(?:this|it|the~(?:file|sample|binary))\b", boost="any")
_r("vm_answer_with", "verdict_manip", "medium",
   r"\b(?:answer|respond|reply|conclude|output|report|say|state)~(?:only~|just~|exactly~|simply~)?"
   r"(?:with|that)~[\"']?(?:benign|harmless|safe|clean|no~(?:malware|threat|findings|issues)|"
   r"nothing|all~clear|not~malicious)\b", boost="any")
_r("vm_de_dar", "verdict_manip", "medium",
   r"\bstell\w*~(?:\w+~){0,4}?(?:als~)?" + _DE_BENIGN + r"~(?:\w+~)?dar\b|"
   r"\bals~" + _DE_BENIGN + r"~(?:darstellen|einstufen|markieren|bewerten|melden|klassifizieren|"
   r"kennzeichnen|beschreiben|bezeichnen|ansehen|behandeln|deklarieren|werten)\b|"
   r"\b(?:melde\w*|berichte\w*|behaupte\w*|schreibe\w*|sage\w*|gib~an|teile~mit|erklaere\w*|"
   r"bestaetige\w*|stufe\w*)\b[^\n]{0,60}?\b(?:" + _DE_BENIGN[3:-1] + r"|keine~(?:malware|"
   r"schadsoftware|bedrohung))\b", boost="any")
_r("vm_de_assertion", "verdict_manip", "medium",
   r"\b(?:das|dies|dieses|diese|dieser)~(?:\w+~)?(?:ist|sind)~(?:\w+~)?(?:keine|kein|nicht)~"
   r"(?:malware|schadsoftware|schadprogramm|virus|bedrohung|schadcode|trojaner|boesartig|"
   r"schaedlich|gefaehrlich)\b|\bdiese[rs]?~(?:datei|probe|sample|programm|software|anwendung|"
   r"binary|code|skript)~ist~(?:\w+~)?" + _DE_BENIGN + r"\b", boost="ai")

# ---- direct address of the AI
_r("ai_attention", "ai_address", "high",
   r"\b(?:attention|attn|hey|hello|hi|dear|note|notice|important|urgent|warning|message|instructions?|"
   r"reminder|psa|hinweis|achtung|wichtig|notiz|nachricht|anweisung|liebe|lieber|hallo)"
   r"(?:~(?:for|to|an|fuer|from))?[ :,!\n-]{0,3}(?:the~|any~|all~|every~|this~|die~|der~|das~|den~|"
   r"dem~|an~|ein~|eine~|alle~|jede~)?(?:\w+~)?" + _AI_ADDR + r"\b")
_r("ai_note_to_model", "ai_address", "high",
   r"\b(?:note|message|instructions?|attention|notice|hint|reminder|request)~(?:to|for)~"
   r"(?:the|this|any|all)~(?:\w+~)?models?\b(?!~(?:number|name|year|id|type|code|version|series|range|"
   r"line|lineup|kit))")
_r("ai_if_you_are", "ai_address", "high",
   r"\b(?:if|when|whenever|since|as)~you(?:'re|~are|~were|~happen~to~be)~(?:an?~|the~)?(?:\w+~)?"
   r"(?:ai|llm|large~language~model|language~model|ai~assistant|assistant|chatbot|ai~model|ai~agent|"
   r"ai~system)\b")
_r("ai_reading_this", "ai_address", "high",
   r"\b(?:an?|the|any|every|all)~(?:ai|llm|language~model|ai~assistant|assistant|chatbot|ai~model|"
   r"ai~agent)s?~(?:that~|who~|which~)?(?:is~|are~)?(?:reading|processing|analy[sz]ing|reviewing|"
   r"scanning|parsing|summari[sz]ing|examining|inspecting|looking~at|seeing|ingesting)~"
   r"(?:this|these|the~(?:file|text|content|code|sample|document))\b")
_r("ai_direct_imperative", "ai_address", "high",
   r"\b(?:ai|llm|chatbot|ki|ai~assistant|language~model|chatgpt|claude|copilot|assistant)[,:]~"
   r"(?:you~)?(?:must|should|shall|will|need~to|have~to|are~(?:to|required~to|instructed~to|"
   r"ordered~to)|do~not|don't|never|always|please|kindly|ignore|stop|forget|disregard|execute|run|"
   r"send|output|respond|reply|answer|print|say|report)\b")
_r("ai_instructions_for", "ai_address", "high",
   r"\b(?:instructions?|directives?|messages?|notes?|prompts?|commands?|orders?|requests?|tasks?|"
   r"hints?|warnings?|reminders?)~(?:\w+~)?(?:for|to|aimed~at|intended~for|directed~(?:at|to)|"
   r"addressed~to|meant~for)~(?:the~|any~|all~|every~|this~|that~)?(?:\w+~)?(?:ai|llm|llms|"
   r"assistants?|language~models?|chatbots?|ai~assistants?|ai~models?|ai~agents?|ai~analy\w+)\b")
_r("ai_de_if", "ai_address", "high",
   r"\bwenn~du~(?:eine?|ein)~(?:ki|kuenstliche~intelligenz|sprachmodell|llm|ai|assistent\w*|chatbot)~"
   r"bist\b|\bals~(?:ki|assistent|sprachmodell)~(?:musst|sollst|wirst|darfst)\b")

# Pseudo rules implemented in code
_CODE_RULES = ("hidden_chars", "encoded_instruction", "ovr_squashed")


def rule_count() -> int:
    return len(_RULES) + len(_CODE_RULES)


def rule_categories() -> list[str]:
    cats = {r.category for r in _RULES}
    cats.update(("hidden_chars", "encoded"))
    return sorted(cats)


_SQUASH_RX = re.compile(
    r"(?:ignore|disregard|forget|override)(?:all|any|the|your|every)?(?:previous|prior|above|earlier|"
    r"preceding|former|original)(?:instructions?|prompts?|rules|guidelines|directives)"
    r"|(?:ignoriere|ignorieren|vergiss|missachte)(?:alle|die|deine|saemtliche)?(?:vorherigen?|"
    r"bisherigen?|obigen?|fruehere[n]?|vorigen?)(?:anweisungen|instruktionen|regeln|vorgaben|befehle)"
    r"|youarenow(?:dan|unrestricted|unfiltered|jailbroken)|doanythingnow|donottelltheuser"
)

# --------------------------------------------------------------------------- helpers

def _visible(s: str, limit: int = _SNIPPET_MAX) -> str:
    out = []
    for ch in s[: limit * 2]:
        if ch in "\n\r\t":
            out.append(" ")
        elif ch.isprintable():
            out.append(ch)
        else:
            out.append("<U+%04X>" % ord(ch))
    r = "".join(out)
    return r if len(r) <= limit else r[:limit] + "..."


def _mk(rule: str, cat: str, sev: str, text: str, a: int, b: int) -> Detection:
    return Detection(rule, cat, sev, a, b, _visible(text[a:b]))


def _run_rules(nm: _Norm, orig: str) -> list[Detection]:
    out: list[Detection] = []
    for rule in _RULES:
        v = nm.m if rule.view == "M" else nm.a
        s = v.s
        n = 0
        for m in rule.rx.finditer(s):
            a, b = m.span()
            if b <= a:
                continue
            sev = rule.sev
            if rule.boost and sev != rule.to and _boost_hit(rule.boost, s, a, b):
                sev = rule.to
            oa, ob = v.st[a], v.en[b - 1]
            if rule.orig is not None and not rule.orig.search(orig, oa, ob):
                continue
            out.append(_mk(rule.name, rule.category, sev, orig, oa, ob))
            n += 1
            if n >= _MAX_PER_RULE:
                break
    # squashed (letters/digits only) phrases for spaced-out obfuscation
    s = nm.a.s
    if len(s) < 3_000_000:
        parts = [(m.start(), m.end()) for m in re.finditer(r"[a-z0-9]+", s)]
        if parts and len(parts) > 1:
            sq = "".join(s[a:b] for a, b in parts)
            if any(k in sq for k in ("ignor", "disregard", "forget", "override", "vergiss",
                                      "missacht", "youarenow", "anythingnow", "tellthe")):
                idx = array("i")
                for k, (a, b) in enumerate(parts):
                    idx.extend([k] * (b - a))
                for m in _SQUASH_RX.finditer(sq):
                    ka, kb = idx[m.start()], idx[m.end() - 1]
                    oa = nm.a.st[parts[ka][0]]
                    ob = nm.a.en[parts[kb][1] - 1]
                    if any(d.severity == "high" and d.start < ob and oa < d.end for d in out):
                        continue
                    out.append(_mk("ovr_squashed", "override", "high", orig, oa, ob))
    return out


def _hidden_detections(nm: _Norm, text: str, depth: int, budget: list) -> list[Detection]:
    hid = nm.hidden
    if not hid:
        return []
    out: list[Detection] = []
    # tag characters (U+E0020..E007E) carry hidden ASCII
    i = 0
    n = len(hid)
    tag_spans = []
    while i < n:
        s_, e_, ch = hid[i]
        if 0xE0020 <= ord(ch) <= 0xE007E:
            j = i
            chars = []
            while j < n and 0xE0020 <= ord(hid[j][2]) <= 0xE007E and (j == i or hid[j][0] == hid[j - 1][1]):
                chars.append(chr(ord(hid[j][2]) - 0xE0000))
                j += 1
            tag_spans.append((hid[i][0], hid[j - 1][1], "".join(chars)))
            i = j
        else:
            i += 1
    decoded_spans = []
    for a, b, dec in tag_spans:
        if depth < _MAX_DEPTH and len(dec) >= 4:
            sub = _scan_text(dec, depth + 1, budget)
            if any(_SEV_ORDER[d.severity] >= 2 and d.category != "hidden_chars" for d in sub):
                out.append(Detection("encoded_instruction", "encoded", "high", a, b,
                                     _visible("[unicode-tag-text] " + dec)))
                decoded_spans.append((a, b))
    # clusters
    clusters = []
    cur = None
    for s_, e_, ch in hid:
        if cur and s_ - cur[1] <= 40:
            cur[1] = e_
            cur[2].append(ord(ch))
        else:
            cur = [s_, e_, [ord(ch)]]
            clusters.append(cur)
    for a, b, cps in clusters:
        strong = [c for c in cps if c not in _WEAK_HIDDEN]
        sev = "low"
        if any(c in _BIDI for c in cps) or any(0xE0000 <= c <= 0xE007F for c in cps) or len(strong) >= 2:
            sev = "medium"
        out.append(_mk("hidden_chars", "hidden_chars", sev, text, max(0, a - 10), min(len(text), b + 10)))
    return out


def _decode_blob_text(raw: bytes) -> Optional[str]:
    if not raw:
        return None
    if raw.count(0) * 3 > len(raw):
        txt = raw.decode("utf-16-le", errors="ignore")
    else:
        try:
            txt = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if len(txt) < 8:
        return None
    ok = sum(1 for ch in txt if ch.isprintable() or ch in "\t\n\r")
    if ok / len(txt) < 0.9:
        return None
    return txt


_B64_RX = re.compile(
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}(?:[ \t]*\r?\n[ \t]*[A-Za-z0-9+/_-]{4,})*={0,2}"
    r"(?![A-Za-z0-9+/_-])"
)
_HEX_RX = re.compile(
    r"(?<![0-9A-Za-z])(?:(?:0x|\\x|%)?[0-9a-fA-F]{2}[ ,;:.-]{0,2}){12,}"
)


def _b64_decode(blob: str) -> Optional[bytes]:
    s = re.sub(r"\s+", "", blob)[:_MAX_BLOB_DECODE].rstrip("=")
    if len(s) < 16:
        return None
    s = s.replace("-", "+").replace("_", "/")
    if len(s) % 4 == 1:
        s = s[:-1]
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _hex_decode(blob: str) -> Optional[bytes]:
    c = re.sub(r"0x|\\x|%", "", blob) if re.search(r"0x|\\x|%", blob) else blob
    digits = re.sub(r"[^0-9a-fA-F]", "", c)[:_MAX_BLOB_DECODE]
    if len(digits) % 2:
        digits = digits[:-1]
    if len(digits) < 24:
        return None
    try:
        return bytes.fromhex(digits)
    except ValueError:
        return None


def _encoded_detections(text: str, depth: int, budget: list) -> list[Detection]:
    if depth >= _MAX_DEPTH:
        return []
    out: list[Detection] = []
    cands = []
    for m in _B64_RX.finditer(text):
        if len(m.group()) >= 24:
            cands.append((m.start(), m.end(), m.group(), _b64_decode))
            if len(cands) >= _MAX_BLOBS:
                break
    cands2 = []
    for m in _HEX_RX.finditer(text):
        if len(m.group()) >= 24:
            cands2.append((m.start(), m.end(), m.group(), _hex_decode))
            if len(cands2) >= _MAX_BLOBS:
                break
    for a, b, blob, dec in cands + cands2:
        if budget[0] > _MAX_DECODE_BUDGET:
            break
        raw = dec(blob)
        if raw is None:
            continue
        txt = _decode_blob_text(raw)
        if txt is None:
            continue
        budget[0] += len(txt)
        sub = _scan_text(txt, depth + 1, budget)
        if any(_SEV_ORDER[d.severity] >= 2 and d.category != "hidden_chars" for d in sub):
            out.append(Detection("encoded_instruction", "encoded", "high", a, b,
                                 _visible(blob[:50] + " => " + txt[:140])))
    return out


def _scan_text(text: str, depth: int, budget: list) -> list[Detection]:
    nm = _normalize(text)
    dets = _run_rules(nm, text)
    dets += _hidden_detections(nm, text, depth, budget)
    dets += _encoded_detections(text, depth, budget)
    return dets


def scan(text: str) -> list[Detection]:
    """Scan text; returns detections sorted by start offset (offsets refer to `text`)."""
    if text is None:
        return []
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    if not isinstance(text, str):
        text = str(text)
    if not text:
        return []
    dets = _scan_text(text, 0, [0])
    dets.sort(key=lambda d: (d.start, -_SEV_ORDER[d.severity], d.rule))
    seen = set()
    uniq = []
    for d in dets:
        k = (d.rule, d.start, d.end)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(d)
        if len(uniq) >= _MAX_TOTAL:
            break
    return uniq


def rule_extends(rule: str) -> bool:
    r = _RULE_BY_NAME.get(rule)
    return bool(r.extend) if r else False
