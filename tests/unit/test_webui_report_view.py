"""Static checks for the dashboard report/code view (STATUS P5 Code-Tab, P6, P7).

No browser here: the tests pin the classes, functions and the CSP rules that the vanilla-JS dashboard relies on
(`default-src 'self'`, no inline style or script): DOM only through h()/textContent, never innerHTML."""
import re
from pathlib import Path

STATIC = Path(__file__).resolve().parents[2] / "src" / "sw_analyst" / "webui" / "static"
JS = sorted(STATIC.glob("*.js"))


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def test_no_html_injection_or_inline_style_in_any_script():
    bad = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|\.style\.(?!setProperty)|setAttribute\('style'|\bstyle:")
    hits = [f"{p.name}:{i}" for p in JS for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if bad.search(line)]
    assert not hits, hits


def test_markdown_renders_codeblock_callout_value_and_auto_code():
    js = _read("markdown.js")
    for needle in ("codeblock", "cb-head", "cb-gutter", "navigator.clipboard", "CB_LANGS", "parseInfo", "evidenceChip",
                   "CALLOUT", "callout ", "'mark'", "'val'", "AUTO_RE", "{64}", "0x[0-9a-fA-F]", "tk-mn", "tk-reg", "tk-hex", "tk-cmt", "tk-kw"):
        assert needle in js, needle
    assert "md-pre" in js  # fence without info string still renders as the plain block


def test_styles_cover_codeblock_callout_mark_and_both_themes():
    css = _read("styles.css")
    for sel in (".codeblock", ".cb-head", ".cb-gutter", ".callout.warn", ".callout.note", "mark.val", ".tk-mn", ".code-split", ".gh-panes", ".act-fin"):
        assert sel in css, sel
    # tokens exist for light, prefers-color-scheme dark and data-theme=dark
    assert css.count("--code-bg:") == 3 and css.count("--tk-mn:") == 3 and css.count("--tk-kw:") == 3
    ev = re.search(r"^\.ev-prev \{[^}]*\}", css, re.M).group(0)
    assert "max-height" not in ev and "overflow: hidden" not in ev
    assert "@media print" in css and re.search(r"@media print[^@]*max-height: none", css)
    assert "max-width: 1800px" in re.search(r"^\.main \{[^}]*\}", css, re.M).group(0)
    assert re.search(r"\.code-split\.is-ghidra \{[^}]*grid-template-columns: minmax\(0, 1fr\) minmax\(0, 1fr\)", css)
    assert re.search(r"@media \(max-width: 1000px\) \{ \.code-split\.is-ghidra \{ grid-template-columns: minmax\(0, 1fr\)", css)


def test_code_tab_has_ghidra_mode_with_hex_jump():
    js = _read("view_code.js")
    for needle in ("'ghidra'", "ghEnsure", "ghSelect", "ghJump", "parsePE", "loadSections", "/inspect/functions", "/inspect/function'",
                   "/inspect/hex", "image_base", "Kein Sprung", "info.code.available", "Math.floor(off / 16) + 1"):
        assert needle in js, needle
    assert "rva" in js and "s.raw + (rva - s.va)" in js


def test_status_labels_closed_and_refuted():
    rep = _read("view_report.js")
    for needle in ("findingBadge", "'closed'", "Geschlossen", "Widerlegt", "refuted"):
        assert needle in rep, needle
    assert "findingBadge" in _read("view_data.js") and "findingBadge" in _read("view_code.js")


def test_activity_collapses_after_job_end_and_shows_tokens():
    job = _read("view_job.js")
    assert "tokens_in" in job and "tokens_out" in job
    assert "h('details', { cls: 'act-fin' }" in job and "'sw.act.done.open'" in job
    mock = _read("mock.js")
    assert "tokens_in" in mock and "tokens_out" in mock


def test_evidence_preview_is_not_clipped():
    data = _read("view_data.js")
    assert "evPreview" in data and "h('details', { cls: 'ev-more' }" in data
