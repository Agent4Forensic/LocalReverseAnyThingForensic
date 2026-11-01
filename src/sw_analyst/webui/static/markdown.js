/* Kleiner Markdown-Renderer, der ausschliesslich DOM-Knoten aufbaut (kein HTML-Parsing).
   Unterstuetzt: Ueberschriften, Absaetze, Listen (verschachtelt), Tabellen, Codebloecke,
   Zitate, Trennlinien, Code/fett/kursiv im Text. Links werden nicht aktiv (nur #-Anker).
   Bericht-Erweiterungen: Codeblock mit Infostring (asm|c|text, ev=, tool=, version=, sha256=), Callouts
   (> [!WARNING] / > [!NOTE]), ==dekodierter Wert==, Hashes und 0x-Adressen im Fliesstext als Code. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;

  var EV_RE = /\bEV-\d{4,8}\b/;
  var INLINE_RE = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|(\[[^\]\n]+\]\([^)\n]*\))|(\*[^*\s][^*\n]*\*)|(==[^=\n]+==)/;
  /* Fliesstext: SHA-256 (64 Hex) und 0x-Adressen/Offsets werden zu <code>; mit Belegchip auch EV-IDs. */
  var AUTO_RE = /\b[0-9a-fA-F]{64}\b|\b0x[0-9a-fA-F]{2,}\b/;
  var AUTO_EV_RE = /\b[0-9a-fA-F]{64}\b|\b0x[0-9a-fA-F]{2,}\b|\bEV-\d{4,8}\b/;

  function inline(parent, text, opts) {
    var rest = String(text);
    while (rest.length) {
      var m = INLINE_RE.exec(rest);
      if (!m) {
        plain(parent, rest, opts);
        return;
      }
      if (m.index > 0) plain(parent, rest.slice(0, m.index), opts);
      var tok = m[0];
      if (m[1]) {
        parent.appendChild(h('code', { cls: 'md-code', text: tok.slice(1, -1) }));
      } else if (m[2]) {
        var strong = h('strong');
        inline(strong, tok.slice(2, -2), opts);
        parent.appendChild(strong);
      } else if (m[3]) {
        var close = tok.indexOf('](');
        var label = tok.slice(1, close);
        var url = tok.slice(close + 2, -1);
        if (url.charAt(0) === '#') {
          var a = h('a', { href: url, cls: 'md-link' });
          inline(a, label, opts);
          parent.appendChild(a);
        } else {
          var sp = h('span', { cls: 'md-link', title: url });
          inline(sp, label, opts);
          parent.appendChild(sp);
        }
      } else if (m[4]) {
        var em = h('em');
        inline(em, tok.slice(1, -1), opts);
        parent.appendChild(em);
      } else if (m[5]) {
        parent.appendChild(h('mark', { cls: 'val', text: tok.slice(2, -2) }));
      }
      rest = rest.slice(m.index + tok.length);
    }
  }

  function plain(parent, text, opts) {
    var re = opts && opts.evidenceChip ? AUTO_EV_RE : AUTO_RE;
    var rest = text;
    while (rest.length) {
      var m = re.exec(rest);
      if (!m) {
        parent.appendChild(document.createTextNode(rest));
        return;
      }
      if (m.index > 0) parent.appendChild(document.createTextNode(rest.slice(0, m.index)));
      parent.appendChild(m[0].slice(0, 3) === 'EV-' ?opts.evidenceChip(m[0]) : h('code', { cls: 'md-code md-auto', text: m[0] }));
      rest = rest.slice(m.index + m[0].length);
    }
  }

  /* ---------- Codeblock: Kopfzeile, Zeilennummern, Kopieren, einfache Faerbung (nur Textknoten/Spans) ---------- */
  var REGS = 'e?[abcd]x|r?[abcd]l|[abcd][hl]|[re]?[sd]il?|[re]?[sb]pl?|r(?:[89]|1[0-5])[dwb]?|[re]?ip|[cdefgs]s|[xy]mm\\d+|[xw]\\d{1,2}|sp|lr|pc';
  var C_KW = 'if|else|for|while|do|return|void|int|char|short|long|unsigned|signed|struct|union|enum|goto|switch|case|default|break|continue|sizeof|const|static|byte|word|dword|qword|bool|undefined\\d?|uint|ulong|ushort|code';
  var TOK_RE = new RegExp('(0x[0-9a-fA-F]+|\\b[0-9a-fA-F]{2,}h\\b)|(\\b\\d+\\b)|(\\b(?:' + REGS + ')\\b)|(\\b(?:' + C_KW + ')\\b)', 'gi');
  var ASM_HEAD = /^(\s*(?:0x)?[0-9a-fA-F]{4,16}:?\s+)?((?:[0-9a-fA-F]{2}\s+)*)([A-Za-z][A-Za-z0-9.]*)(?=\s|$)/;
  var CB_LANGS = { asm: 1, c: 1, text: 1 };

  function cbSpan(parent, cls, text) {
    if (text) parent.appendChild(cls ? h('span', { cls: cls, text: text }) : document.createTextNode(text));
  }
  function cbLine(parent, line, lang) {
    if (lang === 'text') { parent.appendChild(document.createTextNode(line)); return; }
    var ci = lang === 'asm' ? line.indexOf(';') : line.indexOf('//');
    var code = ci >= 0 ? line.slice(0, ci) : line;
    var cmt = ci >= 0 ? line.slice(ci) : '';
    if (lang === 'asm') {
      var hm = ASM_HEAD.exec(code);
      if (hm) {
        cbSpan(parent, 'tk-hex', hm[1] || '');
        cbSpan(parent, 'tk-byte', hm[2] || '');
        cbSpan(parent, 'tk-mn', hm[3]);
        code = code.slice(hm[0].length);
      }
    }
    TOK_RE.lastIndex = 0;
    var last = 0, m;
    while ((m = TOK_RE.exec(code))) {
      cbSpan(parent, '', code.slice(last, m.index));
      /* Schluesselwoerter nur in C; im Assembler sind "code"/"byte" Operandenwoerter und bleiben neutral. */
      cbSpan(parent, m[1] ? 'tk-hex' : m[2] ? 'tk-num' : m[3] ? 'tk-reg' : lang === 'c' ? 'tk-kw' : '', m[0]);
      last = m.index + m[0].length;
    }
    cbSpan(parent, '', code.slice(last));
    cbSpan(parent, 'tk-cmt', cmt);
  }
  function copyButton(getText) {
    var label = h('span', { text: 'Kopieren' });
    var btn = h('button', { type: 'button', cls: 'btn sm ghost cb-copy', 'aria-label': 'Code in die Zwischenablage kopieren' }, label);
    var timer = 0;
    function say(t) {
      label.textContent = t;
      window.clearTimeout(timer);
      timer = window.setTimeout(function () { label.textContent = 'Kopieren'; }, 2000);
    }
    btn.addEventListener('click', function () {
      if (!navigator.clipboard || !navigator.clipboard.writeText) { say('Nicht möglich'); return; }
      navigator.clipboard.writeText(getText()).then(function () { say('Kopiert'); }, function () { say('Nicht möglich'); });
    });
    return btn;
  }
  function parseInfo(info) {
    var parts = info.split(/\s+/);
    var meta = {};
    parts.slice(1).forEach(function (kv) {
      var i = kv.indexOf('=');
      if (i > 0) meta[kv.slice(0, i)] = kv.slice(i + 1).slice(0, 200);
    });
    return { lang: parts[0].toLowerCase().slice(0, 20), meta: meta };
  }
  function codeblock(info, raw, opts) {
    var lang = info.lang, meta = info.meta;
    var lines = raw.split('\n');
    var gutter = h('pre', { cls: 'cb-gutter', 'aria-hidden': 'true', text: lines.map(function (_, i) { return String(i + 1); }).join('\n') });
    var code = h('code');
    lines.forEach(function (l, i) {
      if (i) code.appendChild(document.createTextNode('\n'));
      cbLine(code, l, lang);
    });
    var evNode = meta.ev ? (opts && opts.evidenceChip && EV_RE.test(meta.ev) ? opts.evidenceChip(meta.ev) : h('span', { cls: 'tag mono', text: meta.ev })) : null;
    var head = h('div', { cls: 'cb-head' },
      evNode,
      meta.tool ? h('span', { cls: 'tag mono', text: meta.tool }) : null,
      meta.version ? h('span', { cls: 'small muted mono', text: meta.version }) : null,
      meta.sha256 ? h('span', { cls: 'small muted mono', title: 'SHA-256 ' + meta.sha256, text: 'sha256 ' + meta.sha256.slice(0, 12) + '…' }) : null,
      h('span', { cls: 'grow' }),
      h('span', { cls: 'small muted', text: lines.length + (lines.length === 1 ? ' Zeile' : ' Zeilen') }),
      copyButton(function () { return raw; }));
    return h('div', { cls: 'codeblock', 'data-lang': lang },
      head, h('div', { cls: 'cb-body', role: 'region', 'aria-label': 'Code' + (meta.ev ? ' aus ' + meta.ev : ''), tabindex: '0' }, gutter, h('pre', { cls: 'cb-pre' }, code)));
  }

  /* ---------- Callouts: "> [!WARNING] Text" und "> [!NOTE] Text" ---------- */
  var CALLOUT = /^\[!(WARNING|NOTE)\]\s*(.*)$/;
  var CALLOUT_KIND = { WARNING: ['warn', 'Warnung', 'alert'], NOTE: ['note', 'Hinweis', 'info'] };
  function quote(q, root, opts) {
    var seg = [];
    function flush() {
      if (!seg.length) return;
      var bq = h('blockquote', { cls: 'md-quote' });
      parseBlocks(seg, bq, opts);
      root.appendChild(bq);
      seg = [];
    }
    for (var i = 0; i < q.length; i++) {
      var cm = CALLOUT.exec(q[i]);
      if (!cm) { seg.push(q[i]); continue; }
      flush();
      var kind = CALLOUT_KIND[cm[1]];
      var body = h('div', { cls: 'callout-b' });
      var first = h('p', { cls: 'md-p' }, h('strong', { text: kind[1] + (cm[2] ? ': ' : '') }));
      inline(first, cm[2], opts);
      body.appendChild(first);
      var more = [];
      while (i + 1 < q.length && !CALLOUT.test(q[i + 1])) more.push(q[++i]);
      if (more.length) parseBlocks(more, body, opts);
      root.appendChild(h('div', { cls: 'callout ' + kind[0], role: 'note' }, SW.dom.icon(kind[2], { size: 16 }), body));
    }
    flush();
  }

  var FENCE = /^\s*```/;
  var HEADING = /^(#{1,6})\s+(.*?)\s*#*\s*$/;
  var HR = /^\s*([-*_])(\s*\1){2,}\s*$/;
  var LIST = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/;
  var TABLE_SEP = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;

  function splitRow(line) {
    var s = line.trim();
    if (s.charAt(0) === '|') s = s.slice(1);
    /* report/builder.py schreibt "\|" für einen Strich in der Zelle und verdoppelt Backslashes davor. */
    var cells = [''], last = 0, re = /(\\*)\|/g, m;
    while ((m = re.exec(s))) {
      var n = m[1].length;
      cells[cells.length - 1] += s.slice(last, m.index) + m[1].slice(0, n >> 1);
      if (n % 2) cells[cells.length - 1] += '|';
      else cells.push('');
      last = re.lastIndex;
    }
    cells[cells.length - 1] += s.slice(last);
    if (cells.length > 1 && cells[cells.length - 1] === '') cells.pop();
    return cells.map(function (c) {
      return c.trim();
    });
  }

  function isBlockStart(lines, i) {
    var l = lines[i];
    if (FENCE.test(l) || HEADING.test(l) || HR.test(l) || LIST.test(l) || /^\s*>/.test(l)) return true;
    if (l.indexOf('|') >= 0 && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1]) && lines[i + 1].indexOf('-') >= 0) return true;
    return false;
  }

  function parseBlocks(lines, root, opts) {
    var i = 0;
    while (i < lines.length) {
      var line = lines[i];
      if (!line.trim()) {
        i++;
        continue;
      }
      if (FENCE.test(line)) {
        var info = line.replace(/^\s*```/, '').trim();
        var buf = [];
        i++;
        while (i < lines.length && !FENCE.test(lines[i])) {
          buf.push(lines[i]);
          i++;
        }
        i++;
        var finfo = parseInfo(info);
        if (CB_LANGS[finfo.lang]) {
          root.appendChild(codeblock(finfo, buf.join('\n'), opts));
          continue;
        }
        var code = h('code', { text: buf.join('\n') });
        var pre = h('pre', { cls: 'md-pre', tabindex: '0' }, code);
        if (info) pre.setAttribute('data-lang', finfo.lang);
        root.appendChild(pre);
        continue;
      }
      var hm = HEADING.exec(line);
      if (hm) {
        var level = Math.min(hm[1].length + 1, 6);
        var head = h('h' + level, { cls: 'md-h md-h' + hm[1].length });
        inline(head, hm[2], opts);
        root.appendChild(head);
        i++;
        continue;
      }
      if (HR.test(line)) {
        root.appendChild(h('hr', { cls: 'md-hr' }));
        i++;
        continue;
      }
      if (/^\s*>/.test(line)) {
        var q = [];
        while (i < lines.length && /^\s*>/.test(lines[i])) {
          q.push(lines[i].replace(/^\s*>\s?/, ''));
          i++;
        }
        quote(q, root, opts);
        continue;
      }
      if (line.indexOf('|') >= 0 && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1]) && lines[i + 1].indexOf('-') >= 0) {
        var head = splitRow(line);
        i += 2;
        var thead = h('thead', null, h('tr', null, head.map(function (c) {
          var th = h('th', { scope: 'col' });
          inline(th, c, opts);
          return th;
        })));
        var tbody = h('tbody');
        while (i < lines.length && lines[i].trim() && lines[i].indexOf('|') >= 0) {
          var cells = splitRow(lines[i]);
          var tr = h('tr');
          for (var c = 0; c < head.length; c++) {
            var td = h('td');
            inline(td, cells[c] || '', opts);
            tr.appendChild(td);
          }
          tbody.appendChild(tr);
          i++;
        }
        root.appendChild(h('div', { cls: 'md-table-wrap' }, h('table', { cls: 'md-table' }, thead, tbody)));
        continue;
      }
      var lm = LIST.exec(line);
      if (lm) {
        i = parseList(lines, i, root, opts);
        continue;
      }
      var para = [];
      while (i < lines.length && lines[i].trim() && (para.length === 0 || !isBlockStart(lines, i))) {
        para.push(lines[i].trim());
        i++;
      }
      var p = h('p', { cls: 'md-p' });
      inline(p, para.join(' '), opts);
      root.appendChild(p);
    }
  }

  function parseList(lines, start, root, opts) {
    /* Stapel aus {indent, el}; jede Ebene ist ein ul/ol. */
    var stack = [];
    var i = start;
    while (i < lines.length) {
      var m = LIST.exec(lines[i]);
      if (!m) {
        /* Fortsetzungszeile eines Eintrags */
        if (lines[i].trim() && /^\s{2,}\S/.test(lines[i]) && stack.length) {
          var lastLi = stack[stack.length - 1].last;
          if (lastLi) lastLi.appendChild(document.createTextNode(' ' + lines[i].trim()));
          i++;
          continue;
        }
        break;
      }
      var indent = m[1].replace(/\t/g, '    ').length;
      var ordered = /\d/.test(m[2].charAt(0));
      while (stack.length && indent < stack[stack.length - 1].indent) stack.pop();
      if (!stack.length || indent > stack[stack.length - 1].indent) {
        var listEl = h(ordered ? 'ol' : 'ul', { cls: 'md-list' });
        var parentLi = stack.length ? stack[stack.length - 1].last : null;
        if (parentLi) parentLi.appendChild(listEl);
        else root.appendChild(listEl);
        stack.push({ indent: indent, el: listEl, last: null });
      }
      var top = stack[stack.length - 1];
      var li = h('li');
      inline(li, m[3], opts);
      top.el.appendChild(li);
      top.last = li;
      i++;
    }
    return i;
  }

  function render(text, opts) {
    var root = h('div', { cls: 'markdown' });
    parseBlocks(String(text || '').split(/\r?\n/), root, opts || null);
    return root;
  }

  SW.markdown = { render: render, splitRow: splitRow };
})();
