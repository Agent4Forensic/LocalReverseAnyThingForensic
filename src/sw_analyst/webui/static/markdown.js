/* Kleiner Markdown-Renderer, der ausschliesslich DOM-Knoten aufbaut (kein HTML-Parsing).
   Unterstuetzt: Ueberschriften, Absaetze, Listen (verschachtelt), Tabellen, Codebloecke,
   Zitate, Trennlinien, Code/fett/kursiv im Text. Links werden nicht aktiv (nur #-Anker). */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;

  var EV_RE = /\bEV-\d{4,8}\b/;
  var INLINE_RE = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|(\[[^\]\n]+\]\([^)\n]*\))|(\*[^*\s][^*\n]*\*)/;

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
      }
      rest = rest.slice(m.index + tok.length);
    }
  }

  function plain(parent, text, opts) {
    if (!opts || !opts.evidenceChip) {
      parent.appendChild(document.createTextNode(text));
      return;
    }
    var rest = text;
    while (rest.length) {
      var m = EV_RE.exec(rest);
      if (!m) {
        parent.appendChild(document.createTextNode(rest));
        return;
      }
      if (m.index > 0) parent.appendChild(document.createTextNode(rest.slice(0, m.index)));
      parent.appendChild(opts.evidenceChip(m[0]));
      rest = rest.slice(m.index + m[0].length);
    }
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
        var lang = line.replace(/^\s*```/, '').trim();
        var buf = [];
        i++;
        while (i < lines.length && !FENCE.test(lines[i])) {
          buf.push(lines[i]);
          i++;
        }
        i++;
        var code = h('code', { text: buf.join('\n') });
        var pre = h('pre', { cls: 'md-pre', tabindex: '0' }, code);
        if (lang) pre.setAttribute('data-lang', lang.slice(0, 20));
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
        var bq = h('blockquote', { cls: 'md-quote' });
        parseBlocks(q, bq, opts);
        root.appendChild(bq);
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
