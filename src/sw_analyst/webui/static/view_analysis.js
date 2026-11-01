/* Tab Analyse: ein logischer Tab fuer Code und Datei. Oben der Umwandlungsprozess als Flowchart (SVG, ohne Bibliothek):
   sample -> derived/... -> Endergebnis, je Kante Werkzeug, Methode und Beleg, je Knoten Groesse, SHA-256, Art und
   Vorschau. Darunter die Ansicht des gewaehlten Knotens: Text (ganze Datei, virtuell), Hex (ganze Datei) oder Ghidra
   (Funktionen, Assembler mit Erklaerung, Pseudocode, Basic Blocks, Querverweise, Lernpfad). Alle Inhalte stammen aus
   dem Sample und werden nur als Text eingefuegt (kein innerHTML), nichts daraus wird ausgefuehrt. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var svg = SW.dom.svg;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var api = SW.api;
  var ui = SW.ui;

  var RH = 20, CH = 400, MAXPX = 8000000;
  var NW = 230, NH = 92, GX = 170, GY = 26, PAD = 14;

  function clip(s, n) { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n - 1) + '…' : s; }
  function oneLine(s) { return String(s || '').replace(/\s+/g, ' ').trim(); }
  function ensureCss() {
    if (document.querySelector('link[data-an-css]')) return;
    var l = document.createElement('link');
    l.rel = 'stylesheet'; l.href = 'analysis.css'; l.setAttribute('data-an-css', '1');
    document.head.appendChild(l);
  }

  /* ================= Text: ganze Datei, virtuell gescrollt ================= */
  function textView(jobId, path, size, startLine, endLine) {
    var chunks = new Map();     /* Index -> Zeilen | 'loading' | 'error' */
    var annots = new Map();
    var total = 0, binary = false, dead = false, raf = 0, err = null;
    var active = startLine ? { s: startLine, e: endLine || startLine } : null;
    var selLine = null;
    var viewH = Math.max(260, Math.min(560, Math.round(window.innerHeight * 0.55)));
    var vis = Math.ceil(viewH / RH) + 3;
    var win = h('div', { cls: 'an-win' });
    var sizer = h('div', { cls: 'an-sizer' }, win);
    var scroller = h('div', { cls: 'an-scroll', tabindex: '0', role: 'region', 'aria-label': 'Ganze Datei, zeilenweise, scrollbar', vars: { '--vh': viewH + 'px' } }, sizer);
    var info = h('span', { cls: 'small muted' });
    var annHost = h('div', { cls: 'an-anns' });
    var gotoIn = h('input', { type: 'number', min: 1, 'aria-label': 'Zeilennummer', cls: 'small', placeholder: 'Zeile' });
    gotoIn.addEventListener('keydown', function (e) { if (e.key === 'Enter') { jumpTo(parseInt(gotoIn.value, 10)); } });
    var el = h('div', { cls: 'stack' },
      h('div', { cls: 'an-tools' }, info, h('span', { cls: 'grow' }), h('label', { cls: 'row small' }, 'Springe zu ', gotoIn),
        h('button', { type: 'button', cls: 'btn sm', on: { click: function () { jumpTo(parseInt(gotoIn.value, 10)); } } }, 'Los')),
      scroller, annHost);

    function capped() { return total * RH > MAXPX; }
    function sizerH() { return capped() ? MAXPX : Math.max(RH, total * RH); }
    function firstRow() {
      var st = scroller.scrollTop;
      if (!capped()) return Math.floor(st / RH);
      var span = Math.max(1, sizerH() - viewH);
      return Math.round(st / span * Math.max(0, total - vis));
    }
    function scrollForRow(r) {
      if (!capped()) return r * RH;
      return r / Math.max(1, total - vis) * Math.max(1, sizerH() - viewH);
    }
    function load(ci) {
      if (chunks.has(ci)) return;
      chunks.set(ci, 'loading');
      api.get('/jobs/' + encodeURIComponent(jobId) + '/files/content', { path: path, start: ci * CH + 1, end: (ci + 1) * CH }).then(function (d) {
        if (dead) return;
        binary = !!d.binary;
        var first = !total;
        total = d.total_lines || 0;
        var arr = [];
        (d.lines || []).forEach(function (l) { arr[l.n - 1 - ci * CH] = l.text; });
        chunks.set(ci, arr);
        (d.annotations || []).forEach(function (a) { annots.set(a.id, a); });
        if (first) {
          sizer.style.setProperty('--h', sizerH() + 'px');
          if (active) jumpTo(active.s, active.e);
        }
        paintInfo(); paintAnns(); schedule();
      }, function (e) {
        if (dead) return;
        chunks.set(ci, 'error'); err = e; schedule();
      });
    }
    function paintInfo() {
      info.textContent = total ? total.toLocaleString('de-DE') + ' Zeilen' + (binary ? ' (Binärdatei: Hexzeilen à 16 Byte)' : '') + ' · ' + fmt.bytes(size) : 'Lädt …';
    }
    function render() {
      raf = 0;
      if (dead) return;
      if (err && !total) { SW.dom.fill(win, ui.errorBox(err.status === 404 ? 'Diese Datei ist nicht verfügbar.' : err.message)); return; }
      if (!total) { load(0); SW.dom.fill(win, ui.loading('Datei wird geladen …')); return; }
      var f = Math.max(0, Math.min(firstRow(), Math.max(0, total - 1)));
      var last = Math.min(total, f + vis);
      var cover = {};
      annots.forEach(function (a) {
        for (var n = Math.max(a.line_start, f + 1); n <= Math.min(a.line_end, last); n++) if (!cover[n]) cover[n] = a.kind;
      });
      var frag = document.createDocumentFragment();
      for (var i = f; i < last; i++) {
        var ci = Math.floor(i / CH);
        var c = chunks.get(ci);
        if (c === undefined) load(ci);
        var txt = Array.isArray(c) ? c[i - ci * CH] : null;
        var n = i + 1;
        var inAct = active && n >= active.s && n <= active.e;
        frag.appendChild(h('div', {
          cls: ['an-ln', txt == null ? 'an-loadrow' : '', cover[n] ? 'has-ann ak-' + cover[n] : '', inAct ? 'is-active' : '', selLine === n ? 'is-sel' : ''],
          'data-line': n, on: { click: function () { selLine = n; paintAnns(); schedule(); } }
        }, h('span', { cls: 'g', text: String(n) }), h('span', { cls: 't', text: txt == null ? (c === 'error' ? '(Fehler beim Laden)' : '…') : txt })));
      }
      SW.dom.clear(win);
      win.appendChild(frag);
      win.style.setProperty('--y', (capped() ? scroller.scrollTop : f * RH) + 'px');
    }
    function schedule() { if (!raf) raf = window.requestAnimationFrame(render); }
    function jumpTo(line, end) {
      if (!(line > 0)) return;
      line = Math.min(line, total || line);
      active = { s: line, e: end >= line ? end : line };
      selLine = line;
      if (total) { scroller.scrollTop = scrollForRow(Math.max(0, line - 4)); }
      paintAnns(); schedule();
    }
    function paintAnns() {
      var list = [];
      annots.forEach(function (a) { list.push(a); });
      list.sort(function (a, b) { return a.line_start - b.line_start; });
      var sel = selLine ? list.filter(function (a) { return selLine >= a.line_start && selLine <= a.line_end; }) : [];
      SW.dom.fill(annHost,
        sel.length ? sel.map(note) : (selLine ? h('p', { cls: 'small muted', text: 'Zeile ' + selLine + ' hat keine KI-Anmerkung.' }) : null),
        list.length ? h('details', null, h('summary', { text: 'Alle Anmerkungen (' + list.length + ')' }),
          h('ul', { cls: 'quotes' }, list.slice(0, 300).map(function (a) {
            return h('li', null, h('button', { type: 'button', cls: 'btn sm', on: { click: function () { jumpTo(a.line_start, a.line_end); } } }, 'Z. ' + a.line_start),
              ' ', h('span', { cls: 'tag', text: fmt.ANN_KIND[a.kind] || a.kind }), ' ', clip(fmt.textDe(a, 'text'), 160));
          }))) : h('p', { cls: 'small muted', text: 'Noch keine KI-Anmerkungen zu dieser Datei.' }));
    }
    function note(a) {
      return h('div', { cls: 'note ann-' + a.kind, role: 'note' },
        h('div', { cls: 'note-h' }, h('span', { cls: 'tag', text: fmt.ANN_KIND[a.kind] || a.kind }),
          h('span', { cls: 'mono small muted', text: 'Z. ' + a.line_start + (a.line_end !== a.line_start ? '–' + a.line_end : '') })),
        h('p', { text: fmt.textDe(a, 'text') }),
        h('div', { cls: 'row note-l' }, a.evidence_id ? ui.evidenceChip(jobId, a.evidence_id) : null,
          a.finding_id ? h('a', { cls: 'chip mono', href: ui.tabHref(jobId, 'live', { finding: a.finding_id }), text: 'Befund ' + a.finding_id }) : null));
    }
    scroller.addEventListener('scroll', schedule, { passive: true });
    var off = SW.store.on(function (kind, a) {
      if (kind !== 'annotation' || !a || (a.path || a.file) !== path) return;
      annots.set(a.id, a); paintAnns(); schedule();
    });
    paintInfo(); paintAnns(); load(0); schedule();
    return {
      el: el, jumpTo: jumpTo,
      dispose: function () { dead = true; off(); if (raf) window.cancelAnimationFrame(raf); }
    };
  }

  /* ================= Ghidra ================= */
  function ghidraView(jobId, path, opts) {
    var base = '/jobs/' + encodeURIComponent(jobId);
    var dead = false, info = null, fnData = null, fnSel = null, gen = 0, section = opts.lern ? 'lern' : 'disasm';
    var filter = '', cur = null, wt = null, wtState = 'none', stepIdx = 0;
    var host = h('div', { cls: 'stack' });
    var listHost = h('div', { cls: 'an-fnlist' });
    var bodyHost = h('div');

    function notice(msg) { SW.dom.fill(host, h('div', { cls: 'notice tone-info', role: 'note' }, icon('info'), h('p', { text: msg }))); }
    function start() {
      SW.dom.fill(host, ui.loading('Ghidra-Export wird geprüft …'));
      api.get(base + '/inspect', { path: path }).then(function (d) {
        if (dead) return;
        info = d;
        if (!d.code || !d.code.available) { notice((d.code && d.code.reason) || 'Ghidra ist für diese Datei nicht verfügbar.'); return; }
        SW.dom.fill(host, ui.loading('Ghidra liest die Datei … Der erste Aufruf je Datei kann einige Minuten dauern, danach kommt das Ergebnis aus dem Cache.'));
        api.get(base + '/inspect/functions', { path: path }).then(function (f) {
          if (dead) return;
          fnData = f; paintAll();
          var pick = (opts.fn && f.functions.filter(function (x) { return x.name === opts.fn || x.entry === opts.fn; })[0]) ||
            f.functions.filter(function (x) { return x.entry === f.program.entry; })[0] ||
            f.functions.filter(function (x) { return !x.thunk; })[0] || f.functions[0];
          if (pick) selectFn(pick.name);
        }, function (e) { if (!dead) notice(e.status === 409 ? e.message : 'Ghidra-Ergebnis nicht verfügbar: ' + e.message); });
      }, function (e) { if (!dead) notice(e.status === 404 ? 'Datei nicht verfügbar.' : 'Ghidra-Ansicht nicht verfügbar: ' + e.message); });
    }
    function paintAll() {
      var p = fnData.program || {};
      SW.dom.fill(host,
        h('p', { cls: 'small muted', text: [p.format, p.language, p.compiler && 'Compiler ' + p.compiler, 'Image-Basis ' + (p.image_base || '–'), 'Einstieg ' + (p.entry || '–'),
          fnData.total + ' Funktion(en)', fnData.tool_version].filter(Boolean).join(' · ') }),
        fnData.truncated ? h('div', { cls: 'notice tone-warn', role: 'note' }, icon('alert'), h('p', { text: 'Exportgrenze erreicht: nicht jede Funktion ist aufgeführt.' })) : null,
        h('div', { cls: 'an-gh' },
          h('section', { cls: 'card', 'aria-label': 'Funktionen' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Funktionen' })),
            h('div', { cls: 'card-b tight' }, (function () {
              var inp = h('input', { type: 'search', 'aria-label': 'Funktionen filtern', placeholder: 'Filter (Name oder Adresse)' });
              inp.value = filter;
              inp.addEventListener('input', function () { filter = inp.value.toLowerCase(); paintList(); });
              return h('div', { cls: 'stack' }, inp, listHost);
            })())),
          bodyHost));
      paintList();
    }
    function paintList() {
      var fl = fnData.functions.filter(function (f) { return !filter || (f.name || '').toLowerCase().indexOf(filter) >= 0 || (f.entry || '').toLowerCase().indexOf(filter) >= 0; });
      SW.dom.fill(listHost, h('ul', { cls: 'flist' }, fl.map(function (f) {
        var on = fnSel === f.name;
        return h('li', null, h('button', { type: 'button', cls: on ? 'is-sel' : '', 'aria-pressed': on ? 'true' : 'false', title: f.signature, on: { click: function () { selectFn(f.name); } } },
          h('span', { cls: 'mono grow trunc', text: f.name }), f.thunk ? h('span', { cls: 'tag', text: 'Thunk' }) : null,
          h('span', { cls: 'small muted mono nowrap', text: f.entry })));
      })));
    }
    function selectFn(name) {
      fnSel = name; paintList();
      var my = ++gen;
      wt = null; wtState = 'none'; stepIdx = 0;
      SW.dom.fill(bodyHost, ui.loading('Funktion ' + name + ' wird geladen …'));
      api.get(base + '/inspect/function', { path: path, function: name }).then(function (f) {
        if (dead || my !== gen) return;
        cur = f; paintFn();
        ui.softGet(base + '/walkthroughs', { path: path, function: name }).then(function (r) {
          if (dead || my !== gen) return;
          var w = r.ok ? (Array.isArray(r.data) ? r.data[0] : r.data) : null;
          if (w && w.steps && w.steps.length) { wt = w; wtState = 'ok'; stepIdx = 0; } else wtState = 'none';
          paintFn();
        });
      }, function (e) { if (!dead && my === gen) SW.dom.fill(bodyHost, ui.errorBox(e.message)); });
    }
    function setSection(s) { section = s; paintFn(); }
    function selectStep(i) { if (!wt) return; stepIdx = Math.max(0, Math.min(wt.steps.length - 1, i)); paintFn(true); }

    function asmTable(f) {
      var st = section === 'lern' && wt ? wt.steps[stepIdx] : null;
      var tbl = h('table', { cls: 'asm' }, h('caption', { cls: 'sr-only', text: 'Assembler mit Erklärung je Befehl' }),
        h('thead', null, h('tr', null, ['Zeile', 'Adresse', 'Bytes', 'Befehl', 'Erklärung'].map(function (c) { return h('th', { scope: 'col', text: c }); }))),
        h('tbody', null, f.disasm.map(function (r, i) {
          var n = i + 1;
          var inStep = st && n >= st.line_start && n <= st.line_end;
          return h('tr', { cls: inStep ? 'is-step' : '', 'data-line': n }, h('td', { cls: 'muted', text: String(n) }), h('td', { cls: 'a-addr', text: r.address }), h('td', { cls: 'a-bytes', text: r.bytes }),
            h('td', { cls: 'a-ins', text: r.text }), h('td', { cls: 'a-exp', text: r.explain || '–' }));
        })));
      return h('div', { cls: 'tbl-wrap asm-wrap an-asm', tabindex: '0', role: 'region', 'aria-label': 'Assembler von ' + f.name }, tbl);
    }
    function blocksView(f) {
      var b = f.blocks;
      if (Array.isArray(b)) {
        if (!b.length) return h('p', { cls: 'muted', text: 'Keine Basic Blocks im Export.' });
        return h('div', { cls: 'tbl-wrap' }, h('table', null, h('thead', null, h('tr', null, ['Block', 'Start', 'Ende', 'Nachfolger'].map(function (c) { return h('th', { scope: 'col', text: c }); }))),
          h('tbody', null, b.map(function (x, i) {
            var succ = (x.succ || []).map(function (s) { return Array.isArray(s) ? s[0] + ' (' + s[1] + ')' : String(s); }).join(', ') || '(keine)';
            return h('tr', null, h('td', { text: String(i + 1) }), h('td', { cls: 'mono', text: x.start }), h('td', { cls: 'mono', text: x.end }), h('td', { cls: 'mono', text: succ }));
          }))));
      }
      return h('p', { cls: 'muted', text: (typeof b === 'number' ? b + ' Basic Block(s) im Export. ' : '') + 'Die Liste der Blöcke mit Nachfolgern liefert der Server für diese Funktion nicht.' });
    }
    function xrefsView(f) {
      var x = f.xrefs;
      if (!x) return h('p', { cls: 'muted', text: 'Der Server liefert für diese Funktion keine Querverweise.' });
      function list(title, arr) {
        return h('div', null, h('h3', { text: title + ' (' + (arr || []).length + ')' }), (arr || []).length ? h('ul', { cls: 'quotes' }, arr.slice(0, 500).map(function (r) {
          return h('li', { cls: 'mono small', text: Array.isArray(r) ? r.join('  ') : (typeof r === 'object' ? [r.from, r.to, r.type].filter(Boolean).join('  ') : String(r)) });
        })) : h('p', { cls: 'muted small', text: 'keine' }));
      }
      return h('div', { cls: 'stack' }, list('Verweise auf diese Funktion', x.to), list('Verweise aus dieser Funktion', x.from));
    }
    function paintFn(keepScroll) {
      if (!cur) return;
      var f = cur;
      var findings = f.findings || [];
      var seg = ui.seg('Ghidra-Ansicht', [['disasm', 'Assembler'], ['pseudo', 'Pseudocode'], ['blocks', 'Basic Blocks'], ['xrefs', 'Querverweise'], ['lern', 'Lernpfad']], section, setSection);
      var content;
      if (section === 'pseudo') {
        content = f.decompiled ? h('pre', { cls: 'an-pseudo', tabindex: '0', text: f.decompiled }) : h('p', { cls: 'muted', text: 'Für diese Funktion gibt es keine Decompiler-Ausgabe (Thunk, Zeitlimit oder Exportgrenze). Der Assembler ist vollständig.' });
        content = h('div', { cls: 'stack' }, content, h('p', { cls: 'small muted', text: 'Pseudocode nähert den Code nur an. Belege zitieren Assembler oder Dekompilat mit Evidence-ID.' }));
      } else if (section === 'blocks') content = blocksView(f);
      else if (section === 'xrefs') content = xrefsView(f);
      else if (section === 'lern') content = h('div', null, lernBar(), asmTable(f));
      else content = h('div', null, asmTable(f), f.disasm_truncated ? h('p', { cls: 'small muted', text: 'Die Funktion ist länger als die Exportgrenze; nicht alle Befehle sind aufgeführt.' }) : null);
      SW.dom.fill(bodyHost, h('div', { cls: 'stack' },
        h('div', { cls: 'row' }, h('h3', { cls: 'grow mono', text: f.name + '  ' + (f.signature || '') }), h('span', { cls: 'tag mono', text: f.entry }),
          h('span', { cls: 'tag', text: f.size + ' Byte' }), h('span', { cls: 'tag', text: f.disasm.length + ' Befehle' }),
          h('span', { cls: 'tag', text: (Array.isArray(f.blocks) ? f.blocks.length : f.blocks) + ' Blöcke' })),
        seg, content,
        h('div', { cls: 'notice tone-neutral', role: 'note' }, icon('info'), h('p', { text: 'Die Erklärungen beschreiben, was ein Befehl allgemein tut (feste Tabelle, ohne KI). Was die Funktion im Sample bewirkt, belegen nur die Befunde der Analyse.' })),
        findings.length ? ui.section('Befunde zu dieser Funktion', h('ul', { cls: 'quotes' }, findings.map(function (x) {
          return h('li', null, fmt.badge(x.status), ' ', h('a', { cls: 'mono', href: ui.tabHref(jobId, 'live', { finding: x.id }), text: x.id }), ' ', x.statement_de || x.statement_en, ' ', ui.chips(jobId, x.evidence_ids));
        }))) : null));
      if (section === 'lern' && keepScroll) {
        var row = bodyHost.querySelector('tr.is-step');
        if (row && row.scrollIntoView) row.scrollIntoView({ block: 'nearest' });
      }
    }
    function lernBar() {
      if (wtState !== 'ok' || !wt) return h('div', { cls: 'notice tone-info', role: 'note' }, icon('info'), h('p', { text: 'Für diese Funktion gibt es keinen Lernpfad (kein Assembler im Export).' }));
      var n = wt.steps.length, s = wt.steps[stepIdx];
      return h('div', { cls: 'stepbar card an-step' },
        h('button', { type: 'button', cls: 'btn sm', disabled: stepIdx <= 0, on: { click: function () { selectStep(stepIdx - 1); } } }, 'Zurück'),
        h('div', { cls: 'grow', 'aria-live': 'polite' },
          h('div', { cls: 'small muted', text: 'Schritt ' + (stepIdx + 1) + ' von ' + n + ' · Zeilen ' + s.line_start + (s.line_end > s.line_start ? '–' + s.line_end : '') + ' · ' + s.address }),
          h('strong', { text: s.title }), h('p', { cls: 'small', text: s.explanation }), ui.bar(((stepIdx + 1) / n) * 100)),
        h('button', { type: 'button', cls: 'btn sm primary', disabled: stepIdx >= n - 1, on: { click: function () { selectStep(stepIdx + 1); } } }, 'Weiter', icon('chevronright')));
    }
    start();
    return { el: host, dispose: function () { dead = true; } };
  }

  /* ================= Flowchart ================= */
  function layout(lin) {
    var idx = {};
    lin.nodes.forEach(function (n, i) { idx[n.path] = i; });
    var out = lin.nodes.map(function () { return []; });
    var indeg = lin.nodes.map(function () { return 0; });
    lin.edges.forEach(function (e) {
      if (idx[e.from] === undefined || idx[e.to] === undefined) return;
      out[idx[e.from]].push(idx[e.to]); indeg[idx[e.to]]++;
    });
    var level = lin.nodes.map(function () { return -1; });
    function bfs(r) {
      level[r] = 0;
      var q = [r];
      for (var k = 0; k < q.length; k++) {
        out[q[k]].forEach(function (v) { if (level[v] < 0) { level[v] = level[q[k]] + 1; q.push(v); } });
      }
    }
    var roots = [];
    lin.nodes.forEach(function (n, i) { if (!indeg[i]) roots.push(i); });
    if (idx.sample !== undefined && roots.indexOf(idx.sample) < 0) roots.unshift(idx.sample);
    roots.forEach(function (r) { if (level[r] < 0) bfs(r); });
    lin.nodes.forEach(function (n, i) { if (level[i] < 0) bfs(i); });
    var cols = [];
    var pos = lin.nodes.map(function () { return null; });
    lin.nodes.forEach(function (n, i) {
      (cols[level[i]] = cols[level[i]] || []).push(i);
      pos[i] = { col: level[i], row: cols[level[i]].length - 1 };
    });
    var rows = cols.reduce(function (m, c) { return Math.max(m, c ? c.length : 0); }, 1);
    pos.forEach(function (p) { p.x = PAD + p.col * (NW + GX); p.y = PAD + p.row * (NH + GY); });
    return { idx: idx, pos: pos, w: PAD * 2 + cols.length * NW + (cols.length - 1) * GX, h: PAD * 2 + rows * NH + (rows - 1) * GY + 56 };
  }

  function flowchart(jobId, lin, selected, onSelect) {
    var L = layout(lin);
    var finals = {};
    (lin.final || []).forEach(function (p) { finals[p] = true; });
    var inEdge = {};
    var s = svg('svg', { cls: 'an-flow', width: L.w, height: L.h, viewBox: '0 0 ' + L.w + ' ' + L.h, role: 'group', 'aria-label': 'Umwandlungsprozess der Dateien' },
      svg('defs', null, svg('marker', { id: 'an-arr', viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse' }, svg('path', { d: 'M0 0L10 5L0 10z', cls: 'an-arrow' }))));
    var gE = svg('g'), gN = svg('g');
    s.appendChild(gE); s.appendChild(gN);
    lin.edges.forEach(function (e) {
      var a = L.idx[e.from], b = L.idx[e.to];
      if (a === undefined || b === undefined) return;
      var pa = L.pos[a], pb = L.pos[b];
      var d, mx, my;
      if (pb.col > pa.col) {
        var x1 = pa.x + NW, y1 = pa.y + NH / 2, x2 = pb.x, y2 = pb.y + NH / 2, dx = (x2 - x1) / 2;
        d = 'M' + x1 + ' ' + y1 + ' C' + (x1 + dx) + ' ' + y1 + ' ' + (x2 - dx) + ' ' + y2 + ' ' + x2 + ' ' + y2;
        mx = (x1 + x2) / 2; my = (y1 + y2) / 2;
      } else {
        var xa = pa.x + NW / 2, ya = pa.y + NH, xb = pb.x + NW / 2, yb = pb.y + NH, dep = 40;
        d = 'M' + xa + ' ' + ya + ' C' + xa + ' ' + (ya + dep) + ' ' + xb + ' ' + (yb + dep) + ' ' + xb + ' ' + yb;
        mx = (xa + xb) / 2; my = Math.max(ya, yb) + dep * 0.75 + 6;
      }
      var m = [e.tool, e.method].filter(Boolean).join(' · ');
      var tip = e.tool + (e.method ? ' · Methode ' + e.method : '') + ' · ' + JSON.stringify(e.params || {}) + ' · Beleg ' + (e.evidence_ids || [e.evidence_id]).join(', ');
      var g = svg('g', { 'data-edge': e.from + '>' + e.to }, svg('title', null, tip), svg('path', { d: d, cls: 'an-edge', 'marker-end': 'url(#an-arr)', 'data-to': e.to }));
      g.appendChild(svg('text', { x: mx, y: my - 8, 'text-anchor': 'middle', cls: 'an-elabel' }, clip(m, 24)));
      var ev = svg('text', { x: mx, y: my + 5, 'text-anchor': 'middle', cls: 'an-elabel ev', tabindex: 0, role: 'button', 'aria-label': 'Beleg ' + e.evidence_id + ' öffnen' }, e.evidence_id);
      ev.addEventListener('click', function (ev2) { ev2.stopPropagation(); ui.openEvidence(jobId, e.evidence_id, ev); });
      ev.addEventListener('keydown', function (k) { if (k.key === 'Enter' || k.key === ' ') { k.preventDefault(); ui.openEvidence(jobId, e.evidence_id, ev); } });
      g.appendChild(ev);
      gE.appendChild(g);
      inEdge[e.to] = g.querySelector('path');
    });
    var nodeEls = {};
    lin.nodes.forEach(function (n, i) {
      var p = L.pos[i];
      var g = svg('g', { cls: ['an-node', finals[n.path] ? 'is-final' : '', n.missing ? 'is-missing' : ''].join(' '), transform: 'translate(' + p.x + ' ' + p.y + ')', tabindex: 0, role: 'button', 'data-path': n.path,
        'aria-label': 'Datei ' + n.path + ', ' + n.size + ' Byte' + (finals[n.path] ? ', Endergebnis' : '') });
      g.appendChild(svg('title', null, n.path + '\nSHA-256 ' + (n.sha256 || '–') + '\n' + (n.label || '') + '\n\n' + clip(n.preview, 400)));
      g.appendChild(svg('rect', { cls: 'box', width: NW, height: NH, rx: 8 }));
      g.appendChild(svg('text', { x: 10, y: 18, cls: 'nt' }, clip(n.path, 24)));
      if (finals[n.path]) g.appendChild(svg('text', { x: NW - 8, y: 18, 'text-anchor': 'end', cls: 'nf' }, 'Endergebnis'));
      g.appendChild(svg('text', { x: 10, y: 35, cls: 'nm' }, clip(fmt.bytes(n.size) + ' · ' + (n.label || (n.missing ? 'nicht vorhanden' : '')), 38)));
      g.appendChild(svg('text', { x: 10, y: 51, cls: 'nm' }, 'SHA-256 ' + (n.sha256 ? n.sha256.slice(0, 16) + '…' : '–')));
      var pv = oneLine(n.preview);
      g.appendChild(svg('text', { x: 10, y: 69, cls: 'np' }, clip(pv, 33)));
      g.appendChild(svg('text', { x: 10, y: 83, cls: 'np' }, clip(pv.slice(32), 33)));
      g.addEventListener('click', function () { onSelect(n.path); });
      g.addEventListener('keydown', function (k) { if (k.key === 'Enter' || k.key === ' ') { k.preventDefault(); onSelect(n.path); } });
      gN.appendChild(g);
      nodeEls[n.path] = g;
    });
    function mark(path) {
      Object.keys(nodeEls).forEach(function (k) {
        var on = k === path;
        nodeEls[k].classList.toggle('is-sel', on);
        nodeEls[k].setAttribute('aria-pressed', on ? 'true' : 'false');
      });
      Object.keys(inEdge).forEach(function (k) { inEdge[k].classList.toggle('is-in', k === path); });
    }
    mark(selected);
    return { el: h('div', { cls: 'an-flow-wrap', tabindex: '0', role: 'region', 'aria-label': 'Flowchart der Umwandlung, scrollbar' }, s), mark: mark };
  }

  /* ================= Tab ================= */
  SW.registerTab({
    id: 'analysis', label: 'Analyse', icon: 'code',
    mount: function (host, ctx) {
      ensureCss();
      var jobId = ctx.jobId;
      var dead = false;
      var q = ctx.route.query || {};
      var path = q.path || q.file || 'sample';
      var view = q.view === 'text' || q.view === 'hex' || q.view === 'ghidra' ? q.view : null;
      var lin = null, chart = null, inst = null;
      var flowHost = h('div'), detailHost = h('div'), viewHost = h('div');
      var vq = { line: parseInt(q.line, 10) || 0, end: parseInt(q.end, 10) || 0, lern: q.lern === '1', fn: q.function || '' };

      function node(p) { return lin && lin.nodes.filter(function (n) { return n.path === p; })[0]; }
      function producing(p) { return lin ? lin.edges.filter(function (e) { return e.to === p; }) : []; }

      function paintDetail() {
        var n = node(path);
        if (!n) { SW.dom.fill(detailHost, ui.empty('Datei nicht gefunden', path + ' gehört nicht zu diesem Auftrag.', 'file')); SW.dom.clear(viewHost); return; }
        var via = producing(path);
        SW.dom.fill(detailHost, ui.section('Datei ' + n.path,
          h('div', { cls: 'stack' },
            h('div', { cls: 'an-head' },
              h('div', { cls: 'tile' }, h('div', { cls: 'tile-l', text: 'Größe' }), h('div', { cls: 'tile-v fv-big', text: fmt.bytes(n.size) + (n.size >= 1024 ? ' (' + n.size.toLocaleString('de-DE') + ' Byte)' : '') })),
              h('div', { cls: 'tile' }, h('div', { cls: 'tile-l', text: 'Art' }), h('div', { cls: 'tile-v fv-big', text: n.label || '–' }), h('div', { cls: 'tile-s muted small', text: n.path === 'sample' ? 'Original-Sample (nie ausgeführt)' : 'abgeleitete Datei' })),
              h('div', { cls: 'tile' }, h('div', { cls: 'tile-l', text: 'SHA-256' }), h('div', { cls: 'tile-v mono small', text: n.sha256 || '–' }))),
            via.length ? h('div', null, h('h3', { text: 'Entstanden durch' }), h('ul', { cls: 'an-via' }, via.map(function (e) {
              var pr = Object.keys(e.params || {}).filter(function (k) { return k !== 'path'; }).map(function (k) { return k + '=' + e.params[k]; }).join(', ');
              return h('li', null, h('span', { cls: 'mono', text: e.from }), ' → ', h('strong', { text: e.tool }), e.method ? ' (' + e.method + ')' : '', pr ? ' · ' + pr + ' · ' : ' · ', ui.chips(jobId, e.evidence_ids || [e.evidence_id]));
            }))) : h('p', { cls: 'small muted', text: n.path === 'sample' ? 'Ausgangsdatei: Upload des Auftrags.' : 'Kein Beleg nennt die Herkunft dieser Datei.' }),
            n.preview ? h('details', { open: true }, h('summary', { text: 'Zwischenstand: so sieht die Datei hier aus (Anfang, Text)' }), h('pre', { cls: 'an-pre', text: n.preview })) : null)));
        paintView();
      }

      function autoView(n) { return n && n.kind === 'text' ? 'text' : 'hex'; }
      function paintView() {
        var n = node(path);
        if (inst) { inst.dispose(); inst = null; }
        var v = view || autoView(n);
        var seg = ui.seg('Ansicht', [['text', 'Text'], ['hex', 'Hex'], ['ghidra', 'Ghidra']], v, function (x) { view = x; vq.lern = false; paintView(); });
        var body;
        if (!n || n.missing) body = ui.noData('Diese Datei ist (noch) nicht verfügbar.');
        else if (v === 'text') { inst = textView(jobId, path, n.size, vq.line, vq.end); body = inst.el; }
        else if (v === 'hex') { inst = SW.hexView({ jobId: jobId, path: path, size: n.size }); body = inst.el; }
        else { inst = ghidraView(jobId, path, { lern: vq.lern, fn: vq.fn }); body = inst.el; }
        SW.dom.fill(viewHost, ui.section('Inhalt: ' + path, h('div', { cls: 'stack' }, seg, body),
          h('span', { cls: 'small muted', text: v === 'text' ? 'ganze Datei, mit KI-Anmerkungen' : v === 'hex' ? 'ganze Datei, mit Anmerkungen' : 'Ghidra im Offline-Container' })));
      }

      function select(p) {
        if (p === path && lin && node(p)) { return; }
        path = p; view = null; vq = { line: 0, end: 0, lern: false, fn: '' };
        if (chart) chart.mark(p);
        try { window.history.replaceState(null, '', ui.tabHref(jobId, 'analysis', { path: p })); } catch (e) { /* ohne Adressleisten-Update weiter */ }
        paintDetail();
      }

      function paintFlow() {
        if (!lin.nodes.length) { SW.dom.fill(flowHost, ui.section('Umwandlungsprozess', ui.noData('Für diesen Auftrag gibt es noch keine Dateien.'))); return; }
        chart = flowchart(jobId, lin, path, select);
        var nEdges = lin.edges.length;
        SW.dom.fill(flowHost, ui.section('Umwandlungsprozess: vom Sample zum Endergebnis',
          h('div', { cls: 'stack' },
            chart.el,
            h('p', { cls: 'small muted', text: nEdges ? 'Jeder Pfeil nennt Werkzeug, Methode und Beleg-ID. Ein Klick auf eine Datei zeigt unten ihren Inhalt; die Vorschau zeigt den Zwischenstand an dieser Stelle.'
              : 'Bisher wurde keine Datei aus dem Sample abgeleitet. Dekodierte Schichten, entpackte Member und Ausschnitte erscheinen hier, sobald die Analyse sie erzeugt.' }))));
      }

      SW.dom.fill(host, h('div', { cls: 'an' }, flowHost, detailHost, viewHost));
      SW.dom.fill(flowHost, ui.loading('Umwandlungsprozess wird geladen …'));
      ui.softGet('/jobs/' + encodeURIComponent(jobId) + '/lineage').then(function (r) {
        if (dead) return;
        if (r.ok && r.data && Array.isArray(r.data.nodes)) lin = r.data;
        else {
          var files = (ctx.st && ctx.st.files) || [];
          lin = { nodes: files.map(function (f) { return { path: f.path, size: f.size, sha256: f.sha256, kind: '', label: f.kind === 'sample' ? 'Original-Sample' : 'abgeleitete Datei', preview: '' }; }), edges: [], final: files.map(function (f) { return f.path; }) };
        }
        lin.edges = lin.edges || []; lin.final = lin.final || [];
        if (!node(path) && lin.nodes.length) path = (node('sample') || lin.nodes[0]).path;
        paintFlow();
        paintDetail();
      });

      var offFiles = ui.live(['files'], function () {
        ui.softGet('/jobs/' + encodeURIComponent(jobId) + '/lineage').then(function (r) {
          if (dead || !r.ok || !r.data || !Array.isArray(r.data.nodes)) return;
          var changed = JSON.stringify(r.data.edges) !== JSON.stringify(lin && lin.edges) || r.data.nodes.length !== (lin && lin.nodes.length);
          if (changed) { lin = r.data; paintFlow(); if (!node(path)) paintDetail(); }
        });
      }, 400);

      return {
        dispose: function () { dead = true; offFiles(); if (inst) inst.dispose(); },
        update: function (r) {
          var nq = r.query || {};
          var np = nq.path || nq.file;
          if (np && np !== path) { vq = { line: parseInt(nq.line, 10) || 0, end: parseInt(nq.end, 10) || 0, lern: nq.lern === '1', fn: nq.function || '' }; path = np; view = nq.view || null; if (chart) chart.mark(np); paintDetail(); }
          else if (nq.line && inst && inst.jumpTo) inst.jumpTo(parseInt(nq.line, 10), parseInt(nq.end, 10));
        }
      };
    }
  });
})();
