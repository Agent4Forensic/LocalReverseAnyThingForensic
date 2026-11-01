/* Hex-Ansicht fuer den Tab Datei: die ganze Datei als Hex und ASCII, fluessig scrollbar bis zum letzten Byte.
   Virtuelles Scrollen: nur die sichtbaren Zeilen existieren im DOM, die Bytes kommen in Bloecken zu 64 KiB vom Server
   (Base64) und liegen in einem kleinen Cache. Markierungen kommen aus /inspect/structure: Formatstruktur (feste
   Parser, ohne KI) sowie Belege und Befundzitate der Analyse. Alle Texte aus dem Sample werden nur als Text eingefuegt. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var api = SW.api;
  var ui = SW.ui;

  var ROW = 16;            /* Byte je Zeile */
  var ROWH = 20;           /* Pixel je Zeile, muss zu .hx-row in styles.css passen */
  var CHUNK = 65536;       /* Byte je Abruf (Servergrenze) */
  var CACHE = 48;          /* Bloecke im Speicher: 3 MiB */
  var MAXPX = 8000000;     /* Browser begrenzen Elementhoehen; darueber wird die Scrollbahn skaliert */
  var PRIO = { finding: 3, evidence: 2, structure: 1 };
  var GROUPS = [['structure', 'Struktur'], ['evidence', 'Belege'], ['finding', 'Befunde']];
  var STATUS_DE = { confirmed: 'bestätigt', hypothesis: 'Hypothese', open: 'offener Punkt', rejected: 'verworfen' };

  function hexN(n, w) { var s = n.toString(16); while (s.length < w) s = '0' + s; return s; }
  function rangeText(r) { return '0x' + hexN(r.offset, 8) + '–0x' + hexN(r.offset + r.length - 1, 8) + ' (' + r.length.toLocaleString('de-DE') + ' Byte)'; }
  function b64ToBytes(s) {
    var bin = window.atob(s || '');
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function toneClass(r) {
    if (r.source === 'finding') return 'r-' + (r.status || 'open');
    if (r.source === 'evidence') return 'r-evidence';
    return 'r-' + (r.tone || 'struct') + (r.id % 2 ? ' r-alt' : '');
  }
  function better(a, b) {   /* true, wenn Region a fuer ein Byte vor b angezeigt wird */
    if (!b) return true;
    var pa = PRIO[a.source] + (a.level || 0) * 0.1, pb = PRIO[b.source] + (b.level || 0) * 0.1;
    return pa !== pb ? pa > pb : a.length < b.length;
  }

  SW.hexView = function (opts) {
    var jobId = opts.jobId, path = opts.path, size = opts.size;
    var base = '/jobs/' + encodeURIComponent(jobId);
    var rows = Math.max(1, Math.ceil(size / ROW));
    var chunks = new Map();          /* idx -> Uint8Array | 'loading' | 'error' */
    var regions = [];
    var notes = [];
    var structState = 'loading';
    var show = { structure: true, evidence: true, finding: true };
    var selByte = null, selRegion = null;
    var dead = false, raf = 0;

    /* ---------- DOM ---------- */
    var viewH = Math.max(240, Math.min(560, Math.round(window.innerHeight * 0.6)));
    var visRows = Math.ceil(viewH / ROWH) + 2;
    var natural = rows * ROWH <= MAXPX;
    var sizerH = natural ? rows * ROWH : MAXPX;
    var win = h('div', { cls: 'hx-win' });
    var sizer = h('div', { cls: 'hx-sizer', vars: { '--h': sizerH + 'px' } }, win);
    var scroller = h('div', { cls: 'hx-scroll', tabindex: '0', role: 'region', 'aria-label': 'Hexdump der ganzen Datei, scrollbar', vars: { '--vh': viewH + 'px' } }, sizer);
    var pool = [];
    for (var i = 0; i < visRows; i++) {
      var hexSpans = [], ascSpans = [];
      var hx = h('span', { cls: 'hx-hex' }), as = h('span', { cls: 'hx-asc' });
      for (var j = 0; j < ROW; j++) {
        var bh = h('span', { cls: 'hx-b', 'data-i': String(j) }), ba = h('span', { cls: 'hx-a', 'data-i': String(j) });
        hexSpans.push(bh); ascSpans.push(ba);
        hx.appendChild(bh); as.appendChild(ba);
      }
      var off = h('span', { cls: 'hx-off' });
      var rowEl = h('div', { cls: 'hx-row' }, off, hx, as);
      win.appendChild(rowEl);
      pool.push({ el: rowEl, off: off, hex: hexSpans, asc: ascSpans, row: -1 });
    }

    var posLabel = h('span', { cls: 'small muted nowrap' });
    var goInput = h('input', { type: 'text', 'aria-label': 'Springe zu Offset', placeholder: '0x1f00 oder 7936' });
    var inspector = h('div', { cls: 'hx-insp' });
    var listHost = h('div', { cls: 'hx-list' });
    var legendHost = h('div');
    var notesHost = h('div');

    function firstRow() {
      var st = scroller.scrollTop;
      if (natural) return Math.floor(st / ROWH);
      var span = Math.max(1, sizerH - viewH);
      return Math.round(Math.min(1, st / span) * Math.max(0, rows - visRows + 2));
    }
    function scrollToRow(r) {
      r = Math.max(0, Math.min(rows - 1, r));
      if (natural) scroller.scrollTop = r * ROWH;
      else scroller.scrollTop = r / Math.max(1, rows - visRows + 2) * Math.max(1, sizerH - viewH);
      schedule();
    }
    function goTo(offset, center) {
      var r = Math.floor(offset / ROW);
      scrollToRow(center ? r - Math.floor(visRows / 3) : r);
    }

    /* ---------- Daten ---------- */
    function chunkFor(idx) {
      var c = chunks.get(idx);
      if (c && c !== 'loading' && c !== 'error') { chunks.delete(idx); chunks.set(idx, c); return c; }   /* LRU */
      if (!c) {
        chunks.set(idx, 'loading');
        api.get(base + '/inspect/hex', { path: path, offset: idx * CHUNK, length: CHUNK, format: 'b64' }).then(function (d) {
          if (dead) return;
          chunks.set(idx, b64ToBytes(d.data_b64));
          while (chunks.size > CACHE) chunks.delete(chunks.keys().next().value);
          schedule();
        }, function () { if (!dead) { chunks.set(idx, 'error'); schedule(); } });
      }
      return null;
    }
    function byteAt(o) {
      if (o < 0 || o >= size) return null;
      var c = chunkFor(Math.floor(o / CHUNK));
      return c ? c[o % CHUNK] : null;
    }

    /* ---------- Zeichnen ---------- */
    function schedule() { if (!raf && !dead) raf = window.requestAnimationFrame(paint); }
    function visibleRegions(a, b) {
      return regions.filter(function (r) { return show[r.source] && r.offset < b && r.offset + r.length > a; });
    }
    function paint() {
      raf = 0;
      if (dead) return;
      var fr = firstRow();
      win.style.transform = 'translateY(' + (natural ? fr * ROWH : scroller.scrollTop) + 'px)';
      var a = fr * ROW, b = Math.min(size, (fr + visRows) * ROW);
      var vis = visibleRegions(a, b);
      for (var k = 0; k < pool.length; k++) {
        var p = pool[k];
        var r = fr + k;
        if (r >= rows) { p.el.hidden = true; continue; }
        p.el.hidden = false;
        p.off.textContent = hexN(r * ROW, 8);
        for (var j = 0; j < ROW; j++) {
          var o = r * ROW + j;
          var bh = p.hex[j], ba = p.asc[j];
          if (o >= size) { bh.textContent = '  '; ba.textContent = ' '; bh.className = ba.className = 'hx-b'; bh.title = ba.title = ''; continue; }
          var v = byteAt(o);
          var best = null, ev = null;
          for (var q = 0; q < vis.length; q++) {
            var rg = vis[q];
            if (rg.offset > o || o >= rg.offset + rg.length) continue;
            if (rg.source === 'evidence') { if (!ev || rg.length < ev.length) ev = rg; }   /* eigene Ebene: Unterstreichung */
            else if (better(rg, best)) best = rg;
          }
          var cls = 'hx-b' + (best ? ' ' + toneClass(best) : '') + (ev ? ' u-ev' : '') +
            (selRegion && (best === selRegion || ev === selRegion) ? ' r-sel' : '') + (o === selByte ? ' is-cur' : '');
          bh.className = cls;
          ba.className = cls.replace('hx-b', 'hx-a');
          bh.textContent = v === null ? '··' : hexN(v, 2);
          ba.textContent = v === null ? '·' : (v >= 32 && v < 127 ? String.fromCharCode(v) : '.');
          var tip = [best && best.label, ev && ev.label].filter(Boolean).join(' · ');
          if (bh.title !== tip) { bh.title = tip; ba.title = tip; }
        }
      }
      posLabel.textContent = 'Zeile ' + (fr + 1).toLocaleString('de-DE') + ' von ' + rows.toLocaleString('de-DE') +
        ' · Offset 0x' + hexN(a, 8) + ' · ' + Math.round(100 * Math.min(1, (fr + visRows) / rows)) + ' %';
      if (selByte !== null) paintInspector();
    }

    /* ---------- Auswahl und Inspektor ---------- */
    function regionsAt(o) {
      return regions.filter(function (r) { return show[r.source] && r.offset <= o && o < r.offset + r.length; })
        .sort(function (x, y) { return y.length - x.length; });
    }
    function select(o, region) {
      selByte = o;
      var at = regionsAt(o);
      selRegion = region || at.reduce(function (acc, r) { return better(r, acc) ? r : acc; }, null);
      paintInspector();
      schedule();
    }
    function byteText(v) {
      if (v === null) return 'lädt …';
      return '0x' + hexN(v, 2) + ' · ' + v + ' · 0b' + ('0000000' + v.toString(2)).slice(-8) +
        (v >= 32 && v < 127 ? " · '" + String.fromCharCode(v) + "'" : '');
    }
    function num(bytes) {
      var v = 0;
      for (var i = bytes - 1; i >= 0; i--) {
        var b = byteAt(selByte + i);
        if (b === null) return '–';
        v = v * 256 + b;
      }
      return v.toLocaleString('de-DE') + ' (0x' + v.toString(16) + ')';
    }
    function paintInspector() {
      if (selByte === null) {
        SW.dom.fill(inspector, h('p', { cls: 'small muted', text: 'Ein Byte anklicken: Wert, Zahlen ab dieser Stelle und alle Bedeutungen dieser Stelle erscheinen hier.' }));
        return;
      }
      var v = byteAt(selByte);
      var at = regionsAt(selByte);
      SW.dom.fill(inspector,
        h('dl', { cls: 'kv small' },
          h('dt', { text: 'Offset' }), h('dd', { cls: 'mono', text: '0x' + hexN(selByte, 8) + ' (' + selByte.toLocaleString('de-DE') + ')' }),
          h('dt', { text: 'Byte' }), h('dd', { cls: 'mono', text: byteText(v) }),
          h('dt', { text: 'uint16 LE' }), h('dd', { cls: 'mono', text: num(2) }),
          h('dt', { text: 'uint32 LE' }), h('dd', { cls: 'mono', text: num(4) })),
        at.length ? h('ol', { cls: 'hx-at' }, at.map(function (r) { return regionItem(r, true); }))
          : h('p', { cls: 'small muted', text: 'Für diese Stelle gibt es keine Struktur- oder Analyse-Anmerkung.' }));
    }
    function regionItem(r, detail) {
      var links = [];
      if (r.finding_id) links.push(h('a', { cls: 'mono', href: ui.tabHref(jobId, 'live', { finding: r.finding_id }), text: r.finding_id }));
      if (r.finding_ids) r.finding_ids.forEach(function (f) { links.push(h('a', { cls: 'mono', href: ui.tabHref(jobId, 'live', { finding: f }), text: f })); });
      if (r.evidence_id) links.push(ui.chips(jobId, [r.evidence_id]));
      return h('li', { cls: 'hx-item ' + toneClass(r) + (r === selRegion ? ' is-sel' : '') },
        h('button', { type: 'button', cls: 'hx-jump', title: 'Zu ' + rangeText(r) + ' springen', on: { click: function () { goTo(r.offset, true); select(r.offset, r); } } },
          h('span', { cls: 'hx-sw', 'aria-hidden': 'true' }), h('span', { cls: 'hx-lbl', text: r.label }), h('span', { cls: 'small muted mono nowrap', text: '0x' + hexN(r.offset, 6) })),
        detail || r.source === 'finding' ? h('p', { cls: 'small', text: r.explain }) : null,
        detail ? h('p', { cls: 'small muted mono', text: rangeText(r) }) : null,
        links.length ? h('p', { cls: 'small row' }, links) : null);
    }

    /* ---------- Liste der Anmerkungen ---------- */
    function paintList() {
      if (structState === 'loading') { SW.dom.fill(listHost, ui.loading('Struktur und Befunde werden zugeordnet …')); return; }
      if (structState === 'error') { SW.dom.fill(listHost, ui.errorBox('Anmerkungen nicht verfügbar.')); return; }
      var groups = GROUPS.map(function (g) {
        var items = regions.filter(function (r) { return r.source === g[0]; });
        var box = h('input', { type: 'checkbox', checked: show[g[0]] });
        box.addEventListener('change', function () { show[g[0]] = box.checked; schedule(); if (selByte !== null) paintInspector(); });
        return h('details', { cls: 'hx-grp', open: g[0] !== 'evidence' && items.length < 60 ? true : null },
          h('summary', null, h('label', { cls: 'chk small', on: { click: function (e) { e.stopPropagation(); } } }, box, ' markieren'), ' ', h('strong', { text: g[1] }), ' ', h('span', { cls: 'tag', text: String(items.length) })),
          items.length ? h('ol', { cls: 'hx-items' }, items.slice(0, 600).map(function (r) { return regionItem(r, false); }))
            : h('p', { cls: 'small muted', text: g[0] === 'structure' ? 'Kein bekanntes Format (PE, ELF, ZIP/APK, gzip) erkannt.' : g[0] === 'finding' ? 'Kein Befundzitat steht wörtlich in dieser Datei.' : 'Kein Beleg nennt einen Bytebereich dieser Datei.' }));
      });
      SW.dom.fill(listHost, groups);
      SW.dom.fill(notesHost, notes.length ? h('div', { cls: 'notice tone-warn', role: 'note' }, icon('alert'), h('div', null, h('p', { text: 'Hinweise der Formatprüfung (die Datei weicht vom Format ab oder ist sehr groß):' }), h('ul', { cls: 'small' }, notes.map(function (n) { return h('li', { text: n }); })))) : null);
    }

    function loadStructure() {
      api.get(base + '/inspect/structure', { path: path }).then(function (d) {
        if (dead) return;
        regions = d.regions || [];
        notes = d.notes || [];
        if (d.quote_search_bytes < size) notes.push('Befundzitate wurden in den ersten ' + Math.round(d.quote_search_bytes / 1048576) + ' MiB gesucht; Belegbereiche gelten für die ganze Datei.');
        structState = 'ok';
        paintList();
        schedule();
      }, function () { if (!dead) { structState = 'error'; paintList(); } });
    }

    /* ---------- Ereignisse ---------- */
    scroller.addEventListener('scroll', schedule, { passive: true });
    scroller.addEventListener('click', function (e) {
      var t = e.target;
      if (!t || !t.getAttribute || t.getAttribute('data-i') === null) return;
      var k = pool.map(function (p) { return p.el; }).indexOf(t.parentNode.parentNode);
      if (k < 0) return;
      var o = (firstRow() + k) * ROW + Number(t.getAttribute('data-i'));
      if (o < size) select(o, null);
    });
    function go() {
      var raw = String(goInput.value).trim();
      var v = /^0x/i.test(raw) ? parseInt(raw.slice(2), 16) : parseInt(raw, 10);
      if (isNaN(v) || v < 0) { goInput.setAttribute('aria-invalid', 'true'); return; }
      goInput.removeAttribute('aria-invalid');
      v = Math.min(v, size - 1);
      goTo(v, true);
      select(v, null);
    }
    goInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') go(); });

    var legend = h('ul', { cls: 'dg-legend hx-legend' }, [
      ['r-struct', 'Formatstruktur'], ['r-note', 'wichtige Stelle'], ['r-warn', 'auffällig'], ['r-evidence', 'gelesen als Beleg'],
      ['r-confirmed', 'Befund bestätigt'], ['r-hypothesis', 'Hypothese'], ['r-open', 'offener Punkt']
    ].map(function (x) { return h('li', null, h('span', { cls: 'hx-key ' + x[0], 'aria-hidden': 'true' }), x[1]); }));
    SW.dom.fill(legendHost, legend);

    var el = h('div', { cls: 'hx' },
      h('div', { cls: 'hex-nav' },
        h('button', { type: 'button', cls: 'btn sm', on: { click: function () { scrollToRow(0); } } }, 'Anfang'),
        h('button', { type: 'button', cls: 'btn sm', on: { click: function () { scrollToRow(rows); } } }, 'Ende'),
        h('label', { cls: 'row small' }, 'Offset ', goInput),
        h('button', { type: 'button', cls: 'btn sm', on: { click: go } }, 'Springen'),
        posLabel),
      legendHost,
      h('div', { cls: 'hx-split' },
        h('div', { cls: 'hx-main' },
          h('div', { cls: 'hx-row hx-head', 'aria-hidden': 'true' }, h('span', { text: 'Offset' }),
            h('span', { cls: 'hx-hex', text: '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f' }), h('span', { cls: 'hx-asc', text: 'ASCII' })),
          scroller,
          h('p', { cls: 'small muted', text: 'Ganze Datei: scrollen, Bild-auf/ab, Pos1/Ende. 16 Byte je Zeile, nicht druckbare Zeichen als Punkt. Farbige Bytes tragen eine Anmerkung (Maus darüber zeigt sie, Klick öffnet sie rechts).' })),
        h('aside', { cls: 'hx-side', 'aria-label': 'Anmerkungen zur Datei' },
          h('section', { cls: 'card' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Ausgewählte Stelle' })), h('div', { cls: 'card-b' }, inspector)),
          h('section', { cls: 'card' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Was bedeutet was' })), h('div', { cls: 'card-b' },
            h('p', { cls: 'small muted', text: 'Struktur: feste Formatregeln, ohne KI. Belege: Bereiche, die ein Werkzeug gelesen hat. Befunde: Stellen, an denen ein Zitat eines Befunds wörtlich in der Datei steht, also die Erkenntnisse der Analyse im Code.' }),
            notesHost, listHost)))));

    paintInspector();
    paintList();
    loadStructure();
    schedule();
    return { el: el, dispose: function () { dead = true; if (raf) window.cancelAnimationFrame(raf); } };
  };
})();
