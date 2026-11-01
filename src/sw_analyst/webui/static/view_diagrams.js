/* Tab Diagramme: Ablauf des Auftrags, Wissensfortschritt, Aufgabengraph und Belegfluss als SVG.
   Ohne Bibliothek und ohne KI: jedes Diagramm wird aus Aufgaben, Befunden und Belegen des Stores gezeichnet und
   aktualisiert sich live. Texte aus dem Sample oder vom Modell (Titel, Aussagen) erscheinen nur als Textknoten. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var s = SW.dom.svg;
  var icon = SW.dom.icon;
  var store = SW.store;
  var ui = SW.ui;

  var FINISHED = { done: 1, failed: 1, skipped: 1, blocked: 1 };
  var STATE_WORD = { done: 'erledigt', cur: 'läuft', part: 'teilweise', open: 'offen', skip: 'nicht nötig' };
  var F_STATUS = [['confirmed', 'bestätigt'], ['hypothesis', 'Hypothese'], ['open', 'offener Punkt'], ['rejected', 'verworfen']];

  function trunc(t, n) { t = String(t || ''); return t.length > n ? t.slice(0, n - 1) + '…' : t; }
  function isSynth(t) { return /^Synthesis/i.test(t.title || ''); }

  /* ---------- 1. Ablauf ---------- */
  function stageState(list, ended) {
    var total = list.length;
    var fin = list.filter(function (t) { return FINISHED[t.status]; }).length;
    var run = list.some(function (t) { return t.status === 'running'; });
    var st = run ? 'cur' : !total ? (ended ? 'skip' : 'open') : fin === total ? 'done' : fin ? 'part' : 'open';
    return { state: st, done: fin, total: total };
  }

  function stages(tasks, job) {
    var work = tasks.filter(function (t) { return t.kind !== 'group'; });
    var synth = work.filter(isSynth);
    var synthIds = {};
    synth.forEach(function (t) { synthIds[t.id] = true; });
    var by = function (fn) { return work.filter(fn); };
    var ended = job && ['done', 'partial', 'failed', 'cancelled'].indexOf(job.status) >= 0;
    var list = [
      ['Triage ohne KI', 'Hashes, Dateityp, Rezeptwahl', by(function (t) { return t.origin === 'triage'; })],
      ['Rezeptschritte', 'Mindestabdeckung aus dem Rezept', by(function (t) { return t.origin === 'recipe' && !isSynth(t); })],
      ['Abgeleitete Dateien', 'entpackte oder dekodierte Schichten', by(function (t) { return t.origin === 'artifact'; })],
      ['Folgeaufgaben', 'vom Bewerter aus Lücken und Hypothesen', by(function (t) { return (t.origin === 'evaluator' || t.origin === 'prioritizer' || t.origin === 'split') && !synthIds[t.parent_id]; })],
      ['Planer', 'höchstens 4 Aufgaben aus dem Job-Ziel', by(function (t) { return t.origin === 'planner'; })],
      ['Synthese', 'Widersprüche, Standardfragen, Lücken', synth],
      ['Lückenrunde', 'eine Runde nach der Synthese', by(function (t) { return synthIds[t.parent_id]; })],
      ['Zielfragen', 'Antworten nur aus bestätigten Befunden', by(function (t) { return t.kind === 'question'; })]
    ].map(function (x) { var r = stageState(x[2], ended); r.label = x[0]; r.sub = x[1]; return r; });
    list.push({ label: 'Bericht', sub: 'Übersetzung, Defanging, Evidence-Tabelle', state: ended ? 'done' : 'open', done: ended ? 1 : 0, total: 1 });
    return list;
  }

  function flowSvg(list) {
    var W = 560, BH = 46, GAP = 18, X = 40, BW = 400;
    var H = list.length * (BH + GAP) + 10;
    var kids = [s('defs', null, s('marker', { id: 'dg-arr', viewBox: '0 0 10 10', refX: '9', refY: '5', markerWidth: '7', markerHeight: '7', orient: 'auto-start-reverse' },
      s('path', { d: 'M0,0 L10,5 L0,10 z', 'class': 'dg-arrhead' })))];
    list.forEach(function (n, i) {
      var y = 6 + i * (BH + GAP);
      var cnt = n.total ? n.done + '/' + n.total : '–';
      kids.push(s('g', { 'class': 'dg-node is-' + n.state },
        s('title', null, n.label + ': ' + STATE_WORD[n.state] + (n.total ? ' (' + cnt + ')' : '')),
        s('rect', { x: X, y: y, width: BW, height: BH, rx: 8 }),
        s('text', { x: X + 14, y: y + 19, 'class': 'dg-t' }, (i + 1) + '. ' + n.label),
        s('text', { x: X + 14, y: y + 36, 'class': 'dg-s' }, n.sub),
        s('text', { x: X + BW - 12, y: y + 19, 'class': 'dg-c', 'text-anchor': 'end' }, cnt),
        s('text', { x: X + BW - 12, y: y + 36, 'class': 'dg-s', 'text-anchor': 'end' }, STATE_WORD[n.state])));
      if (n.total > 0) {
        var pw = Math.round((BW - 2) * n.done / n.total);
        kids.push(s('rect', { x: X + 1, y: y + BH - 4, width: pw, height: 3, 'class': 'dg-prog' }));
      }
      if (i < list.length - 1) kids.push(s('line', { x1: X + BW / 2, y1: y + BH, x2: X + BW / 2, y2: y + BH + GAP - 2, 'class': 'dg-edge', 'marker-end': 'url(#dg-arr)' }));
    });
    /* Rueckkopplung: Bewerter und Planer legen neue Aufgaben in die Queue (Schritte 2 bis 7). */
    var y1 = 6 + 1 * (BH + GAP) + BH / 2, y2 = 6 + 6 * (BH + GAP) + BH / 2;
    kids.push(s('path', { d: 'M' + (X + BW) + ',' + y2 + ' C' + (X + BW + 70) + ',' + y2 + ' ' + (X + BW + 70) + ',' + y1 + ' ' + (X + BW) + ',' + y1, 'class': 'dg-loop', 'marker-end': 'url(#dg-arr)' }));
    kids.push(s('text', { x: X + BW + 62, y: (y1 + y2) / 2, 'class': 'dg-s', transform: 'rotate(90 ' + (X + BW + 62) + ' ' + (y1 + y2) / 2 + ')', 'text-anchor': 'middle' }, 'Bewerter: Lücken → neue Aufgaben'));
    return s('svg', { viewBox: '0 0 ' + W + ' ' + H, 'class': 'dg-svg', role: 'img', 'aria-label': 'Ablauf des Auftrags mit Zustand je Schritt' }, kids);
  }

  /* ---------- 2. Wissensfortschritt ---------- */
  function progressData(tasks, findings) {
    var order = tasks.filter(function (t) { return t.kind !== 'group' && t.finished_at; })
      .sort(function (a, b) { return a.finished_at < b.finished_at ? -1 : a.finished_at > b.finished_at ? 1 : a.seq - b.seq; });
    var byTask = {};
    findings.forEach(function (f) { (byTask[f.task_id] = byTask[f.task_id] || []).push(f); });
    var acc = { confirmed: 0, hypothesis: 0, open: 0, rejected: 0 };
    var pts = [{ task: null, c: Object.assign({}, acc) }];
    order.forEach(function (t) {
      (byTask[t.id] || []).forEach(function (f) { if (acc[f.status] !== undefined) acc[f.status]++; });
      pts.push({ task: t, c: Object.assign({}, acc) });
    });
    return pts;
  }

  function progressSvg(pts, jobId) {
    var W = 560, H = 220, L = 40, R = 12, T = 12, B = 30;
    var max = 1;
    pts.forEach(function (p) { F_STATUS.forEach(function (k) { max = Math.max(max, p.c[k[0]]); }); });
    var n = Math.max(1, pts.length - 1);
    var xs = function (i) { return L + (W - L - R) * i / n; };
    var ys = function (v) { return T + (H - T - B) * (1 - v / max); };
    var kids = [];
    var step = Math.max(1, Math.ceil(max / 4));
    max = Math.ceil(max / step) * step;
    for (var v = 0; v <= max; v += step) {
      kids.push(s('line', { x1: L, x2: W - R, y1: ys(v), y2: ys(v), 'class': 'dg-grid' }));
      kids.push(s('text', { x: L - 6, y: ys(v) + 4, 'class': 'dg-s', 'text-anchor': 'end' }, String(v)));
    }
    kids.push(s('text', { x: (L + W - R) / 2, y: H - 6, 'class': 'dg-s', 'text-anchor': 'middle' }, 'abgeschlossene Aufgaben (zeitliche Reihenfolge) → ' + n));
    F_STATUS.forEach(function (k) {
      var d = pts.map(function (p, i) { return (i ? 'L' : 'M') + xs(i).toFixed(1) + ',' + ys(p.c[k[0]]).toFixed(1); }).join(' ');
      kids.push(s('path', { d: d, 'class': 'dg-line st-' + k[0] }));
    });
    /* Punkte nur fuer bestaetigte Befunde: Hover nennt die Aufgabe, Klick oeffnet sie im Aufgabenbaum. */
    pts.forEach(function (p, i) {
      if (!p.task) return;
      var prev = pts[i - 1].c.confirmed;
      if (p.c.confirmed === prev) return;
      kids.push(s('a', { href: ui.tabHref(jobId, 'tree', { task: p.task.id }) },
        s('circle', { cx: xs(i), cy: ys(p.c.confirmed), r: 4, 'class': 'dg-dot st-confirmed' },
          s('title', null, p.task.id + ': ' + trunc(p.task.title, 80) + ' · +' + (p.c.confirmed - prev) + ' bestätigt'))));
    });
    return s('svg', { viewBox: '0 0 ' + W + ' ' + H, 'class': 'dg-svg', role: 'img', 'aria-label': 'Anzahl der Befunde je Status über die abgeschlossenen Aufgaben' }, kids);
  }

  function legend() {
    return h('ul', { cls: 'dg-legend' }, F_STATUS.map(function (k) {
      return h('li', null, h('span', { cls: 'dg-key st-' + k[0], 'aria-hidden': 'true' }), k[1]);
    }));
  }

  /* ---------- 3. Aufgabengraph ---------- */
  function treeSvg(tasks, jobId) {
    var ids = {};
    tasks.forEach(function (t) { ids[t.id] = t; });
    var kids = {};
    var roots = [];
    tasks.forEach(function (t) {
      if (t.parent_id && ids[t.parent_id]) (kids[t.parent_id] = kids[t.parent_id] || []).push(t);
      else roots.push(t);
    });
    var pos = {};
    var leaf = 0, maxD = 0;
    function place(t, d) {
      maxD = Math.max(maxD, d);
      var c = (kids[t.id] || []).sort(function (a, b) { return a.seq - b.seq; });
      if (!c.length) { pos[t.id] = { x: leaf++, d: d }; return; }
      c.forEach(function (k) { place(k, d + 1); });
      pos[t.id] = { x: (pos[c[0].id].x + pos[c[c.length - 1].id].x) / 2, d: d };
    }
    roots.sort(function (a, b) { return a.seq - b.seq; }).forEach(function (r) { place(r, 0); });
    var CW = 34, RH = 70, P = 20;
    var W = Math.max(320, leaf * CW + 2 * P), H = (maxD + 1) * RH + 30;
    var X = function (id) { return P + pos[id].x * CW + CW / 2; };
    var Y = function (id) { return 20 + pos[id].d * RH; };
    var out = [];
    tasks.forEach(function (t) {
      if (t.parent_id && ids[t.parent_id]) {
        var x1 = X(t.parent_id), y1 = Y(t.parent_id), x2 = X(t.id), y2 = Y(t.id);
        out.push(s('path', { d: 'M' + x1 + ',' + y1 + ' C' + x1 + ',' + (y1 + RH / 2) + ' ' + x2 + ',' + (y2 - RH / 2) + ' ' + x2 + ',' + y2, 'class': 'dg-tedge' }));
      }
    });
    tasks.forEach(function (t) {
      var grp = t.kind === 'group';
      out.push(s('a', { href: ui.tabHref(jobId, 'tree', { task: t.id }) },
        s('g', { 'class': 'dg-task ts-' + (t.status || 'pending') + ' or-' + (t.origin || 'x') },
          s('title', null, t.id + ' · ' + (t.origin || '') + ' · ' + (t.status || '') + '\n' + trunc(t.title, 120)),
          grp ? s('rect', { x: X(t.id) - 9, y: Y(t.id) - 9, width: 18, height: 18, rx: 3 }) : s('circle', { cx: X(t.id), cy: Y(t.id), r: 9 }),
          s('text', { x: X(t.id), y: Y(t.id) + 24, 'class': 'dg-s', 'text-anchor': 'middle' }, t.id.replace(/^T-0*/, 'T')))));
    });
    return s('svg', { viewBox: '0 0 ' + W + ' ' + H, width: W, height: H, 'class': 'dg-svg dg-tree', role: 'img', 'aria-label': 'Aufgabengraph: wer hat welche Aufgabe erzeugt' }, out);
  }

  /* ---------- 4. Belegfluss: Werkzeug -> Befundstatus ---------- */
  function flowData(findings, evList) {
    var toolOf = {};
    (evList || []).forEach(function (e) { toolOf[e.id] = e.tool; });
    var links = {}, tools = {}, stat = {};
    findings.forEach(function (f) {
      var seen = {};
      (f.evidence_ids || []).forEach(function (id) {
        var tool = toolOf[id] || 'unbekannt';
        if (seen[tool]) return;
        seen[tool] = true;
        var k = tool + '|' + f.status;
        links[k] = (links[k] || 0) + 1;
        tools[tool] = (tools[tool] || 0) + 1;
        stat[f.status] = (stat[f.status] || 0) + 1;
      });
      if (!(f.evidence_ids || []).length) {
        links['ohne Beleg|' + f.status] = (links['ohne Beleg|' + f.status] || 0) + 1;
        tools['ohne Beleg'] = (tools['ohne Beleg'] || 0) + 1;
        stat[f.status] = (stat[f.status] || 0) + 1;
      }
    });
    return { links: links, tools: tools, stat: stat };
  }

  function sankeySvg(d) {
    var tl = Object.keys(d.tools).sort(function (a, b) { return d.tools[b] - d.tools[a]; });
    var sl = F_STATUS.map(function (k) { return k[0]; }).filter(function (k) { return d.stat[k]; });
    var total = 0;
    tl.forEach(function (t) { total += d.tools[t]; });
    var W = 560, H = Math.max(160, 26 * Math.max(tl.length, sl.length) + 40), X1 = 150, X2 = W - 150, NW = 10, GAP = 6;
    var scale = (H - 20 - GAP * Math.max(tl.length, sl.length)) / Math.max(1, total);
    var kids = [];
    function column(list, sizes, x, anchor, labelFn) {
      var y = 10, at = {};
      list.forEach(function (k) {
        var hh = Math.max(3, sizes[k] * scale);
        at[k] = { y: y, used: 0 };
        kids.push(s('rect', { x: x, y: y, width: NW, height: hh, 'class': 'dg-sn ' + (anchor === 'start' ? 'st-' + k : 'dg-tool') }));
        kids.push(s('text', { x: anchor === 'end' ? x - 6 : x + NW + 6, y: y + hh / 2 + 4, 'class': 'dg-s', 'text-anchor': anchor }, labelFn(k) + ' (' + sizes[k] + ')'));
        y += hh + GAP;
      });
      return at;
    }
    var A = column(tl, d.tools, X1 - NW, 'end', function (k) { return trunc(k, 22); });
    var Bc = column(sl, d.stat, X2, 'start', function (k) { return F_STATUS.filter(function (x) { return x[0] === k; })[0][1]; });
    tl.forEach(function (t) {
      sl.forEach(function (st) {
        var n = d.links[t + '|' + st];
        if (!n) return;
        var w = Math.max(1.5, n * scale);
        var ya = A[t].y + A[t].used + w / 2, yb = Bc[st].y + Bc[st].used + w / 2;
        A[t].used += w; Bc[st].used += w;
        kids.push(s('path', { d: 'M' + X1 + ',' + ya + ' C' + (X1 + X2) / 2 + ',' + ya + ' ' + (X1 + X2) / 2 + ',' + yb + ' ' + X2 + ',' + yb, 'class': 'dg-band st-' + st, 'stroke-width': w.toFixed(1) },
          s('title', null, t + ' → ' + st + ': ' + n + ' Befund(e)')));
      });
    });
    return s('svg', { viewBox: '0 0 ' + W + ' ' + H, 'class': 'dg-svg', role: 'img', 'aria-label': 'Belegfluss: aus welchem Werkzeug stammen die Belege der Befunde je Status' }, kids);
  }

  /* ---------- Tab ---------- */
  SW.registerTab({
    id: 'diagrams', label: 'Diagramme', icon: 'chart',
    mount: function (host, ctx) {
      var st = ctx.st;
      var dead = false;
      var flowHost = h('div'), progHost = h('div'), treeHost = h('div'), sankHost = h('div');

      function card(title, note, body) {
        return h('section', { cls: 'card dg-card' }, h('div', { cls: 'card-h' }, h('h2', { text: title })),
          h('div', { cls: 'card-b' }, h('p', { cls: 'small muted', text: note }), body));
      }
      function paint() {
        if (dead) return;
        var tasks = store.tasksSorted(st);
        var findings = st.findings || [];
        if (!tasks.length) {
          var empty = st.loaded ? ui.noData('Die Diagramme entstehen, sobald die Triage Aufgaben angelegt hat.') : ui.loading();
          SW.dom.fill(flowHost, empty);
          SW.dom.clear(progHost); SW.dom.clear(treeHost); SW.dom.clear(sankHost);
          return;
        }
        SW.dom.fill(flowHost, card('Ablauf des Auftrags',
          'Jeder Schritt zeigt erledigte von geplanten Aufgaben. Die Schleife rechts: Der Bewerter prüft jede Aufgabe und legt für Lücken und Hypothesen Folgeaufgaben an (ADR-0007).',
          h('div', { cls: 'dg-scroll' }, flowSvg(stages(tasks, st.summary)))));
        var pts = progressData(tasks, findings);
        var last = pts[pts.length - 1].c;
        SW.dom.fill(progHost, card('Wissensfortschritt',
          'So wächst das Wissen über die Probe: bestätigt heißt, ein wörtliches Zitat aus einer Werkzeugausgabe trägt die Aussage. Ein Punkt markiert eine Aufgabe, die neue bestätigte Befunde brachte (Klick öffnet sie).',
          h('div', null, legend(),
            h('p', { cls: 'small', text: 'Stand: ' + last.confirmed + ' bestätigt · ' + last.hypothesis + ' Hypothesen · ' + last.open + ' offene Punkte · ' + last.rejected + ' verworfen' }),
            h('div', { cls: 'dg-scroll' }, progressSvg(pts, st.id)))));
        SW.dom.fill(treeHost, card('Aufgabengraph',
          'Wer hat welche Aufgabe erzeugt: Quadrat = Gruppe, Kreis = Aufgabe. Farbe = Status, Rand = Herkunft (Rezept, Bewerter, Planer, Artefakt, Zielfrage). Klick öffnet die Aufgabe.',
          h('div', { cls: 'dg-scroll' }, treeSvg(tasks, st.id))));
        if (!findings.length) { SW.dom.fill(sankHost, card('Belegfluss', 'Noch keine Befunde.', null)); return; }
        if (!st.evidenceList) {
          SW.dom.fill(sankHost, card('Belegfluss', 'Belegliste wird geladen …', ui.loading()));
          store.ensureEvidenceList(st).then(null, function () { if (!dead) SW.dom.fill(sankHost, ui.errorBox('Belegliste nicht verfügbar.')); });
          return;
        }
        SW.dom.fill(sankHost, card('Belegfluss',
          'Aus welchen Werkzeugen stammen die Belege der Befunde. Breite = Anzahl der Befunde. Viele Hypothesen aus einem Werkzeug zeigen, wo ein zweites, unabhängiges Werkzeug die Aussage prüfen sollte.',
          h('div', { cls: 'dg-scroll' }, sankeySvg(flowData(findings, st.evidenceList)))));
      }

      SW.dom.fill(host, h('div', { cls: 'stack dg' },
        h('div', { cls: 'notice tone-neutral', role: 'note' }, icon('info'), h('p', { text: 'Alle Diagramme werden ohne KI aus den gespeicherten Aufgaben, Befunden und Belegen gezeichnet und aktualisieren sich während des Laufs.' })),
        flowHost, progHost, treeHost, sankHost));
      paint();
      var offA = ui.live(['tasks', 'findings', 'summary', 'loaded'], function (kind) { if (kind === 'findings') st.evidenceList = null; paint(); }, 400);
      var offB = ui.live(['evidencelist'], paint, 50);
      return { dispose: function () { dead = true; offA(); offB(); } };
    }
  });
})();
