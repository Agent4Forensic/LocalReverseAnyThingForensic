/* Tab Bericht: Gutachten (Markdown aus gespeicherten Daten, DE/EN), Diagramme (Ablauf, Befundverteilung) und die
   Befunde mit Belegen. Der fruehere Tab "Live-Bericht" (id live) ist nur noch eine Weiterleitung hierher. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var s = SW.dom.svg;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var api = SW.api;
  var store = SW.store;
  var ui = SW.ui;

  var FINISHED = { done: 1, failed: 1, skipped: 1, blocked: 1 };
  var F_ORDER = [['confirmed', 'bestätigt'], ['hypothesis', 'Hypothese'], ['open', 'offen'], ['rejected', 'verworfen']];

  function findingCard(st, f, target) {
    var fresh = store.freshAge(st, 'f:' + f.id) !== null;
    return h('article', { cls: ['fcard', 'f-' + f.status, fresh ? 'is-fresh' : '', target ? 'is-target' : ''], id: 'f-' + f.id, tabindex: '-1' },
      h('div', { cls: 'row' }, h('span', { cls: 'mono fid', text: f.id }), fmt.badge(f.status), h('span', { cls: 'grow' }),
        f.task_id ? h('a', { cls: 'small mono', href: ui.tabHref(st.id, 'tree', { task: f.task_id }), text: 'Aufgabe ' + f.task_id }) : null),
      h('p', { cls: 'fstmt', text: f.statement_de || f.statement_en }),
      f.statement_de && f.statement_en ? h('details', { cls: 'step-prev' }, h('summary', { text: 'Englisches Original' }), h('p', { cls: 'small', text: f.statement_en })) : null,
      f.status === 'rejected' && f.reject_reason ? h('div', { cls: 'notice tone-err', role: 'note' }, icon('xcircle'), h('p', { text: 'Verworfen: ' + f.reject_reason })) : null,
      f.status === 'hypothesis' ? h('p', { cls: 'small muted', text: 'Hypothese: nicht bestätigt und nicht Grundlage einer Antwort.' }) : null,
      (f.quotes || []).length ? h('div', { cls: 'quotes' }, f.quotes.map(function (q) {
        return h('blockquote', { cls: 'quote' }, h('code', { text: q.quote }), ' ', ui.evidenceChip(st.id, q.evidence_id));
      })) : null,
      (f.evidence_ids || []).length ? h('p', { cls: 'small' }, h('span', { cls: 'muted', text: 'Belege: ' }), ui.chips(st.id, f.evidence_ids)) : h('p', { cls: 'small muted', text: 'Kein Beleg angegeben.' })
    );
  }

  /* ---------- Diagramme (eigene kleine SVGs, nur Textknoten) ---------- */
  function stageOf(tasks, pick) {
    var list = tasks.filter(pick);
    var fin = list.filter(function (t) { return FINISHED[t.status]; }).length;
    var run = list.some(function (t) { return t.status === 'running'; });
    return { state: run ? 'cur' : !list.length ? 'open' : fin === list.length ? 'done' : fin ? 'part' : 'open', done: fin, total: list.length };
  }
  var STATE_WORD = { done: 'erledigt', cur: 'läuft', part: 'teilweise', open: 'offen' };

  function flowFigure(st) {
    var tasks = Array.from(st.tasks.values()).filter(function (t) { return t.kind !== 'group'; });
    var ended = st.summary && ['done', 'partial', 'failed', 'cancelled'].indexOf(st.summary.status) >= 0;
    var stages = [
      ['Triage', function (t) { return t.origin === 'triage'; }],
      ['Rezept', function (t) { return t.origin === 'recipe' && !/^Synthesis/i.test(t.title || ''); }],
      ['Folgeaufgaben', function (t) { return t.origin === 'evaluator' || t.origin === 'prioritizer' || t.origin === 'split' || t.origin === 'artifact' || t.origin === 'planner'; }],
      ['Synthese', function (t) { return /^Synthesis/i.test(t.title || ''); }],
      ['Zielfragen', function (t) { return t.kind === 'question'; }]
    ].map(function (x) { var r = stageOf(tasks, x[1]); r.label = x[0]; return r; });
    stages.push({ label: 'Bericht', state: ended ? 'done' : 'open', done: ended ? 1 : 0, total: 1 });
    var BW = 104, BH = 46, GAP = 26, X0 = 8, Y0 = 8;
    var W = X0 * 2 + stages.length * BW + (stages.length - 1) * GAP;
    var kids = [s('defs', null, s('marker', { id: 'rp-arr', viewBox: '0 0 10 10', refX: '9', refY: '5', markerWidth: '7', markerHeight: '7', orient: 'auto' }, s('path', { d: 'M0,0 L10,5 L0,10 z', 'class': 'rp-arrhead' })))];
    stages.forEach(function (n, i) {
      var x = X0 + i * (BW + GAP);
      if (i) kids.push(s('line', { x1: x - GAP + 2, y1: Y0 + BH / 2, x2: x - 2, y2: Y0 + BH / 2, 'class': 'rp-edge', 'marker-end': 'url(#rp-arr)' }));
      kids.push(s('g', { 'class': 'rp-node is-' + n.state },
        s('title', null, n.label + ': ' + STATE_WORD[n.state] + (n.total ? ' (' + n.done + '/' + n.total + ')' : '')),
        s('rect', { x: x, y: Y0, width: BW, height: BH, rx: 8 }),
        s('text', { x: x + BW / 2, y: Y0 + 20, 'text-anchor': 'middle', 'class': 'rp-t' }, n.label),
        s('text', { x: x + BW / 2, y: Y0 + 36, 'text-anchor': 'middle', 'class': 'rp-s' }, n.total ? n.done + '/' + n.total : '–')));
    });
    var DY = Y0 + BH + 22;
    kids.push(s('g', { 'class': 'rp-node is-off' },
      s('title', null, 'Dynamische Analyse: nicht ausgeführt, Analyse-VM fehlt (ADR-0005)'),
      s('rect', { x: X0 + 4 * (BW + GAP), y: DY, width: BW * 2 + GAP, height: 34, rx: 8 }),
      s('text', { x: X0 + 4 * (BW + GAP) + BW + GAP / 2, y: DY + 21, 'text-anchor': 'middle', 'class': 'rp-s' }, 'Dynamische Analyse: nicht ausgeführt')));
    var H = DY + 34 + 8;
    return h('figure', { cls: 'rp-fig' },
      s('svg', { viewBox: '0 0 ' + W + ' ' + H, width: W, height: H, 'class': 'rp-svg', role: 'img', 'aria-label': 'Ablauf der Analyse in Stufen mit erledigten und gesamten Aufgaben' }, kids),
      h('figcaption', { cls: 'small muted', text: 'Abb.: Ablauf der Analyse (erledigte/gesamte Aufgaben je Stufe). Die dynamische Analyse ist bewusst nicht ausgeführt.' }));
  }

  function distFigure(st) {
    var c = {};
    st.findings.forEach(function (f) { c[f.status] = (c[f.status] || 0) + 1; });
    var ans = { answered: 0, unresolved: 0 };
    st.answers.forEach(function (a) { if (a.status === 'answered') ans.answered++; else ans.unresolved++; });
    var rows = F_ORDER.map(function (x) { return [x[0], x[1], c[x[0]] || 0]; })
      .concat([['answered', 'Fragen beantwortet', ans.answered], ['unresolved', 'Fragen ungeklärt', ans.unresolved]]);
    var max = Math.max(1, Math.max.apply(null, rows.map(function (r) { return r[2]; })));
    var LW = 130, BWm = 360, RH = 26;
    var W = LW + BWm + 50, H = rows.length * RH + 8;
    var kids = [];
    rows.forEach(function (r, i) {
      var y = 4 + i * RH, w = Math.round(BWm * r[2] / max);
      kids.push(s('text', { x: LW - 8, y: y + 16, 'text-anchor': 'end', 'class': 'rp-s' }, r[1]));
      kids.push(s('rect', { x: LW, y: y + 3, width: Math.max(w, r[2] ? 3 : 0), height: RH - 8, rx: 3, 'class': 'rp-bar b-' + r[0] }, s('title', null, r[1] + ': ' + r[2])));
      kids.push(s('text', { x: LW + Math.max(w, 3) + 6, y: y + 16, 'class': 'rp-t' }, String(r[2])));
    });
    return h('figure', { cls: 'rp-fig' },
      s('svg', { viewBox: '0 0 ' + W + ' ' + H, width: W, height: H, 'class': 'rp-svg', role: 'img', 'aria-label': 'Verteilung der Befunde nach Status und Stand der Zielfragen' }, kids),
      h('figcaption', { cls: 'small muted', text: 'Abb.: Befunde nach Status und Stand der Zielfragen.' }));
  }

  /* Hängt ein Diagramm hinter die Überschrift, die mit der R-Kennung beginnt (sprachunabhängig); sonst ans Ende. */
  function place(root, rid, fig) {
    var heads = root.querySelectorAll('h3.md-h2');
    for (var i = 0; i < heads.length; i++) {
      if (heads[i].textContent.indexOf(rid + ' ') === 0) {
        var nxt = heads[i].nextSibling;
        if (nxt) heads[i].parentNode.insertBefore(fig, nxt); else heads[i].parentNode.appendChild(fig);
        return;
      }
    }
    root.appendChild(fig);
  }

  function tocNav(root) {
    var heads = Array.from(root.querySelectorAll('h3.md-h2'));
    if (heads.length < 3) return null;
    return h('nav', { cls: 'rp-toc', 'aria-label': 'Gliederung des Berichts' }, heads.map(function (hd) {
      return h('button', { type: 'button', cls: 'chip', on: { click: function () { hd.scrollIntoView({ block: 'start' }); } }, text: hd.textContent.slice(0, 40) });
    }));
  }

  /* =================== Tab Bericht =================== */
  SW.registerTab({
    id: 'report', label: 'Bericht', icon: 'report',
    mount: function (host, ctx) {
      var st = ctx.st;
      var lang = 'de';
      var text = null;
      var seq = 0;
      var filter = 'all';
      var target = ctx.route.query.finding || null;
      var out = h('div', { cls: 'report-body' }, ui.loading('Bericht wird erzeugt …'));
      var banner = h('div');
      var tocHost = h('div');
      var fHost = h('div', { cls: 'stack' });
      var segHost = h('div');
      var dead = false;
      var mdDone = false;

      function jump() {
        if (!target || !mdDone) return;
        var node = document.getElementById('f-' + target);
        if (node) { node.scrollIntoView({ block: 'center' }); node.focus({ preventScroll: true }); target = null; }
      }
      function paintFilter() {
        var c = { all: st.findings.length };
        st.findings.forEach(function (f) { c[f.status] = (c[f.status] || 0) + 1; });
        SW.dom.fill(segHost, ui.seg('Befunde filtern', [['all', 'Alle (' + c.all + ')']].concat(F_ORDER.map(function (x) {
          return [x[0], x[1].charAt(0).toUpperCase() + x[1].slice(1) + ' (' + (c[x[0]] || 0) + ')'];
        })), filter, function (v) { filter = v; paintFindings(); }));
      }
      function paintFindings() {
        var list = st.findings.filter(function (f) { return filter === 'all' || f.status === filter; });
        SW.dom.fill(fHost, list.length ? list.map(function (f) { return findingCard(st, f, f.id === target); })
          : (st.loaded ? ui.empty('Noch keine Befunde', filter === 'all' ? 'Befunde und offene Punkte erscheinen hier, sobald die Analyse sie liefert.' : 'Kein Befund mit diesem Status.', 'search') : ui.loading()));
        jump();
      }
      function paintDiagrams() {
        /* Diagramme neu setzen: alte entfernen, dann hinter R7 (Ablauf) und R4 (Verteilung) einfügen. */
        Array.from(out.querySelectorAll('figure.rp-fig')).forEach(function (n) { n.parentNode.removeChild(n); });
        if (!out.querySelector('.markdown')) return;
        place(out, 'R4', distFigure(st));
        place(out, 'R7', flowFigure(st));
      }
      function load() {
        var mine = ++seq;
        api.text('/jobs/' + st.id + '/report', { lang: lang, format: 'md' }).then(function (md) {
          if (dead || mine !== seq) return;
          text = md;
          var running = st.summary && st.summary.status === 'running';
          SW.dom.fill(banner, running ? h('div', { cls: 'notice tone-info', role: 'status' }, icon('info'), h('p', { text: 'Zwischenstand: Der Auftrag läuft noch. Inhalte können sich ändern; der Bericht aktualisiert sich automatisch.' })) : null);
          if (md && md.trim()) {
            var rendered = SW.markdown.render(md, { evidenceChip: function (id) { return ui.evidenceChip(st.id, id); } });
            SW.dom.fill(out, rendered);
            paintDiagrams();
            SW.dom.fill(tocHost, tocNav(rendered));
          } else {
            SW.dom.fill(out, ui.noData('Der Bericht ist noch leer.'));
            SW.dom.fill(tocHost, null);
          }
          mdDone = true;
          jump();
        }, function (err) {
          if (dead || mine !== seq) return;
          text = null;
          SW.dom.fill(out, err.status === 404 ? ui.noData('Der Bericht wird erzeugt, sobald erste Ergebnisse vorliegen.') : ui.errorBox('Bericht konnte nicht geladen werden: ' + err.message));
        });
      }
      function save() {
        if (!text) return;
        var blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'bericht-' + st.id + '-' + lang + '.md';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      }
      host.appendChild(h('div', { cls: 'stack' },
        ui.section('Bericht',
          h('div', { cls: 'stack' }, banner, tocHost, out),
          h('span', { cls: 'row' },
            ui.seg('Sprache', [['de', 'Deutsch'], ['en', 'English']], lang, function (v) { lang = v; load(); }),
            h('button', { type: 'button', cls: 'btn sm', on: { click: load } }, icon('refresh'), 'Aktualisieren'),
            h('button', { type: 'button', cls: 'btn sm', on: { click: save } }, icon('arrowdown'), 'Als Markdown speichern'))),
        ui.section('Befunde mit Belegen', h('div', { cls: 'stack' }, segHost, fHost),
          h('span', { cls: 'muted small', text: 'Jeder Befund nennt Zitat und Beleg; Hypothesen sind keine Grundlage einer Antwort' }))));
      paintFilter();
      paintFindings();
      load();
      var offF = ui.live(['findings', 'loaded'], function () { paintFilter(); paintFindings(); }, 100);
      var off = ui.live(['findings', 'answers', 'jobfinished'], function () { load(); }, 1500);
      var offT = ui.live(['tasks'], paintDiagrams, 600);
      return {
        dispose: function () { dead = true; off(); offF(); offT(); },
        update: function (r) {
          target = r.query.finding || null;
          if (target) { filter = 'all'; paintFilter(); }
          paintFindings();
        }
      };
    }
  });

  /* Alter Tab "Live-Bericht": Weiterleitung auf den Bericht, der Parameter finding= bleibt erhalten. */
  SW.registerTab({
    id: 'live', label: 'Live-Bericht', icon: 'live',
    mount: function (host, ctx) {
      var q = {};
      Object.keys(ctx.route.query || {}).forEach(function (k) { q[k] = ctx.route.query[k]; });
      host.appendChild(ui.loading('Weiterleitung zum Bericht …'));
      window.location.replace(ui.tabHref(ctx.jobId, 'report', q));
      return {};
    }
  });
})();
