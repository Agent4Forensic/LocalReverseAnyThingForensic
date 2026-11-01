/* Tab "Erhobene Daten": alles, was der Lauf bisher gesammelt hat, an einer Stelle.
   Probe, Ueberblick in Zahlen, jeder Beleg (Werkzeugergebnis mit Parametern und Vorschau),
   abgeleitete Dateien, Befunde und Antworten. Aktualisiert sich live. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var api = SW.api;
  var store = SW.store;
  var ui = SW.ui;

  function tile(iconName, label, value, sub) {
    return h('div', { cls: 'tile' },
      h('div', { cls: 'tile-l' }, icon(iconName, { size: 15 }), h('span', { text: label })),
      h('div', { cls: 'tile-v', text: value }),
      sub ? h('div', { cls: 'tile-s muted small', text: sub }) : null);
  }

  function params(p) {
    if (!p || typeof p !== 'object') return '–';
    var keys = Object.keys(p);
    if (!keys.length) return '–';
    return keys.map(function (k) {
      var v = p[k];
      return k + '=' + (typeof v === 'string' ? v : JSON.stringify(v));
    }).join(', ');
  }

  function firstLines(text, n) {
    return String(text || '').split('\n').filter(function (l) { return l.trim(); }).slice(0, n).join('\n');
  }

  SW.registerTab({
    id: 'data', label: 'Erhobene Daten', icon: 'list',
    mount: function (host, ctx) {
      var st = ctx.st;
      var ev = null;          /* Belegliste vom Server */
      var evErr = null;
      var files = st.files;
      var tool = '';
      var dead = false;
      var inflight = false;
      var again = false;

      var sampleHost = h('div');
      var tilesHost = h('div');
      var evHost = h('div');
      var filterHost = h('span');
      var filesHost = h('div');
      var resHost = h('div');

      function load() {
        if (inflight) { again = true; return; }
        inflight = true;
        Promise.all([
          api.get('/jobs/' + st.id + '/evidence').then(function (l) { ev = l || []; evErr = null; }, function (e) { evErr = e.message || 'Fehler'; }),
          api.get('/jobs/' + st.id + '/files').then(function (f) { files = f || []; }, function () { /* Dateien bleiben wie sie sind */ })
        ]).then(function () {
          inflight = false;
          if (dead) return;
          paint();
          if (again) { again = false; load(); }
        });
      }

      function citedBy() {
        var map = {};
        (st.findings || []).forEach(function (f) {
          (f.evidence_ids || []).forEach(function (id) { (map[id] = map[id] || []).push(f.id); });
        });
        return map;
      }

      function paintSample() {
        var s = st.summary;
        if (!s) { SW.dom.fill(sampleHost, ui.loading()); return; }
        SW.dom.fill(sampleHost, h('dl', { cls: 'kv' },
          h('dt', { text: 'Datei' }), h('dd', { cls: 'mono', text: s.sample_name || '–' }),
          h('dt', { text: 'Größe' }), h('dd', { text: s.sample_size === null || s.sample_size === undefined ? 'unbekannt' : fmt.bytes(s.sample_size) + ' (' + s.sample_size + ' Byte)' }),
          h('dt', { text: 'SHA-256' }), h('dd', { cls: 'mono wrap', text: s.sample_sha256 || '–' }),
          h('dt', { text: 'Erkannter Typ' }), h('dd', { text: s.detected_type || 'noch nicht bestimmt (Triage)' }),
          h('dt', { text: 'Rezept' }), h('dd', { text: s.recipe || 'noch nicht gewählt (Planung)' })));
      }

      function paintTiles() {
        var list = ev || [];
        var tools = {};
        var bytes = 0;
        var flagged = 0;
        list.forEach(function (e) { tools[e.tool] = (tools[e.tool] || 0) + 1; bytes += e.size || 0; if ((e.injection_flags || []).length) flagged++; });
        var fc = { confirmed: 0, hypothesis: 0, rejected: 0, open: 0 };
        (st.findings || []).forEach(function (f) { fc[f.status] = (fc[f.status] || 0) + 1; });
        var ans = st.answers || [];
        var answered = ans.filter(function (a) { return a.status === 'answered'; }).length;
        var derived = (files || []).filter(function (f) { return f.kind !== 'sample' && f.path !== 'sample'; }).length;
        var t = st.totals || {};
        SW.dom.fill(tilesHost, h('div', { cls: 'tiles' },
          tile('link', 'Belege', String(list.length), fmt.bytes(bytes) + ' Werkzeugausgabe' + (flagged ? ' · ' + flagged + ' mit Schutzhinweis' : '')),
          tile('tool', 'Werkzeuge', String(Object.keys(tools).length), Object.keys(tools).sort().map(function (k) { return k + ' ×' + tools[k]; }).join(', ') || 'noch keins'),
          tile('search', 'Befunde', String((st.findings || []).length), fc.confirmed + ' bestätigt · ' + fc.hypothesis + ' Hypothese · ' + fc.rejected + ' verworfen'),
          tile('question', 'Zielfragen', ans.length ? answered + '/' + ans.length : '–', ans.length ? 'beantwortet' : 'keine gestellt'),
          tile('file', 'Abgeleitete Dateien', String(derived), 'unter derived/ im Auftragsordner'),
          tile('pulse', 'Aufrufe', String((t.tool_calls || 0) + (t.llm_calls || 0)), (t.tool_calls || 0) + ' Werkzeug · ' + (t.llm_calls || 0) + ' Modell · ' + (t.steps || 0) + ' Schritte')));
      }

      function paintFilter() {
        var tools = {};
        (ev || []).forEach(function (e) { tools[e.tool] = true; });
        var names = Object.keys(tools).sort();
        if (tool && !tools[tool]) tool = '';
        var sel = h('select', { 'aria-label': 'Belege nach Werkzeug filtern' },
          h('option', { value: '', text: 'Alle Werkzeuge' }), names.map(function (n) { return h('option', { value: n, text: n }); }));
        sel.value = tool;
        sel.addEventListener('change', function () { tool = sel.value; paintEvidence(); });
        SW.dom.fill(filterHost, sel);
      }

      function paintEvidence() {
        if (evErr) { SW.dom.fill(evHost, ui.errorBox('Belege konnten nicht geladen werden: ' + evErr)); return; }
        if (!ev) { SW.dom.fill(evHost, ui.loading('Belege werden geladen …')); return; }
        var list = ev.filter(function (e) { return !tool || e.tool === tool; });
        if (!list.length) {
          SW.dom.fill(evHost, ui.empty('Noch keine Belege', 'Jeder Werkzeugaufruf legt einen Beleg mit Prüfsumme an. Die ersten entstehen in der Triage.', 'link'));
          return;
        }
        var cites = citedBy();
        SW.dom.fill(evHost, h('div', { cls: 'tbl-wrap' }, h('table', { cls: 'tbl ev-tbl' },
          h('caption', { cls: 'sr-only', text: 'Belege in der Reihenfolge ihrer Entstehung' }),
          h('thead', null, h('tr', null, ['Beleg', 'Werkzeug', 'Parameter', 'Aufgabe', 'Größe', 'Zeit', 'Inhalt (Anfang)', 'Zitiert in'].map(function (c, i) {
            return h('th', { scope: 'col', cls: i === 4 ? 'num' : '', text: c });
          }))),
          h('tbody', null, list.map(function (e) {
            var flags = e.injection_flags || [];
            var used = cites[e.id] || [];
            return h('tr', null,
              h('td', null, ui.evidenceChip(st.id, e.id)),
              h('td', null, h('span', { cls: 'tag mono', text: e.tool }), e.tool_version ? h('div', { cls: 'small muted mono', text: e.tool_version }) : null),
              h('td', { cls: 'mono small ev-par', text: params(e.params) }),
              h('td', null, e.task_id ? h('a', { cls: 'mono small', href: ui.tabHref(st.id, 'tree', { task: e.task_id }), text: e.task_id }) : h('span', { cls: 'muted', text: '–' })),
              h('td', { cls: 'num small nowrap', text: fmt.bytes(e.size || 0) }),
              h('td', { cls: 'mono small nowrap', text: fmt.time(e.created_at) }),
              h('td', null, h('pre', { cls: 'ev-prev', text: firstLines(e.preview, 3) || '(leer)' }),
                flags.length ? h('span', { cls: 'badge tone-warn', title: 'Der Prompt-Schutz hat in dieser Ausgabe verdächtige Muster gefunden.' }, icon('shield', { size: 12 }), 'Schutzhinweis') : null),
              h('td', null, used.length ? h('span', { cls: 'chips' }, used.map(function (fid) {
                return h('a', { cls: 'chip mono', href: ui.tabHref(st.id, 'live', { finding: fid }), text: fid });
              })) : h('span', { cls: 'muted small', text: '–' })));
          })))));
      }

      function paintFiles() {
        var list = (files || []);
        if (!list.length) { SW.dom.fill(filesHost, h('p', { cls: 'muted', text: 'Keine Dateien im Auftragsordner.' })); return; }
        SW.dom.fill(filesHost, h('ul', { cls: 'recent' }, list.map(function (f) {
          var isSample = f.kind === 'sample' || f.path === 'sample';
          return h('li', null, icon(isSample ? 'file' : 'code', { size: 14 }),
            h('a', { cls: 'mono grow trunc', href: ui.tabHref(st.id, 'file', { path: f.path }), text: f.path }),
            h('span', { cls: 'tag', text: isSample ? 'Original' : 'abgeleitet' }),
            h('span', { cls: 'small muted nowrap', text: fmt.bytes(f.size) }),
            h('span', { cls: 'mono small muted nowrap', title: f.sha256, text: fmt.shortHash(f.sha256, 12) }));
        })));
      }

      function paintResults() {
        var fs = st.findings || [];
        var ans = st.answers || [];
        SW.dom.fill(resHost, h('div', { cls: 'stack' },
          ans.length ? h('ul', { cls: 'recent' }, ans.map(function (a) {
            return h('li', null, fmt.statusIcon(a.status, 14), h('span', { cls: 'mono small', text: a.question_id }),
              h('span', { cls: 'grow', text: (a.text_orig || a.text_en) + (a.answer_de || a.answer_en ? ' → ' + (a.answer_de || a.answer_en) : '') }),
              fmt.badge(a.status));
          })) : null,
          fs.length ? h('ul', { cls: 'recent' }, fs.map(function (f) {
            return h('li', null, fmt.statusIcon(f.status, 14),
              h('a', { cls: 'mono small', href: ui.tabHref(st.id, 'live', { finding: f.id }), text: f.id }),
              h('span', { cls: 'grow', text: f.statement_de || f.statement_en }),
              ui.chips(st.id, f.evidence_ids || []), fmt.badge(f.status));
          })) : h('p', { cls: 'muted', text: 'Noch keine Befunde. Befunde entstehen erst, wenn die KI eine Aussage mit einem Beleg stützt.' })));
      }

      function paint() {
        paintSample(); paintTiles(); paintFilter(); paintEvidence(); paintFiles(); paintResults();
      }

      host.appendChild(h('div', { cls: 'stack' },
        ui.section('Probe', sampleHost, h('span', { cls: 'muted small', text: 'wird nie ausgeführt, nur statisch gelesen' })),
        ui.section('Überblick', tilesHost),
        ui.section('Belege (Werkzeugergebnisse)', evHost, h('span', { cls: 'row' }, filterHost,
          h('span', { cls: 'muted small', text: 'Klick auf eine Beleg-ID zeigt die volle Ausgabe mit SHA-256' }))),
        ui.section('Befunde und Antworten', resHost),
        ui.section('Dateien im Auftragsordner', filesHost)));
      paint();
      load();
      var offData = ui.live(['log', 'jobfinished'], load, 500);
      var offLocal = ui.live(['summary', 'findings', 'answers', 'loaded'], paint, 150);
      return { dispose: function () { dead = true; offData(); offLocal(); } };
    }
  });
})();
