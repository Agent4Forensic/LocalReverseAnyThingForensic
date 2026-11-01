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

  var TOOL_DO = {
    strings_extract: 'Lesbare Zeichenketten ausgelesen',
    identify_type: 'Dateityp bestimmt',
    hash_file: 'Prüfsumme berechnet',
    hash_text: 'Prüfsumme berechnet',
    list_imports: 'Importierte Funktionen aufgelistet',
    list_exports: 'Exportierte Funktionen aufgelistet',
    decode_text: 'Text dekodiert',
    hexdump: 'Rohbytes als Hexdump gelesen',
    read_bytes: 'Rohbytes gelesen',
    read_text: 'Text gelesen',
    entropy: 'Entropie gemessen',
    pe_info: 'PE-Kopfdaten gelesen',
    pe_sections: 'PE-Abschnitte gelesen',
    find_indicators: 'Nach Indikatoren gesucht',
    grep: 'Nach Muster gesucht',
    search: 'Nach Muster gesucht'
  };
  var SKIP_PARAMS = { path: 1, file: 1 };

  function targetOf(e) {
    var p = e.params || {};
    var v = p.path || p.file || p.source || '';
    return typeof v === 'string' ? v : '';
  }
  function describe(e) {
    var p = e.params || {};
    var extra = Object.keys(p).filter(function (k) { return !SKIP_PARAMS[k]; }).map(function (k) {
      var v = p[k];
      return k + ' ' + (typeof v === 'string' ? v : JSON.stringify(v));
    });
    var tgt = targetOf(e);
    return (TOOL_DO[e.tool] || 'Ausgabe von ' + e.tool) + (tgt ? ' aus ' + tgt : '') + (extra.length ? ' (' + extra.join(', ') + ')' : '');
  }
  var PAGE = 40;

  SW.registerTab({
    id: 'data', label: 'Erhobene Daten', icon: 'list',
    mount: function (host, ctx) {
      var st = ctx.st;
      var ev = null;          /* Belegliste vom Server */
      var evErr = null;
      var files = st.files;
      var tool = '';
      var query = '';
      var citedMode = '';   /* '', 'yes', 'no' */
      var groupBy = 'tool'; /* 'tool' | 'file' */
      var openKeys = {};
      var shown = {};
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
        var tfiles = {};
        var bytes = 0;
        var flagged = 0;
        var cites = citedBy();
        var citedN = 0;
        list.forEach(function (e) {
          tools[e.tool] = (tools[e.tool] || 0) + 1; bytes += e.size || 0;
          if ((e.injection_flags || []).length) flagged++;
          var tg = targetOf(e); if (tg) tfiles[tg] = true;
          if (cites[e.id]) citedN++;
        });
        var fc = { confirmed: 0, hypothesis: 0, rejected: 0, open: 0 };
        (st.findings || []).forEach(function (f) { fc[f.status] = (fc[f.status] || 0) + 1; });
        var ans = st.answers || [];
        var answered = ans.filter(function (a) { return a.status === 'answered'; }).length;
        var derived = (files || []).filter(function (f) { return f.kind !== 'sample' && f.path !== 'sample'; }).length;
        var t = st.totals || {};
        SW.dom.fill(tilesHost, h('div', { cls: 'tiles' },
          tile('link', 'Belege', String(list.length), fmt.bytes(bytes) + ' Werkzeugausgabe' + (flagged ? ' · ' + flagged + ' mit Schutzhinweis' : '')),
          tile('tool', 'Werkzeuge', String(Object.keys(tools).length), Object.keys(tools).sort().map(function (k) { return k + ' ×' + tools[k]; }).join(', ') || 'noch keins'),
          tile('file', 'Untersuchte Dateien', String(Object.keys(tfiles).length), 'Quellen der Belege'),
          tile('checkcircle', 'Zitierte Belege', list.length ? citedN + '/' + list.length : '–', list.length ? (list.length - citedN) + ' noch in keinem Befund genutzt' : 'noch keine Belege'),
          tile('search', 'Befunde', String((st.findings || []).length), fc.confirmed + ' bestätigt · ' + fc.hypothesis + ' Hypothese · ' + fc.rejected + ' verworfen'),
          tile('question', 'Zielfragen', ans.length ? answered + '/' + ans.length : '–', ans.length ? 'beantwortet' : 'keine gestellt'),
          tile('code', 'Abgeleitete Dateien', String(derived), 'unter derived/ im Auftragsordner'),
          tile('pulse', 'Aufrufe', String((t.tool_calls || 0) + (t.llm_calls || 0)), (t.tool_calls || 0) + ' Werkzeug · ' + (t.llm_calls || 0) + ' Modell · ' + (t.steps || 0) + ' Schritte')));
      }

      var filterSig = null;
      var evSig = null;
      function paintFilter() {
        var tools = {};
        (ev || []).forEach(function (e) { tools[e.tool] = true; });
        var names = Object.keys(tools).sort();
        if (filterSig === names.join('|')) return;
        filterSig = names.join('|');
        if (tool && !tools[tool]) tool = '';
        var sel = h('select', { 'aria-label': 'Belege nach Werkzeug filtern' },
          h('option', { value: '', text: 'Alle Werkzeuge' }), names.map(function (n) { return h('option', { value: n, text: n }); }));
        sel.value = tool;
        sel.addEventListener('change', function () { tool = sel.value; shown = {}; paintEvidence(); });
        var cs = h('select', { 'aria-label': 'Nach Zitierung filtern' },
          h('option', { value: '', text: 'Zitiert und nicht zitiert' }), h('option', { value: 'yes', text: 'Nur zitierte' }), h('option', { value: 'no', text: 'Nur nicht zitierte' }));
        cs.value = citedMode;
        cs.addEventListener('change', function () { citedMode = cs.value; shown = {}; paintEvidence(); });
        var gs = h('select', { 'aria-label': 'Gruppieren nach' },
          h('option', { value: 'tool', text: 'Gruppiert nach Werkzeug' }), h('option', { value: 'file', text: 'Gruppiert nach Datei' }));
        gs.value = groupBy;
        gs.addEventListener('change', function () { groupBy = gs.value; shown = {}; paintEvidence(); });
        var q = h('input', { type: 'search', placeholder: 'Suchen: Beleg-ID, Werkzeug, Datei, Inhalt …', 'aria-label': 'Belege durchsuchen', value: query });
        q.value = query;
        var timer = null;
        q.addEventListener('input', function () {
          window.clearTimeout(timer);
          timer = window.setTimeout(function () { query = q.value; shown = {}; paintEvidence(); }, 200);
        });
        SW.dom.fill(filterHost, h('div', { cls: 'evtools' }, q, sel, cs, gs));
      }

      function matches(e, cites) {
        if (tool && e.tool !== tool) return false;
        var isCited = !!cites[e.id];
        if (citedMode === 'yes' && !isCited) return false;
        if (citedMode === 'no' && isCited) return false;
        if (query) {
          var hay = (e.id + ' ' + e.tool + ' ' + describe(e) + ' ' + params(e.params) + ' ' + (e.task_id || '') + ' ' + (e.preview || '') + ' ' + (cites[e.id] || []).join(' ')).toLowerCase();
          if (hay.indexOf(query.toLowerCase()) < 0) return false;
        }
        return true;
      }

      function evRow(e, cites) {
        var used = cites[e.id] || [];
        var flags = e.injection_flags || [];
        var det = h('div', { cls: 'evrow-det' });
        var row = h('details', { cls: 'evrow' },
          h('summary', null, icon('chevronright', { size: 12 }),
            h('span', { cls: 'mono small nowrap', text: e.id }),
            h('span', { cls: 'evrow-d', title: describe(e), text: describe(e) }),
            flags.length ? h('span', { cls: 'badge tone-warn', title: 'Der Prompt-Schutz hat in dieser Ausgabe verdächtige Muster gefunden.' }, icon('shield', { size: 12 }), 'Schutzhinweis') : null,
            h('span', { cls: 'small muted nowrap', text: fmt.bytes(e.size || 0) }),
            used.length ? h('span', { cls: 'badge tone-ok', title: 'In diesen Befunden zitiert: ' + used.join(', ') }, icon('check', { size: 12 }), 'zitiert: ' + used.join(', '))
              : h('span', { cls: 'badge tone-neutral', title: 'Bisher in keinem Befund als Beleg verwendet.', text: 'nicht zitiert' })),
          det);
        row.addEventListener('toggle', function () {
          if (!row.open || det.firstChild) return;
          det.appendChild(h('dl', { cls: 'kv' },
            h('dt', { text: 'Werkzeug' }), h('dd', null, h('span', { cls: 'tag mono', text: e.tool }), e.tool_version ? h('span', { cls: 'small muted mono', text: ' ' + e.tool_version }) : null),
            h('dt', { text: 'Parameter' }), h('dd', { cls: 'mono small', text: params(e.params) }),
            h('dt', { text: 'Aufgabe' }), h('dd', null, e.task_id ? h('a', { cls: 'mono small', href: ui.tabHref(st.id, 'tree', { task: e.task_id }), text: e.task_id }) : '–'),
            h('dt', { text: 'Zeit' }), h('dd', { cls: 'mono small', text: fmt.time(e.created_at) }),
            h('dt', { text: 'Zitiert in' }), h('dd', null, used.length ? h('span', { cls: 'chips' }, used.map(function (fid) {
              return h('a', { cls: 'chip mono', href: ui.tabHref(st.id, 'live', { finding: fid }), text: fid });
            })) : h('span', { cls: 'muted', text: 'noch in keinem Befund' }))),
            h('pre', { text: firstLines(e.preview, 8) || '(leer)' }),
            h('div', { cls: 'row' }, ui.evidenceChip(st.id, e.id), h('span', { cls: 'small muted', text: 'öffnet die volle Ausgabe mit SHA-256' })));
        });
        return row;
      }

      function paintEvidence() {
        if (evErr) { SW.dom.fill(evHost, ui.errorBox('Belege konnten nicht geladen werden: ' + evErr)); return; }
        if (!ev) { SW.dom.fill(evHost, ui.loading('Belege werden geladen …')); return; }
        if (!ev.length) {
          SW.dom.fill(evHost, ui.empty('Noch keine Belege', 'Jeder Werkzeugaufruf legt einen Beleg mit Prüfsumme an. Die ersten entstehen in der Triage.', 'link'));
          return;
        }
        var cites = citedBy();
        var sig = [ev.length, Object.keys(cites).length, tool, query, citedMode, groupBy, Object.keys(shown).length].join('|');
        if (sig === evSig) return;
        evSig = sig;
        var list = ev.filter(function (e) { return matches(e, cites); });
        if (!list.length) { SW.dom.fill(evHost, ui.empty('Keine Treffer', 'Kein Beleg passt zu Suche und Filtern.', 'search')); return; }
        var groups = {};
        var order = [];
        list.forEach(function (e) {
          var k = groupBy === 'file' ? (targetOf(e) || '(ohne Datei)') : e.tool;
          if (!groups[k]) { groups[k] = []; order.push(k); }
          groups[k].push(e);
        });
        order.sort();
        var forceOpen = !!query;
        SW.dom.fill(evHost,
          h('p', { cls: 'small muted', text: list.length + ' von ' + ev.length + ' Belegen in ' + order.length + (groupBy === 'file' ? ' Dateien' : ' Werkzeugen') + '. Gruppe aufklappen, dann Beleg anklicken für Einzelheiten.' }),
          order.map(function (k) {
            var items = groups[k];
            var citedN = items.filter(function (e) { return cites[e.id]; }).length;
            var bytes = items.reduce(function (n, e) { return n + (e.size || 0); }, 0);
            var rowsHost = h('div');
            var det = h('details', { cls: 'evgrp' },
              h('summary', null, icon('chevronright', { size: 14 }),
                h('strong', { cls: groupBy === 'file' ? 'mono' : 'mono', text: k }),
                h('span', { cls: 'evgrp-n' },
                  h('span', { cls: 'badge tone-neutral', text: items.length + (items.length === 1 ? ' Beleg' : ' Belege') }),
                  h('span', { cls: 'badge ' + (citedN ? 'tone-ok' : 'tone-neutral'), text: citedN + ' zitiert' }),
                  h('span', { cls: 'badge tone-neutral', text: fmt.bytes(bytes) }))),
              rowsHost);
            function fillRows() {
              var n = shown[groupBy + k] || PAGE;
              SW.dom.fill(rowsHost, h('div', { cls: 'evrows' }, items.slice(0, n).map(function (e) { return evRow(e, cites); })),
                items.length > n ? h('button', { type: 'button', cls: 'btn sm evmore', on: { click: function () { shown[groupBy + k] = n + PAGE * 2; fillRows(); } } },
                  (items.length - n) + ' weitere anzeigen') : null);
            }
            det.addEventListener('toggle', function () {
              openKeys[groupBy + k] = det.open;
              if (det.open && !rowsHost.firstChild) fillRows();
            });
            if (forceOpen || openKeys[groupBy + k]) { det.open = true; fillRows(); }
            return det;
          }));
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
        ui.section('Probe', sampleHost, h('span', { cls: 'muted small', text: 'wird derzeit nicht ausgeführt (dynamische Ausführung deaktiviert bis zur Analyse-VM)' })),
        ui.section('Überblick', tilesHost),
        ui.section('Belege (Werkzeugergebnisse)', h('div', null, filterHost, evHost)),
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
