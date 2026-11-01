/* Tab Datei: Groesse, Art und Ablage der Datei, Hex und ASCII der ganzen Datei mit Anmerkungen, Funktionsliste, Assembler mit Erklaerung
   je Befehl und Pseudocode (Ghidra). Alle Inhalte stammen aus dem Sample und werden nur als Text eingefuegt. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var api = SW.api;
  var ui = SW.ui;

  function sizeText(n) { return fmt.bytes(n) + (n >= 1024 ? ' (' + n.toLocaleString('de-DE') + ' Byte)' : ''); }

  function tile(label, value, sub) {
    return h('div', { cls: 'tile' }, h('div', { cls: 'tile-l', text: label }), h('div', { cls: 'tile-v fv-big' }, value), sub ? h('div', { cls: 'tile-s muted small', text: sub }) : null);
  }

  SW.registerTab({
    id: 'file', label: 'Datei', icon: 'file',
    mount: function (host, ctx) {
      var jobId = ctx.jobId;
      var dead = false;
      var path = ctx.route.query.path || 'sample';
      var info = null;
      var fnData = null;
      var fnSel = null;
      var fnGen = 0;

      var sumHost = h('div');
      var hexHost = h('div');
      var codeHost = h('div');
      var base = '/jobs/' + encodeURIComponent(jobId);

      /* ---------- Uebersicht ---------- */
      function paintSummary() {
        if (!info) return;
        var files = info.files || [];
        var picker = files.length > 1 ? h('label', { cls: 'row small' }, 'Datei ',
          (function () {
            var sel = h('select', { 'aria-label': 'Datei wählen' }, files.map(function (f) { return h('option', { value: f.path, text: f.path + ' · ' + fmt.bytes(f.size) }); }));
            sel.value = path;
            sel.addEventListener('change', function () { ui.go(ui.tabHref(jobId, 'file', { path: sel.value })); });
            return sel;
          })()) : null;
        SW.dom.fill(sumHost, ui.section('Datei ' + info.path,
          h('div', { cls: 'stack' },
            h('div', { cls: 'fv-sum' },
              tile('Größe', sizeText(info.size)),
              tile('Art', info.kind.label, info.is_sample ? 'Original-Sample (nie ausgeführt)' : 'abgeleitete Datei'),
              tile('SHA-256', h('span', { cls: 'mono small', text: info.sha256 }))),
            h('dl', { cls: 'kv small' },
              h('dt', { text: 'Ablage' }), h('dd', { cls: 'mono', text: info.location }),
              h('dt', { text: 'Text und Skripte' }), h('dd', null, h('a', { href: ui.tabHref(jobId, 'code', { file: info.path }), text: 'im Tab Code lesen (mit KI-Anmerkungen)' })))),
          picker));
      }

      /* ---------- Hex: ganze Datei, virtuell gescrollt, mit Anmerkungen (view_hex.js) ---------- */
      var hexInst = null;
      function loadHex() {
        if (hexInst) hexInst.dispose();
        hexInst = SW.hexView({ jobId: jobId, path: path, size: info.size });
        SW.dom.fill(hexHost, ui.section('Hex und ASCII mit Anmerkungen', hexInst.el));
      }

      /* ---------- Assembler und Pseudocode ---------- */
      function paintCodeUnavailable(reason) {
        SW.dom.fill(codeHost, ui.section('Assembler und Pseudocode',
          h('div', { cls: 'notice tone-info', role: 'note' }, icon('info'), h('p', { text: reason }))));
      }
      function loadFunctions() {
        if (!info.code.available) { paintCodeUnavailable(info.code.reason); return; }
        SW.dom.fill(codeHost, ui.section('Assembler und Pseudocode', ui.loading('Ghidra liest die Datei … Der erste Aufruf je Datei kann einige Minuten dauern, danach kommt das Ergebnis aus dem Cache.')));
        api.get(base + '/inspect/functions', { path: path }).then(function (d) {
          if (dead) return;
          fnData = d;
          var pick = d.functions.filter(function (f) { return f.entry === d.program.entry; })[0] ||
            d.functions.filter(function (f) { return !f.thunk; })[0] || d.functions[0];
          paintCode();
          if (pick) selectFn(pick.name);
        }, function (err) { if (!dead) paintCodeUnavailable('Ghidra-Ergebnis nicht verfügbar: ' + err.message); });
      }
      var fnListHost = h('div', { cls: 'fv-fns' });
      var fnBodyHost = h('div');
      function paintFnList() {
        SW.dom.fill(fnListHost, h('ul', { cls: 'flist' }, fnData.functions.map(function (f) {
          var on = fnSel === f.name;
          return h('li', null, h('button', { type: 'button', cls: on ? 'is-sel' : '', 'aria-pressed': on ? 'true' : 'false', title: f.signature, on: { click: function () { selectFn(f.name); } } },
            h('span', { cls: 'mono grow trunc', text: f.name }),
            f.thunk ? h('span', { cls: 'tag', text: 'Thunk' }) : null,
            h('span', { cls: 'small muted mono nowrap', text: f.entry })));
        })));
      }
      function paintCode() {
        var p = fnData.program || {};
        SW.dom.fill(codeHost, ui.section('Assembler und Pseudocode',
          h('div', { cls: 'stack' },
            h('p', { cls: 'small muted' }, (p.format || '–') + ' · ' + (p.language || '–') + ' · Image-Basis ' + (p.image_base || '–') + ' · Einstieg ' + (p.entry || '–') + ' · ' + fnData.total + ' Funktion(en) · ' + fnData.tool_version),
            fnData.truncated ? h('div', { cls: 'notice tone-warn', role: 'note' }, icon('alert'), h('p', { text: 'Exportgrenze erreicht: nicht jede Funktion ist aufgeführt.' })) : null,
            h('div', { cls: 'fv-code' },
              h('section', { cls: 'card', 'aria-label': 'Funktionen' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Funktionen' })), h('div', { cls: 'card-b tight' }, fnListHost)),
              fnBodyHost)),
          h('span', { cls: 'small muted', text: (info && info.code && info.code.tool) || 'Ghidra im Offline-Container' })));
        paintFnList();
      }
      function selectFn(name) {
        fnSel = name;
        paintFnList();
        var my = ++fnGen;
        SW.dom.fill(fnBodyHost, ui.loading('Funktion ' + name + ' wird geladen …'));
        api.get(base + '/inspect/function', { path: path, function: name }).then(function (f) {
          if (dead || my !== fnGen) return;
          paintFn(f);
        }, function (err) { if (!dead) SW.dom.fill(fnBodyHost, ui.errorBox(err.message)); });
      }
      function paintFn(f) {
        var asm = h('div', { cls: 'tbl-wrap asm-wrap', tabindex: '0', role: 'region', 'aria-label': 'Assembler von ' + f.name },
          h('table', { cls: 'asm' },
            h('caption', { cls: 'sr-only', text: 'Assembler mit Erklärung je Befehl' }),
            h('thead', null, h('tr', null, ['Adresse', 'Bytes', 'Befehl', 'Erklärung'].map(function (c) { return h('th', { scope: 'col', text: c }); }))),
            h('tbody', null, f.disasm.map(function (r) {
              return h('tr', null, h('td', { cls: 'a-addr', text: r.address }), h('td', { cls: 'a-bytes', text: r.bytes }),
                h('td', { cls: 'a-ins', text: r.text }), h('td', { cls: 'a-exp', text: r.explain || '–' }));
            }))));
        var findings = f.findings || [];
        SW.dom.fill(fnBodyHost, h('div', { cls: 'stack' },
          h('div', { cls: 'row' }, h('h3', { cls: 'grow mono', text: f.name + '  ' + (f.signature || '') }),
            h('span', { cls: 'tag mono', text: f.entry }), h('span', { cls: 'tag', text: f.size + ' Byte' }), h('span', { cls: 'tag', text: f.disasm.length + ' Befehle' })),
          h('div', { cls: 'fv-panes' },
            h('section', { cls: 'card', 'aria-label': 'Assembler' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Assembler mit Erklärung' })), h('div', { cls: 'card-b tight' }, asm,
              f.disasm_truncated ? h('p', { cls: 'small muted', text: 'Funktion ist länger als die Exportgrenze; nicht alle Befehle sind aufgeführt.' }) : null)),
            h('section', { cls: 'card', 'aria-label': 'Pseudocode' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Pseudocode (Ghidra-Decompiler)' })), h('div', { cls: 'card-b' },
              f.decompiled ? h('pre', { cls: 'pseudo', tabindex: '0', text: f.decompiled }) : h('p', { cls: 'muted', text: 'Für diese Funktion gibt es keine Decompiler-Ausgabe (Thunk, Zeitlimit oder Exportgrenze). Der Assembler links ist vollständig.' }),
              h('p', { cls: 'small muted', text: 'Pseudocode nähert den Code nur an. Belege der Analyse zitieren Assembler oder Dekompilat mit Evidence-ID.' })))),
          h('div', { cls: 'notice tone-neutral', role: 'note' }, icon('info'), h('p', { text: 'Die Erklärungen beschreiben, was ein Befehl allgemein tut (feste Tabelle, ohne KI). Was diese Funktion im Sample bewirkt, belegen nur die Befunde der Analyse.' })),
          ui.section('Befunde zu dieser Funktion', findings.length ? h('ul', { cls: 'quotes' }, findings.map(function (x) {
            return h('li', null, fmt.badge(x.status), ' ', h('a', { cls: 'mono', href: ui.tabHref(jobId, 'live', { finding: x.id }), text: x.id }), ' ', x.statement_de || x.statement_en, ' ', ui.chips(jobId, x.evidence_ids));
          })) : h('p', { cls: 'muted', text: 'Kein Befund nennt diese Funktion (Name oder Adresse).' }))));
      }

      /* ---------- Start ---------- */
      SW.dom.fill(host, h('div', { cls: 'fv' }, sumHost, hexHost, codeHost));
      SW.dom.fill(sumHost, ui.loading('Datei wird geprüft …'));
      api.get(base + '/inspect', { path: path }).then(function (d) {
        if (dead) return;
        info = d;
        paintSummary();
        loadHex();
        loadFunctions();
      }, function (err) {
        if (dead) return;
        SW.dom.fill(sumHost, err.status === 404 ? ui.empty('Datei nicht verfügbar', err.message, 'file') : ui.errorBox(err.message));
      });

      /* Kein update(): ein Wechsel der Datei baut den Tab neu auf (view_job.js mountet dann frisch). */
      return { dispose: function () { dead = true; if (hexInst) hexInst.dispose(); } };
    }
  });
})();
