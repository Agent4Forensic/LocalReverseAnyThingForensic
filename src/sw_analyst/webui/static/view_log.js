/* Tabs Log (Hintergrundprotokoll mit Stufenfilter) und Schutz (Guard-Ereignisse, Audit-Kette). Nur Text. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var store = SW.store;
  var ui = SW.ui;

  var RANK = { debug: 0, info: 1, warn: 2, error: 3 };

  SW.registerTab({
    id: 'log', label: 'Log', icon: 'terminal',
    mount: function (host, ctx) {
      var st = ctx.st;
      var level = 'info';
      var follow = true;
      var listHost = h('div', { cls: 'log', role: 'log', 'aria-label': 'Protokoll', tabindex: '0' });
      var countHost = h('span', { cls: 'small muted' });
      var followBox = h('input', { type: 'checkbox', checked: true });
      followBox.checked = true;
      followBox.addEventListener('change', function () { follow = followBox.checked; });

      function paint() {
        var min = RANK[level];
        var rows = (st.log || []).filter(function (e) { return (RANK[e.level] || 1) >= min; });
        var shown = rows.slice(-1500);
        SW.dom.fill(countHost, shown.length + ' von ' + rows.length + ' Einträgen');
        SW.dom.fill(listHost, !shown.length ? h('p', { cls: 'muted', text: st.loaded ? 'Keine Einträge für diese Stufe.' : 'Wird geladen …' }) :
          shown.map(function (e) {
            var extra = e.data && typeof e.data === 'object' && Object.keys(e.data).length ? '  ' + JSON.stringify(e.data) : '';
            return h('div', { cls: 'log-row lv-' + e.level },
              h('span', { cls: 'muted', text: '#' + e.seq }), h('span', { cls: 'muted', text: fmt.time(e.ts) }),
              h('span', { text: e.level }), h('span', { cls: 'log-msg', text: (e.message || '') + extra }));
          }));
        if (follow) listHost.scrollTop = listHost.scrollHeight;
      }
      host.appendChild(ui.section('Hintergrundprotokoll',
        h('div', { cls: 'stack' },
          h('div', { cls: 'row' },
            ui.seg('Stufe', [['debug', 'Alles'], ['info', 'Info'], ['warn', 'Warnungen'], ['error', 'Fehler']], level, function (v) { level = v; paint(); }),
            h('label', { cls: 'chk' }, followBox, ' Ans Ende springen'), countHost),
          listHost)));
      paint();
      var off = ui.live(['log', 'loaded'], paint, 200);
      return { dispose: off };
    }
  });

  SW.registerTab({
    id: 'guard', label: 'Schutz', icon: 'shield',
    mount: function (host, ctx) {
      var st = ctx.st;
      var auditHost = h('div');
      var guardHost = h('div');

      function paintAudit() {
        var a = st.audit;
        SW.dom.fill(auditHost, !a ? ui.loading('Audit-Kette wird geprüft …') :
          h('div', { cls: 'notice ' + (a.valid ? 'tone-ok' : 'tone-err'), role: 'status' }, icon(a.valid ? 'checkcircle' : 'alertcircle'),
            h('div', null,
              h('p', null, h('strong', { text: a.valid ? 'Audit-Kette gültig' : 'Audit-Kette gebrochen' }), ' · ' + a.entries + ' Einträge' + (a.broken_at ? ' · gebrochen bei Eintrag ' + a.broken_at : '')),
              h('p', { cls: 'mono small', text: 'Kopf-Hash ' + (a.head_hash || '–') }))));
      }
      function paintGuard() {
        var g = st.guard || [];
        SW.dom.fill(guardHost, !g.length ? ui.empty('Keine Schutzereignisse', 'Der Prompt-Schutz hat in diesem Auftrag nichts markiert, geschwärzt oder blockiert.', 'shieldcheck') :
          h('div', { cls: 'tbl-wrap' }, h('table', { cls: 'tbl' },
            h('caption', { cls: 'sr-only', text: 'Schutzereignisse' }),
            h('thead', null, h('tr', null, ['Zeit', 'Aufgabe', 'Stufe', 'Regel', 'Schwere', 'Aktion', 'Ausschnitt'].map(function (c) { return h('th', { scope: 'col', text: c }); }))),
            h('tbody', null, g.map(function (e) {
              var tone = e.severity === 'high' ? 'err' : e.severity === 'medium' ? 'warn' : 'neutral';
              return h('tr', null, h('td', { cls: 'nowrap', text: fmt.time(e.ts) }), h('td', { cls: 'mono small', text: e.task_id || '–' }),
                h('td', { text: e.stage === 'input' ? 'Eingang' : e.stage === 'output' ? 'Ausgang' : e.stage }),
                h('td', { cls: 'mono small', text: e.rule }), h('td', null, h('span', { cls: 'badge tone-' + tone, text: e.severity })),
                h('td', { text: e.action }), h('td', { cls: 'mono small', text: e.snippet || '' }));
            })))));
      }
      host.appendChild(h('div', { cls: 'stack' }, ui.section('Audit-Kette', auditHost), ui.section('Prompt-Schutz', guardHost)));
      paintAudit();
      paintGuard();
      var off1 = ui.live(['audit', 'loaded'], paintAudit, 200);
      var off2 = ui.live(['guard', 'loaded'], paintGuard, 200);
      return { dispose: function () { off1(); off2(); } };
    }
  });
})();
