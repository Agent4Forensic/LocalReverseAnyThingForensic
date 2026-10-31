/* Tabs: Log (Ereignisprotokoll mit Audit-Kette) und Guard (Wächter-Ereignisse). Sample-Inhalte nur als Text. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var ui = SW.ui;

  var LEVEL_TONE = { error: 'err', warn: 'warn', info: 'neutral', debug: 'neutral' };
  var SEVERITY_TONE = { high: 'err', medium: 'warn', low: 'info' };

  function auditNotice(a) {
    if (!a) return ui.loading('Prüfe Audit-Kette …');
    var ok = a.valid;
    return h('div', { cls: ['notice', ok ? 'tone-ok' : 'tone-err'], role: ok ? 'status' : 'alert' },
      icon(ok ? 'shieldcheck' : 'alertcircle'),
      h('p', null,
        ok ? 'Audit-Kette intakt: ' + a.entries + ' Einträge. ' : 'Audit-Kette gebrochen bei Eintrag ' + a.broken_at + '. ',
        a.head_hash ? h('span', { cls: 'mono small', text: 'Kopf-Hash ' + fmt.shortHash(a.head_hash) }) : null));
  }

  SW.registerTab({
    id: 'log', label: 'Log', icon: 'list',
    mount: function (host, ctx) {
      var st = ctx.st;
      var level = 'info';
      var auditHost = h('div');
      var listHost = h('div', { cls: 'tbl-wrap' });
      var segHost = h('div');
      var RANK = { debug: 0, info: 1, warn: 2, error: 3 };

      function paintList() {
        var rows = st.log.filter(function (e) { return (RANK[e.level] || 0) >= RANK[level]; }).slice(-400).reverse();
        SW.dom.fill(listHost, !rows.length
          ? (st.loaded ? ui.empty('Keine Einträge', 'Für diese Stufe liegen keine Ereignisse vor.', 'list') : ui.loading())
          : h('table', { cls: 'tbl' },
              h('caption', { cls: 'sr-only', text: 'Ereignisprotokoll, neueste zuerst' }),
              h('thead', null, h('tr', null, ['Zeit', 'Stufe', 'Typ', 'Meldung'].map(function (c) { return h('th', { scope: 'col', text: c }); }))),
              h('tbody', null, rows.map(function (e) {
                return h('tr', null,
                  h('td', { cls: 'mono small nowrap', text: fmt.time(e.ts) }),
                  h('td', null, h('span', { cls: 'badge tone-' + (LEVEL_TONE[e.level] || 'neutral'), text: e.level })),
                  h('td', { cls: 'mono small', text: e.type || '–' }),
                  h('td', { text: e.message || '' }));
              }))));
      }
      function paintSeg() {
        SW.dom.fill(segHost, h('div', { cls: 'seg', role: 'group', 'aria-label': 'Log-Stufe' }, ['info', 'warn', 'error', 'debug'].map(function (l) {
          return h('button', { type: 'button', cls: 'seg-b', 'aria-pressed': String(l === level), on: { click: function () { level = l; paintSeg(); paintList(); } }, text: l });
        })));
      }
      function paintAudit() { SW.dom.fill(auditHost, auditNotice(st.audit)); }

      host.appendChild(h('div', { cls: 'stack' }, auditHost, ui.section('Ereignisprotokoll', listHost, segHost)));
      paintSeg(); paintAudit(); paintList();
      var off = ui.live(['log', 'audit', 'loaded'], function (k) { if (k === 'audit') paintAudit(); else paintList(); }, 150);
      return { dispose: off };
    }
  });

  SW.registerTab({
    id: 'guard', label: 'Guard', icon: 'shield',
    mount: function (host, ctx) {
      var st = ctx.st;
      var body = h('div');

      function paint() {
        var g = st.guard || [];
        SW.dom.fill(body, !g.length
          ? (st.loaded ? ui.empty('Keine Wächter-Ereignisse', 'Der Prompt-Schutz hat bisher nichts geschwärzt oder blockiert.', 'shieldcheck') : ui.loading())
          : h('div', { cls: 'tbl-wrap' }, h('table', { cls: 'tbl' },
              h('caption', { cls: 'sr-only', text: 'Wächter-Ereignisse in zeitlicher Reihenfolge' }),
              h('thead', null, h('tr', null, ['Zeit', 'Aufgabe', 'Stufe', 'Regel', 'Schwere', 'Aktion', 'Ausschnitt'].map(function (c) { return h('th', { scope: 'col', text: c }); }))),
              h('tbody', null, g.map(function (e) {
                return h('tr', null,
                  h('td', { cls: 'mono small nowrap', text: fmt.time(e.ts) }),
                  h('td', { cls: 'mono small' }, e.task_id ? h('a', { href: ui.tabHref(st.id, 'tree', { task: e.task_id }), text: e.task_id }) : '–'),
                  h('td', { text: e.stage || '–' }),
                  h('td', { cls: 'mono small', text: e.rule || '–' }),
                  h('td', null, h('span', { cls: 'badge tone-' + (SEVERITY_TONE[e.severity] || 'neutral'), text: e.severity || '–' })),
                  h('td', { text: e.action || '–' }),
                  h('td', null, h('code', { cls: 'small', text: e.snippet || '' })));
              })))));
      }
      host.appendChild(h('div', { cls: 'stack' }, ui.section('Wächter-Ereignisse', body, h('span', { cls: 'muted small', text: 'Ausschnitte sind geschwärzt und werden nur als Text gezeigt' }))));
      paint();
      var off = ui.live(['guard', 'loaded'], paint, 150);
      return { dispose: off };
    }
  });
})();
