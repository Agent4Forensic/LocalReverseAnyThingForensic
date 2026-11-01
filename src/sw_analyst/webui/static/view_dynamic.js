/* Tab Dynamische Analyse: sichtbar, Ausfuehrung AUS (Entscheidung Jan, ADR-0005). Zeigt Status, Voraussetzungen und
   die Luecken (GAP-Befunde), die nur ein Lauf klaeren kann, als Plan. Es wird nichts gestartet; Texte nur als Textknoten. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var api = SW.api;
  var ui = SW.ui;

  function gapCard(st, g) {
    function row(label, val, mono) {
      return val ? [h('dt', { text: label }), h('dd', { cls: mono ? 'mono' : null, text: val })] : [];
    }
    return h('article', { cls: 'fcard f-hypothesis dy-gap' },
      h('div', { cls: 'row' }, h('a', { cls: 'mono fid', href: ui.tabHref(st.id, 'report', { finding: g.finding_id }), text: g.finding_id }),
        h('span', { cls: 'badge tone-neutral' }, icon('clock', { size: 13 }), 'nicht ausgeführt')),
      h('p', { cls: 'fstmt', text: g.what || 'Lücke ohne nähere Beschreibung' }),
      h('dl', { cls: 'kv' }, [].concat(row('Würde geklärt durch', g.close_by), row('Frage', g.question), row('Eingabe', g.input, true))));
  }

  SW.registerTab({
    id: 'dynamic', label: 'Dynamische Analyse', icon: 'cpu',
    mount: function (host, ctx) {
      var st = ctx.st;
      var body = h('div', { cls: 'stack' }, ui.loading());
      var dead = false;
      var seq = 0;
      function load() {
        var mine = ++seq;
        api.get('/jobs/' + st.id + '/dynamic').then(function (p) {
          if (dead || mine !== seq) return;
          var reqs = Array.isArray(p.requirements) ? p.requirements : [];
          var gaps = Array.isArray(p.gaps) ? p.gaps : [];
          SW.dom.fill(body, [
            h('div', { cls: 'notice tone-warn', role: 'status' }, icon('alertcircle'),
              h('p', null, h('strong', { text: p.enabled ? 'Ausführung freigegeben' : 'Ausführung AUS' }), ' – ' + (p.reason || 'nicht ausgeführt'))),
            ui.section('Voraussetzungen für einen Lauf',
              reqs.length ? h('ul', { cls: 'md-list' }, reqs.map(function (r) { return h('li', { text: r }); })) : ui.noData('Keine Angaben.')),
            ui.section('Lücken, die nur ein Lauf klärt (' + gaps.length + ')',
              gaps.length ? h('div', { cls: 'stack' }, gaps.map(function (g) { return gapCard(st, g); }))
                : ui.empty('Keine Lücken gemeldet', 'Die statische Analyse hat keinen Punkt als „nur dynamisch klärbar“ markiert (GAP-Befund).', 'check'),
              h('span', { cls: 'muted small', text: 'Plan, keine Ausführung' }))
          ]);
        }, function (err) {
          if (dead || mine !== seq) return;
          SW.dom.fill(body, err.status === 404 ? ui.noData('Für diesen Server liegt kein Plan zur dynamischen Analyse vor.') : ui.errorBox('Plan konnte nicht geladen werden: ' + err.message));
        });
      }
      host.appendChild(ui.section('Dynamische Analyse', body));
      load();
      var off = ui.live(['findings', 'jobfinished'], load, 1500);
      return { dispose: function () { dead = true; off(); } };
    }
  });
})();
