/* Ansicht Beispiele: harmlose Challenges aus example/, sortiert nach Schwierigkeit, mit Dateigroesse,
   Ablageort des Codes (challenge.json, Erzeuger in samples.py) und Start als Auftrag. Alles nur als Text eingefuegt. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var api = SW.api;
  var store = SW.store;
  var ui = SW.ui;

  var LEVELS = [[1, 'Leicht'], [2, 'Mittel'], [3, 'Schwer'], [9, 'Ohne Stufe']];

  function runRow(r) {
    var res = r.flag_found === true ? h('span', { cls: 'badge tone-ok', text: 'Flagge gefunden' })
      : r.flag_found === false ? h('span', { cls: 'badge tone-err', text: 'Flagge nicht gefunden' })
        : h('span', { cls: 'badge tone-info', text: 'läuft' });
    return h('li', null,
      h('a', { cls: 'mono', href: '#/job/' + encodeURIComponent(r.job_id) + '/activity', text: r.job_id }),
      fmt.badge(r.status), res, h('span', { cls: 'muted', text: fmt.dateTime(r.created_at) }));
  }

  function card(e, onStarted) {
    var srcHost = h('div');
    var errHost = h('div', { role: 'alert' });
    var minutes = h('input', { type: 'number', min: '1', max: '240', step: '1', value: '10', 'aria-label': 'Zeitbudget in Minuten für ' + e.title });
    minutes.value = '10';
    var startBtn = h('button', { type: 'button', cls: 'btn primary sm' }, icon('play'), 'Als Auftrag starten');
    var srcBtn = h('button', { type: 'button', cls: 'btn sm', 'aria-expanded': 'false' }, icon('code'), 'Code und Probe ansehen');
    var open = false;

    srcBtn.addEventListener('click', function () {
      open = !open;
      srcBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (!open) { SW.dom.clear(srcHost); return; }
      SW.dom.fill(srcHost, ui.loading('Quelltext wird geladen …'));
      api.get('/examples/' + encodeURIComponent(e.id)).then(function (d) {
        if (!open) return;
        var p = d.preview || {};
        SW.dom.fill(srcHost,
          h('h3', { cls: 'step-title', text: 'Erzeuger ' + e.sample.builder + '() in ' + e.paths.builder_file + ', Zeile ' + e.paths.builder_line }),
          h('pre', { cls: 'ex-src', tabindex: '0', text: d.builder_source || '–' }),
          h('h3', { cls: 'step-title', text: 'Beschreibung ' + e.paths.challenge }),
          h('pre', { cls: 'ex-src', tabindex: '0', text: d.challenge_json || '–' }),
          h('h3', { cls: 'step-title', text: 'Erzeugte Probe (' + fmt.bytes(e.sample.size) + ', ' + ((p.kind && p.kind.label) || '–') + ')' }),
          p.text ? h('pre', { cls: 'ex-src', tabindex: '0', text: p.text }) : null,
          h('div', { cls: 'hex ex-src', tabindex: '0' }, (p.hex || []).map(function (r) {
            return h('div', { cls: 'hex-row' }, h('span', { cls: 'hex-off', text: ('00000000' + r.offset.toString(16)).slice(-8) }), h('span', { text: r.hex }), h('span', { cls: 'hex-asc', text: r.ascii }));
          })),
          h('details', null, h('summary', { text: 'Lösung anzeigen (erwartete Flagge)' }), h('p', { cls: 'mono', text: d.flag || '–' }))
        );
      }, function (err) { SW.dom.fill(srcHost, ui.errorBox(err.message)); });
    });

    startBtn.addEventListener('click', function () {
      var m = parseInt(minutes.value, 10);
      if (isNaN(m) || m < 1 || m > 240) m = 10;
      startBtn.disabled = true;
      SW.dom.fill(errHost, ui.loading('Auftrag wird angelegt …'));
      api.postJson('/examples/' + encodeURIComponent(e.id) + '/job', { budget_max_minutes: m }).then(function (s) {
        store.refreshGlobal();
        onStarted();
        window.location.hash = '#/job/' + encodeURIComponent(s.id) + '/activity';
      }, function (err) {
        startBtn.disabled = false;
        SW.dom.fill(errHost, ui.errorBox('Start fehlgeschlagen: ' + err.message));
      });
    });

    return h('article', { cls: 'card ex-card', id: 'ex-' + e.id },
      h('div', { cls: 'card-h' },
        h('h2', { text: e.title }),
        h('span', { cls: 'badge lvl-' + e.level_rank, text: e.level || '–' })),
      h('div', { cls: 'card-b' },
        h('div', { cls: 'ex-meta' },
          h('span', { cls: 'tag mono', text: e.id }),
          h('span', { cls: 'tag', title: 'Größe der erzeugten Probe' }, icon('file', { size: 13 }), ' ' + e.sample.name + ' · ' + fmt.bytes(e.sample.size)),
          h('span', { cls: 'tag mono', title: 'SHA-256 der Probe', text: fmt.shortHash(e.sample.sha256, 12) })),
        h('p', { cls: 'ex-desc', text: e.description }),
        h('dl', { cls: 'kv small' },
          h('dt', { text: 'Ziel' }), h('dd', { text: e.goal || '–' }),
          h('dt', { text: 'Prüft' }), h('dd', { text: e.tests || '–' }),
          h('dt', { text: 'Zielfragen' }), h('dd', null, h('ol', { cls: 'md-list' }, (e.questions || []).map(function (q) { return h('li', { text: q }); })))),
        h('dl', { cls: 'kv ex-paths', 'aria-label': 'Wo der Code liegt' },
          h('dt', { text: 'Ordner' }), h('dd', { text: e.paths.folder + '/' }),
          h('dt', { text: 'Beschreibung' }), h('dd', { text: e.paths.challenge }),
          h('dt', { text: 'Erzeuger' }), h('dd', { text: e.paths.builder_file + ':' + e.paths.builder_line + '  ' + e.sample.builder + '()' }),
          h('dt', { text: 'Ablage im Lauf' }), h('dd', { text: e.paths.stored_as }),
          h('dt', { text: 'Skriptlauf' }), h('dd', { text: e.paths.runner + ' -Challenge ' + e.id })),
        e.runs && e.runs.length ? h('div', null, h('h3', { text: 'Letzte Läufe' }), h('ul', { cls: 'ex-runs' }, e.runs.map(runRow))) : null,
        h('div', { cls: 'ex-actions' }, startBtn, h('label', { cls: 'small muted' }, 'Budget ', minutes, ' min'), srcBtn),
        errHost,
        srcHost));
  }

  SW.views.examples = function () {
    var host = h('div', { cls: 'stack' }, ui.loading('Beispiele werden geladen …'));
    var dead = false;

    function load() {
      api.get('/examples').then(function (d) {
        if (dead) return;
        if (!d.available || !d.items.length) {
          SW.dom.fill(host, ui.empty('Keine Beispiele gefunden', 'Der Ordner example/ mit challenges/ und samples.py fehlt in dieser Installation.', 'list'));
          return;
        }
        SW.dom.fill(host,
          h('div', { cls: 'notice tone-info', role: 'note' }, icon('info'),
            h('div', null,
              h('p', { text: 'Alle Beispiele sind harmlose, selbst erzeugte Proben. Quelle: Ordner ' + d.folder + '/ im Projekt (je Beispiel challenge.json, die Probe erzeugt eine Funktion in ' + d.folder + '/samples.py).' }),
              h('p', { text: 'Beim Start wird die Probe im Speicher gebaut und wie ein Upload unter data/jobs/<Auftrag>/sample abgelegt. Die erwartete Flagge geht nicht an die KI; der Abgleich passiert erst nach dem Lauf.' }))),
          LEVELS.map(function (lv) {
            var items = d.items.filter(function (e) { return (e.level_rank || 9) === lv[0]; });
            if (!items.length) return null;
            return h('section', { cls: 'ex-level', 'aria-labelledby': 'lv-' + lv[0] },
              h('h2', { cls: 'ex-level-h', id: 'lv-' + lv[0] }, h('span', { cls: 'badge lvl-' + lv[0], text: lv[1] }), h('span', { cls: 'muted small', text: items.length + (items.length === 1 ? ' Beispiel' : ' Beispiele') })),
              h('div', { cls: 'ex-grid' }, items.map(function (e) { return card(e, load); })));
          }));
      }, function (err) { if (!dead) SW.dom.fill(host, ui.errorBox('Beispiele konnten nicht geladen werden: ' + err.message)); });
    }
    load();
    return {
      title: 'Beispiele',
      el: h('div', { cls: 'stack' },
        h('div', { cls: 'page-h' }, h('div', { cls: 'grow' }, h('h1', { text: 'Beispiele' }), h('p', { cls: 'page-sub', text: 'Challenges zum Ausprobieren, sortiert von leicht nach schwer.' }))),
        host),
      dispose: function () { dead = true; }
    };
  };
})();
