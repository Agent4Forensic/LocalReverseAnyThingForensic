/* Ansicht Beispiele: links Liste nach Schwierigkeit (Bereitschaft, letztes Ergebnis), rechts das gewaehlte Beispiel
   mit einem Startknopf. Budget und Voraussetzungen kommen aus challenge.json; der Server prueft vor dem Start,
   ob Modell und benoetigte Werkzeuge bereit sind und ob das Beispiel schon laeuft. Alles nur als Text eingefuegt. */
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

  function lastRun(e) { return (e.runs || [])[0] || null; }

  function resultBadge(r) {
    if (!r) return h('span', { cls: 'badge tone-neutral', text: 'noch nicht gelaufen' });
    if (r.flag_found === true) return h('span', { cls: 'badge tone-ok', text: 'bestanden' });
    if (r.flag_found === false) return h('span', { cls: 'badge tone-err', text: 'nicht bestanden' });
    return h('span', { cls: 'badge tone-info', text: r.status === 'running' ? 'läuft' : 'wartet' });
  }

  function hexBlock(rows) {
    return h('div', { cls: 'hex ex-src', tabindex: '0' }, (rows || []).map(function (r) {
      return h('div', { cls: 'hex-row' }, h('span', { cls: 'hex-off', text: ('00000000' + r.offset.toString(16)).slice(-8) }), h('span', { text: r.hex }), h('span', { cls: 'hex-asc', text: r.ascii }));
    }));
  }

  SW.views.examples = function (route) {
    var data = null;
    var selected = (route && route.query && route.query.id) || null;
    var dead = false;
    var timer = null;
    var busy = false;
    var msgHost = h('div', { role: 'status' });
    var barHost = h('div');
    var listHost = h('div', { cls: 'ex-list' });
    var detailHost = h('div');
    var srcOpen = false;

    function pickDefault() {
      if (!data || !data.items.length) return null;
      if (selected && data.items.some(function (e) { return e.id === selected; })) return selected;
      var open = data.items.filter(function (e) { var r = lastRun(e); return e.ready && !(r && r.flag_found === true); })[0];
      return (open || data.items[0]).id;
    }

    function load() {
      api.get('/examples').then(function (d) {
        if (dead) return;
        data = d;
        selected = pickDefault();
        paint();
        var active = d.items.some(function (e) { return e.active_job; });
        window.clearTimeout(timer);
        timer = window.setTimeout(load, active ? 4000 : 15000);   /* Ergebnisse erscheinen von selbst */
      }, function (err) {
        if (!dead) SW.dom.fill(listHost, ui.errorBox('Beispiele konnten nicht geladen werden: ' + err.message));
      });
    }

    function select(id) {
      selected = id;
      srcOpen = false;
      try { window.history.replaceState(null, '', '#/examples?id=' + encodeURIComponent(id)); } catch (e) { /* egal */ }
      paint();
    }

    function start(e, force, minutes) {
      if (busy) return;
      busy = true;
      paint();
      SW.dom.fill(msgHost, ui.loading('Auftrag für ' + e.id + ' wird angelegt …'));
      var body = { force: !!force };
      if (minutes) body.budget_max_minutes = minutes;
      api.postJson('/examples/' + encodeURIComponent(e.id) + '/job', body).then(function (s) {
        busy = false;
        store.refreshGlobal();
        window.location.hash = '#/job/' + encodeURIComponent(s.id) + '/activity';
      }, function (err) {
        busy = false;
        SW.dom.fill(msgHost, ui.errorBox('Nicht gestartet: ' + err.message));
        load();
      });
    }

    function startAll() {
      if (busy) return;
      busy = true;
      paint();
      SW.dom.fill(msgHost, ui.loading('Beispiele werden in die Warteschlange gestellt …'));
      api.postJson('/examples-batch', { force: false }).then(function (r) {
        busy = false;
        store.refreshGlobal();
        SW.dom.fill(msgHost, h('div', { cls: 'notice ' + (r.started.length ? 'tone-ok' : 'tone-warn') }, icon(r.started.length ? 'checkcircle' : 'alert'),
          h('div', null,
            h('p', { text: r.started.length ? r.started.length + ' Beispiel(e) gestartet; sie laufen nacheinander, leicht zuerst: ' + r.started.map(function (s) { return s.id; }).join(', ') + '.' : 'Kein Beispiel gestartet.' }),
            r.skipped.length ? h('ul', { cls: 'md-list small' }, r.skipped.map(function (x) { return h('li', { text: x.id + ': ' + x.reason }); })) : null)));
        load();
      }, function (err) {
        busy = false;
        SW.dom.fill(msgHost, ui.errorBox('Nicht gestartet: ' + err.message));
      });
    }

    function paintBar() {
      var items = data.items;
      var ready = items.filter(function (e) { return e.ready && !e.active_job; }).length;
      var passed = items.filter(function (e) { var r = lastRun(e); return r && r.flag_found === true; }).length;
      var llmMissing = items.some(function (e) { return e.missing.some(function (m) { return m.key === 'llm'; }); });
      SW.dom.fill(barHost, h('div', { cls: 'card' }, h('div', { cls: 'card-b row' },
        h('span', { cls: 'badge ' + (llmMissing ? 'tone-err' : 'tone-ok'), text: llmMissing ? 'Modell nicht erreichbar' : 'Modell bereit' }),
        h('span', { cls: 'small muted', text: passed + ' von ' + items.length + ' bestanden · ' + ready + ' startbereit · Warteschlange ' + data.queue_length + (data.worker_busy ? ' · Worker arbeitet' : '') }),
        h('span', { cls: 'grow' }),
        h('button', { type: 'button', cls: 'btn', id: 'ex-all', disabled: busy || !ready, title: 'Startet jedes startbereite Beispiel einmal, leicht zuerst. Die Aufträge laufen nacheinander.', on: { click: startAll } }, icon('play'), 'Alle startbereiten nacheinander starten'))));
    }

    function paintList() {
      SW.dom.fill(listHost, LEVELS.map(function (lv) {
        var items = data.items.filter(function (e) { return (e.level_rank || 9) === lv[0]; });
        if (!items.length) return null;
        return h('section', { cls: 'ex-group', 'aria-label': lv[1] },
          h('h2', { cls: 'ex-level-h' }, h('span', { cls: 'badge lvl-' + lv[0], text: lv[1] })),
          h('ul', { cls: 'flist' }, items.map(function (e) {
            var on = e.id === selected;
            return h('li', null, h('button', { type: 'button', cls: ['ex-item', on ? 'is-sel' : ''], 'aria-pressed': on ? 'true' : 'false', 'data-key': 'ex-' + e.id, on: { click: function () { select(e.id); } } },
              h('span', { cls: 'ex-item-t' }, h('strong', { text: e.title }), h('span', { cls: 'small muted mono', text: e.id + ' · ' + fmt.bytes(e.sample.size) })),
              h('span', { cls: 'ex-item-s' },
                e.active_job ? h('span', { cls: 'badge tone-info', text: 'läuft' }) : resultBadge(lastRun(e)),
                !e.ready ? h('span', { cls: 'badge tone-warn', title: e.missing.map(function (m) { return m.text; }).join('; '), text: 'Voraussetzung fehlt' }) : null)));
          })));
      }));
    }

    function paintDetail() {
      var e = data.items.filter(function (x) { return x.id === selected; })[0];
      if (!e) { SW.dom.fill(detailHost, ui.empty('Beispiel wählen', 'Links ein Beispiel auswählen.', 'list')); return; }
      var minutes = h('input', { type: 'number', min: '1', max: '240', step: '1', id: 'ex-min', 'aria-describedby': 'ex-min-h' });
      minutes.value = String(e.budget_minutes);
      function chosenMinutes() {
        var m = parseInt(minutes.value, 10);
        return isNaN(m) || m < 1 || m > 240 ? e.budget_minutes : m;
      }
      var actions;
      if (e.active_job) {
        actions = [h('a', { cls: 'btn primary', href: '#/job/' + encodeURIComponent(e.active_job) + '/activity' }, icon('pulse'), 'Laufenden Auftrag ' + e.active_job + ' öffnen'),
          h('button', { type: 'button', cls: 'btn', disabled: busy, on: { click: function () { start(e, true, chosenMinutes()); } } }, 'Trotzdem zusätzlich starten')];
      } else if (!e.ready) {
        actions = [h('button', { type: 'button', cls: 'btn primary', disabled: true }, icon('play'), 'Beispiel starten'),
          h('button', { type: 'button', cls: 'btn', id: 'ex-force', disabled: busy, title: 'Ohne die fehlende Voraussetzung ist ein Fehlschlag wahrscheinlich.', on: { click: function () { start(e, true, chosenMinutes()); } } }, 'Trotzdem starten')];
      } else {
        actions = [h('button', { type: 'button', cls: 'btn primary', id: 'ex-start', disabled: busy, on: { click: function () { start(e, false, chosenMinutes()); } } }, icon('play'), 'Beispiel starten')];
      }
      var srcHost = h('div');
      var srcBtn = h('button', { type: 'button', cls: 'btn sm', 'aria-expanded': srcOpen ? 'true' : 'false' }, icon('code'), srcOpen ? 'Code und Probe ausblenden' : 'Code und Probe ansehen');
      srcBtn.addEventListener('click', function () { srcOpen = !srcOpen; paintDetail(); });
      if (srcOpen) {
        SW.dom.fill(srcHost, ui.loading('Quelltext wird geladen …'));
        api.get('/examples/' + encodeURIComponent(e.id)).then(function (d) {
          if (dead || selected !== e.id || !srcOpen) return;
          var p = d.preview || {};
          SW.dom.fill(srcHost,
            h('h3', { cls: 'step-title', text: 'Erzeuger ' + e.sample.builder + '() in ' + e.paths.builder_file + ', Zeile ' + e.paths.builder_line }),
            h('pre', { cls: 'ex-src', tabindex: '0', text: d.builder_source || '–' }),
            h('h3', { cls: 'step-title', text: 'Beschreibung ' + e.paths.challenge }),
            h('pre', { cls: 'ex-src', tabindex: '0', text: d.challenge_json || '–' }),
            h('h3', { cls: 'step-title', text: 'Probe ' + e.paths.sample_file + ' (' + fmt.bytes(e.sample.size) + ', ' + ((p.kind && p.kind.label) || '–') + ')' }),
            p.text ? h('pre', { cls: 'ex-src', tabindex: '0', text: p.text }) : null,
            hexBlock(p.hex),
            h('details', null, h('summary', { text: 'Lösung anzeigen (erwartete Flagge)' }), h('p', { cls: 'mono', text: d.flag || '–' })));
        }, function (err) { SW.dom.fill(srcHost, ui.errorBox(err.message)); });
      }
      var r = lastRun(e);
      SW.dom.fill(detailHost, h('article', { cls: 'card', 'aria-labelledby': 'ex-h' },
        h('div', { cls: 'card-h' }, h('h2', { id: 'ex-h', text: e.title }), h('span', { cls: 'badge lvl-' + e.level_rank, text: e.level || '–' })),
        h('div', { cls: 'card-b stack' },
          h('p', { cls: 'ex-desc', text: e.description }),
          !e.ready ? h('div', { cls: 'notice tone-warn', role: 'alert' }, icon('alert'), h('div', null,
            h('p', null, h('strong', { text: 'Vor dem Start fehlt:' })),
            h('ul', { cls: 'md-list' }, e.missing.map(function (m) { return h('li', { text: m.text }); })))) : null,
          h('div', { cls: 'ex-start' },
            h('div', { cls: 'row' }, actions),
            h('label', { cls: 'row small', for: 'ex-min' }, 'Zeitbudget ', minutes, ' min'),
            h('p', { cls: 'hint', id: 'ex-min-h', text: 'Empfohlen für dieses Beispiel: ' + e.budget_minutes + ' min (aus challenge.json). Aufgaben 20, Schritte 200 wie im Skriptlauf. Die erwartete Flagge geht nicht an die KI; nach dem Lauf vergleicht das Dashboard sie automatisch mit den akzeptierten Antworten.' })),
          h('dl', { cls: 'kv small' },
            h('dt', { text: 'Ziel' }), h('dd', { text: e.goal || '–' }),
            h('dt', { text: 'Prüft' }), h('dd', { text: e.tests || '–' }),
            h('dt', { text: 'Zielfragen' }), h('dd', null, h('ol', { cls: 'md-list' }, (e.questions || []).map(function (q) { return h('li', { text: q }); }))),
            h('dt', { text: 'Benötigt' }), h('dd', { text: e.requires && e.requires.length ? e.requires.join(', ') + ' (zusätzlich zum Modell)' : 'nur das Sprachmodell' }),
            h('dt', { text: 'Letztes Ergebnis' }), h('dd', null, resultBadge(r), r ? ' ' : null, r ? h('a', { cls: 'mono', href: '#/job/' + encodeURIComponent(r.job_id) + '/report', text: r.job_id }) : null)),
          h('dl', { cls: 'kv ex-paths', 'aria-label': 'Wo der Code liegt' },
            h('dt', { text: 'Ordner' }), h('dd', { text: e.paths.folder + '/' }),
            h('dt', { text: 'Beschreibung' }), h('dd', { text: e.paths.challenge }),
            h('dt', { text: 'Erzeuger' }), h('dd', { text: e.paths.builder_file + ':' + e.paths.builder_line + '  ' + e.sample.builder + '()' }),
            h('dt', { text: 'Probe im Repo' }), h('dd', null, e.paths.sample_file + '  ',
              e.paths.sample_file_ok === true ? h('span', { cls: 'badge tone-ok', text: 'gleich Erzeuger' })
                : e.paths.sample_file_ok === false ? h('span', { cls: 'badge tone-err', text: 'weicht ab' })
                  : h('span', { cls: 'badge tone-neutral', text: 'fehlt' })),
            h('dt', { text: 'Ablage im Lauf' }), h('dd', { text: e.paths.stored_as }),
            h('dt', { text: 'Skriptlauf' }), h('dd', { text: e.paths.runner + ' -Challenge ' + e.id })),
          (e.runs || []).length > 1 ? h('details', null, h('summary', { text: 'Frühere Läufe (' + e.runs.length + ')' }),
            h('ul', { cls: 'ex-runs' }, e.runs.map(function (x) {
              return h('li', null, h('a', { cls: 'mono', href: '#/job/' + encodeURIComponent(x.job_id) + '/report', text: x.job_id }), fmt.badge(x.status), resultBadge(x), h('span', { cls: 'muted', text: fmt.dateTime(x.created_at) }));
            }))) : null,
          h('div', null, srcBtn, srcHost))));
    }

    function paint() {
      if (!data) return;
      if (!data.available || !data.items.length) {
        SW.dom.fill(listHost, ui.empty('Keine Beispiele gefunden', 'Der Ordner example/ mit challenges/ und samples.py fehlt in dieser Installation.', 'list'));
        SW.dom.clear(detailHost);
        return;
      }
      paintBar();
      SW.dom.keepFocus(listHost, paintList);
      paintDetail();
    }

    SW.dom.fill(listHost, ui.loading('Beispiele werden geladen …'));
    load();
    return {
      title: 'Beispiele',
      el: h('div', { cls: 'stack' },
        h('div', { cls: 'page-h' }, h('div', { cls: 'grow' }, h('h1', { text: 'Beispiele' }),
          h('p', { cls: 'page-sub', text: 'Harmlose, selbst erzeugte Challenges aus example/. Beispiel wählen, starten, das Ergebnis erscheint automatisch.' }))),
        barHost, msgHost,
        h('div', { cls: 'split ex-split' }, h('nav', { cls: 'card card-b', 'aria-label': 'Beispiele nach Schwierigkeit' }, listHost), detailHost)),
      update: function (r) { var id = r.query && r.query.id; if (id && id !== selected) select(id); },
      dispose: function () { dead = true; window.clearTimeout(timer); }
    };
  };
})();
