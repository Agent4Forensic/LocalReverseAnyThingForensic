/* Ansichten: Uebersicht, Neuer Auftrag. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var api = SW.api;
  var store = SW.store;
  var ui = SW.ui;

  /* =================== Uebersicht =================== */
  function tile(iconName, label, value, sub, tone) {
    return h('div', { cls: 'tile' },
      h('div', { cls: 'tile-l' }, icon(iconName, { size: 15 }), h('span', { text: label })),
      h('div', { cls: 'tile-v' }, value),
      sub ? h('div', { cls: 'tile-s muted small', text: sub }) : null,
      tone ? h('span', { cls: 'tile-flag badge tone-' + tone, text: tone === 'ok' ? 'OK' : tone === 'err' ? 'Störung' : 'Hinweis' }) : null
    );
  }

  function statusTiles(sys, err) {
    if (err && !sys) return ui.errorBox('Server nicht erreichbar: ' + err);
    if (!sys) return ui.loading('Systemstatus wird geladen …');
    var w = sys.worker || {};
    var llm = sys.llm || {};
    var g = sys.guard || {};
    var gw = sys.gateway || {};
    return h('div', { cls: 'tiles' },
      tile('cpu', 'Worker', w.state === 'running' ? 'Läuft' : 'Leerlauf', w.job_id ? 'Auftrag ' + w.job_id : 'wartet auf Aufträge', null),
      tile('server', 'Sprachmodell', llm.reachable ? 'Erreichbar' : 'Nicht erreichbar', (llm.model || '–') + ' · ' + (llm.base_url || '–'), llm.reachable ? 'ok' : 'err'),
      tile('shieldcheck', 'Prompt-Schutz', g.active ? 'Aktiv' : 'Inaktiv', (g.rules || 0) + ' Regeln · v' + (g.version || '–'), g.active ? 'ok' : 'err'),
      tile('terminal', 'Werkzeug-Gateway', gw.kind || '–', (gw.tools || 0) + ' freigegebene Werkzeuge', null),
      tile('code', 'Assembler / Pseudocode', gw.ghidra ? 'Ghidra bereit' : 'Ghidra fehlt', gw.ghidra ? 'Offline-Container geladen' : 'Docker starten oder scripts\\start.ps1 -BuildTools', gw.ghidra ? 'ok' : 'warn'),
      sys.storage ? tile('server', 'Datenablage', sys.storage.data_dir || '–', sys.storage.inside_project ? 'im Projektordner (Virenschutz-Ausnahme)' : 'außerhalb des Projektordners', sys.storage.inside_project ? 'ok' : 'warn') : null,
      tile('queue', 'Warteschlange', String(sys.queue_length || 0), 'wartende Aufträge', null),
      tile('info', 'Version', sys.version || '–', 'sw-analyst', null)
    );
  }

  var BUSY = ['queued', 'running', 'uploading'];
  SW.canDeleteJob = function (j) { return !j.imported && BUSY.indexOf(j.status) < 0; };
  /* Loescht einen Auftrag nach Bestaetigung; danach Liste neu laden und zur Uebersicht. */
  SW.deleteJob = function (j) {
    var msg = 'Auftrag „' + j.title + '“ (' + j.id + ') aus dem Dashboard löschen?\n\nSample, abgeleitete Dateien und Datenbankeinträge werden entfernt. Das Audit-Log und ein Export der Einträge bleiben unverändert unter data/deleted/ archiviert; ein hash-verketteter Nachweis steht in deleted_jobs.jsonl.';
    if (!window.confirm(msg)) return Promise.resolve(false);
    var done = function () {
      store.refreshGlobal();
      if (window.location.hash !== '' && window.location.hash !== '#/') window.location.hash = '#/';
      return true;
    };
    if (api.isMock) return Promise.resolve(done());
    return window.fetch(api.href('/jobs/' + encodeURIComponent(j.id)), { method: 'DELETE', headers: { Accept: 'application/json' }, credentials: 'same-origin' }).then(function (r) {
      if (r.ok) return done();
      return r.json().then(function (b) { return (b && b.error && b.error.message) || 'Fehler ' + r.status; }, function () { return 'Fehler ' + r.status; }).then(function (m) { window.alert('Löschen abgelehnt: ' + m); return false; });
    }, function () { window.alert('Server nicht erreichbar.'); return false; });
  };

  function jobRow(j) {
    return h('tr', null,
      h('td', null, h('a', { href: '#/job/' + encodeURIComponent(j.id) + '/activity', text: j.title }),
        h('div', { cls: 'mono small muted' }, j.id, j.imported ? ' ' : null, j.imported ? h('span', { cls: 'tag tone-info', text: 'importiert' }) : null)),
      h('td', null, fmt.badge(j.status)),
      h('td', null, h('span', { text: j.sample_name || '–' }), h('div', { cls: 'mono small muted', text: fmt.shortHash(j.sample_sha256, 16) })),
      h('td', { cls: 'num nowrap', text: j.sample_size === null || j.sample_size === undefined ? '–' : fmt.bytes(j.sample_size) }),
      h('td', { text: [j.detected_type, j.recipe].filter(Boolean).join(' / ') || '–' }),
      h('td', { cls: 'nowrap', text: fmt.dateTime(j.created_at) }),
      h('td', { cls: 'num nowrap', text: j.finished_at || j.started_at ? fmt.duration(j.duration_ms) : '–' }),
      h('td', { cls: 'nowrap' }, SW.canDeleteJob(j)
        ? h('button', { type: 'button', cls: 'btn sm danger', 'aria-label': 'Auftrag ' + j.title + ' löschen', on: { click: function () { SW.deleteJob(j); } } }, icon('trash'), 'Löschen')
        : h('span', { cls: 'muted small', text: j.imported ? 'schreibgeschützt' : '' })))
    ;
  }

  SW.views.overview = function () {
    var filter = 'all';
    var statusHost = h('div');
    var currentHost = h('div');
    var listHost = h('div');
    var curDetail = null;
    var curActivity = null;
    var curId = null;

    function paintStatus() { SW.dom.fill(statusHost, statusTiles(store.state.system, store.state.systemError)); }

    function paintCurrent() {
      var run = store.state.jobs.filter(function (j) { return j.status === 'running'; })[0];
      if (!run) {
        curId = null;
        SW.dom.fill(currentHost, ui.empty('Kein Auftrag in Bearbeitung', store.state.jobs.some(function (j) { return j.status === 'queued'; }) ? 'Der nächste Auftrag startet automatisch.' : 'Legen Sie einen neuen Auftrag an, um eine Analyse zu starten.', 'pulse'));
        return;
      }
      if (curId !== run.id) { curId = run.id; curDetail = null; curActivity = null; }
      api.get('/jobs/' + run.id).then(function (d) { if (curId === run.id) { curDetail = d; draw(); } }, function () {});
      ui.softGet('/jobs/' + run.id + '/activity').then(function (r) { if (curId === run.id) { curActivity = r.ok ? r.data : null; draw(); } });
      function draw() {
        var p = curDetail && curDetail.progress;
        var a = curActivity;
        SW.dom.fill(currentHost,
          h('div', { cls: 'cur' },
            h('div', { cls: 'row' },
              h('a', { cls: 'cur-t', href: '#/job/' + encodeURIComponent(run.id) + '/activity', text: run.title }),
              fmt.badge('running'),
              h('span', { cls: 'muted small', text: 'seit ' + fmt.time(run.started_at) })
            ),
            p ? h('div', { cls: 'cur-p' }, ui.bar(p.percent), h('span', { cls: 'small muted nowrap', text: p.done + ' von ' + p.tasks_total + ' Aufgaben · ' + fmt.percent(p.percent) })) : null,
            a && a.task ? h('p', { cls: 'cur-task' }, icon('chevronright', { size: 13 }), ' ', h('strong', { text: a.task.title }), a.step ? h('span', { cls: 'muted', text: ' – ' + (a.step.what || '') }) : null) : null,
            curDetail && curDetail.totals ? h('p', { cls: 'muted small', text: curDetail.totals.steps + ' Schritte · ' + curDetail.totals.tool_calls + ' Werkzeugaufrufe · ' + curDetail.totals.llm_calls + ' Modellaufrufe' }) : null
          )
        );
      }
      draw();
    }

    function paintList() {
      var jobs = store.state.jobs.filter(function (j) {
        if (filter === 'active') return j.status === 'running' || j.status === 'queued';
        if (filter === 'done') return j.status === 'done' || j.status === 'partial';
        if (filter === 'bad') return j.status === 'failed' || j.status === 'cancelled';
        return true;
      });
      SW.dom.fill(listHost, !store.state.jobsLoaded ? ui.loading() : jobs.length
        ? h('div', { cls: 'tbl-wrap' }, h('table', { cls: 'tbl' },
            h('caption', { cls: 'sr-only', text: 'Aufträge, neueste zuerst' }),
            h('thead', null, h('tr', null, ['Auftrag', 'Status', 'Sample', 'Größe', 'Typ / Rezept', 'Angelegt', 'Dauer', 'Aktion'].map(function (c, i) { return h('th', { scope: 'col', cls: i === 3 || i === 6 ? 'num' : '', text: c }); }))),
            h('tbody', null, jobs.map(jobRow))))
        : ui.empty('Keine Aufträge', filter === 'all' ? 'Mit „Neuer Auftrag“ legen Sie die erste Analyse an.' : 'Kein Auftrag passt zum Filter.', 'list'));
    }

    var off = store.on(function (kind) {
      if (kind === 'system') paintStatus();
      if (kind === 'jobs') { paintList(); paintCurrent(); }
    });
    paintStatus(); paintCurrent(); paintList();

    var importMsg = h('div', { role: 'status' });
    var importInput = h('input', { type: 'file', accept: '.zip,application/zip', cls: 'sr-only', tabindex: '-1', 'aria-label': 'Exportierte Analyse (ZIP) wählen' });
    var importBtn = h('button', { type: 'button', cls: 'btn', on: { click: function () { importInput.click(); } } }, icon('upload'), 'Analyse importieren');
    importInput.addEventListener('change', function () {
      var f = importInput.files[0];
      if (!f) return;
      var fd = new FormData();
      fd.append('bundle', f, f.name);
      importBtn.disabled = true;
      SW.dom.fill(importMsg, ui.loading('Paket wird geprüft (Prüfsummen, Audit-Kette, Bericht) …'));
      api.post('/imports', fd).then(function (r) {
        importBtn.disabled = false;
        importInput.value = '';
        store.refreshGlobal();
        SW.dom.fill(importMsg, h('div', { cls: 'notice tone-ok' }, icon('checkcircle'), h('p', null, (r.duplicate ? 'Bereits importiert: ' : 'Importiert und geprüft: '), h('a', { href: '#/job/' + encodeURIComponent(r.job_id) + '/report', text: r.job_id }))));
      }, function (err) {
        importBtn.disabled = false;
        importInput.value = '';
        SW.dom.fill(importMsg, ui.errorBox('Import abgelehnt: ' + err.message));
      });
    });
    var el = h('div', { cls: 'stack' },
      h('div', { cls: 'page-h' }, h('div', { cls: 'grow' }, h('h1', { text: 'Übersicht' }), h('p', { cls: 'page-sub', text: 'Systemzustand, laufende Analyse und alle Aufträge.' })),
        importBtn, importInput,
        h('a', { cls: 'btn', href: '#/examples' }, icon('list'), 'Beispiele'),
        h('a', { cls: 'btn primary', href: '#/new' }, icon('plus'), 'Neuer Auftrag')),
      importMsg,
      ui.section('Systemstatus', statusHost),
      ui.section('Aktueller Auftrag', currentHost),
      ui.section('Aufträge', listHost, ui.seg('Filter', [['all', 'Alle'], ['active', 'Aktiv'], ['done', 'Fertig'], ['bad', 'Fehler']], filter, function (v) { filter = v; paintList(); }))
    );
    return { el: el, title: 'Übersicht', dispose: off };
  };

  /* =================== Neuer Auftrag =================== */
  var MAX_SAMPLE = 64 * 1024 * 1024;

  SW.views.new = function () {
    var file = null;
    var qHost = h('div', { cls: 'qlist' });
    var qid = 0;
    var qs = [];
    var errBox = h('div', { role: 'alert' });
    var dropInfo = h('p', { cls: 'drop-info muted', text: 'Datei hierher ziehen oder auswählen. Maximal 64 MiB. Das Sample wird derzeit nicht ausgeführt: Die dynamische Ausführung ist deaktiviert, bis die Analyse-VM steht.' });
    var fileInput = h('input', { type: 'file', id: 'f-sample', cls: 'sr-only', tabindex: '-1' });
    var drop = h('div', { cls: 'drop', role: 'button', tabindex: '0', 'aria-describedby': 'drop-hint', 'aria-label': 'Sample auswählen oder ablegen' },
      icon('upload', { size: 26 }), h('div', { id: 'drop-hint' }, h('strong', { text: 'Sample ablegen' }), dropInfo), fileInput);
    var submit = h('button', { type: 'submit', cls: 'btn primary' }, icon('play'), 'Analyse starten');

    function setFile(f) {
      if (f && f.size > MAX_SAMPLE) {
        file = null;
        SW.dom.fill(dropInfo, 'Die Datei ist größer als 64 MiB und wird abgelehnt.');
        drop.classList.add('is-bad');
        return;
      }
      file = f || null;
      drop.classList.remove('is-bad');
      SW.dom.fill(dropInfo, file ? file.name + ' · ' + fmt.bytes(file.size) : 'Datei hierher ziehen oder auswählen. Maximal 64 MiB. Das Sample wird derzeit nicht ausgeführt: Die dynamische Ausführung ist deaktiviert, bis die Analyse-VM steht.');
      drop.classList.toggle('has-file', !!file);
    }
    drop.addEventListener('click', function () { fileInput.click(); });
    drop.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
    fileInput.addEventListener('change', function () { setFile(fileInput.files[0]); });
    ['dragenter', 'dragover'].forEach(function (t) { drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.add('is-over'); }); });
    ['dragleave', 'drop'].forEach(function (t) { drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.remove('is-over'); }); });
    drop.addEventListener('drop', function (e) { if (e.dataTransfer && e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]); });

    function addQuestion(text, expected) {
      qs.push({ key: ++qid, text: text || '', expected: expected || '' });
      paintQs(true);
    }
    function paintQs(focusLast) {
      SW.dom.fill(qHost, qs.map(function (q, i) {
        var t = h('input', { type: 'text', id: 'q-t-' + q.key, 'aria-label': 'Zielfrage ' + (i + 1), placeholder: 'z. B. Welche Persistenzmechanismen nutzt das Sample?', maxlength: '2000', value: q.text });
        t.value = q.text;
        t.addEventListener('input', function () { q.text = t.value; });
        var x = h('input', { type: 'text', id: 'q-x-' + q.key, 'aria-label': 'Erwartete Antwort zu Frage ' + (i + 1) + ' (optional)', placeholder: 'Erwartete Antwort (optional)', maxlength: '500' });
        x.value = q.expected;
        x.addEventListener('input', function () { q.expected = x.value; });
        return h('div', { cls: 'qrow' },
          h('span', { cls: 'qn mono', text: 'Q' + (i + 1) }),
          h('div', { cls: 'qf' }, t, x),
          h('button', { type: 'button', cls: 'btn sm ghost', 'aria-label': 'Frage ' + (i + 1) + ' entfernen', on: { click: function () { qs.splice(i, 1); paintQs(); } } }, icon('trash'))
        );
      }));
      if (focusLast && qs.length) document.getElementById('q-t-' + qs[qs.length - 1].key).focus();
    }

    function num(id, label, val, min, max, unit) {
      return h('div', { cls: 'field' }, h('label', { for: id, text: label }), h('input', { type: 'number', id: id, value: val, min: min, max: max, step: '1' }), h('span', { cls: 'hint', text: unit + ' (' + min + ' bis ' + max + ')' }));
    }
    var f = {
      title: h('input', { type: 'text', id: 'f-title', maxlength: '200', required: true, autocomplete: 'off' }),
      desc: h('textarea', { id: 'f-desc', maxlength: '8000', rows: '4' }),
      ctx: h('textarea', { id: 'f-ctx', maxlength: '8000', rows: '3' }),
      focus: h('input', { type: 'text', id: 'f-focus', maxlength: '2000', autocomplete: 'off' })
    };

    var form = h('form', { cls: 'stack newjob', novalidate: true },
      h('section', { cls: 'card' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Auftrag' })), h('div', { cls: 'card-b' },
        h('div', { cls: 'field' }, h('label', { for: 'f-title', text: 'Titel *' }), f.title),
        h('div', { cls: 'field' }, h('label', { for: 'f-desc', text: 'Beschreibung' }), f.desc, h('span', { cls: 'hint', text: 'Was ist das für ein Sample, woher stammt es, was ist der Anlass? Die Eingabe wird intern ins Englische übersetzt.' })),
        h('div', { cls: 'field' }, h('label', { for: 'f-ctx', text: 'Weitere Infos' }), f.ctx, h('span', { cls: 'hint', text: 'Kontext wie Fundort, Betriebssystem, bekannte Indikatoren oder Vorabanalysen.' })),
        h('div', { cls: 'field' }, h('label', { for: 'f-focus', text: 'Fokus' }), f.focus, h('span', { cls: 'hint', text: 'Worauf soll die Analyse besonders achten, z. B. Netzwerk, Persistenz, Verschleierung?' }))
      )),
      h('section', { cls: 'card' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Zielfragen' }),
        h('button', { type: 'button', cls: 'btn sm', on: { click: function () { addQuestion('', ''); } } }, icon('plus'), 'Frage hinzufügen')),
        h('div', { cls: 'card-b' }, h('p', { cls: 'hint', text: 'Jede Frage wird als eigene Aufgabe geplant und mit Belegen beantwortet. Eine erwartete Antwort (optional) wird nur zum Abgleich genutzt, nicht als Vorgabe.' }), qHost)),
      h('section', { cls: 'card' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Sample' })), h('div', { cls: 'card-b' }, drop)),
      h('section', { cls: 'card' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Budget' })), h('div', { cls: 'card-b budget' },
        num('f-bt', 'Aufgaben', 60, 5, 300, 'maximale Anzahl'), num('f-bs', 'Schritte', 600, 20, 5000, 'maximale Anzahl'), num('f-bm', 'Laufzeit', 120, 1, 1440, 'Minuten'))),
      errBox,
      h('div', { cls: 'row' }, submit, h('a', { cls: 'btn', href: '#/', text: 'Abbrechen' }))
    );

    function readInt(id, min, max, def) {
      var v = parseInt(document.getElementById(id).value, 10);
      if (isNaN(v)) return def;
      return Math.max(min, Math.min(max, v));
    }

    var busy = false;
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (busy) return;
      var problems = [];
      if (!f.title.value.trim()) problems.push('Bitte einen Titel angeben.');
      if (!file) problems.push('Bitte ein Sample auswählen (maximal 64 MiB).');
      if (problems.length) {
        SW.dom.fill(errBox, h('div', { cls: 'notice tone-err' }, icon('alertcircle'), h('div', null, problems.map(function (p) { return h('p', { text: p }); }))));
        return;
      }
      var spec = {
        title: f.title.value.trim(), description: f.desc.value, context_info: f.ctx.value, focus: f.focus.value,
        target_questions: qs.filter(function (q) { return q.text.trim(); }).map(function (q) {
          var o = { text: q.text.trim() };
          if (q.expected.trim()) o.expected = q.expected.trim();
          return o;
        }),
        emulation_opt_in: false,
        budget_max_tasks: readInt('f-bt', 5, 300, 60), budget_max_steps: readInt('f-bs', 20, 5000, 600), budget_max_minutes: readInt('f-bm', 1, 1440, 120)
      };
      var fd = new FormData();
      fd.append('spec', JSON.stringify(spec));
      fd.append('sample', file, file.name);
      busy = true;
      submit.disabled = true;
      SW.dom.fill(errBox, ui.loading('Auftrag wird angelegt und das Sample übertragen …'));
      api.post('/jobs', fd).then(function (s) {
        busy = false;
        store.refreshGlobal();
        window.location.hash = '#/job/' + encodeURIComponent(s.id) + '/activity';
      }, function (err) {
        busy = false;
        submit.disabled = false;
        SW.dom.fill(errBox, ui.errorBox('Der Auftrag wurde nicht angelegt: ' + err.message));
      });
    });

    qs.push({ key: ++qid, text: '', expected: '' });
    paintQs(false);
    var el = h('div', { cls: 'stack' },
      h('div', { cls: 'page-h' }, h('div', { cls: 'grow' }, h('h1', { text: 'Neuer Auftrag' }), h('p', { cls: 'page-sub', text: 'Beschreiben Sie die Aufgabe, formulieren Sie Zielfragen und laden Sie das Sample hoch.' }))),
      form
    );
    return { el: el, title: 'Neuer Auftrag' };
  };
})();
