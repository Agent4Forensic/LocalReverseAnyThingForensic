/* Ansichten: Übersicht und Prompts. Der Dialog "Neuer Auftrag" liegt in view_new.js. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var api = SW.api;
  var store = SW.store;
  var ui = SW.ui;

  /* =================== Übersicht =================== */
  function jobHref(id) { return '/job/' + encodeURIComponent(id) + '/activity'; }

  function stat(label, value, sub) {
    return h('div', { cls: 'stat' },
      h('div', { cls: 'stat-v', text: String(value) }),
      h('div', { cls: 'stat-l', text: label }),
      sub ? h('div', { cls: 'stat-s', text: sub }) : null);
  }

  /* Eine Zelle je Aufgabe, nach Zustand gefärbt: der Auftrag auf einen Blick. */
  function strip(p) {
    var cells = [];
    function add(n, cls) { for (var i = 0; i < n; i++) cells.push(h('span', { cls: 'cell ' + cls })); }
    var skipped = Math.max(0, p.tasks_total - p.done - p.failed - p.blocked - p.running - p.pending);
    add(p.done, 'is-done'); add(skipped, 'is-skipped'); add(p.failed, 'is-failed'); add(p.blocked, 'is-blocked');
    add(p.running, 'is-running'); add(p.pending, 'is-pending');
    return h('div', { cls: 'strip', role: 'img', 'aria-label': p.done + ' von ' + p.tasks_total + ' Aufgaben erledigt' }, cells);
  }

  function heroJob(job, d, act, findings, answers) {
    var running = job.status === 'running';
    var p = d && d.progress;
    var t = d && d.totals;
    var asked = answers ? answers.length : 0;
    var solved = answers ? answers.filter(function (a) { return a.status === 'answered'; }).length : 0;
    var confirmed = findings ? findings.filter(function (f) { return f.status === 'confirmed'; }).length : 0;
    var ms = running && job.started_at ? Math.max(0, Date.now() - Date.parse(job.started_at)) : 0;
    return h('section', { cls: ['hero', running ? 'is-live' : ''], 'aria-labelledby': 'hero-t' },
      h('div', { cls: 'hero-h' },
        h('div', { cls: 'grow' },
          h('p', { cls: 'hero-k', text: running ? 'Läuft gerade' : 'Wartet auf den Start' }),
          h('h2', { cls: 'hero-t', id: 'hero-t' }, h('a', { href: jobHref(job.id), text: job.title }))),
        h('a', { cls: 'btn primary', href: jobHref(job.id) }, icon('pulse'), 'Live ansehen')),
      h('p', { cls: 'hero-meta muted' },
        h('span', null, 'Datei ', h('span', { cls: 'mono', text: job.sample_name || '–' })),
        job.detected_type || job.recipe ? h('span', { text: [job.detected_type, job.recipe].filter(Boolean).join(' / ') }) : null,
        running && job.started_at ? h('span', { text: 'gestartet um ' + fmt.time(job.started_at) }) : null),
      p && p.tasks_total ? h('div', { cls: 'hero-p' }, strip(p),
        h('p', { cls: 'small muted', text: p.done + ' von ' + p.tasks_total + ' Aufgaben erledigt, ' + fmt.percent(p.percent) })) : null,
      act && act.task ? h('p', { cls: 'hero-now' }, icon('chevronright', { size: 14 }), ' ', h('strong', { text: act.task.title }),
        act.step && act.step.what ? h('span', { cls: 'muted', text: ' – ' + act.step.what }) : null) : null,
      h('div', { cls: 'stats' },
        stat('Laufzeit', running ? fmt.duration(ms) : '–'),
        stat('Aufgaben', p ? p.done + ' / ' + p.tasks_total : '–'),
        stat('Schritte', t ? t.steps : '–'),
        stat('Werkzeugaufrufe', t ? t.tool_calls : '–'),
        stat('Modellaufrufe', t ? t.llm_calls : '–'),
        stat('Befunde', findings ? findings.length : '–', findings ? confirmed + ' bestätigt' : ''),
        stat('Zielfragen', asked ? solved + ' / ' + asked : '–', asked ? 'beantwortet' : 'keine gestellt')));
  }

  function heroEmpty(jobs, examples) {
    var last = jobs.filter(function (j) { return j.status !== 'queued' && j.status !== 'running'; })[0];
    return h('section', { cls: 'hero is-idle', 'aria-labelledby': 'hero-t' },
      h('h2', { cls: 'hero-t', id: 'hero-t', text: 'Kein Auftrag in Bearbeitung' }),
      h('p', { cls: 'muted', text: 'Legen Sie einen Auftrag an. Die Analyse startet danach von selbst und läuft, bis die Zielfragen beantwortet sind.' }),
      h('div', { cls: 'row' }, h('a', { cls: 'btn primary', href: '/new' }, icon('plus'), 'Auftrag anlegen')),
      examples && examples.length ? h('div', { cls: 'hero-ex' },
        h('p', { cls: 'small muted', text: 'Oder mit einem Beispiel beginnen:' }),
        h('div', { cls: 'chips' }, examples.map(function (e) { return h('a', { cls: 'chip', href: '/new?example=' + encodeURIComponent(e.id), text: e.title }); }))) : null,
      last ? h('p', { cls: 'small muted' }, 'Zuletzt: ', h('a', { href: jobHref(last.id), text: last.title }), ' ', fmt.badge(last.status)) : null);
  }

  function jobRow(j) {
    return h('tr', null,
      h('td', null, h('a', { href: jobHref(j.id), text: j.title }), h('div', { cls: 'mono small muted', text: j.id })),
      h('td', null, fmt.badge(j.status)),
      h('td', null, h('span', { text: j.sample_name || '–' }), h('div', { cls: 'mono small muted', text: fmt.shortHash(j.sample_sha256, 16) })),
      h('td', { text: [j.detected_type, j.recipe].filter(Boolean).join(' / ') || '–' }),
      h('td', { cls: 'nowrap', text: fmt.dateTime(j.created_at) }),
      h('td', { cls: 'num nowrap', text: j.finished_at || j.started_at ? fmt.duration(j.duration_ms) : '–' })
    );
  }

  SW.views.overview = function () {
    var filter = 'all';
    var currentHost = h('div');
    var listHost = h('div');
    var cur = { id: null, detail: null, act: null, findings: null, answers: null };
    var examples = null;

    function currentJob() {
      var jobs = store.state.jobs;
      return jobs.filter(function (j) { return j.status === 'running'; })[0] || jobs.filter(function (j) { return j.status === 'queued'; }).pop() || null;
    }

    function paintCurrent() {
      var job = currentJob();
      if (!job) {
        cur = { id: null, detail: null, act: null, findings: null, answers: null };
        if (!store.state.jobsLoaded) { SW.dom.fill(currentHost, ui.loading()); return; }
        SW.dom.fill(currentHost, heroEmpty(store.state.jobs, examples));
        return;
      }
      if (cur.id !== job.id) cur = { id: job.id, detail: null, act: null, findings: null, answers: null };
      function draw() { SW.dom.fill(currentHost, heroJob(job, cur.detail, cur.act, cur.findings, cur.answers)); }
      draw();
      function keep(field, fn) { return function (r) { if (cur.id === job.id) { cur[field] = fn(r); draw(); } }; }
      api.get('/jobs/' + job.id).then(keep('detail', function (d) { return d; }), function () {});
      ui.softGet('/jobs/' + job.id + '/findings').then(keep('findings', function (r) { return r.ok ? r.data : null; }));
      ui.softGet('/jobs/' + job.id + '/answers').then(keep('answers', function (r) { return r.ok ? r.data : null; }));
      if (job.status === 'running') ui.softGet('/jobs/' + job.id + '/activity').then(keep('act', function (r) { return r.ok ? r.data : null; }));
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
            h('thead', null, h('tr', null, ['Auftrag', 'Status', 'Datei', 'Typ / Rezept', 'Angelegt', 'Dauer'].map(function (c, i) { return h('th', { scope: 'col', cls: i === 5 ? 'num' : '', text: c }); }))),
            h('tbody', null, jobs.map(jobRow))))
        : ui.empty('Keine Aufträge', filter === 'all' ? 'Mit „Neuer Auftrag“ legen Sie die erste Analyse an.' : 'Kein Auftrag passt zum Filter.', 'list'));
    }

    var off = store.on(function (kind) {
      if (kind === 'jobs') { paintList(); paintCurrent(); }
    });
    paintCurrent(); paintList();
    ui.softGet('/examples').then(function (r) { examples = r.ok ? r.data : []; if (!currentJob()) paintCurrent(); });

    var el = h('div', { cls: 'stack' },
      h('div', { cls: 'page-h' }, h('div', { cls: 'grow' }, h('h1', { text: 'Übersicht' }), h('p', { cls: 'page-sub', text: 'Der aktuelle Auftrag mit Zahlen, darunter alle Aufträge. Den Systemzustand zeigt die linke Leiste.' })),
        h('a', { cls: 'btn primary', href: '/new' }, icon('plus'), 'Neuer Auftrag')),
      currentHost,
      ui.section('Aufträge', listHost, ui.seg('Filter', [['all', 'Alle'], ['active', 'Aktiv'], ['done', 'Fertig'], ['bad', 'Fehler']], filter, function (v) { filter = v; paintList(); }))
    );
    return { el: el, title: 'Übersicht', dispose: off };
  };

  /* =================== Prompts =================== */
  SW.views.prompts = function () {
    var listHost = h('div', { cls: 'plist' });
    var detailHost = h('div', { cls: 'pdetail' }, ui.empty('Prompt auswählen', 'Wählen Sie links einen Prompt, um Version, Hash und Text zu sehen.', 'book'));
    var selected = null;

    function select(id) {
      selected = id;
      paint(store.state.prompts || []);
      SW.dom.fill(detailHost, ui.loading());
      api.get('/prompts/' + id).then(function (p) {
        if (selected !== id) return;
        SW.dom.fill(detailHost,
          h('div', { cls: 'row' }, h('h2', { cls: 'grow mono', text: p.id }), h('span', { cls: 'tag mono', text: 'v' + p.version })),
          h('p', { text: p.purpose }),
          h('dl', { cls: 'kv' }, h('dt', { text: 'SHA-256' }), h('dd', { cls: 'mono small', text: p.sha256 })),
          h('h3', { cls: 'step-title', text: 'Text (wird unverändert an das Modell gesendet)' }),
          h('pre', { cls: 'prompt-text', tabindex: '0', text: p.text })
        );
      }, function (err) { SW.dom.fill(detailHost, ui.errorBox(err.message)); });
    }
    function paint(list) {
      SW.dom.fill(listHost, list.map(function (p) {
        return h('button', { type: 'button', cls: 'plist-i', 'aria-pressed': selected === p.id ? 'true' : 'false', on: { click: function () { select(p.id); } } },
          h('span', { cls: 'mono plist-id', text: p.id }), h('span', { cls: 'tag mono', text: 'v' + p.version }), h('span', { cls: 'plist-p muted small', text: p.purpose }));
      }));
    }
    SW.dom.fill(listHost, ui.loading());
    store.loadPrompts().then(function (l) {
      if (!l.length) SW.dom.fill(listHost, ui.noData('Der Server liefert noch keine Prompts.'));
      else paint(l);
    }, function (err) { SW.dom.fill(listHost, ui.errorBox(err.message)); });

    return {
      title: 'Prompts',
      el: h('div', { cls: 'stack' },
        h('div', { cls: 'page-h' }, h('div', { cls: 'grow' }, h('h1', { text: 'Prompts' }), h('p', { cls: 'page-sub', text: 'Versionierte Prompts der Analysekette. Jeder Lauf protokolliert ID, Version und Hash des verwendeten Prompts.' }))),
        h('div', { cls: 'split' }, h('section', { cls: 'card', 'aria-label': 'Promptliste' }, listHost), h('section', { cls: 'card card-b', 'aria-label': 'Promptdetail' }, detailHost)))
    };
  };
})();
