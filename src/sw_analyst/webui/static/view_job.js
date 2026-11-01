/* Auftragsansicht: Kopf, dauerhaft sichtbare Aktivitaetsanzeige, Tab-Leiste sowie die Tabs
   Aktivitaet, Aufgabenbaum und Queue. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var api = SW.api;
  var store = SW.store;
  var ui = SW.ui;

  var TAB_ORDER = ['activity', 'data', 'tree', 'queue', 'live', 'code', 'file', 'log', 'guard', 'report'];
  var PHASES = [
    ['triage', 'Triage'], ['planning', 'Planung'], ['analysis', 'Analyse'], ['evaluation', 'Bewertung'],
    ['prioritization', 'Priorisierung'], ['translation', 'Übersetzung'], ['finalizing', 'Abschluss']
  ];
  var STATE_LABEL = { idle: 'Leerlauf', working: 'Arbeitet', finished: 'Abgeschlossen' };

  /* =================== Aktivitaetsanzeige =================== */
  function activityPanel(st) {
    var data = null;
    var status = 'loading';
    var collapsed = false;
    try { collapsed = window.localStorage.getItem('sw.act.collapsed') === '1'; } catch (e) { collapsed = false; }
    var finOpen = false;
    try { finOpen = window.localStorage.getItem('sw.act.done.open') === '1'; } catch (e) { finOpen = false; }
    var body = h('div', { cls: 'act-body' });
    var toggle = h('button', { type: 'button', cls: 'btn sm ghost', 'aria-expanded': 'true', on: { click: function () {
      collapsed = !collapsed;
      try { window.localStorage.setItem('sw.act.collapsed', collapsed ? '1' : '0'); } catch (e) { /* ignorieren */ }
      paint();
    } } });
    var el = h('section', { cls: 'card act', 'aria-labelledby': 'act-h' },
      h('div', { cls: 'card-h' }, icon('pulse'), h('h2', { id: 'act-h', text: 'Live-Aktivität' }), toggle), body);
    var dead = false;
    var inflight = false;
    var again = false;

    function load() {
      /* Ereignisse waehrend einer laufenden Abfrage nicht verwerfen: danach genau einmal neu laden. */
      if (inflight) { again = true; return; }
      inflight = true;
      ui.softGet('/jobs/' + st.id + '/activity').then(function (r) {
        inflight = false;
        if (dead) return;
        if (r.ok) { data = r.data; status = 'ok'; } else { status = r.missing ? 'missing' : 'error'; }
        paint();
        if (again) { again = false; load(); }
      });
    }

    function elapsedNode(startIso, ms, running) {
      if (running && startIso) return SW.elapsed(startIso);
      return h('span', { text: fmt.duration(ms) });
    }

    function paint() {
      toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      SW.dom.fill(toggle, icon(collapsed ? 'chevronright' : 'chevrondown'), collapsed ? ' Ausklappen' : ' Einklappen');
      if (status === 'loading') { SW.dom.fill(body, ui.loading('Aktivität wird geladen …')); return; }
      if (status === 'missing') { SW.dom.fill(body, ui.noData('Der Server liefert für diesen Auftrag noch keine Aktivitätsdaten.')); return; }
      if (status === 'error' || !data) { SW.dom.fill(body, ui.errorBox('Aktivität konnte nicht geladen werden.')); return; }
      var a = data;
      toggle.hidden = a.state === 'finished'; /* danach steuert das <details> darin das Einklappen */
      var working = a.state === 'working';
      var phase = PHASES.filter(function (p) { return p[0] === a.phase; })[0];
      var pstate = {};
      (a.phases || []).forEach(function (p) { pstate[p.id] = p; });
      var stepper = h('ol', { cls: 'phases', 'aria-label': 'Phasen der Analyse' }, PHASES.map(function (p) {
        var ps = pstate[p[0]] || { state: working && p[0] === a.phase ? 'cur' : 'open', count: 0 };
        var cur = ps.state === 'cur';
        var n = ps.total ? ps.count + '/' + ps.total : (ps.count ? String(ps.count) : '');
        var word = { cur: 'läuft gerade', done: 'erledigt', open: a.state === 'finished' ? 'nicht erreicht' : 'noch offen' }[ps.state];
        return h('li', { cls: ['phase', 'is-' + ps.state], 'aria-current': cur ? 'step' : null, title: p[1] + ': ' + word + (n ? ' (' + n + ')' : '') },
          ps.state === 'done' ? icon('check', { size: 12 }) : cur ? icon('spinner', { size: 12, cls: 'is-spin' }) : null,
          h('span', { text: p[1] }), n ? h('span', { cls: 'phase-n', text: n }) : null,
          h('span', { cls: 'sr-only', text: ' – ' + word }));
      }));
      var end = a.end ? endBox(a.end) : null;
      var head = h('div', { cls: 'act-head' },
        h('span', { cls: 'badge tone-' + (working ? 'info' : a.state === 'finished' ? 'ok' : 'neutral') }, icon(working ? 'spinner' : a.state === 'finished' ? 'checkcircle' : 'clock', { size: 13, cls: working ? 'is-spin' : '' }), h('span', { text: STATE_LABEL[a.state] || a.state })),
        working && phase ? h('span', { cls: 'act-phase', text: 'Phase: ' + phase[1] }) : null,
        a.model ? h('span', { cls: 'muted small mono act-model', text: (a.model.name || '') + ' · ' + (a.model.tokens_in || 0) + ' Token ein / ' + (a.model.tokens_out || 0) + ' aus' }) : null
      );
      if (collapsed && a.state !== 'finished') {
        SW.dom.fill(body, head, stepper, a.step ? h('p', { cls: 'act-one' }, h('strong', { text: 'Schritt: ' }), a.step.what || '–') : null);
        return;
      }
      var t = a.task;
      var s = a.step;
      var next = (a.next || []).slice(0, 3);
      var recent = (a.recent || []).slice(0, 10);
      if (a.state === 'finished') {
        /* Nach Jobende nur Kopf und Ergebnis; Phasen und letzte Schritte stehen standardmaessig eingeklappt in <details>. */
        var recentDone = (a.recent || []).slice(0, 10);
        var det = h('details', { cls: 'act-fin' }, h('summary', { text: 'Phasen und letzte Schritte' }), stepper,
          recentDone.length ? h('ul', { cls: 'recent' }, recentDone.map(function (r) {
            return h('li', null, fmt.statusIcon(r.status, 14), h('span', { cls: 'mono small muted', text: fmt.time(r.ts) }),
              h('span', { cls: 'tag', text: fmt.STEP_KIND[r.kind] || r.kind }), h('span', { cls: 'grow trunc', title: r.what, text: r.what }),
              h('span', { cls: 'small muted nowrap', text: fmt.duration(r.duration_ms) }));
          })) : null);
        det.open = finOpen;
        det.addEventListener('toggle', function () {
          finOpen = det.open;
          try { window.localStorage.setItem('sw.act.done.open', finOpen ? '1' : '0'); } catch (e) { /* ignorieren */ }
        });
        SW.dom.fill(body, head, end, det);
        return;
      }
      SW.dom.fill(body,
        head, stepper, end,
        h('div', { cls: 'act-grid' },
          h('div', { cls: 'act-col' }, h('h3', { text: 'Aktuelle Aufgabe' }),
            t ? [
              h('p', { cls: 'act-title' }, t.title, ' ', h('span', { cls: 'mono muted small', text: t.id })),
              h('dl', { cls: 'kv' },
                h('dt', { text: 'Ziel' }), h('dd', { text: t.goal || '–' }),
                h('dt', { text: 'Herkunft' }), h('dd', { text: fmt.ORIGIN[t.origin] || t.origin || '–' }),
                h('dt', { text: 'Laufzeit' }), h('dd', null, elapsedNode(t.started_at, t.elapsed_ms, working)))
            ] : h('p', { cls: 'muted', text: a.state === 'finished' ? 'Keine Aufgabe offen.' : 'Derzeit wird keine Aufgabe bearbeitet.' })),
          h('div', { cls: 'act-col' }, h('h3', { text: 'Aktueller Schritt' }),
            s ? [
              h('p', { cls: 'row act-tags' }, h('span', { cls: 'tag', text: fmt.STEP_KIND[s.kind] || s.kind }), s.tool ? h('span', { cls: 'tag mono', text: s.tool }) : null,
                h('span', { cls: 'muted small', text: 'läuft seit ' }), h('span', { cls: 'small' }, elapsedNode(s.started_at, s.elapsed_ms, working))),
              h('dl', { cls: 'kv' },
                h('dt', { text: 'Was' }), h('dd', { text: s.what || '–' }),
                h('dt', { text: 'Wie' }), h('dd', { text: s.how || '–' }),
                h('dt', { text: 'Warum' }), h('dd', { text: s.why || '–' })),
              s.input_preview ? h('details', { cls: 'step-prev' }, h('summary', { text: 'Eingabe-Vorschau' }), h('pre', { text: s.input_preview })) : null
            ] : h('p', { cls: 'muted', text: 'Kein Schritt aktiv.' })),
          h('div', { cls: 'act-col' }, h('h3', { text: 'Nächste Aufgaben' }),
            next.length ? h('ol', { cls: 'act-next' }, next.map(function (n) {
              return h('li', null, h('span', { cls: 'mono muted small', text: n.task_id }), ' ', n.title);
            })) : h('p', { cls: 'muted', text: 'Keine weiteren Aufgaben in der Warteschlange.' }),
            a.queue_length > next.length ? h('p', { cls: 'muted small', text: '+ ' + (a.queue_length - next.length) + ' weitere in der Queue' }) : null)
        ),
        h('details', { cls: 'act-recent', open: true }, h('summary', { text: 'Letzte ' + recent.length + ' Schritte' }),
          recent.length ? h('ul', { cls: 'recent' }, recent.map(function (r) {
            return h('li', null, fmt.statusIcon(r.status, 14), h('span', { cls: 'mono small muted', text: fmt.time(r.ts) }),
              h('span', { cls: 'tag', text: fmt.STEP_KIND[r.kind] || r.kind }), h('span', { cls: 'grow trunc', title: r.what, text: r.what }),
              h('span', { cls: 'small muted nowrap', text: fmt.duration(r.duration_ms) }));
          })) : h('p', { cls: 'muted', text: 'Noch keine Schritte.' }))
      );
    }

    paint();
    load();
    var off = ui.live(['step', 'tasks', 'summary', 'queue'], load, 350);
    var poll = window.setInterval(function () { if (!document.hidden && st.summary && st.summary.status === 'running') load(); }, 5000);
    return { el: el, dispose: function () { dead = true; off(); window.clearInterval(poll); } };
  }

  /* Warum ein Lauf endete: Gruende aus orchestrator/engine.py und worker.py, auf Deutsch. */
  var END_REASON = [
    [/^stopping: time budget exhausted/, 'Zeitbudget aufgebraucht'],
    [/^stopping: step budget exhausted/, 'Schrittbudget aufgebraucht'],
    [/^stopping: task budget exhausted/, 'Aufgabenbudget aufgebraucht'],
    [/^stopping: model not reachable/, 'Sprachmodell nicht erreichbar'],
    [/^stopping: host protection: /, 'Host-Schutz hat gestoppt: '],
    [/^job crashed: /, 'Interner Fehler: '],
    [/^job interrupted by restart/, 'Durch Neustart des Servers unterbrochen'],
    [/^upload interrupted by restart/, 'Upload durch Neustart unterbrochen'],
    [/^worker caught an error: /, 'Fehler im Worker: ']
  ];
  function reasonDe(r) {
    for (var i = 0; i < END_REASON.length; i++) {
      var m = r.match(END_REASON[i][0]);
      if (m) return END_REASON[i][1] + r.slice(m[0].length);
    }
    return r;
  }
  function endBox(e) {
    var tone = { done: 'ok', partial: 'warn', failed: 'err', cancelled: 'neutral' }[e.status] || 'neutral';
    var why = e.reason ? reasonDe(e.reason)
      : e.status === 'done' && /follow-up/.test(e.summary_en || '') ? 'Alle Zielfragen beantwortet, Stand nach einem Nachlauf ohne Modell. Übersprungene Aufgaben nennt die Bilanz.'
      : e.status === 'done' ? 'Alle Aufgaben erledigt und alle Zielfragen beantwortet.'
      : e.status === 'partial' ? 'Nicht alle Aufgaben erledigt oder nicht alle Zielfragen beantwortet.'
      : e.status === 'cancelled' ? 'Vom Benutzer abgebrochen.'
      : e.status === 'failed' ? 'Keine Analyseaufgabe wurde erfolgreich abgeschlossen.' : '';
    var more = [why ? [h('span', { cls: 'muted', text: 'Grund: ' }), why] : null, e.summary_de || e.summary_en ? [h('span', { cls: 'muted', text: 'Bilanz: ' }), e.summary_de || e.summary_en] : null].filter(Boolean);
    return h('div', { cls: 'notice end-box tone-' + tone, role: 'status' }, fmt.statusIcon(e.status, 16), h('div', null,
      h('p', null, h('strong', { text: 'Ergebnis: ' + fmt.statusInfo(e.status).label }), e.finished_at ? h('span', { cls: 'muted small', text: ' · beendet ' + fmt.dateTime(e.finished_at) }) : null),
      more.length ? h('p', { cls: 'small' }, more.map(function (m, i) { return h('span', { cls: 'end-part' }, i ? ' · ' : null, m); })) : null));
  }

  /* =================== Kopf =================== */
  function jobHeader(st) {
    var host = h('div', { cls: 'jh' });
    var confirming = false;
    var cancelling = false;

    function paint() {
      var s = st.summary;
      if (!s) {
        SW.dom.fill(host, st.error ? ui.errorBox(st.error) : ui.loading('Auftrag wird geladen …'));
        return;
      }
      var p = st.progress;
      var active = s.status === 'running' || s.status === 'queued';
      var connLabel = { live: 'Live-Verbindung', polling: 'Abfrage alle 3 s', connecting: 'Verbinde …', offline: 'Getrennt' }[st.conn] || st.conn;
      var cancelCtl = !active ? null : confirming
        ? h('span', { cls: 'row' }, h('span', { cls: 'small', text: 'Auftrag wirklich abbrechen?' }),
            h('button', { type: 'button', cls: 'btn sm danger', disabled: cancelling, on: { click: doCancel } }, 'Ja, abbrechen'),
            h('button', { type: 'button', cls: 'btn sm', on: { click: function () { confirming = false; paint(); } } }, 'Nein'))
        : h('button', { type: 'button', cls: 'btn sm danger', on: { click: function () { confirming = true; paint(); } } }, icon('stop'), 'Abbrechen');
      var imp = st.importInfo;
      SW.dom.fill(host,
        h('p', { cls: 'crumb' }, h('a', { href: '#/', text: '← Übersicht' })),
        h('div', { cls: 'page-h jh-top' },
          h('div', { cls: 'grow' }, h('h1', { id: 'job-h', tabindex: '-1', text: s.title }),
            h('p', { cls: 'page-sub' }, h('span', { cls: 'mono', text: s.id }), ' · ', s.sample_name || '–',
              ' · ', h('span', { title: 'Größe des Samples', text: s.sample_size === null || s.sample_size === undefined ? 'Größe unbekannt' : fmt.bytes(s.sample_size) }),
              ' · ', h('span', { cls: 'mono', title: s.sample_sha256, text: fmt.shortHash(s.sample_sha256, 16) }))),
          h('div', { cls: 'row' }, s.imported ? h('span', { cls: 'badge tone-info', text: 'Importiert' }) : null,
            st.example ? h('a', { cls: 'badge ' + (st.example.flag_found === true ? 'tone-ok' : st.example.flag_found === false ? 'tone-err' : 'tone-neutral'),
              href: '#/examples?id=' + encodeURIComponent(st.example.id),
              title: 'Die erwartete Flagge wurde nicht an die KI gegeben; der Abgleich erfolgt nach dem Lauf.',
              text: 'Beispiel ' + st.example.id.slice(0, 2) + ': ' + (st.example.flag_found === true ? 'bestanden' : st.example.flag_found === false ? 'nicht bestanden' : 'Prüfung nach dem Lauf') }) : null, fmt.badge(s.status), cancelCtl, s.imported ? null : exportCtl(s))),
        s.imported ? h('div', { cls: 'notice tone-info', role: 'note' }, icon('info'), h('div', null,
          h('p', { text: 'Importierte Analyse, schreibgeschützt. Original-ID ' + (s.original_id || '–') + (imp && imp.imported_at ? ' · importiert ' + fmt.dateTime(imp.imported_at) : '') + '.' }),
          imp ? h('p', { cls: 'small', text: importChecks(imp) }) : null)) : null,
        h('div', { cls: 'jh-meta' },
          p ? h('div', { cls: 'jh-prog' }, ui.bar(p.percent, s.status === 'done' ? 'ok' : ''), h('span', { cls: 'small muted nowrap', text: p.done + '/' + p.tasks_total + ' Aufgaben · ' + (p.running ? p.running + ' läuft · ' : '') + (p.pending || 0) + ' offen' + (p.failed ? ' · ' + p.failed + ' fehlgeschlagen' : '') })) : null,
          h('span', { cls: 'small muted', text: 'Typ ' + (s.detected_type || '–') + ' / Rezept ' + (s.recipe || '–') }),
          h('span', { cls: 'small muted' }, 'Dauer ', s.status === 'running' && s.started_at ? SW.elapsed(s.started_at) : (s.started_at ? fmt.duration(s.duration_ms) : '–')),
          st.totals ? h('span', { cls: 'small muted', text: st.totals.steps + ' Schritte · ' + st.totals.tool_calls + ' Werkzeug- · ' + st.totals.llm_calls + ' Modellaufrufe' }) : null,
          h('span', { cls: 'small conn-pill tone-' + (st.conn === 'live' ? 'ok' : st.conn === 'offline' ? 'err' : 'warn') }, h('span', { cls: 'dot', 'aria-hidden': 'true' }), connLabel))
      );
    }
    function exportCtl(s) {
      if (s.status === 'running' || s.status === 'queued') return null;
      var withFiles = h('input', { type: 'checkbox', 'aria-label': 'Sample und abgeleitete Dateien einschließen' });
      var link = h('a', { cls: 'btn sm', href: api.href('/jobs/' + encodeURIComponent(s.id) + '/export', { include_files: 0 }), download: '' }, icon('arrowdown'), 'Exportieren');
      withFiles.addEventListener('change', function () {
        link.setAttribute('href', api.href('/jobs/' + encodeURIComponent(s.id) + '/export', { include_files: withFiles.checked ? 1 : 0 }));
      });
      return h('span', { cls: 'row', title: 'ZIP mit Daten, Audit-Kette, Bericht und Prüfsummen. Eine Kopie bleibt im Projektordner unter data/exports/. Mit Sample nur für harmlose Proben oder geschützte Ablage.' },
        link, h('label', { cls: 'chk small' }, withFiles, ' mit Sample'));
    }
    function importChecks(imp) {
      var c = imp.checks || {};
      var parts = [];
      parts.push('Prüfsummen aller ' + (c.entries_verified || 0) + ' Einträge ok');
      parts.push('Audit-Kette ' + (c.audit_valid === false ? 'gebrochen' : 'gültig') + (c.audit_entries ? ' (' + c.audit_entries + ' Einträge)' : ''));
      if (c.report_reproducible !== undefined) parts.push('Bericht ' + (c.report_reproducible ? 'bytegleich reproduziert' : 'weicht vom exportierten Bericht ab'));
      if (imp.bundle_sha256) parts.push('Paket-SHA-256 ' + imp.bundle_sha256);
      return parts.join(' · ');
    }
    function doCancel() {
      cancelling = true;
      paint();
      api.post('/jobs/' + st.id + '/cancel').then(function (s) {
        cancelling = false; confirming = false;
        st.summary = Object.assign({}, st.summary, s);
        store.refreshGlobal();
        paint();
      }, function (err) {
        cancelling = false; confirming = false;
        paint();
        host.appendChild(ui.errorBox('Abbruch fehlgeschlagen: ' + err.message));
      });
    }
    paint();
    return { el: host, repaint: paint };
  }

  /* =================== Job-Ansicht =================== */
  SW.views.job = function (route) {
    var st = store.openJob(route.jobId);
    var header = jobHeader(st);
    var activity = activityPanel(st);
    var tabsNav = h('nav', { cls: 'tabs', 'aria-label': 'Ansichten des Auftrags' });
    var tabHost = h('div', { cls: 'tab-host', id: 'tab-host' });
    var curTab = null; /* { id, inst } */
    var lastRoute = route;

    function paintTabs(activeId) {
      var defs = TAB_ORDER.map(function (id) { return SW.tabs.filter(function (t) { return t.id === id; })[0]; }).filter(Boolean);
      SW.dom.fill(tabsNav, defs.map(function (t) {
        return h('a', { cls: 'tab', href: ui.tabHref(route.jobId, t.id), 'aria-current': t.id === activeId ? 'page' : null }, icon(t.icon, { size: 15 }), h('span', { text: t.label }));
      }));
    }

    function showTab(r) {
      lastRoute = r;
      var def = SW.tabs.filter(function (t) { return t.id === r.tab; })[0] || SW.tabs.filter(function (t) { return t.id === 'activity'; })[0];
      paintTabs(def.id);
      if (curTab && curTab.id === def.id && curTab.inst.update) {
        curTab.inst.update(r);
        return;
      }
      if (curTab && curTab.inst.dispose) curTab.inst.dispose();
      SW.dom.clear(tabHost);
      var inst = def.mount(tabHost, { st: st, jobId: route.jobId, route: r }) || {};
      curTab = { id: def.id, inst: inst };
      document.title = def.label + ' · ' + ((st.summary && st.summary.title) || route.jobId) + ' – sw-analyst';
    }

    var off = store.on(function (kind) {
      if (kind === 'summary' || kind === 'loaded' || kind === 'conn') header.repaint();
    });
    showTab(route);

    var el = h('div', { cls: 'stack job' }, header.el, activity.el, tabsNav, tabHost);
    return {
      el: el,
      title: 'Auftrag',
      update: function (r) { showTab(r); },
      dispose: function () {
        off();
        activity.dispose();
        if (curTab && curTab.inst.dispose) curTab.inst.dispose();
        store.closeJob();
      }
    };
  };

  /* =================== Tab: Aktivitaet =================== */
  SW.registerTab({
    id: 'activity', label: 'Aktivität', icon: 'pulse',
    mount: function (host, ctx) {
      var st = ctx.st;
      var follow = true;
      var chosen = '';
      var detail = null;
      var detailHost = h('div');
      var sel = h('select', { id: 'act-sel', 'aria-label': 'Aufgabe wählen' });
      var followBox = h('input', { type: 'checkbox', id: 'act-follow', checked: true });
      followBox.checked = true;

      function runningId() {
        var r = store.tasksSorted(st).filter(function (t) { return t.status === 'running'; })[0];
        return r ? r.id : null;
      }
      function lastActiveId() {
        var list = store.tasksSorted(st).filter(function (t) { return t.started_at; });
        return list.length ? list[list.length - 1].id : null;
      }
      function paintOptions() {
        var tasks = store.tasksSorted(st);
        var keep = chosen;
        SW.dom.fill(sel, tasks.map(function (t) {
          return h('option', { value: t.id, text: t.id + ' · ' + t.title + ' (' + fmt.statusInfo(t.status).label + ')' });
        }));
        if (keep) sel.value = keep;
      }
      function show(id) {
        if (id === chosen) return;
        chosen = id;
        if (detail) detail.dispose();
        detail = null;
        SW.dom.clear(detailHost);
        if (!id) { detailHost.appendChild(ui.noData('Es gibt noch keine Aufgaben. Der Plan entsteht nach der Triage.')); return; }
        detail = ui.taskDetail(st, id);
        detailHost.appendChild(detail.el);
        sel.value = id;
      }
      function refresh() {
        paintOptions();
        if (follow) show(runningId() || chosen || lastActiveId() || (store.tasksSorted(st)[0] || {}).id || null);
        else if (!chosen) show(lastActiveId());
      }
      sel.addEventListener('change', function () { follow = false; followBox.checked = false; show(sel.value); });
      followBox.addEventListener('change', function () { follow = followBox.checked; if (follow) refresh(); });

      host.appendChild(ui.section('Schrittprotokoll',
        h('div', { cls: 'stack' },
          h('div', { cls: 'row' }, h('label', { for: 'act-sel', text: 'Aufgabe' }), sel,
            h('label', { cls: 'chk' }, followBox, ' Laufende Aufgabe verfolgen')),
          detailHost),
        null));
      refresh();
      var off = ui.live(['tasks', 'loaded'], refresh, 150);
      return { dispose: function () { off(); if (detail) detail.dispose(); } };
    }
  });

  /* =================== Tab: Aufgabenbaum =================== */
  function buildChildren(tasks) {
    var map = {};
    tasks.forEach(function (t) {
      var k = t.parent_id || '';
      (map[k] = map[k] || []).push(t);
    });
    return map;
  }

  SW.registerTab({
    id: 'tree', label: 'Aufgabenbaum', icon: 'tree',
    mount: function (host, ctx) {
      var st = ctx.st;
      var selected = ctx.route.query.task || null;
      var detail = null;
      var treeHost = h('div', { cls: 'tree-host' });
      var detailHost = h('div', { cls: 'tree-detail' }, ui.empty('Aufgabe auswählen', 'Klicken Sie links auf eine Aufgabe, um Ziel, Prompt und alle Schritte zu sehen.', 'tree'));

      function select(id) {
        selected = id;
        if (detail) detail.dispose();
        detail = ui.taskDetail(st, id);
        SW.dom.fill(detailHost, detail.el);
        paintTree();
      }
      function node(t, kids, depth) {
        var children = kids[t.id] || [];
        var li = h('li', { cls: 'tn' },
          h('button', { type: 'button', cls: ['tn-b', selected === t.id ? 'is-sel' : ''], 'aria-pressed': selected === t.id ? 'true' : 'false', 'data-key': 'tn-' + t.id, on: { click: function () { select(t.id); } } },
            fmt.statusIcon(t.status, 15),
            h('span', { cls: 'tn-t grow', text: t.title }),
            h('span', { cls: 'tag', text: fmt.ORIGIN[t.origin] || t.origin || '' }),
            h('span', { cls: 'mono small muted nowrap', text: 'P' + t.priority }),
            h('span', { cls: 'small muted nowrap tn-d', text: t.status === 'running' ? 'läuft' : fmt.duration(t.duration_ms) })),
          children.length ? h('ul', { cls: 'tn-list' }, children.map(function (c) { return node(c, kids, depth + 1); })) : null);
        return li;
      }
      function paintTree() {
        SW.dom.keepFocus(treeHost, function () {
          var tasks = store.tasksSorted(st);
          if (!tasks.length) { SW.dom.fill(treeHost, st.loaded ? ui.noData('Der Aufgabenbaum entsteht nach der Triage.') : ui.loading()); return; }
          var kids = buildChildren(tasks);
          var ids = {};
          tasks.forEach(function (t) { ids[t.id] = true; });
          var roots = tasks.filter(function (t) { return !t.parent_id || !ids[t.parent_id]; });
          SW.dom.fill(treeHost, h('ul', { cls: 'tn-list tn-root' }, roots.map(function (t) { return node(t, kids, 0); })));
        });
      }
      host.appendChild(h('div', { cls: 'split split-tree' },
        h('section', { cls: 'card', 'aria-label': 'Aufgabenbaum' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Aufgaben' })), h('div', { cls: 'card-b' }, treeHost)),
        h('section', { cls: 'card card-b', 'aria-label': 'Aufgabendetail' }, detailHost)));
      paintTree();
      if (selected) select(selected);
      var off = ui.live(['tasks', 'loaded'], paintTree, 120);
      return { dispose: function () { off(); if (detail) detail.dispose(); } };
    }
  });

  /* =================== Tab: Queue =================== */
  SW.registerTab({
    id: 'queue', label: 'Queue', icon: 'queue',
    mount: function (host, ctx) {
      var st = ctx.st;
      var tableHost = h('div');
      var detail = null;
      var detailHost = h('div');
      var picked = null;

      function pick(id) {
        picked = id;
        if (detail) detail.dispose();
        detail = ui.taskDetail(st, id);
        SW.dom.fill(detailHost, ui.section('Aufgabe ' + id, detail.el));
      }
      function paint() {
        var q = st.queue || [];
        SW.dom.fill(tableHost, !q.length
          ? (st.loaded ? ui.empty('Die Queue ist leer', 'Alle Aufgaben sind abgearbeitet oder noch nicht geplant.', 'queue') : ui.loading())
          : h('div', { cls: 'tbl-wrap' }, h('table', { cls: 'tbl' },
              h('caption', { cls: 'sr-only', text: 'Aufgaben in Ausführungsreihenfolge' }),
              h('thead', null, h('tr', null, ['Pos.', 'Aufgabe', 'Herkunft', 'Status', 'Priorität', 'Begründung'].map(function (c, i) { return h('th', { scope: 'col', cls: i === 4 || i === 0 ? 'num' : '', text: c }); }))),
              h('tbody', null, q.map(function (r) {
                return h('tr', { cls: picked === r.task_id ? 'is-sel' : '' },
                  h('td', { cls: 'num mono', text: String(r.position) }),
                  h('td', null, h('button', { type: 'button', cls: 'linkbtn', on: { click: function () { pick(r.task_id); } } }, r.title), h('div', { cls: 'mono small muted', text: r.task_id })),
                  h('td', { text: fmt.ORIGIN[r.origin] || r.origin || '–' }),
                  h('td', null, fmt.badge(r.status)),
                  h('td', { cls: 'num mono', text: String(r.priority) }),
                  h('td', { cls: 'qreason' }, r.reason || '–', r.done_when ? h('div', { cls: 'small muted', text: 'Fertig, wenn: ' + r.done_when }) : null));
              })))));
      }
      host.appendChild(h('div', { cls: 'stack' },
        ui.section('Ausführungsreihenfolge', tableHost, h('span', { cls: 'muted small', text: 'kleinere Priorität läuft früher' })), detailHost));
      paint();
      var off = ui.live(['queue', 'tasks', 'loaded'], paint, 120);
      return { dispose: function () { off(); if (detail) detail.dispose(); } };
    }
  });
})();
