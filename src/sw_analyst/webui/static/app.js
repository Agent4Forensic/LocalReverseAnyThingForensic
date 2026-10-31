/* Shell, Hash-Routing und Theme-Umschalter. Ansichten registrieren sich in SW.views / SW.tabs.
   Routen: #/  #/new  #/prompts  #/job/<id>/<tab>?<params> */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var store = SW.store;
  var ui = SW.ui;

  function safeDecode(s) {
    try {
      return decodeURIComponent(s);
    } catch (e) {
      return s;
    }
  }

  function parseHash() {
    var raw = (window.location.hash || '').replace(/^#\/?/, '');
    var qi = raw.indexOf('?');
    var path = qi >= 0 ? raw.slice(0, qi) : raw;
    var qs = qi >= 0 ? raw.slice(qi + 1) : '';
    var query = {};
    qs.split('&').forEach(function (p) {
      if (!p) return;
      var i = p.indexOf('=');
      query[safeDecode(i < 0 ? p : p.slice(0, i))] = i < 0 ? '' : safeDecode(p.slice(i + 1));
    });
    var parts = path.split('/').filter(Boolean).map(safeDecode);
    var r = { query: query, name: 'overview', jobId: null, tab: null };
    if (parts[0] === 'new') r.name = 'new';
    else if (parts[0] === 'prompts') r.name = 'prompts';
    else if (parts[0] === 'job' && parts[1]) {
      r.name = 'job';
      r.jobId = parts[1];
      r.tab = parts[2] || 'activity';
    }
    return r;
  }
  SW.parseHash = parseHash;

  /* ---------- Shell ---------- */
  var main = null;
  var jobsNav = null;
  var connBox = null;
  var themeBtn = null;
  var live = null;

  var THEMES = [['auto', 'Automatisch', 'cpu'], ['light', 'Hell', 'sun'], ['dark', 'Dunkel', 'moon']];
  function themeMode() {
    var m = document.documentElement.getAttribute('data-theme');
    return m === 'light' || m === 'dark' ? m : 'auto';
  }
  function paintTheme() {
    var cur = THEMES.filter(function (t) { return t[0] === themeMode(); })[0];
    SW.dom.fill(themeBtn, icon(cur[2]), h('span', { text: 'Design: ' + cur[1] }));
  }
  function cycleTheme() {
    var i = 0;
    THEMES.forEach(function (t, n) { if (t[0] === themeMode()) i = n; });
    var next = THEMES[(i + 1) % THEMES.length][0];
    if (next === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', next);
    try {
      if (next === 'auto') window.localStorage.removeItem('sw.theme');
      else window.localStorage.setItem('sw.theme', next);
    } catch (e) { /* Speicher gesperrt: Einstellung gilt nur fuer diese Sitzung */ }
    paintTheme();
  }

  function navLink(href, iconName, label, current) {
    return h('a', { href: href, 'aria-current': current ? 'page' : null }, icon(iconName), h('span', { cls: 'lbl', text: label }));
  }

  function paintNav() {
    var r = parseHash();
    var nav = document.getElementById('nav-main');
    SW.dom.fill(nav,
      navLink('#/', 'dashboard', 'Übersicht', r.name === 'overview'),
      navLink('#/new', 'plus', 'Neuer Auftrag', r.name === 'new'),
      navLink('#/prompts', 'book', 'Prompts', r.name === 'prompts')
    );
    var jobs = store.state.jobs.slice(0, 8);
    SW.dom.fill(jobsNav,
      h('p', { cls: 'nav-h', id: 'nav-jobs-h', text: 'Aufträge' }),
      jobs.length ? jobs.map(function (j) {
        return h('a', { href: '#/job/' + encodeURIComponent(j.id) + '/activity', title: j.title, 'aria-current': r.jobId === j.id ? 'page' : null }, fmt.statusIcon(j.status), h('span', { cls: 'lbl', text: j.title }));
      }) : h('p', { cls: 'hint', text: 'Noch keine Aufträge.' })
    );
  }

  function paintConn() {
    var s = store.state;
    var tone = 'warn';
    var text = 'Verbinde …';
    if (s.systemError) { tone = 'err'; text = 'Server nicht erreichbar'; }
    else if (s.system) {
      var llm = s.system.llm && s.system.llm.reachable;
      tone = llm ? 'ok' : 'warn';
      text = (s.system.worker && s.system.worker.state === 'running' ? 'Worker läuft' : 'Worker bereit') + (llm ? ' · LLM erreichbar' : ' · LLM offline');
    }
    connBox.setAttribute('class', 'conn tone-' + tone);
    SW.dom.fill(connBox, h('span', { cls: 'dot', 'aria-hidden': 'true' }), h('span', { text: text }));
  }

  function buildShell() {
    var app = document.getElementById('app');
    jobsNav = h('nav', { cls: 'nav nav-jobs', 'aria-labelledby': 'nav-jobs-h' });
    connBox = h('div', { cls: 'conn', role: 'status' });
    themeBtn = h('button', { type: 'button', cls: 'btn sm', on: { click: cycleTheme }, 'aria-label': 'Farbschema wechseln' });
    main = h('main', { cls: 'main', id: 'main', tabindex: '-1' });
    live = h('div', { cls: 'sr-only', 'aria-live': 'polite', id: 'live' });
    var panel = h('aside', { cls: 'panel', id: 'panel', role: 'dialog', 'aria-modal': 'false', hidden: true });
    ui.initPanel(panel);
    SW.dom.fill(app,
      h('div', { cls: 'shell' },
        h('aside', { cls: 'side' },
          h('a', { cls: 'brand', href: '#/', 'aria-label': 'sw-analyst, zur Übersicht' },
            h('span', { cls: 'brand-mark' }, icon('shieldcheck', { size: 16 })),
            h('span', { cls: 'brand-name' }, 'sw-analyst', h('span', { cls: 'brand-sub', text: 'Statische Analyse' }))
          ),
          h('nav', { cls: 'nav', id: 'nav-main', 'aria-label': 'Hauptnavigation' }),
          jobsNav,
          h('div', { cls: 'side-foot' },
            SW.api.isMock ? h('div', { cls: 'mock-flag', text: 'Mock-Daten (?mock=1)' }) : null,
            connBox,
            themeBtn
          )
        ),
        main
      ),
      panel,
      live
    );
    paintTheme();
    paintConn();
  }

  /* ---------- Router ---------- */
  var current = null; /* { key, view } */

  function mountView(route) {
    var key = route.name === 'job' ? 'job:' + route.jobId : route.name;
    if (current && current.key === key && current.view.update) {
      current.view.update(route);
      return;
    }
    if (current && current.view.dispose) current.view.dispose();
    ui.closePanel();
    SW.dom.clear(main);
    var factory = SW.views[route.name];
    var view = factory ? factory(route) : null;
    if (!view) {
      main.appendChild(ui.empty('Ansicht nicht verfügbar', 'Diese Ansicht ist nicht geladen.'));
      current = null;
      return;
    }
    current = { key: key, view: view };
    main.appendChild(view.el);
    if (view.title) {
      document.title = view.title + ' – sw-analyst';
      SW.dom.fill(live, 'Ansicht: ' + view.title);
    }
    window.scrollTo(0, 0);
    if (route.name !== 'job') main.focus({ preventScroll: true });
  }

  function onRoute() {
    var route = parseHash();
    paintNav();
    mountView(route);
  }

  /* ---------- Start ---------- */
  function boot() {
    buildShell();
    store.on(function (kind) {
      if (kind === 'jobs') paintNav();
      if (kind === 'system') paintConn();
    });
    store.startGlobal();
    window.addEventListener('hashchange', onRoute);
    onRoute();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
