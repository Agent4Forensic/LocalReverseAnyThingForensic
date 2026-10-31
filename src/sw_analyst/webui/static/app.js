/* Shell, Pfad-Routing (History API) und Theme-Umschalter. Ansichten registrieren sich in SW.views / SW.tabs.
   Routen: /  /new  /prompts  /job/<id>/<tab>?<params>. Alte Links mit #/ werden umgeschrieben. */
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

  function parseRoute() {
    var path = (window.location.pathname || '').replace(/^\/+|\/+$/g, '');
    var qs = (window.location.search || '').replace(/^\?/, '');
    var query = {};
    qs.split('&').forEach(function (p) {
      if (!p) return;
      var i = p.indexOf('=');
      var k = safeDecode(i < 0 ? p : p.slice(0, i));
      if (k !== 'mock') query[k] = i < 0 ? '' : safeDecode(p.slice(i + 1));
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
  SW.parseRoute = parseRoute;

  /* Mock-Modus (?mock=1) bleibt beim Navigieren erhalten. */
  function withMock(url) {
    return SW.api.isMock ? url + (url.indexOf('?') < 0 ? '?' : '&') + 'mock=1' : url;
  }
  SW.navigate = function (url, replace) {
    var target = withMock(url);
    if (target === window.location.pathname + window.location.search) {
      onRoute();
      return;
    }
    window.history[replace ? 'replaceState' : 'pushState'](null, '', target);
    onRoute();
  };
  /* Alter Link http://host/#/job/x/code -> /job/x/code. */
  function legacyHash() {
    var m = /^#(\/.*)$/.exec(window.location.hash || '');
    if (!m) return false;
    window.history.replaceState(null, '', withMock(m[1]));
    return true;
  }
  document.addEventListener('click', function (e) {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    var a = e.target.closest ? e.target.closest('a[href]') : null;
    if (!a || a.target || a.hasAttribute('download')) return;
    var url = a.getAttribute('href');
    if (url.charAt(0) !== '/' || url.charAt(1) === '/' || url.indexOf('/api/') === 0) return;
    e.preventDefault();
    SW.navigate(url);
  });

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
    var r = parseRoute();
    var nav = document.getElementById('nav-main');
    SW.dom.fill(nav,
      navLink('/', 'dashboard', 'Übersicht', r.name === 'overview'),
      navLink('/new', 'plus', 'Neuer Auftrag', r.name === 'new'),
      navLink('/prompts', 'book', 'Prompts', r.name === 'prompts')
    );
    var jobs = store.state.jobs.slice(0, 8);
    SW.dom.fill(jobsNav,
      h('p', { cls: 'nav-h', id: 'nav-jobs-h', text: 'Aufträge' }),
      jobs.length ? jobs.map(function (j) {
        return h('a', { href: '/job/' + encodeURIComponent(j.id) + '/activity', title: j.title, 'aria-current': r.jobId === j.id ? 'page' : null }, fmt.statusIcon(j.status), h('span', { cls: 'lbl', text: j.title }));
      }) : h('p', { cls: 'hint', text: 'Noch keine Aufträge.' })
    );
  }

  function sysItem(label, value, tone) {
    return h('div', { cls: 'sys-i', title: label + ': ' + value },
      h('dt', null, h('span', { cls: 'dot' + (tone ? ' tone-' + tone : ''), 'aria-hidden': 'true' }), label),
      h('dd', { text: value }));
  }

  function paintConn() {
    var s = store.state;
    var sys = s.system;
    if (!sys) {
      SW.dom.fill(connBox, s.systemError ? sysItem('Server', 'nicht erreichbar', 'err') : sysItem('Server', 'verbindet …'));
      return;
    }
    var w = sys.worker || {};
    var llm = sys.llm || {};
    var g = sys.guard || {};
    var gw = sys.gateway || {};
    SW.dom.fill(connBox,
      s.systemError ? sysItem('Server', 'nicht erreichbar', 'err') : null,
      sysItem('Worker', w.state === 'running' ? 'läuft' : 'bereit', w.state === 'running' ? 'info' : 'ok'),
      sysItem('Modell', (llm.model || '–') + (llm.reachable ? '' : ' (offline)'), llm.reachable ? 'ok' : 'err'),
      sysItem('Schutz', g.active ? (g.rules || 0) + ' Regeln' : 'inaktiv', g.active ? 'ok' : 'err'),
      sysItem('Werkzeuge', String(gw.tools || 0)),
      sysItem('Warteschlange', String(sys.queue_length || 0)),
      sysItem('Version', sys.version || '–'));
  }

  function buildShell() {
    var app = document.getElementById('app');
    jobsNav = h('nav', { cls: 'nav nav-jobs', 'aria-labelledby': 'nav-jobs-h' });
    connBox = h('dl', { cls: 'sys', 'aria-label': 'Systemstatus', role: 'status' });
    themeBtn = h('button', { type: 'button', cls: 'btn sm', on: { click: cycleTheme }, 'aria-label': 'Farbschema wechseln' });
    main = h('main', { cls: 'main', id: 'main', tabindex: '-1' });
    live = h('div', { cls: 'sr-only', 'aria-live': 'polite', id: 'live' });
    var panel = h('aside', { cls: 'panel', id: 'panel', role: 'dialog', 'aria-modal': 'false', hidden: true });
    ui.initPanel(panel);
    SW.dom.fill(app,
      h('div', { cls: 'shell' },
        h('aside', { cls: 'side' },
          h('a', { cls: 'brand', href: '/', 'aria-label': 'sw-analyst, zur Übersicht' },
            h('span', { cls: 'brand-mark' }, icon('shieldcheck', { size: 16 })),
            h('span', { cls: 'brand-name' }, 'sw-analyst', h('span', { cls: 'brand-sub', text: 'Statische Analyse' }))
          ),
          h('nav', { cls: 'nav', id: 'nav-main', 'aria-label': 'Hauptnavigation' }),
          jobsNav,
          h('div', { cls: 'side-foot' },
            SW.api.isMock ? h('div', { cls: 'mock-flag', text: 'Mock-Daten (?mock=1)' }) : null,
            h('p', { cls: 'nav-h', text: 'System' }),
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
    var route = parseRoute();
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
    legacyHash();
    window.addEventListener('popstate', onRoute);
    window.addEventListener('hashchange', function () { if (legacyHash()) onRoute(); });
    onRoute();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
