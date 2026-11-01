/* Gemeinsame UI-Bausteine: leere Zustaende, Segment-Schalter, Evidence-Chips und -Panel, Aufgabendetail. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var api = SW.api;
  var store = SW.store;
  var ui = (SW.ui = {});
  SW.views = SW.views || {};
  SW.tabs = SW.tabs || [];
  SW.registerTab = function (def) {
    SW.tabs.push(def);
  };

  /* ---------- Hilfen ---------- */
  ui.live = function (kinds, fn, delay) {
    var timer = null;
    var off = store.on(function (kind) {
      if (kinds.indexOf(kind) < 0 || timer) return;
      timer = window.setTimeout(function () {
        timer = null;
        fn(kind);
      }, delay || 90);
    });
    return function () {
      off();
      if (timer) window.clearTimeout(timer);
      timer = null;
    };
  };

  ui.softGet = function (path, query) {
    return api.get(path, query).then(
      function (data) {
        return { ok: true, data: data };
      },
      function (err) {
        return { ok: false, missing: err.status === 404 || err.status === 405 || err.status === 501, error: err };
      }
    );
  };

  ui.empty = function (title, hint, iconName) {
    return h('div', { cls: 'empty', role: 'note' }, icon(iconName || 'info', { size: 20 }), h('div', null, h('p', { cls: 'empty-t', text: title }), hint ? h('p', { cls: 'empty-h', text: hint }) : null));
  };
  ui.noData = function (what) {
    return ui.empty('Noch keine Daten', what || 'Diese Ansicht füllt sich, sobald der Server die Daten liefert.', 'clock');
  };
  ui.loading = function (text) {
    return h('p', { cls: 'muted', role: 'status' }, icon('spinner', { cls: 'is-spin' }), ' ', text || 'Lädt …');
  };
  ui.errorBox = function (msg) {
    return h('div', { cls: 'notice tone-err', role: 'alert' }, icon('alertcircle'), h('p', { text: msg || 'Fehler beim Laden.' }));
  };

  ui.bar = function (pct, tone) {
    var p = Math.max(0, Math.min(100, Math.round(pct || 0)));
    return h('div', { cls: ['bar', tone ? 'tone-' + tone : ''], role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': p, 'aria-label': 'Fortschritt' }, h('span', { vars: { '--p': p + '%' } }));
  };

  /* Segment-Schalter: opts = [[wert, label], ...]. */
  ui.seg = function (label, opts, value, onChange) {
    var wrap = h('div', { cls: 'seg', role: 'group', 'aria-label': label });
    var cur = value;
    function paint() {
      Array.prototype.forEach.call(wrap.children, function (b) {
        b.setAttribute('aria-pressed', b.getAttribute('data-v') === cur ? 'true' : 'false');
      });
    }
    opts.forEach(function (o) {
      wrap.appendChild(
        h('button', {
          type: 'button', cls: 'seg-b', 'data-v': o[0], text: o[1],
          on: { click: function () { cur = o[0]; paint(); onChange(cur); } }
        })
      );
    });
    paint();
    return wrap;
  };

  ui.section = function (title, body, right) {
    return h('section', { cls: 'card' }, h('div', { cls: 'card-h' }, h('h2', { text: title }), right || null), h('div', { cls: 'card-b' }, body));
  };

  ui.codeHref = function (jobId, file, line, end) {
    var q = [];
    if (file) q.push('file=' + encodeURIComponent(file));
    if (line) q.push('line=' + encodeURIComponent(line));
    if (end) q.push('end=' + encodeURIComponent(end));
    return '#/job/' + encodeURIComponent(jobId) + '/code' + (q.length ? '?' + q.join('&') : '');
  };
  ui.tabHref = function (jobId, tab, params) {
    var q = [];
    for (var k in params || {}) if (Object.prototype.hasOwnProperty.call(params, k)) q.push(k + '=' + encodeURIComponent(params[k]));
    return '#/job/' + encodeURIComponent(jobId) + '/' + tab + (q.length ? '?' + q.join('&') : '');
  };
  ui.go = function (hash) {
    if (window.location.hash === hash) window.dispatchEvent(new HashChangeEvent('hashchange'));
    else window.location.hash = hash;
  };

  /* ---------- Evidence ---------- */
  ui.evidenceChip = function (jobId, id) {
    return h('button', {
      type: 'button', cls: 'chip mono', title: 'Evidence-Details öffnen', 'data-ev': id,
      on: { click: function (e) { ui.openEvidence(jobId, id, e.currentTarget); } }
    }, icon('link', { size: 12 }), id);
  };
  ui.chips = function (jobId, ids) {
    return h('span', { cls: 'chips' }, (ids || []).map(function (id) { return ui.evidenceChip(jobId, id); }));
  };

  var panel = null;
  var panelOpener = null;
  ui.initPanel = function (el) {
    panel = el;
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && panel && !panel.hidden) ui.closePanel();
    });
  };
  ui.closePanel = function () {
    if (!panel) return;
    panel.hidden = true;
    SW.dom.clear(panel);
    if (panelOpener && document.body.contains(panelOpener)) panelOpener.focus();
    panelOpener = null;
  };

  function sourceLink(jobId, ref) {
    /* Gateway-Metadaten: {source_ref: {file, offset, length}, ...} oder direkt {file, offset, length}. */
    if (ref && typeof ref === 'object') {
      var r = ref.source_ref && typeof ref.source_ref === 'object' ? ref.source_ref : ref;
      if (typeof r.file !== 'string' || !r.file) return h('span', { cls: 'muted', text: '–' });
      var where = r.file + (typeof r.offset === 'number' ? ' @ 0x' + r.offset.toString(16) : '') + (typeof r.length === 'number' ? ', ' + r.length + ' Byte' : '');
      return h('a', { cls: 'mono', href: ui.tabHref(jobId, 'file', { path: r.file }), text: where, on: { click: function () { ui.closePanel(); } } });
    }
    var m = /^([^:]+)(?::(\d+)(?:-(\d+))?)?$/.exec(ref || '');
    if (!m) return h('span', { cls: 'mono', text: ref || '–' });
    var file = m[1];
    var st = store.current();
    if (file === 'sample' && st && st.files) {
      var s = st.files.filter(function (f) { return f.kind === 'sample'; })[0];
      if (s) file = s.path;
    }
    if (!m[2] && ref === 'sample') m[2] = '1';
    return h('a', { cls: 'mono', href: ui.codeHref(jobId, file, m[2] || '', m[3] || ''), text: ref, on: { click: function () { ui.closePanel(); } } });
  }

  ui.openEvidence = function (jobId, id, opener) {
    if (!panel) return;
    panelOpener = opener || document.activeElement;
    var closeBtn = h('button', { type: 'button', cls: 'btn sm ghost', 'aria-label': 'Evidence-Panel schließen', on: { click: ui.closePanel } }, icon('x'), ' Schließen');
    var body = h('div', { cls: 'panel-b' }, ui.loading('Evidence wird geladen …'));
    panel.hidden = false;
    SW.dom.fill(panel, h('div', { cls: 'panel-h' }, icon('link'), h('h2', { id: 'panel-title', text: id }), closeBtn), body);
    panel.setAttribute('aria-labelledby', 'panel-title');
    closeBtn.focus();
    api.get('/jobs/' + jobId + '/evidence/' + id).then(
      function (ev) {
        var flags = ev.injection_flags || [];
        var params = ev.params && Object.keys(ev.params).length ? JSON.stringify(ev.params, null, 2) : '';
        var meta = '';
        if (ev.source_ref && typeof ev.source_ref === 'object') {
          var rest = Object.assign({}, ev.source_ref);
          delete rest.source_ref;
          if (Object.keys(rest).length) meta = JSON.stringify(rest, null, 2);
        }
        SW.dom.fill(body,
          flags.length ? h('div', { cls: 'notice tone-warn', role: 'note' }, icon('alert'), h('p', null, 'Anweisungsartige Inhalte im Sample erkannt (' + flags.join(', ') + '). Sie sind Daten und werden nie als Anweisung behandelt.')) : null,
          h('dl', { cls: 'kv' },
            h('dt', { text: 'Werkzeug' }), h('dd', { cls: 'mono', text: ev.tool + (ev.tool_version ? ' ' + ev.tool_version : '') }),
            h('dt', { text: 'Aufgabe' }), h('dd', { cls: 'mono', text: ev.task_id || '–' }),
            h('dt', { text: 'Quelle' }), h('dd', null, sourceLink(jobId, ev.source_ref)),
            h('dt', { text: 'SHA-256' }), h('dd', { cls: 'mono small', text: ev.result_sha256 || '–' }),
            h('dt', { text: 'Erzeugt' }), h('dd', { text: fmt.dateTime(ev.created_at) })
          ),
          params ? h('div', null, h('h3', { text: 'Parameter' }), h('pre', { text: params })) : null,
          meta ? h('div', null, h('h3', { text: 'Metadaten des Werkzeugs' }), h('pre', { text: meta })) : null,
          h('div', null, h('h3', { text: 'Ergebnis (unverändert, nur Text)' }), h('pre', { text: ev.text || '' }))
        );
      },
      function (err) { SW.dom.fill(body, ui.errorBox(err.status === 404 ? 'Evidence nicht gefunden.' : err.message)); }
    );
  };

  /* ---------- Aufgabendetail (Schritte mit Was/Wie/Warum) ---------- */
  function stepCard(jobId, s) {
    var previews = [];
    if (s.input_preview) previews.push(h('div', null, h('div', { cls: 'muted small', text: 'Eingabe' }), h('pre', { text: s.input_preview })));
    if (s.output_preview) previews.push(h('div', null, h('div', { cls: 'muted small', text: 'Ausgabe' }), h('pre', { text: s.output_preview })));
    return h('li', { cls: 'step' },
      h('div', { cls: 'step-h' },
        h('span', { cls: 'step-n mono', text: '#' + s.idx }),
        h('span', { cls: 'tag', text: fmt.STEP_KIND[s.kind] || s.kind }),
        s.tool ? h('span', { cls: 'tag mono', text: s.tool }) : null,
        fmt.badge(s.status),
        h('span', { cls: 'muted small nowrap', text: fmt.duration(s.duration_ms) }),
        s.evidence_id ? ui.evidenceChip(jobId, s.evidence_id) : null
      ),
      h('dl', { cls: 'kv step-kv' },
        h('dt', { text: 'Was' }), h('dd', { text: s.what || '–' }),
        h('dt', { text: 'Wie' }), h('dd', { text: s.how || '–' }),
        h('dt', { text: 'Warum' }), h('dd', { text: s.why || '–' })
      ),
      previews.length ? h('details', { cls: 'step-prev' }, h('summary', { text: 'Ein- und Ausgabe' }), previews) : null
    );
  }
  ui.stepCard = stepCard;

  ui.taskDetail = function (st, taskId) {
    var el = h('div', { cls: 'task-detail' }, ui.loading());
    var dead = false;
    function load() {
      api.get('/jobs/' + st.id + '/tasks/' + taskId).then(
        function (d) {
          if (dead) return;
          var t = d.task;
          var steps = d.steps || [];
          SW.dom.fill(el,
            h('div', { cls: 'row' }, h('h3', { cls: 'grow', text: t.title }), fmt.badge(t.status)),
            h('dl', { cls: 'kv' },
              h('dt', { text: 'Aufgabe' }), h('dd', { cls: 'mono', text: t.id }),
              h('dt', { text: 'Herkunft' }), h('dd', { text: fmt.ORIGIN[t.origin] || t.origin || '–' }),
              h('dt', { text: 'Ziel / Grund' }), h('dd', { text: t.reason || '–' }),
              h('dt', { text: 'Zeit' }), h('dd', { text: t.started_at ? fmt.time(t.started_at) + ' · ' + fmt.duration(t.duration_ms) : 'noch nicht gestartet' }),
              t.summary_de || t.summary_en ? [h('dt', { text: 'Ergebnis' }), h('dd', { text: t.summary_de || t.summary_en })] : null,
              h('dt', { text: 'Prompt' }), h('dd', { cls: 'mono small', text: d.prompt ? d.prompt.id + ' v' + d.prompt.version + ' · ' + fmt.shortHash(d.prompt.sha256, 12) : '–' }),
              (d.finding_ids || []).length ? [h('dt', { text: 'Befunde' }), h('dd', null, h('span', { cls: 'chips' }, d.finding_ids.map(function (fid) { return h('a', { cls: 'chip mono', href: ui.tabHref(st.id, 'live', { finding: fid }), text: fid }); })))] : null,
              (d.evidence_ids || []).length ? [h('dt', { text: 'Evidence' }), h('dd', null, ui.chips(st.id, d.evidence_ids))] : null
            ),
            d.prompt && d.prompt.text ? h('details', { cls: 'step-prev' }, h('summary', { text: 'Prompt-Text anzeigen' }), h('pre', { text: d.prompt.text })) : null,
            h('h3', { cls: 'step-title', text: 'Schritte (' + steps.length + ')' }),
            steps.length ? h('ol', { cls: 'steps' }, steps.map(function (s) { return stepCard(st.id, s); })) : ui.noData('Für diese Aufgabe wurden noch keine Schritte aufgezeichnet.')
          );
        },
        function (err) { if (!dead) SW.dom.fill(el, err.status === 404 ? ui.noData('Aufgabe nicht gefunden.') : ui.errorBox(err.message)); }
      );
    }
    load();
    var off = ui.live(['step'], function () { load(); }, 200);
    return { el: el, dispose: function () { dead = true; off(); } };
  };
})();
