/* Tab Code: Quelltext/Disassembly mit KI-Anmerkungen, Hexdump fuer Binaerdaten und Modus "Lernpfad"
   (Funktionsliste, Ablaufplan je Funktion, Randnotizen). Alle Zeilen werden nur als Text eingefuegt. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var api = SW.api;
  var ui = SW.ui;

  var CHUNK = 400;
  var ROLE_TONE = { Entry: 'info', Decoder: 'warn', Netzwerk: 'err', Krypto: 'warn', Persistenz: 'err' };

  SW.registerTab({
    id: 'code', label: 'Code', icon: 'code',
    mount: function (host, ctx) {
      var st = ctx.st;
      var jobId = ctx.jobId;
      var dead = false;
      var mode = ctx.route.query.mode === 'lern' ? 'lern' : 'read';
      var wrap = false;
      var files = st.files;
      var fns = null;
      var wts = null;
      var cur = null;
      var active = null; /* { start, end, type: 'step' | 'focus' } */
      var wt = null;
      var stepIdx = -1;
      var fnSel = null;
      var gen = 0;

      var sideHost = h('div', { cls: 'code-side' });
      var barHost = h('div', { cls: 'stepbar-host' });
      var codeHost = h('div', { cls: 'code', role: 'region', 'aria-label': 'Quelltext', tabindex: '0' });
      var toolHost = h('div', { cls: 'code-tools row' });

      /* ---------- Laden ---------- */
      function newCur(path) {
        return { path: path, total: 0, lines: [], annots: new Map(), binary: false, loading: true, error: null, id: ++gen };
      }

      function ensure(c, upto) {
        if (c.total && c.lines.length >= Math.min(upto, c.total)) return Promise.resolve();
        var start = c.lines.length + 1;
        var end = Math.max(upto, start + CHUNK - 1);
        c.loading = true;
        return api.get('/jobs/' + jobId + '/files/content', { path: c.path, start: start, end: end }).then(function (d) {
          if (dead || cur !== c) return null;
          c.loading = false;
          c.error = null;
          c.total = d.total_lines || 0;
          c.binary = !!d.binary;
          var got = 0;
          (d.lines || []).forEach(function (l) {
            if (l.n === c.lines.length + 1) { c.lines.push(l); got++; }
          });
          (d.annotations || []).forEach(function (a) { c.annots.set(a.id, a); });
          if (got && c.lines.length < Math.min(upto, c.total)) return ensure(c, upto);
          return null;
        }, function (err) {
          if (cur === c) { c.loading = false; c.error = err; }
        });
      }

      function openFile(path, upto) {
        if (!cur || cur.path !== path) {
          cur = newCur(path);
          paintCode();
          paintSide();
        }
        var c = cur;
        return ensure(c, upto || 1).then(function () {
          if (!dead && cur === c) { paintCode(); paintTools(); }
        });
      }

      function scrollToActive() {
        if (!active) return;
        var row = codeHost.querySelector('[data-line="' + active.start + '"]');
        if (row) row.scrollIntoView({ block: 'center' });
      }

      function jumpTo(path, start, end, type) {
        active = { start: start, end: end || start, type: type || 'focus' };
        paintBar();
        return openFile(path || (cur && cur.path), (end || start) + 60).then(function () {
          paintCode();
          scrollToActive();
        });
      }

      /* ---------- Lernpfad ---------- */
      function selectStep(i) {
        if (!wt || !wt.steps || !wt.steps.length) return;
        stepIdx = Math.max(0, Math.min(wt.steps.length - 1, i));
        var s = wt.steps[stepIdx];
        paintSide();
        jumpTo(s.file, s.line_start, s.line_end, 'step');
      }
      function selectWalkthrough(w) {
        wt = w;
        stepIdx = -1;
        var f = fns && fns.filter(function (x) { return x.id === w.function_id; })[0];
        fnSel = f || null;
        selectStep(0);
      }
      function selectFn(f) {
        fnSel = f;
        var w = wts && wts.filter(function (x) { return x.function_id === f.id; })[0];
        if (w) { selectWalkthrough(w); return; }
        wt = null;
        stepIdx = -1;
        paintSide();
        jumpTo(f.file, f.line_start, f.line_end, 'focus');
      }
      function setMode(m) {
        mode = m;
        if (m === 'lern' && !wt && wts && wts.length) selectWalkthrough(wts[0]);
        else { paintSide(); paintBar(); paintCode(); }
        paintTools();
      }

      /* ---------- Darstellung ---------- */
      function paintTools() {
        SW.dom.fill(toolHost,
          ui.seg('Modus', [['read', 'Lesen'], ['lern', 'Lernpfad']], mode, setMode),
          h('label', { cls: 'chk' }, (function () {
            var cb = h('input', { type: 'checkbox' });
            cb.checked = wrap;
            cb.addEventListener('change', function () { wrap = cb.checked; codeHost.classList.toggle('wrap', wrap); });
            return cb;
          })(), ' Zeilen umbrechen'),
          cur && cur.path ? h('span', { cls: 'mono small muted trunc', title: cur.path, text: cur.path + (cur.total ? ' · ' + cur.total + ' Zeilen' : '') + (cur.binary ? ' · Hexdump' : '') }) : null
        );
      }

      function fileList() {
        if (!files) return ui.loading();
        if (!files.length) return ui.noData('Für diesen Auftrag gibt es noch keine Dateien.');
        return h('ul', { cls: 'flist' }, files.map(function (f) {
          var on = cur && cur.path === f.path;
          return h('li', null, h('button', { type: 'button', cls: ['flist-b', on ? 'is-sel' : ''], 'aria-pressed': on ? 'true' : 'false', title: f.path + ' · SHA-256 ' + f.sha256,
            on: { click: function () { active = null; openFile(f.path, 1); paintBar(); } } },
            icon(f.kind === 'sample' ? 'file' : 'code', { size: 14 }),
            h('span', { cls: 'mono grow trunc', text: f.path }),
            h('span', { cls: 'small muted nowrap', text: fmt.bytes(f.size) })));
        }));
      }

      function lernPanel() {
        if (fns === null && wts === null) return ui.loading();
        if (!(fns && fns.length) && !(wts && wts.length)) {
          return ui.noData('Der Server hat noch keine Funktionen oder Ablaufpläne geliefert. Sie entstehen, wenn die Analyse Disassembly oder Dekompilat auswertet.');
        }
        var parts = [];
        if (fns && fns.length) {
          parts.push(h('h3', { text: 'Funktionen' }));
          parts.push(h('ul', { cls: 'flist fnlist' }, fns.map(function (f) {
            var on = fnSel && fnSel.id === f.id;
            return h('li', null, h('button', { type: 'button', cls: ['flist-b', 'fn-b', on ? 'is-sel' : ''], 'aria-pressed': on ? 'true' : 'false', on: { click: function () { selectFn(f); } } },
              h('span', { cls: 'fn-top' }, h('span', { cls: 'mono fn-name', text: f.name }), f.role ? h('span', { cls: 'badge tone-' + (ROLE_TONE[f.role] || 'neutral'), text: f.role }) : null),
              h('span', { cls: 'small muted mono', text: (f.address || '') + ' · Z. ' + f.line_start + '–' + f.line_end }),
              f.summary_de || f.summary_en ? h('span', { cls: 'small fn-sum', text: f.summary_de || f.summary_en }) : null));
          })));
        }
        if (wts && wts.length) {
          if (wts.length > 1) {
            var sel = h('select', { id: 'wt-sel', 'aria-label': 'Ablaufplan wählen' }, wts.map(function (w) { return h('option', { value: w.id, text: fmt.textDe(w, 'title') }); }));
            if (wt) sel.value = wt.id;
            sel.addEventListener('change', function () { selectWalkthrough(wts.filter(function (w) { return w.id === sel.value; })[0]); });
            parts.push(h('h3', { text: 'Ablaufplan' }), sel);
          } else parts.push(h('h3', { text: 'Ablaufplan' }));
          if (wt) {
            parts.push(h('p', { cls: 'small', text: fmt.textDe(wt, 'summary') }));
            parts.push(h('ol', { cls: 'wsteps' }, (wt.steps || []).map(function (s, i) {
              var on = i === stepIdx;
              return h('li', null, h('button', { type: 'button', cls: ['wstep', on ? 'is-sel' : ''], 'aria-current': on ? 'step' : null, 'data-key': 'ws-' + i, on: { click: function () { selectStep(i); } } },
                h('span', { cls: 'wn mono', text: String(s.n || i + 1) }),
                h('span', { cls: 'grow' }, h('span', { cls: 'wt', text: fmt.textDe(s, 'title') }), h('span', { cls: 'small muted mono wa', text: (s.address || '') + ' · Z. ' + s.line_start + (s.line_end && s.line_end !== s.line_start ? '–' + s.line_end : '') }))));
            })));
          } else parts.push(h('p', { cls: 'muted small', text: 'Für die gewählte Funktion liegt kein Ablaufplan vor.' }));
        }
        return parts;
      }

      function paintSide() {
        SW.dom.keepFocus(sideHost, function () {
          SW.dom.fill(sideHost,
            h('section', { cls: 'card' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Dateien' })), h('div', { cls: 'card-b tight' }, fileList())),
            mode === 'lern' ? h('section', { cls: 'card' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Lernpfad' })), h('div', { cls: 'card-b tight' }, lernPanel())) : null);
        });
      }

      function paintBar() {
        if (mode !== 'lern' || !wt || stepIdx < 0) { SW.dom.clear(barHost); return; }
        var n = wt.steps.length;
        var s = wt.steps[stepIdx];
        SW.dom.fill(barHost, h('div', { cls: 'stepbar card' },
          h('button', { type: 'button', cls: 'btn sm', disabled: stepIdx <= 0, on: { click: function () { selectStep(stepIdx - 1); } } }, icon('chevronright', { cls: 'flip' }), 'Zurück'),
          h('div', { cls: 'grow', 'aria-live': 'polite' }, h('div', { cls: 'small muted', text: 'Schritt ' + (stepIdx + 1) + ' von ' + n + ' · ' + fmt.textDe(wt, 'title') }), h('strong', { text: fmt.textDe(s, 'title') }), ui.bar(((stepIdx + 1) / n) * 100)),
          h('button', { type: 'button', cls: 'btn sm primary', disabled: stepIdx >= n - 1, on: { click: function () { selectStep(stepIdx + 1); } } }, 'Weiter', icon('chevronright'))));
      }

      function annNote(a) {
        return h('div', { cls: 'note ann-' + a.kind, role: 'note' },
          h('div', { cls: 'note-h' }, h('span', { cls: 'tag', text: fmt.ANN_KIND[a.kind] || a.kind }), h('span', { cls: 'mono small muted', text: 'Z. ' + a.line_start + (a.line_end !== a.line_start ? '–' + a.line_end : '') })),
          h('p', { text: fmt.textDe(a, 'text') }),
          h('div', { cls: 'row note-l' },
            a.evidence_id ? ui.evidenceChip(jobId, a.evidence_id) : null,
            a.finding_id ? h('a', { cls: 'chip mono', href: ui.tabHref(jobId, 'live', { finding: a.finding_id }), text: 'Befund ' + a.finding_id }) : null));
      }
      function stepNote(s) {
        return h('div', { cls: 'note note-step', role: 'note' },
          h('div', { cls: 'note-h' }, h('span', { cls: 'tag tone-info', text: 'Schritt ' + (stepIdx + 1) + '/' + wt.steps.length }), s.address ? h('span', { cls: 'mono small', text: s.address }) : null),
          h('strong', { text: fmt.textDe(s, 'title') }),
          h('p', { text: fmt.textDe(s, 'explanation') }),
          h('div', { cls: 'row note-l' },
            s.evidence_id ? ui.evidenceChip(jobId, s.evidence_id) : null,
            s.finding_id ? h('a', { cls: 'chip mono', href: ui.tabHref(jobId, 'live', { finding: s.finding_id }), text: 'Befund ' + s.finding_id }) : null));
      }

      function paintCode() {
        codeHost.classList.toggle('wrap', wrap);
        if (!cur) { SW.dom.fill(codeHost, files && !files.length ? ui.noData('Keine Dateien vorhanden.') : ui.loading('Datei wird geladen …')); return; }
        if (cur.error) { SW.dom.fill(codeHost, cur.error.status === 404 ? ui.noData('Diese Datei ist (noch) nicht verfügbar.') : ui.errorBox(cur.error.message)); return; }
        if (!cur.lines.length) { SW.dom.fill(codeHost, cur.loading ? ui.loading('Datei wird geladen …') : ui.noData('Die Datei ist leer.')); return; }
        var starts = {};
        var cover = {};
        cur.annots.forEach(function (a) {
          (starts[a.line_start] = starts[a.line_start] || []).push(a);
          for (var n = a.line_start; n <= Math.min(a.line_end, a.line_start + 400); n++) if (!cover[n]) cover[n] = a.kind;
        });
        var step = mode === 'lern' && wt && stepIdx >= 0 ? wt.steps[stepIdx] : null;
        var frag = document.createDocumentFragment();
        cur.lines.forEach(function (l) {
          var inAct = active && l.n >= active.start && l.n <= active.end;
          var notes = (starts[l.n] || []).map(annNote);
          if (step && active && active.type === 'step' && l.n === active.start) notes.unshift(stepNote(step));
          frag.appendChild(h('div', { cls: ['cl', cover[l.n] ? 'has-ann ak-' + cover[l.n] : '', inAct ? 'is-' + (active.type === 'step' ? 'active' : 'focus') : ''], 'data-line': l.n },
            h('span', { cls: 'cg', text: String(l.n) }),
            h('span', { cls: 'cc', text: l.text }),
            h('div', { cls: 'cn' }, notes)));
        });
        SW.dom.clear(codeHost);
        codeHost.appendChild(frag);
        if (cur.lines.length < cur.total) {
          codeHost.appendChild(h('div', { cls: 'more' }, h('button', { type: 'button', cls: 'btn sm', on: { click: function () {
            var c = cur;
            ensure(c, c.lines.length + CHUNK).then(function () { if (cur === c) paintCode(); });
          } } }, icon('arrowdown'), 'Weitere ' + Math.min(CHUNK, cur.total - cur.lines.length) + ' Zeilen laden'),
          h('span', { cls: 'small muted', text: ' ' + cur.lines.length + ' von ' + cur.total + ' Zeilen geladen' })));
        }
      }

      /* ---------- Start ---------- */
      function handleQuery(q) {
        if (q.mode === 'lern' && mode !== 'lern') { mode = 'lern'; }
        var file = q.file || (cur && cur.path);
        var line = parseInt(q.line, 10);
        if (file && line > 0) {
          var end = parseInt(q.end, 10);
          jumpTo(file, line, end >= line ? end : line, 'focus').then(function () { paintSide(); paintTools(); });
        } else if (file && (!cur || cur.path !== file)) {
          active = null;
          openFile(file, 1).then(paintSide);
        }
      }

      host.appendChild(h('div', { cls: 'code-view' },
        toolHost,
        h('div', { cls: 'code-grid' }, sideHost, h('div', { cls: 'code-main' }, barHost, h('div', { cls: 'card code-card' }, codeHost)))));
      paintTools();
      paintSide();
      paintCode();

      var filesP = files ? Promise.resolve() : ui.softGet('/jobs/' + jobId + '/files').then(function (r) { files = r.ok ? r.data : []; });
      var fnsP = ui.softGet('/jobs/' + jobId + '/functions').then(function (r) { fns = r.ok && Array.isArray(r.data) ? r.data : []; });
      var wtsP = ui.softGet('/jobs/' + jobId + '/walkthroughs').then(function (r) { wts = r.ok && Array.isArray(r.data) ? r.data : []; });
      Promise.all([filesP, fnsP, wtsP]).then(function () {
        if (dead) return;
        files = files || st.files || [];
        paintSide();
        var q = ctx.route.query;
        var first = q.file || ((files.filter(function (f) { return f.kind === 'sample'; })[0] || files[0] || {}).path);
        if (mode === 'lern' && wts.length && !q.file) selectWalkthrough(wts[0]);
        else if (first) {
          if (q.line) handleQuery(q);
          else openFile(first, 1).then(paintSide);
        } else paintCode();
        paintTools();
      });

      /* neue Anmerkungen aus dem Stream */
      var offAnn = SW.store.on(function (kind, a) {
        if (kind !== 'annotation' || !cur || !a) return;
        var p = a.path || a.file;
        if (p && p !== cur.path) return;
        cur.annots.set(a.id, a);
        paintCode();
      });
      var offFiles = ui.live(['files'], function () { files = st.files; paintSide(); }, 100);

      return {
        dispose: function () { dead = true; offAnn(); offFiles(); },
        update: function (r) { handleQuery(r.query); }
      };
    }
  });
})();
