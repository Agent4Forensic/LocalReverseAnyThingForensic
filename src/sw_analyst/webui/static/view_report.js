/* Tabs: Live-Bericht (Zielfragen, Befunde) und Bericht (Markdown, DE/EN). */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var api = SW.api;
  var store = SW.store;
  var ui = SW.ui;

  /* =================== Live-Bericht =================== */
  function questionCard(st, a) {
    var matchBadge = a.match === true
      ? h('span', { cls: 'badge tone-ok' }, icon('check', { size: 13 }), 'Entspricht der Erwartung')
      : a.match === false ? h('span', { cls: 'badge tone-err' }, icon('x', { size: 13 }), 'Weicht von der Erwartung ab') : null;
    var fresh = store.freshAge(st, 'a:' + a.question_id) !== null;
    return h('article', { cls: ['qcard', fresh ? 'is-fresh' : ''], id: 'q-' + a.question_id },
      h('div', { cls: 'row' }, h('span', { cls: 'mono qid', text: a.question_id }), h('h3', { cls: 'grow', text: a.text_orig || a.text_en }), fmt.badge(a.status)),
      a.answer_de || a.answer_en
        ? h('p', { cls: 'answer', text: a.answer_de || a.answer_en })
        : h('p', { cls: 'muted', text: a.status === 'unresolved' ? 'Ungeklärt: Es liegen keine bestätigten Befunde vor, die die Frage beantworten.' : 'Noch keine Antwort. Die Frage wird nach den zugehörigen Aufgaben beantwortet.' }),
      a.expected ? h('p', { cls: 'small' }, h('span', { cls: 'muted', text: 'Erwartet: ' }), h('span', { cls: 'mono', text: a.expected }), ' ', matchBadge) : null,
      a.evaluation_de || a.evaluation_en ? h('p', { cls: 'small muted', text: 'Bewertung: ' + (a.evaluation_de || a.evaluation_en) }) : null,
      (a.finding_ids || []).length ? h('p', { cls: 'small' }, h('span', { cls: 'muted', text: 'Stützende Befunde: ' }), h('span', { cls: 'chips' }, a.finding_ids.map(function (fid) { return h('a', { cls: 'chip mono', href: ui.tabHref(st.id, 'live', { finding: fid }), text: fid }); }))) : null
    );
  }

  function findingCard(st, f, target) {
    var fresh = store.freshAge(st, 'f:' + f.id) !== null;
    return h('article', { cls: ['fcard', 'f-' + f.status, fresh ? 'is-fresh' : '', target ? 'is-target' : ''], id: 'f-' + f.id, tabindex: '-1' },
      h('div', { cls: 'row' }, h('span', { cls: 'mono fid', text: f.id }), fmt.badge(f.status), h('span', { cls: 'grow' }),
        f.task_id ? h('a', { cls: 'small mono', href: ui.tabHref(st.id, 'tree', { task: f.task_id }), text: 'Aufgabe ' + f.task_id }) : null),
      h('p', { cls: 'fstmt', text: f.statement_de || f.statement_en }),
      f.statement_de && f.statement_en ? h('details', { cls: 'step-prev' }, h('summary', { text: 'Englisches Original' }), h('p', { cls: 'small', text: f.statement_en })) : null,
      f.status === 'rejected' && f.reject_reason ? h('div', { cls: 'notice tone-err', role: 'note' }, icon('xcircle'), h('p', { text: 'Verworfen: ' + f.reject_reason })) : null,
      f.status === 'hypothesis' ? h('p', { cls: 'small muted', text: 'Hypothese: nicht bestätigt und nicht Grundlage einer Antwort.' }) : null,
      (f.quotes || []).length ? h('div', { cls: 'quotes' }, f.quotes.map(function (q) {
        return h('blockquote', { cls: 'quote' }, h('code', { text: q.quote }), ' ', ui.evidenceChip(st.id, q.evidence_id));
      })) : null,
      (f.evidence_ids || []).length ? h('p', { cls: 'small' }, h('span', { cls: 'muted', text: 'Belege: ' }), ui.chips(st.id, f.evidence_ids)) : h('p', { cls: 'small muted', text: 'Kein Beleg angegeben.' })
    );
  }

  SW.registerTab({
    id: 'live', label: 'Live-Bericht', icon: 'live',
    mount: function (host, ctx) {
      var st = ctx.st;
      var filter = 'all';
      var target = ctx.route.query.finding || null;
      var qHost = h('div', { cls: 'stack' });
      var fHost = h('div', { cls: 'stack' });
      var segHost = h('div');

      function counts() {
        var c = { all: st.findings.length };
        st.findings.forEach(function (f) { c[f.status] = (c[f.status] || 0) + 1; });
        return c;
      }
      function paintFilter() {
        var c = counts();
        SW.dom.fill(segHost, ui.seg('Befunde filtern', [
          ['all', 'Alle (' + c.all + ')'], ['confirmed', 'Bestätigt (' + (c.confirmed || 0) + ')'], ['hypothesis', 'Hypothese (' + (c.hypothesis || 0) + ')'],
          ['open', 'Offen (' + (c.open || 0) + ')'], ['rejected', 'Verworfen (' + (c.rejected || 0) + ')']
        ], filter, function (v) { filter = v; paintFindings(); }));
      }
      function paintQuestions() {
        SW.dom.fill(qHost, st.answers.length ? st.answers.map(function (a) { return questionCard(st, a); })
          : (st.loaded ? ui.empty('Keine Zielfragen', 'Für diesen Auftrag wurden keine Zielfragen gestellt. Die Analyse folgt dem Rezept.', 'question') : ui.loading()));
      }
      function paintFindings() {
        var list = st.findings.filter(function (f) { return filter === 'all' || f.status === filter; });
        SW.dom.fill(fHost, list.length ? list.map(function (f) { return findingCard(st, f, f.id === target); })
          : (st.loaded ? ui.empty('Noch keine Befunde', filter === 'all' ? 'Befunde erscheinen hier, sobald sie belegt und geprüft sind.' : 'Kein Befund mit diesem Status.', 'search') : ui.loading()));
        if (target) {
          var node = document.getElementById('f-' + target);
          if (node) { node.scrollIntoView({ block: 'center' }); node.focus({ preventScroll: true }); target = null; }
        }
      }
      function paintAll() { paintQuestions(); paintFilter(); paintFindings(); }

      host.appendChild(h('div', { cls: 'stack' },
        ui.section('Zielfragen', qHost, h('span', { cls: 'muted small', text: 'Antworten stützen sich nur auf bestätigte Befunde' })),
        ui.section('Befunde', h('div', { cls: 'stack' }, segHost, fHost))));
      paintAll();
      var off = ui.live(['findings', 'answers', 'loaded'], paintAll, 100);
      return {
        dispose: off,
        update: function (r) {
          target = r.query.finding || null;
          if (target) { filter = 'all'; paintFilter(); }
          paintFindings();
        }
      };
    }
  });

  /* =================== Bericht =================== */
  SW.registerTab({
    id: 'report', label: 'Bericht', icon: 'report',
    mount: function (host, ctx) {
      var st = ctx.st;
      var lang = 'de';
      var text = null;
      var seq = 0;
      var out = h('div', { cls: 'report-body' }, ui.loading('Bericht wird erzeugt …'));
      var banner = h('div');
      var dead = false;

      function load() {
        var mine = ++seq;
        api.text('/jobs/' + st.id + '/report', { lang: lang, format: 'md' }).then(function (md) {
          if (dead || mine !== seq) return;
          text = md;
          var running = st.summary && st.summary.status === 'running';
          SW.dom.fill(banner, running ? h('div', { cls: 'notice tone-info', role: 'status' }, icon('info'), h('p', { text: 'Zwischenstand: Der Auftrag läuft noch. Inhalte können sich ändern; der Bericht aktualisiert sich automatisch.' })) : null);
          SW.dom.fill(out, md && md.trim() ? SW.markdown.render(md, { evidenceChip: function (id) { return ui.evidenceChip(st.id, id); } }) : ui.noData('Der Bericht ist noch leer.'));
        }, function (err) {
          if (dead || mine !== seq) return;
          text = null;
          SW.dom.fill(out, err.status === 404 ? ui.noData('Der Bericht wird erzeugt, sobald erste Ergebnisse vorliegen.') : ui.errorBox('Bericht konnte nicht geladen werden: ' + err.message));
        });
      }
      function save() {
        if (!text) return;
        var blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'bericht-' + st.id + '-' + lang + '.md';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      }
      host.appendChild(ui.section('Bericht',
        h('div', { cls: 'stack' }, banner, out),
        h('span', { cls: 'row' },
          ui.seg('Sprache', [['de', 'Deutsch'], ['en', 'English']], lang, function (v) { lang = v; load(); }),
          h('button', { type: 'button', cls: 'btn sm', on: { click: load } }, icon('refresh'), 'Aktualisieren'),
          h('button', { type: 'button', cls: 'btn sm', on: { click: save } }, icon('arrowdown'), 'Als Markdown speichern'))));
      load();
      var off = ui.live(['findings', 'answers', 'jobfinished'], function () { load(); }, 1500);
      return { dispose: function () { dead = true; off(); } };
    }
  });
})();
