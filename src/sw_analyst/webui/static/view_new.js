/* Ansicht "Neuer Auftrag": Quelle wählen (Beispiel aus example/ oder eigene Datei), der Rest ist vorausgefüllt.
   Ein Budget gibt es hier nicht: der Server setzt die Obergrenzen, das Ergebnis zählt, nicht die Dauer. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var fmt = SW.fmt;
  var api = SW.api;
  var store = SW.store;
  var ui = SW.ui;

  var MAX_SAMPLE = 64 * 1024 * 1024;
  var OWN = 'own';
  var LEVEL_TONE = { leicht: 'ok', mittel: 'warn', schwer: 'err' };
  var DROP_TEXT = 'Datei hierher ziehen oder auswählen. Maximal 64 MiB. Die Datei wird nie ausgeführt.';

  SW.views.new = function (route) {
    var examples = [];
    var source = null;
    var file = null;
    var qs = [];
    var qid = 0;
    var picks = {};
    var busy = false;

    var pickHost = h('div', { cls: 'picks', role: 'radiogroup', 'aria-labelledby': 'src-h' }, ui.loading('Beispiele werden geladen …'));
    var errBox = h('div', { role: 'alert' });
    var pickMsg = h('div', { role: 'alert' });
    var qHost = h('div', { cls: 'qlist' });
    var fileHost = h('div');
    var submit = h('button', { type: 'submit', cls: 'btn primary' }, icon('play'), 'Analyse starten');

    var f = {
      title: h('input', { type: 'text', id: 'f-title', maxlength: '200', required: true, autocomplete: 'off' }),
      desc: h('textarea', { id: 'f-desc', maxlength: '8000', rows: '3' }),
      ctx: h('textarea', { id: 'f-ctx', maxlength: '8000', rows: '3' }),
      focus: h('input', { type: 'text', id: 'f-focus', maxlength: '2000', autocomplete: 'off' })
    };

    /* ---- eigene Datei ---- */
    var dropInfo = h('p', { cls: 'drop-info muted', text: DROP_TEXT });
    var fileInput = h('input', { type: 'file', id: 'f-sample', cls: 'sr-only', tabindex: '-1' });
    var drop = h('div', { cls: 'drop', role: 'button', tabindex: '0', 'aria-describedby': 'drop-hint', 'aria-label': 'Datei auswählen oder ablegen' },
      icon('upload', { size: 26 }), h('div', { id: 'drop-hint' }, h('strong', { text: 'Datei ablegen' }), dropInfo), fileInput);

    function setFile(fl) {
      if (fl && fl.size > MAX_SAMPLE) {
        file = null;
        SW.dom.fill(dropInfo, 'Die Datei ist größer als 64 MiB und wird abgelehnt.');
        drop.classList.add('is-bad');
        drop.classList.remove('has-file');
        return;
      }
      file = fl || null;
      drop.classList.remove('is-bad');
      SW.dom.fill(dropInfo, file ? file.name + ' · ' + fmt.bytes(file.size) : DROP_TEXT);
      drop.classList.toggle('has-file', !!file);
    }
    drop.addEventListener('click', function () { fileInput.click(); });
    drop.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
    fileInput.addEventListener('change', function () { setFile(fileInput.files[0]); });
    ['dragenter', 'dragover'].forEach(function (t) { drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.add('is-over'); }); });
    ['dragleave', 'drop'].forEach(function (t) { drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.remove('is-over'); }); });
    drop.addEventListener('drop', function (e) { if (e.dataTransfer && e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]); });

    /* ---- Zielfragen ---- */
    function addQuestion(text) {
      qs.push({ key: ++qid, text: text || '', expected: '' });
    }
    function paintQs(focusLast) {
      SW.dom.fill(qHost, qs.map(function (q, i) {
        var t = h('input', { type: 'text', id: 'q-t-' + q.key, 'aria-label': 'Zielfrage ' + (i + 1), placeholder: 'z. B. Welche Persistenzmechanismen nutzt die Datei?', maxlength: '2000' });
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

    /* ---- Quelle wählen ---- */
    function pick(id, title, level, text) {
      var input = h('input', { type: 'radio', name: 'source', value: id, cls: 'pick-in' });
      input.addEventListener('change', function () { choose(id); });
      var label = h('label', { cls: 'pick' }, input,
        h('span', { cls: 'pick-b' },
          h('span', { cls: 'pick-t' }, title, level ? h('span', { cls: 'tag tone-' + (LEVEL_TONE[level] || 'neutral'), text: level }) : null),
          h('span', { cls: 'pick-d', text: text })));
      picks[id] = { label: label, input: input };
      return label;
    }

    function choose(id) {
      source = id;
      Object.keys(picks).forEach(function (k) {
        picks[k].label.classList.toggle('is-on', k === id);
        picks[k].input.checked = k === id;
      });
      var ex = examples.filter(function (e) { return e.id === id; })[0];
      qs = [];
      if (ex) {
        f.title.value = ex.title;
        f.desc.value = ex.job_description || '';
        ex.questions.forEach(function (q) { addQuestion(q); });
        setFile(null);
        SW.dom.fill(fileHost, h('p', { cls: 'muted', text: 'Beispieldatei ' + ex.sample_name + ': Sie wird beim Start erzeugt. Sie ist harmlos und wird nie ausgeführt.' }));
      } else {
        f.title.value = '';
        f.desc.value = '';
        addQuestion('');
        SW.dom.fill(fileHost, drop);
      }
      f.ctx.value = '';
      f.focus.value = '';
      paintQs(false);
      form.hidden = false;
      SW.dom.fill(errBox);
    }

    function paintPicks() {
      var nodes = examples.map(function (e) {
        var go = h('button', { type: 'button', cls: 'btn sm pick-go', 'aria-label': 'Beispiel „' + e.title + '“ sofort starten', on: { click: function () { quickStart(e); } } }, icon('play'), 'Sofort starten');
        return h('div', { cls: 'pick-row' }, pick(e.id, e.title, e.level, e.description), go);
      });
      nodes.push(pick(OWN, 'Eigene Datei analysieren', '', 'Eine eigene Datei hochladen und Titel, Beschreibung und Zielfragen selbst angeben.'));
      nodes.push(h('p', { cls: 'hint', text: 'Auswählen füllt das Formular zum Anpassen vor. „Sofort starten“ legt den Auftrag mit Titel, Beschreibung und Zielfragen des Beispiels direkt an.' }));
      SW.dom.fill(pickHost, nodes);
      var want = route && route.query && route.query.example;
      if (want && picks[want]) choose(want);
      else if (!examples.length) choose(OWN);
    }

    /* ---- Formular ---- */
    var form = h('form', { cls: 'stack newjob', novalidate: true, hidden: true },
      h('section', { cls: 'card' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Auftrag' })), h('div', { cls: 'card-b' },
        h('div', { cls: 'field' }, h('label', { for: 'f-title', text: 'Titel *' }), f.title),
        h('div', { cls: 'field' }, h('label', { for: 'f-desc', text: 'Beschreibung' }), f.desc,
          h('span', { cls: 'hint', text: 'Was ist das für eine Datei und was ist der Anlass? Die Eingabe wird intern ins Englische übersetzt.' })),
        h('details', { cls: 'more' }, h('summary', { text: 'Weitere Angaben (optional)' }),
          h('div', { cls: 'field' }, h('label', { for: 'f-ctx', text: 'Weitere Infos' }), f.ctx, h('span', { cls: 'hint', text: 'Fundort, Betriebssystem, bekannte Indikatoren oder Vorabanalysen.' })),
          h('div', { cls: 'field' }, h('label', { for: 'f-focus', text: 'Fokus' }), f.focus, h('span', { cls: 'hint', text: 'Worauf soll die Analyse besonders achten, z. B. Netzwerk, Persistenz, Verschleierung?' }))))),
      h('section', { cls: 'card' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Zielfragen' }),
        h('button', { type: 'button', cls: 'btn sm', on: { click: function () { addQuestion(''); paintQs(true); } } }, icon('plus'), 'Frage hinzufügen')),
        h('div', { cls: 'card-b' }, h('p', { cls: 'hint', text: 'Jede Frage wird als eigene Aufgabe geplant und mit Belegen beantwortet. Eine erwartete Antwort wird nur zum Abgleich genutzt, nicht als Vorgabe.' }), qHost)),
      h('section', { cls: 'card' }, h('div', { cls: 'card-h' }, h('h2', { text: 'Datei' })), h('div', { cls: 'card-b' }, fileHost)),
      errBox,
      h('div', { cls: 'row' }, submit, h('a', { cls: 'btn', href: '/', text: 'Abbrechen' })),
      h('p', { cls: 'hint', text: 'Es gibt keine Zeitvorgabe. Die Analyse arbeitet, bis alle Zielfragen beantwortet sind oder nichts mehr zu tun ist, längstens 24 Stunden.' })
    );

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (busy) return;
      var problems = [];
      if (!source) problems.push('Bitte ein Beispiel oder „Eigene Datei“ wählen.');
      if (!f.title.value.trim()) problems.push('Bitte einen Titel angeben.');
      if (source === OWN && !file) problems.push('Bitte eine Datei auswählen (maximal 64 MiB).');
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
        emulation_opt_in: false
      };
      create(spec, source === OWN ? file : null, source, errBox);
    });

    /* Legt den Auftrag an und öffnet ihn. host zeigt Fortschritt und Fehler. */
    function create(spec, upload, exampleId, host) {
      var fd = new FormData();
      fd.append('spec', JSON.stringify(spec));
      if (upload) fd.append('sample', upload, upload.name);
      else fd.append('example', exampleId);
      busy = true;
      submit.disabled = true;
      SW.dom.fill(host, ui.loading('Auftrag wird angelegt …'));
      api.post('/jobs', fd).then(function (s) {
        busy = false;
        store.refreshGlobal();
        SW.navigate('/job/' + encodeURIComponent(s.id) + '/activity');
      }, function (err) {
        busy = false;
        submit.disabled = false;
        SW.dom.fill(host, ui.errorBox('Der Auftrag wurde nicht angelegt: ' + err.message));
      });
    }

    /* Ein Klick: Beispiel mit Titel, Beschreibung und Zielfragen unverändert starten. */
    function quickStart(ex) {
      if (busy) return;
      create({
        title: ex.title, description: ex.job_description || '', context_info: '', focus: '',
        target_questions: ex.questions.map(function (q) { return { text: q }; }),
        emulation_opt_in: false
      }, null, ex.id, pickMsg);
    }

    ui.softGet('/examples').then(function (r) {
      examples = r.ok && Array.isArray(r.data) ? r.data : [];
      paintPicks();
    });

    var el = h('div', { cls: 'stack narrow' },
      h('div', { cls: 'page-h' }, h('div', { cls: 'grow' }, h('h1', { text: 'Neuer Auftrag' }),
        h('p', { cls: 'page-sub', text: 'Wählen Sie ein Beispiel oder eine eigene Datei. Alles Weitere ist vorausgefüllt und lässt sich anpassen.' }))),
      h('section', { cls: 'card' }, h('div', { cls: 'card-h' }, h('h2', { id: 'src-h', text: 'Womit soll die Analyse beginnen?' })), h('div', { cls: 'card-b' }, pickHost, pickMsg)),
      form
    );
    return { el: el, title: 'Neuer Auftrag' };
  };
})();
