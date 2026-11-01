/* Tab Dynamische Analyse (ADR-0005): Status, Voraussetzungen, Luecken (GAP-Befunde) und Laeufe. Freigabe je Lauf schreibt nur
   ein Paket fuer den getrennten Detonationsrechner; diese Oberflaeche startet nichts. Texte nur als Textknoten. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var h = SW.dom.h;
  var icon = SW.dom.icon;
  var api = SW.api;
  var ui = SW.ui;

  var STATUS = { not_executed: 'nicht ausgeführt', approved: 'freigegeben', packaged: 'Paket bereit', imported: 'Ergebnis eingelesen', failed: 'fehlgeschlagen' };

  function approveForm(st, g, p, reload) {
    var msg = h('div', { role: 'status' });
    var idBase = 'run-' + g.finding_id;
    var profile = h('select', { id: idBase + '-p' }, (p.profiles || []).map(function (x) { return h('option', { value: x.id, text: x.label }); }));
    var reason = h('input', { type: 'text', id: idBase + '-r', maxlength: '500', autocomplete: 'off', placeholder: 'Wozu dieser Lauf, mindestens 10 Zeichen' });
    var go = h('button', { type: 'button', cls: 'btn', on: { click: function () {
      go.disabled = true;
      api.postJson('/jobs/' + st.id + '/dynamic/runs', { finding_id: g.finding_id, profile: profile.value, reason: reason.value.trim() }).then(reload, function (err) {
        go.disabled = false;
        SW.dom.fill(msg, ui.errorBox('Nicht freigegeben: ' + err.message));
      });
    } } }, icon('play'), 'Lauf freigeben, Paket erzeugen');
    return h('div', { cls: 'stack' },
      h('div', { cls: 'field' }, h('label', { for: idBase + '-p', text: 'Profil' }), profile),
      h('div', { cls: 'field' }, h('label', { for: idBase + '-r', text: 'Begründung' }), reason),
      h('div', { cls: 'row' }, go), msg);
  }

  function runCard(st, r, enabled, reload) {
    var msg = h('div', { role: 'status' });
    var out = h('input', { type: 'file', id: 'res-o-' + r.id, accept: '.vhd' });
    var log = h('input', { type: 'file', id: 'res-l-' + r.id, accept: '.json' });
    var send = h('button', { type: 'button', cls: 'btn', on: { click: function () {
      if (!out.files[0] || !log.files[0]) { SW.dom.fill(msg, ui.errorBox('Bitte output.vhd und run-log.json wählen.')); return; }
      var fd = new FormData();
      fd.append('output', out.files[0], 'output.vhd');
      fd.append('run_log', log.files[0], 'run-log.json');
      send.disabled = true;
      SW.dom.fill(msg, ui.loading('Ergebnis wird geprüft …'));
      api.post('/jobs/' + st.id + '/dynamic/runs/' + r.id + '/result', fd).then(reload, function (err) {
        send.disabled = false;
        SW.dom.fill(msg, ui.errorBox('Abgelehnt: ' + err.message));
      });
    } } }, icon('upload'), 'Ergebnis einlesen');
    return h('article', { cls: 'fcard' },
      h('div', { cls: 'row' }, h('span', { cls: 'mono fid', text: r.id }), h('span', { cls: 'badge tone-neutral', text: STATUS[r.status] || r.status }), h('span', { cls: 'muted small', text: r.profile })),
      h('p', { text: r.reason }),
      h('dl', { cls: 'kv' },
        h('dt', { text: 'Paket' }), h('dd', { cls: 'mono', text: r.folder || '–' }),
        h('dt', { text: 'input.vhd SHA-256' }), h('dd', { cls: 'mono', text: r.input_sha256 || '–' }),
        r.evidence_id ? h('dt', { text: 'Beleg' }) : null, r.evidence_id ? h('dd', { cls: 'mono', text: r.evidence_id }) : null,
        r.clock_offset_s !== null && r.clock_offset_s !== undefined ? h('dt', { text: 'Uhrversatz' }) : null,
        r.clock_offset_s !== null && r.clock_offset_s !== undefined ? h('dd', { text: r.clock_offset_s + ' s' }) : null),
      r.status === 'packaged' && enabled ? h('div', { cls: 'stack' },
        h('p', { cls: 'hint', text: 'Ordner auf den Detonationsrechner tragen und dort infra\\detonation\\Invoke-DetonationRun.ps1 starten (docs/runbooks/detonation.md). Danach beide Dateien hier einlesen. Die Datei wird nur als Bytes gelesen, nie eingehängt.' }),
        h('div', { cls: 'field' }, h('label', { for: out.id, text: 'output.vhd' }), out),
        h('div', { cls: 'field' }, h('label', { for: log.id, text: 'run-log.json' }), log),
        h('div', { cls: 'row' }, send), msg) : null);
  }

  function gapCard(st, g, p, reload) {
    function row(label, val, mono) {
      return val ? [h('dt', { text: label }), h('dd', { cls: mono ? 'mono' : null, text: val })] : [];
    }
    return h('article', { cls: 'fcard f-hypothesis dy-gap' },
      h('div', { cls: 'row' }, h('a', { cls: 'mono fid', href: ui.tabHref(st.id, 'report', { finding: g.finding_id }), text: g.finding_id }),
        h('span', { cls: 'badge tone-neutral' }, icon('clock', { size: 13 }), STATUS[g.status] || g.status)),
      h('p', { cls: 'fstmt', text: g.what || 'Lücke ohne nähere Beschreibung' }),
      h('dl', { cls: 'kv' }, [].concat(row('Würde geklärt durch', g.close_by), row('Frage', g.question), row('Eingabe', g.input, true))),
      p.enabled && g.status === 'not_executed' ? approveForm(st, g, p, reload) : null);
  }

  SW.registerTab({
    id: 'dynamic', label: 'Dynamische Analyse', icon: 'cpu',
    mount: function (host, ctx) {
      var st = ctx.st;
      var body = h('div', { cls: 'stack' }, ui.loading());
      var dead = false;
      var seq = 0;
      function load() {
        var mine = ++seq;
        api.get('/jobs/' + st.id + '/dynamic').then(function (p) {
          if (dead || mine !== seq) return;
          var reqs = Array.isArray(p.requirements) ? p.requirements : [];
          var gaps = Array.isArray(p.gaps) ? p.gaps : [];
          var runs = Array.isArray(p.runs) ? p.runs : [];
          var emu = p.emulation || {};
          SW.dom.fill(body, [
            h('div', { cls: 'notice tone-warn', role: 'status' }, icon('alertcircle'),
              h('p', null, h('strong', { text: p.enabled ? 'Schalter an' : 'Schalter aus' }), ' – ' + (p.enabled ? 'Läufe nur je Freigabe und nur auf dem Detonationsrechner' : (p.reason || 'nicht ausgeführt')))),
            h('p', { cls: 'muted small', text: 'Emulation in diesem Auftrag: ' + (emu.opted_in ? 'freigegeben, ' + (emu.calls || 0) + ' Aufruf(e)' : 'nicht freigegeben') }),
            ui.section('Voraussetzungen für einen Lauf',
              reqs.length ? h('ul', { cls: 'md-list' }, reqs.map(function (r) { return h('li', { text: r }); })) : ui.noData('Keine Angaben.')),
            ui.section('Lücken, die nur ein Lauf klärt (' + gaps.length + ')',
              gaps.length ? h('div', { cls: 'stack' }, gaps.map(function (g) { return gapCard(st, g, p, load); }))
                : ui.empty('Keine Lücken gemeldet', 'Die statische Analyse hat keinen Punkt als „nur dynamisch klärbar“ markiert (GAP-Befund).', 'check'),
              h('span', { cls: 'muted small', text: 'Hier startet nichts' })),
            runs.length ? ui.section('Läufe (' + runs.length + ')', h('div', { cls: 'stack' }, runs.map(function (r) { return runCard(st, r, p.enabled, load); }))) : null
          ]);
        }, function (err) {
          if (dead || mine !== seq) return;
          SW.dom.fill(body, err.status === 404 ? ui.noData('Für diesen Server liegt kein Plan zur dynamischen Analyse vor.') : ui.errorBox('Plan konnte nicht geladen werden: ' + err.message));
        });
      }
      host.appendChild(ui.section('Dynamische Analyse', body));
      load();
      var off = ui.live(['findings', 'jobfinished'], load, 1500);
      return { dispose: function () { dead = true; off(); } };
    }
  });
})();
