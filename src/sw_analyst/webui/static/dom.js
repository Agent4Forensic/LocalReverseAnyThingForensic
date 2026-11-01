/* DOM-Helfer, Icons und Formatierung. Alle Inhalte werden ausschliesslich als Text oder
   ueber setAttribute fuer unkritische Attribute in den DOM geschrieben. */
(function () {
  'use strict';
  var SAFE_API_HREF = /^(?!.*\.\.)(?!.*\/\/)\/api\/[A-Za-z0-9_\-\/.%?=&]*$/;
  var SW = (window.SW = window.SW || {});
  var SVGNS = 'http://www.w3.org/2000/svg';

  /* ---------- Elemente bauen ---------- */
  function addChildren(el, list) {
    for (var i = 0; i < list.length; i++) {
      var c = list[i];
      if (c === null || c === undefined || c === false || c === true) continue;
      if (Array.isArray(c)) addChildren(el, c);
      else if (typeof c === 'object' && c.nodeType) el.appendChild(c);
      else el.appendChild(document.createTextNode(String(c)));
    }
  }

  function applyProps(el, props) {
    for (var key in props) {
      if (!Object.prototype.hasOwnProperty.call(props, key)) continue;
      var val = props[key];
      if (val === null || val === undefined || val === false) continue;
      if (key === 'cls') {
        var cl = Array.isArray(val) ? val.filter(Boolean).join(' ') : String(val);
        if (cl) el.setAttribute('class', cl);
      } else if (key === 'text') {
        el.textContent = String(val);
      } else if (key === 'on') {
        for (var ev in val) {
          if (Object.prototype.hasOwnProperty.call(val, ev)) el.addEventListener(ev, val[ev]);
        }
      } else if (key === 'vars') {
        for (var v in val) {
          if (Object.prototype.hasOwnProperty.call(val, v)) el.style.setProperty(v, String(val[v]));
        }
      } else if (key === 'dataset') {
        for (var d in val) {
          if (Object.prototype.hasOwnProperty.call(val, d)) el.setAttribute('data-' + d, String(val[d]));
        }
      } else if (/^on/i.test(key) || key === 'style' || key === 'src' || key === 'srcdoc') {
        continue; /* bewusst nicht erlaubt */
      } else if (key === 'href') {
        /* Nur Anker im Dashboard (#...) und gleich-originige API-Pfade (Export-Download), nie fremde Ziele. */
        if (typeof val === 'string' && (val.charAt(0) === '#' || SAFE_API_HREF.test(val))) el.setAttribute('href', val);
      } else {
        el.setAttribute(key, val === true ? '' : String(val));
      }
    }
  }

  function h(tag, props) {
    var el = document.createElement(tag);
    if (props) applyProps(el, props);
    addChildren(el, Array.prototype.slice.call(arguments, 2));
    return el;
  }

  function svgEl(tag, attrs) {
    var el = document.createElementNS(SVGNS, tag);
    if (attrs) {
      for (var k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
        var v = attrs[k];
        if (v === null || v === undefined || v === false) continue;
        if (/^on/i.test(k)) continue;
        el.setAttribute(k, String(v));
      }
    }
    addChildren(el, Array.prototype.slice.call(arguments, 2));
    return el;
  }

  function clear(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
    return el;
  }

  function fill(el) {
    clear(el);
    addChildren(el, Array.prototype.slice.call(arguments, 1));
    return el;
  }

  /* Fokus ueber einen Neuaufbau hinweg erhalten (Schluessel in data-key). */
  function keepFocus(container, fn) {
    var key = null;
    var active = document.activeElement;
    if (active && container.contains(active) && active.getAttribute) key = active.getAttribute('data-key');
    fn();
    if (key) {
      var nodes = container.querySelectorAll('[data-key]');
      for (var i = 0; i < nodes.length; i++) {
        if (nodes[i].getAttribute('data-key') === key) {
          nodes[i].focus({ preventScroll: true });
          break;
        }
      }
    }
  }

  /* ---------- Icons (selbst gezeichnet, 24x24, Strich) ---------- */
  var CIRCLE = 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z';
  var ICONS = {
    dashboard: ['M4 4h7v7H4z', 'M13 4h7v4h-7z', 'M13 11h7v9h-7z', 'M4 14h7v6H4z'],
    list: ['M8 6h12M8 12h12M8 18h12', 'M4 6h.01M4 12h.01M4 18h.01'],
    plus: ['M12 5v14M5 12h14'],
    book: ['M4 4h12a2 2 0 0 1 2 2v14H6a2 2 0 0 1-2-2z', 'M8 8h6M8 12h6'],
    shield: ['M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'],
    shieldcheck: ['M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z', 'M8.5 12l2.5 2.5 4.5-5'],
    check: ['M5 12.5l4.5 4.5L19 7.5'],
    x: ['M6 6l12 12M18 6L6 18'],
    clock: [CIRCLE, 'M12 7v5l3 2'],
    play: ['M8 5l11 7-11 7z'],
    circle: [CIRCLE],
    checkcircle: [CIRCLE, 'M8 12.5l3 3 5-6'],
    xcircle: [CIRCLE, 'M9 9l6 6M15 9l-6 6'],
    alertcircle: [CIRCLE, 'M12 8v5M12 16h.01'],
    alert: ['M12 4l9 16H3z', 'M12 10v4M12 17h.01'],
    ban: [CIRCLE, 'M5.6 5.6l12.8 12.8'],
    skip: ['M5 5l9 7-9 7z', 'M18 5v14'],
    stop: ['M6 6h12v12H6z'],
    spinner: ['M12 3a9 9 0 0 1 9 9', 'M12 3a9 9 0 1 0 9 9'],
    chevronright: ['M9 6l6 6-6 6'],
    chevrondown: ['M6 9l6 6 6-6'],
    chart: ['M4 20V4', 'M4 20h16', 'M8 16l4-5 3 3 5-7'],
    tree: ['M4 4h6v4H4z', 'M14 10h6v4h-6z', 'M14 17h6v3h-6z', 'M7 8v10h7M7 12h7'],
    queue: ['M4 6h16M4 12h10M4 18h6', 'M17 14l3 4-3 4'],
    report: ['M7 3h7l5 5v13H7z', 'M14 3v5h5M10 13h6M10 17h6'],
    code: ['M9 7l-5 5 5 5M15 7l5 5-5 5'],
    timeline: ['M4 6h9M9 12h11M6 18h8'],
    terminal: ['M4 5h16v14H4z', 'M7 10l3 2-3 2M12 15h5'],
    live: ['M4 5h16v11H4z', 'M8 20h8M12 16v4', 'M7 11l3-3 3 3 3-3'],
    sun: ['M12 8a4 4 0 1 0 0 8a4 4 0 1 0 0-8z', 'M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M5 19l1.5-1.5M17.5 6.5L19 5'],
    moon: ['M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z'],
    upload: ['M12 16V4M7 9l5-5 5 5M4 20h16'],
    trash: ['M5 7h14M9 7V4h6v3M7 7l1 13h8l1-13'],
    refresh: ['M20 11a8 8 0 0 0-14-4L4 9M4 4v5h5M4 13a8 8 0 0 0 14 4l2-2M20 20v-5h-5'],
    search: ['M11 4a7 7 0 1 0 0 14a7 7 0 1 0 0-14z', 'M20 20l-4-4'],
    info: [CIRCLE, 'M12 11v5M12 8h.01'],
    cpu: ['M7 7h10v10H7z', 'M10 10h4v4h-4z', 'M9 3v4M15 3v4M9 17v4M15 17v4M3 9h4M3 15h4M17 9h4M17 15h4'],
    link: ['M10 14a4 4 0 0 0 5.6 0l3-3a4 4 0 0 0-5.6-5.6l-1 1', 'M14 10a4 4 0 0 0-5.6 0l-3 3a4 4 0 0 0 5.6 5.6l1-1'],
    hash: ['M5 9h14M5 15h14M10 4L8 20M16 4l-2 16'],
    question: [CIRCLE, 'M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 1-1 1.7M12 17h.01'],
    server: ['M4 5h16v5H4z', 'M4 14h16v5H4z', 'M8 7.5h.01M8 16.5h.01'],
    file: ['M7 3h7l5 5v13H7z', 'M14 3v5h5'],
    lock: ['M6 11h12v9H6z', 'M8 11V8a4 4 0 0 1 8 0v3'],
    pulse: ['M3 12h4l2-6 4 12 2-6h6'],
    menu: ['M4 7h16M4 12h16M4 17h16'],
    arrowup: ['M12 19V5M6 11l6-6 6 6'],
    arrowdown: ['M12 5v14M6 13l6 6 6-6'],
    wrap: ['M4 7h16M4 12h12a3 3 0 0 1 0 6h-3M4 18h5', 'M13 16l-2 2 2 2']
  };

  function icon(name, opts) {
    opts = opts || {};
    var size = opts.size || 16;
    var svg = svgEl('svg', {
      viewBox: '0 0 24 24',
      width: size,
      height: size,
      class: 'icon' + (opts.cls ? ' ' + opts.cls : ''),
      'aria-hidden': 'true',
      focusable: 'false'
    });
    var paths = ICONS[name] || ICONS.circle;
    for (var i = 0; i < paths.length; i++) svg.appendChild(svgEl('path', { d: paths[i] }));
    return svg;
  }

  /* ---------- Formatierung ---------- */
  function pad2(n) {
    return n < 10 ? '0' + n : String(n);
  }

  function duration(ms) {
    if (ms === null || ms === undefined || isNaN(ms)) return '–';
    ms = Math.max(0, Math.round(ms));
    if (ms < 1000) return ms + ' ms';
    if (ms < 60000) return (ms / 1000).toFixed(1).replace('.', ',') + ' s';
    var s = Math.round(ms / 1000);
    if (s < 3600) return Math.floor(s / 60) + ' min ' + pad2(s % 60) + ' s';
    return Math.floor(s / 3600) + ' h ' + pad2(Math.floor((s % 3600) / 60)) + ' min';
  }

  var dtf = null;
  var tf = null;
  try {
    dtf = new Intl.DateTimeFormat('de-DE', { dateStyle: 'medium', timeStyle: 'medium' });
    tf = new Intl.DateTimeFormat('de-DE', { timeStyle: 'medium' });
  } catch (e) {
    dtf = null;
    tf = null;
  }

  function dateTime(iso) {
    if (!iso) return '–';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return dtf ? dtf.format(d) : d.toISOString();
  }

  function time(iso) {
    if (!iso) return '–';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return tf ? tf.format(d) : d.toISOString().slice(11, 19);
  }

  function bytes(n) {
    if (n === null || n === undefined || isNaN(n)) return '–';
    if (n < 1024) return n + ' B';
    var units = ['KiB', 'MiB', 'GiB'];
    var v = n / 1024;
    var i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return v.toFixed(v < 10 ? 2 : 1).replace('.', ',') + ' ' + units[i];
  }

  function shortHash(hash, n) {
    if (!hash) return '–';
    n = n || 12;
    return hash.length > n ? hash.slice(0, n) + '…' : hash;
  }

  function percent(p) {
    if (p === null || p === undefined || isNaN(p)) return '0 %';
    return Math.round(p) + ' %';
  }

  /* ---------- Status-Katalog (Text + Icon + Ton) ---------- */
  var STATUS = {
    pending: { label: 'Wartend', tone: 'neutral', icon: 'circle' },
    queued: { label: 'In Warteschlange', tone: 'neutral', icon: 'clock' },
    uploading: { label: 'Wird übertragen', tone: 'neutral', icon: 'upload' },
    running: { label: 'Läuft', tone: 'info', icon: 'spinner' },
    done: { label: 'Erledigt', tone: 'ok', icon: 'checkcircle' },
    partial: { label: 'Teilweise', tone: 'warn', icon: 'alertcircle' },
    failed: { label: 'Fehlgeschlagen', tone: 'err', icon: 'xcircle' },
    cancelled: { label: 'Abgebrochen', tone: 'neutral', icon: 'stop' },
    skipped: { label: 'Übersprungen', tone: 'neutral', icon: 'skip' },
    blocked: { label: 'Blockiert', tone: 'err', icon: 'ban' },
    confirmed: { label: 'Bestätigt', tone: 'ok', icon: 'checkcircle' },
    hypothesis: { label: 'Hypothese', tone: 'warn', icon: 'question' },
    open: { label: 'Offen', tone: 'info', icon: 'circle' },
    rejected: { label: 'Verworfen', tone: 'err', icon: 'xcircle' },
    answered: { label: 'Beantwortet', tone: 'ok', icon: 'checkcircle' },
    unresolved: { label: 'Ungeklärt', tone: 'warn', icon: 'alertcircle' },
    ok: { label: 'OK', tone: 'ok', icon: 'check' },
    error: { label: 'Fehler', tone: 'err', icon: 'xcircle' },
    low: { label: 'Niedrig', tone: 'neutral', icon: 'info' },
    medium: { label: 'Mittel', tone: 'warn', icon: 'alert' },
    high: { label: 'Hoch', tone: 'err', icon: 'alert' },
    flagged: { label: 'Markiert', tone: 'warn', icon: 'alert' },
    redacted: { label: 'Geschärzt', tone: 'info', icon: 'lock' }
  };
  STATUS.redacted.label = 'Geschwärzt';

  var ORIGIN = {
    triage: 'Triage',
    recipe: 'Rezept',
    question: 'Zielfrage',
    split: 'Zerlegung',
    evaluator: 'Selbstbewertung',
    prioritizer: 'Priorisierer',
    planner: 'Planer',
    user: 'Nutzer'
  };

  var STEP_KIND = {
    prompt: 'Prompt',
    tool: 'Werkzeug',
    guard: 'Schutz',
    verify: 'Prüfung',
    evaluate: 'Bewertung',
    prioritize: 'Priorisierung',
    translate: 'Übersetzung',
    system: 'System'
  };

  var ANN_KIND = { finding: 'Befund', note: 'Notiz', ioc: 'IOC', warning: 'Warnung' };

  function statusInfo(key) {
    return STATUS[key] || { label: String(key || '–'), tone: 'neutral', icon: 'circle' };
  }

  function statusIcon(key, size) {
    var info = statusInfo(key);
    return icon(info.icon, { size: size || 16, cls: 'st-icon tone-' + info.tone + (key === 'running' ? ' is-spin' : '') });
  }

  function badge(key, label) {
    var info = statusInfo(key);
    return h('span', { cls: 'badge tone-' + info.tone }, icon(info.icon, { size: 13, cls: key === 'running' ? 'is-spin' : '' }), h('span', { text: label || info.label }));
  }

  function tag(text, tone) {
    return h('span', { cls: 'tag' + (tone ? ' tone-' + tone : ''), text: text });
  }

  function textDe(obj, base) {
    if (!obj) return '';
    return obj[base + '_de'] || obj[base + '_en'] || '';
  }

  SW.dom = {
    h: h,
    svg: svgEl,
    clear: clear,
    fill: fill,
    keepFocus: keepFocus,
    icon: icon
  };
  SW.fmt = {
    duration: duration,
    dateTime: dateTime,
    time: time,
    bytes: bytes,
    shortHash: shortHash,
    percent: percent,
    statusInfo: statusInfo,
    statusIcon: statusIcon,
    badge: badge,
    tag: tag,
    textDe: textDe,
    ORIGIN: ORIGIN,
    STEP_KIND: STEP_KIND,
    ANN_KIND: ANN_KIND
  };

  /* Sekundentakt fuer laufende Zeitangaben: Elemente mit class js-elapsed und data-since. */
  window.setInterval(function () {
    var nodes = document.querySelectorAll('.js-elapsed');
    var now = Date.now();
    for (var i = 0; i < nodes.length; i++) {
      var since = Date.parse(nodes[i].getAttribute('data-since'));
      if (!isNaN(since)) nodes[i].textContent = duration(now - since);
    }
  }, 1000);

  SW.elapsed = function (iso) {
    var ms = iso ? Date.now() - Date.parse(iso) : null;
    return h('span', { cls: 'js-elapsed', 'data-since': iso || '', text: duration(ms) });
  };
})();
