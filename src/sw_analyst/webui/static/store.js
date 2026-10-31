/* Zustand: Systemstatus, Jobliste und der aktuell geoeffnete Job (inkrementell per SSE,
   Fallback Polling alle 3 s). Ansichten abonnieren Aenderungen ueber store.on(fn). */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  var api = SW.api;

  var listeners = [];
  var state = { system: null, systemError: null, jobs: [], jobsLoaded: false, prompts: null };
  var cur = null;
  var globalTimer = null;
  var FRESH_MS = 6000;

  function on(fn) {
    listeners.push(fn);
    return function () {
      listeners = listeners.filter(function (f) {
        return f !== fn;
      });
    };
  }
  function emit(kind, payload) {
    listeners.slice().forEach(function (fn) {
      try {
        fn(kind, payload);
      } catch (e) {
        if (window.console) window.console.error(e);
      }
    });
  }

  /* ---------- Global: System und Jobliste ---------- */
  function refreshGlobal() {
    var p1 = api.get('/system').then(
      function (sys) {
        state.system = sys;
        state.systemError = null;
        emit('system');
      },
      function (err) {
        state.systemError = err.message || 'Fehler';
        emit('system');
      }
    );
    var p2 = api.get('/jobs').then(
      function (list) {
        state.jobs = Array.isArray(list) ? list : [];
        state.jobsLoaded = true;
        emit('jobs');
      },
      function () {
        emit('jobs');
      }
    );
    return Promise.all([p1, p2]);
  }

  function startGlobal() {
    if (globalTimer) return;
    refreshGlobal();
    globalTimer = window.setInterval(function () {
      if (!document.hidden) refreshGlobal();
    }, 4000);
  }

  /* ---------- Job-Zustand ---------- */
  function createJobState(id) {
    return {
      id: id, loaded: false, error: null, summary: null, spec: null, progress: null, totals: null,
      tasks: new Map(), queue: [], findings: [], answers: [], guard: [], audit: null, files: null,
      evidenceList: null, log: [], logSeen: new Set(), lastSeq: 0, steps: new Map(), annots: new Map(),
      fresh: new Map(), conn: 'connecting', stream: null, pollTimer: null, reopenTimer: null, auxTimer: null,
      auditTimer: null, destroyed: false
    };
  }

  function flatten(st, nodes) {
    nodes.forEach(function (n) {
      var copy = Object.assign({}, n);
      var kids = copy.children;
      delete copy.children;
      st.tasks.set(copy.id, copy);
      if (kids && kids.length) flatten(st, kids);
    });
  }

  function upsertBy(list, key, obj) {
    for (var i = 0; i < list.length; i++) {
      if (list[i][key] === obj[key]) {
        list[i] = obj;
        return false;
      }
    }
    list.push(obj);
    return true;
  }

  function markFresh(st, key) {
    st.fresh.set(key, Date.now());
  }
  function freshAge(st, key) {
    var t = st && st.fresh.get(key);
    if (!t) return null;
    var age = Date.now() - t;
    return age < FRESH_MS ? age : null;
  }

  function addLog(st, entry) {
    if (st.logSeen.has(entry.seq)) return false;
    st.logSeen.add(entry.seq);
    st.log.push(entry);
    if (entry.seq > st.lastSeq) st.lastSeq = entry.seq;
    if (st.log.length > 3000) {
      var old = st.log.shift();
      st.logSeen.delete(old.seq);
    }
    return true;
  }

  function loadDetail(st) {
    return api.get('/jobs/' + st.id).then(function (d) {
      if (st.destroyed) return;
      st.summary = d.summary;
      st.importInfo = d['import'] || null;
      st.spec = d.spec;
      st.progress = d.progress;
      st.totals = d.totals;
      emit('summary');
    });
  }
  function loadQueue(st) {
    return api.get('/jobs/' + st.id + '/queue').then(function (q) {
      if (st.destroyed) return;
      st.queue = q || [];
      emit('queue');
    });
  }

  function loadAll(st, light) {
    var jobs = '/jobs/' + st.id;
    var reqs = [
      loadDetail(st),
      api.get(jobs + '/tree').then(function (tree) {
        if (st.destroyed) return;
        st.tasks = new Map();
        flatten(st, tree || []);
        emit('tasks');
      }),
      loadQueue(st),
      api.get(jobs + '/findings').then(function (f) {
        if (st.destroyed) return;
        st.findings = f || [];
        emit('findings');
      }),
      api.get(jobs + '/answers').then(function (a) {
        if (st.destroyed) return;
        st.answers = a || [];
        emit('answers');
      }),
      api.get(jobs + '/guard').then(function (g) {
        if (st.destroyed) return;
        st.guard = g || [];
        emit('guard');
      }),
      api.get(jobs + '/audit').then(function (a) {
        if (st.destroyed) return;
        st.audit = a;
        emit('audit');
      }),
      api.get(jobs + '/log', { after: light ? st.lastSeq : 0, level: 'debug' }).then(function (l) {
        if (st.destroyed) return;
        var added = false;
        (l.events || []).forEach(function (e) {
          if (addLog(st, e)) added = true;
        });
        if (l.last_seq > st.lastSeq) st.lastSeq = l.last_seq;
        if (added) emit('log');
      })
    ];
    if (!light) {
      reqs.push(
        api.get(jobs + '/files').then(function (f) {
          if (st.destroyed) return;
          st.files = f || [];
          emit('files');
        })
      );
    }
    return Promise.all(reqs).then(
      function () {
        st.loaded = true;
        st.error = null;
        emit('loaded');
      },
      function (err) {
        if (st.destroyed) return;
        st.error = err.message || 'Fehler beim Laden';
        st.loaded = true;
        emit('loaded');
      }
    );
  }

  function scheduleAux(st) {
    if (st.auxTimer) return;
    st.auxTimer = window.setTimeout(function () {
      st.auxTimer = null;
      if (st.destroyed) return;
      loadDetail(st).catch(function () {});
      loadQueue(st).catch(function () {});
    }, 600);
  }
  function scheduleAudit(st) {
    if (st.auditTimer) return;
    st.auditTimer = window.setTimeout(function () {
      st.auditTimer = null;
      if (st.destroyed) return;
      api.get('/jobs/' + st.id + '/audit').then(function (a) {
        st.audit = a;
        emit('audit');
      }, function () {});
    }, 800);
  }

  function applyEvent(st, env) {
    if (env.seq && env.seq > st.lastSeq) st.lastSeq = env.seq;
    var d = env.data;
    if (!d) return;
    switch (env.type) {
      case 'job':
        var prev = st.summary && st.summary.status;
        st.summary = Object.assign({}, st.summary || {}, d);
        emit('summary');
        scheduleAux(st);
        if (prev && prev !== d.status && d.status !== 'running') {
          loadAll(st, true);
          emit('jobfinished');
        }
        break;
      case 'task':
        var t = Object.assign({}, st.tasks.get(d.id) || {}, d);
        delete t.children;
        st.tasks.set(d.id, t);
        emit('tasks', d.id);
        scheduleAux(st);
        break;
      case 'step':
        var arr = st.steps.get(d.task_id) || [];
        upsertBy(arr, 'id', d);
        st.steps.set(d.task_id, arr);
        emit('step', d.task_id);
        break;
      case 'finding':
        upsertBy(st.findings, 'id', d);
        markFresh(st, 'f:' + d.id);
        emit('findings', d.id);
        break;
      case 'answer':
        upsertBy(st.answers, 'question_id', d);
        markFresh(st, 'a:' + d.question_id);
        emit('answers', d.question_id);
        break;
      case 'annotation':
        st.annots.set(d.id, d);
        markFresh(st, 'n:' + d.id);
        emit('annotation', d);
        break;
      case 'guard':
        upsertBy(st.guard, 'id', d);
        markFresh(st, 'g:' + d.id);
        emit('guard', d.id);
        scheduleAudit(st);
        break;
      case 'log':
        /* Stufe und Text stehen im Umschlag des Ereignisses (api.md, Live-Stream), env.data ist nur die Nutzlast. */
        if (addLog(st, { seq: env.seq, ts: env.ts, level: env.level || 'info', type: env.type, message: env.message || '', data: d })) emit('log');
        break;
      default:
        break;
    }
  }

  /* ---------- Stream und Fallback ---------- */
  function setConn(st, conn) {
    if (st.conn === conn) return;
    st.conn = conn;
    emit('conn');
  }
  function stopPoll(st) {
    if (st.pollTimer) {
      window.clearInterval(st.pollTimer);
      st.pollTimer = null;
    }
  }
  function startPoll(st) {
    if (st.pollTimer) return;
    st.pollTimer = window.setInterval(function () {
      if (!document.hidden) loadAll(st, true);
    }, 3000);
  }
  function openStream(st) {
    if (st.destroyed) return;
    if (st.stream) st.stream.close();
    st.stream = api.openStream('/jobs/' + st.id + '/stream', st.lastSeq, {
      onOpen: function () {
        stopPoll(st);
        if (st.reopenTimer) {
          window.clearTimeout(st.reopenTimer);
          st.reopenTimer = null;
        }
        setConn(st, 'live');
      },
      onError: function (closed) {
        setConn(st, 'polling');
        startPoll(st);
        if (closed && !st.reopenTimer) {
          st.reopenTimer = window.setTimeout(function () {
            st.reopenTimer = null;
            openStream(st);
          }, 6000);
        }
      },
      onEvent: function (env) {
        applyEvent(st, env);
      }
    });
  }

  function openJob(id) {
    if (cur && cur.id === id) return cur;
    closeJob();
    var st = createJobState(id);
    cur = st;
    emit('jobopen');
    loadAll(st, false).then(function () {
      if (st.destroyed) return;
      if (st.error) {
        setConn(st, 'offline');
        return;
      }
      openStream(st);
    });
    return st;
  }

  function closeJob() {
    if (!cur) return;
    var st = cur;
    st.destroyed = true;
    if (st.stream) st.stream.close();
    stopPoll(st);
    [st.reopenTimer, st.auxTimer, st.auditTimer].forEach(function (t) {
      if (t) window.clearTimeout(t);
    });
    cur = null;
    emit('jobclose');
  }

  /* ---------- Lazy-Daten ---------- */
  function ensureEvidenceList(st) {
    return api.get('/jobs/' + st.id + '/evidence').then(function (l) {
      st.evidenceList = l || [];
      emit('evidencelist');
    });
  }

  function loadPrompts() {
    if (state.prompts) return Promise.resolve(state.prompts);
    return api.get('/prompts').then(function (l) {
      state.prompts = l || [];
      return state.prompts;
    });
  }

  function tasksSorted(st) {
    return Array.from(st.tasks.values()).sort(function (a, b) {
      return a.seq - b.seq;
    });
  }

  SW.store = {
    state: state,
    on: on,
    emit: emit,
    startGlobal: startGlobal,
    refreshGlobal: refreshGlobal,
    openJob: openJob,
    closeJob: closeJob,
    current: function () {
      return cur;
    },
    loadAll: loadAll,
    ensureEvidenceList: ensureEvidenceList,
    loadPrompts: loadPrompts,
    freshAge: freshAge,
    tasksSorted: tasksSorted
  };
})();
