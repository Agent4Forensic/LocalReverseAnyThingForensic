/* API-Zugriff (nur same-origin unter /api) mit Umschaltung auf die eingebaute Mock-API. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});

  var isMock = /(^|[?&])mock=1(&|$)/.test(window.location.search || '');
  var EVENT_TYPES = ['job', 'task', 'step', 'finding', 'answer', 'annotation', 'guard', 'log'];

  function ApiError(status, code, message) {
    this.name = 'ApiError';
    this.status = status;
    this.code = code || 'error';
    this.message = message || 'Unbekannter Fehler';
  }
  ApiError.prototype = Object.create(Error.prototype);

  function buildUrl(path, query) {
    var url = '/api' + path;
    if (query) {
      var parts = [];
      for (var k in query) {
        if (!Object.prototype.hasOwnProperty.call(query, k)) continue;
        if (query[k] === null || query[k] === undefined || query[k] === '') continue;
        parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(String(query[k])));
      }
      if (parts.length) url += '?' + parts.join('&');
    }
    return url;
  }

  function failFrom(resp) {
    return resp.text().then(
      function (body) {
        var code = 'http_' + resp.status;
        var msg = 'HTTP ' + resp.status;
        try {
          var j = JSON.parse(body);
          if (j && j.error) {
            code = j.error.code || code;
            msg = j.error.message || msg;
          }
        } catch (e) {
          /* kein JSON */
        }
        throw new ApiError(resp.status, code, msg);
      },
      function () {
        throw new ApiError(resp.status, 'http_' + resp.status, 'HTTP ' + resp.status);
      }
    );
  }

  function netError() {
    return new ApiError(0, 'network', 'Server nicht erreichbar');
  }

  function request(method, path, query, body, wantText, contentType) {
    if (isMock) return SW.mock.request(method, path, query || {}, body, wantText);
    var opts = { method: method, headers: { Accept: wantText ? 'text/markdown, text/plain' : 'application/json' }, credentials: 'same-origin' };
    if (contentType) opts.headers['Content-Type'] = contentType;
    if (body) opts.body = body;
    return fetch(buildUrl(path, query), opts).then(
      function (resp) {
        if (!resp.ok) return failFrom(resp);
        return wantText ? resp.text() : resp.json();
      },
      function () {
        throw netError();
      }
    );
  }

  /* handlers: { onOpen(), onError(), onEvent(envelope) } */
  function openStream(path, after, handlers) {
    if (isMock) return SW.mock.openStream(path, after, handlers);
    var es = new EventSource(buildUrl(path, after ? { after: after } : null));
    es.addEventListener('open', function () {
      handlers.onOpen();
    });
    es.addEventListener('error', function () {
      handlers.onError(es.readyState === 2);
    });
    EVENT_TYPES.forEach(function (type) {
      es.addEventListener(type, function (ev) {
        var env = null;
        try {
          env = JSON.parse(ev.data);
        } catch (e) {
          return;
        }
        if (env && typeof env === 'object') {
          if (!env.type) env.type = type;
          handlers.onEvent(env);
        }
      });
    });
    return {
      close: function () {
        es.close();
      }
    };
  }

  SW.api = {
    isMock: isMock,
    ApiError: ApiError,
    EVENT_TYPES: EVENT_TYPES,
    get: function (path, query) {
      return request('GET', path, query, null, false);
    },
    text: function (path, query) {
      return request('GET', path, query, null, true);
    },
    post: function (path, body) {
      return request('POST', path, null, body || null, false);
    },
    postJson: function (path, obj) {
      return request('POST', path, null, JSON.stringify(obj || {}), false, 'application/json');
    },
    /* Same-origin download link (export). Only paths under /api, built from encoded parts. */
    href: function (path, query) {
      return buildUrl(path, query);
    },
    openStream: openStream
  };
})();
