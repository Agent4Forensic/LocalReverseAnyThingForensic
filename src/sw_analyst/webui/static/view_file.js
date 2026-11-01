/* Tab Datei: Weiterleitung auf den gemeinsamen Tab "Analyse" (view_analysis.js). Der Tab bleibt registriert,
   damit alte Links (#/job/<id>/file?path=...) weiter funktionieren. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  SW.registerTab({
    id: 'file', label: 'Datei', icon: 'file',
    mount: function (host, ctx) {
      var q = {};
      var src = ctx.route.query || {};
      Object.keys(src).forEach(function (k) { q[k] = src[k]; });
      if (q.file && !q.path) { q.path = q.file; }
      delete q.file;
      SW.dom.fill(host, SW.ui.loading('Weiter zum Tab Analyse …'));
      SW.ui.go(SW.ui.tabHref(ctx.jobId, 'analysis', q));
      return { dispose: function () {} };
    }
  });
})();
