/* Tab Code: Weiterleitung auf den gemeinsamen Tab "Analyse" (view_analysis.js). Der Tab bleibt registriert,
   damit alte Links (#/job/<id>/code?file=...&line=...) weiter funktionieren. */
(function () {
  'use strict';
  var SW = (window.SW = window.SW || {});
  SW.registerTab({
    id: 'code', label: 'Code', icon: 'code',
    mount: function (host, ctx) {
      var q = {};
      var src = ctx.route.query || {};
      Object.keys(src).forEach(function (k) { q[k] = src[k]; });
      if (q.file && !q.path) { q.path = q.file; }
      delete q.file;
      if (q.mode === 'lern') { q.view = 'ghidra'; q.lern = '1'; }
      delete q.mode;
      SW.dom.fill(host, SW.ui.loading('Weiter zum Tab Analyse …'));
      SW.ui.go(SW.ui.tabHref(ctx.jobId, 'analysis', q));
      return { dispose: function () {} };
    }
  });
})();
