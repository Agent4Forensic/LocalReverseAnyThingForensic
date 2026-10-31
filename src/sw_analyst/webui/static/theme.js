/* Theme-Vorbelegung: wird synchron im Head geladen, damit kein Aufblitzen entsteht. */
(function () {
  'use strict';
  var mode = null;
  try {
    mode = window.localStorage.getItem('sw.theme');
  } catch (e) {
    mode = null;
  }
  if (mode === 'light' || mode === 'dark') {
    document.documentElement.setAttribute('data-theme', mode);
  }
})();
