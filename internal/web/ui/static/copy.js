// Copy buttons: <button data-copy="ID" data-copied="Copied" hidden>. The
// button copies the value (or text) of the element with that id. Without
// JavaScript the button stays hidden and the text can be selected.
(function () {
  'use strict';
  document.addEventListener('DOMContentLoaded', function () {
    if (!navigator.clipboard) return;
    document.querySelectorAll('button[data-copy]').forEach(function (btn) {
      btn.hidden = false;
      btn.addEventListener('click', function () {
        var el = document.getElementById(btn.dataset.copy);
        if (!el) return;
        var text = el.value !== undefined ? el.value : el.textContent;
        navigator.clipboard.writeText(text).then(function () {
          var note = document.getElementById(btn.dataset.copy + '-copied');
          if (note) note.textContent = btn.dataset.copied || '';
        });
      });
    });
  });
})();
