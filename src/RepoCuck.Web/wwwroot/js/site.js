// Progressive enhancement only: every core flow works without JavaScript.
(function () {
  // Copy buttons: rendered with the `hidden` attribute and only revealed when scripting is available.
  document.querySelectorAll('button.copy[data-copy-target]').forEach(function (btn) {
    var target = document.querySelector(btn.dataset.copyTarget);
    if (!target) return;
    btn.hidden = false;
    var label = btn.querySelector('.label');
    btn.addEventListener('click', function () {
      var text = (target.dataset.copyText || target.textContent || '').trim();
      var done = function () {
        btn.dataset.state = 'done';
        if (label) label.textContent = 'Copied';
        setTimeout(function () { delete btn.dataset.state; if (label) label.textContent = 'Copy'; }, 1800);
      };
      if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done);
      else {  // plain-HTTP LAN installs have no async clipboard: fall back to a selection copy
        var r = document.createRange(); r.selectNodeContents(target);
        var s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
        try { if (document.execCommand('copy')) done(); } catch (e) { /* selected text can still be copied by hand */ }
      }
    });
  });

  // Filter-as-you-type for client-side lists and tables.
  document.querySelectorAll('input[data-filter]').forEach(function (input) {
    var rows = function () { return document.querySelectorAll(input.dataset.filter); };
    input.addEventListener('input', function () {
      var q = input.value.toLowerCase();
      rows().forEach(function (el) { el.hidden = q !== '' && el.textContent.toLowerCase().indexOf(q) < 0; });
    });
  });
})();
