// Progressive enhancement only: copy buttons and filter-as-you-type. Core flows work without JS.
document.querySelectorAll('pre[data-copy]').forEach(function (pre) {
  var b = document.createElement('button'); b.type = 'button'; b.className = 'secondary'; b.textContent = 'Copy';
  b.addEventListener('click', function () { navigator.clipboard.writeText(pre.textContent).then(function () { b.textContent = 'Copied'; setTimeout(function () { b.textContent = 'Copy'; }, 1500); }); });
  pre.after(b);
});
document.querySelectorAll('input[data-filter]').forEach(function (inp) {
  var tbl = document.querySelector(inp.dataset.filter); if (!tbl) return;
  inp.addEventListener('input', function () {
    var q = inp.value.toLowerCase();
    tbl.querySelectorAll('tbody tr').forEach(function (tr) { tr.hidden = q && tr.textContent.toLowerCase().indexOf(q) < 0; });
  });
});
