(function () {
  var THEME_KEY = 'cc-theme', root = document.documentElement, btn = document.getElementById('theme');
  function applyTheme(t) { root.setAttribute('data-theme', t); btn.textContent = t === 'dark' ? '☀️' : '☽'; }
  var saved = 'light';
  try { saved = localStorage.getItem(THEME_KEY) || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'); } catch (e) {}
  applyTheme(saved);
  btn.addEventListener('click', function () {
    var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
    applyTheme(next);
  });
})();
