(function () {
  'use strict';
  var PROVIDERS = JSON.parse(document.getElementById('providers').textContent);
  var tabs = document.getElementById('tabs');
  var panel = document.getElementById('panel');
  var current = PROVIDERS[0].id;

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'html') node.innerHTML = attrs[k]; else if (k === 'text') node.textContent = attrs[k]; else node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { node.appendChild(c); });
    return node;
  }

  function section(title, nodes) {
    return el('div', { 'class': 'card' }, [el('h2', { text: title })].concat(nodes));
  }

  function prettyBody(p) {
    if (p.contentType !== 'application/json') return p.body;
    try { return JSON.stringify(JSON.parse(p.body), null, 2); } catch (e) { return p.body; }
  }

  var renderToken = 0;
  var AGES = [['Just now', 0], ['4 minutes ago', 240], ['6 minutes ago', 360], ['1 hour ago', 3600]];
  var lab = { id: null, age: 0, body: '', secret: '', url: '' };
  var TIMED = { stripe: 1, slack: 1, svix: 1 };

  function wrongSecret(p) {
    return p.id === 'svix' ? 'whsec_' + btoa('a-completely-different-key') : p.secret + 'x';
  }
  function tamper(body) {
    var i = body.search(/[0-9A-Za-z]/);
    if (i < 0) return body + 'x';
    return body.slice(0, i) + (body[i] === 'a' ? 'b' : 'a') + body.slice(i + 1);
  }
  function reencode(body) {
    try { return JSON.stringify(JSON.parse(body), null, 2); } catch (e) { return body + '\n'; }
  }

  function signOptions(p) {
    var sentAt = Math.floor(Date.now() / 1000) - (TIMED[p.id] ? lab.age : 0);
    return { body: p.body, secret: p.secret, url: p.url || '', msgId: p.msgId || 'msg_demo_0001', timestamp: sentAt };
  }

  function headerLines(p, signed) {
    var lines = [{ name: 'Content-Type', value: p.contentType, sig: false }];
    Object.keys(p.extraHeaders).forEach(function (k) { lines.push({ name: k, value: p.extraHeaders[k], sig: false }); });
    Object.keys(signed.headers).forEach(function (k) { lines.push({ name: k, value: signed.headers[k], sig: true }); });
    return lines;
  }

  function render() {
    var p = PROVIDERS.filter(function (x) { return x.id === current; })[0];
    if (lab.id !== p.id) lab = { id: p.id, age: 0, body: p.body, secret: p.secret, url: p.url || '' };
    var token = ++renderToken;
    window.HookScopeSigning.sign(p.id, signOptions(p)).then(function (signed) {
      if (token !== renderToken) return; // a newer tab click won the race
      draw(p, signed);
    }, function (err) {
      panel.textContent = 'Signing failed: ' + err.message + '. This page needs a browser with Web Crypto (any current browser, served over https or from a file).';
    });
  }

  function draw(p, signed) {
    panel.textContent = '';
    panel.appendChild(section('How ' + p.label + ' signs', [el('p', { 'class': 'how', html: p.how })]));

    var reqLine = el('p', { 'class': 'req-line' });
    reqLine.appendChild(el('code', { text: p.method + ' ' + (p.url || p.path) }));
    var headers = el('pre');
    headerLines(p, signed).forEach(function (h, i) {
      if (i) headers.appendChild(document.createTextNode('\n'));
      headers.appendChild(el('span', { 'class': h.sig ? 'hdr-sig' : '', text: h.name + ': ' + h.value }));
    });
    panel.appendChild(section('Example request', [
      reqLine,
      el('p', { 'class': 'label', text: 'Headers (signature in green)' }), headers,
      el('p', { 'class': 'label', text: 'Body' }), el('pre', { text: prettyBody(p) })
    ]));
    panel.appendChild(section('What gets signed', [
      el('p', { 'class': 'how', text: 'The signature is an HMAC of exactly this string, keyed with the secret ' + p.secret + ':' }),
      el('pre', { text: signed.signedString })
    ]));
    panel.appendChild(verifyCard(p, signed));
    document.dispatchEvent(new CustomEvent('provider-change', { detail: { provider: p, signed: signed } }));
  }

  function verifyCard(p, signed) {
    var verdict = el('div', { 'class': 'verdict', role: 'status', id: 'verdict' });
    var bodyBox = el('textarea', { 'class': 'lab-body', id: 'lab-body', spellcheck: 'false', 'aria-label': 'Body the receiver gets' });
    var secretBox = el('input', { type: 'text', id: 'lab-secret', spellcheck: 'false' });
    var urlBox = p.url ? el('input', { type: 'text', id: 'lab-url', spellcheck: 'false' }) : null;
    bodyBox.value = lab.body; secretBox.value = lab.secret; if (urlBox) urlBox.value = lab.url;

    function check() {
      lab.body = bodyBox.value; lab.secret = secretBox.value; lab.url = urlBox ? urlBox.value : '';
      window.HookScopeSigning.verify(p.id, {
        body: lab.body, headers: signed.headers, secret: lab.secret, url: lab.url
      }).then(function (r) {
        var good = r.status === 'valid';
        verdict.className = 'verdict ' + (good ? 'valid' : 'rejected');
        verdict.textContent = '';
        verdict.appendChild(el('span', { 'class': 'verdict-status', text: good ? 'Valid: HookScope accepts this' : 'Rejected (' + r.status + ')' }));
        if (r.reason) verdict.appendChild(el('span', { 'class': 'verdict-reason', text: r.reason }));
      });
    }
    function set(fn) { return function () { fn(); bodyBox.value = lab.body; secretBox.value = lab.secret; if (urlBox) urlBox.value = lab.url; check(); }; }
    function button(label, fn) { var b = el('button', { 'class': 'btn', type: 'button', text: label }); b.addEventListener('click', set(fn)); return b; }
    [bodyBox, secretBox, urlBox].forEach(function (box) { if (box) box.addEventListener('input', check); });

    var rows = [el('p', { 'class': 'how', text: 'The receiver checks the request it gets against its own copy of the secret. Change anything it uses, and watch the verdict.' })];

    var actions = el('div', { 'class': 'controls' }, [
      button('Tamper with one character', function () { lab.body = tamper(lab.body); }),
      p.contentType === 'application/json' ? button('Re-format the JSON (pretty-print)', function () { lab.body = reencode(lab.body); }) : null,
      button('Use the wrong secret', function () { lab.secret = wrongSecret(p); }),
      p.url ? button('Simulate a proxy (http://)', function () { lab.url = lab.url.replace(/^https:/, 'http:'); }) : null,
      button('Reset', function () { lab.body = p.body; lab.secret = p.secret; lab.url = p.url || ''; })
    ].filter(Boolean));
    rows.push(actions);

    var fields = [el('label', {}, [document.createTextNode('Receiver\'s secret'), secretBox])];
    if (urlBox) fields.push(el('label', {}, [document.createTextNode('URL the receiver thinks was called'), urlBox]));
    if (TIMED[p.id]) {
      var age = el('select', { id: 'lab-age', 'aria-label': 'Request age' });
      AGES.forEach(function (a) { var o = el('option', { value: a[1], text: a[0] }); if (a[1] === lab.age) o.selected = true; age.appendChild(o); });
      age.addEventListener('change', function () { lab.age = Number(age.value); render(); });
      fields.push(el('label', {}, [document.createTextNode('Request was signed (tolerance: 5 minutes)'), age]));
    }
    rows.push(el('div', { 'class': 'controls' }, fields));
    rows.push(el('p', { 'class': 'label', text: 'Body the receiver gets' }));
    rows.push(bodyBox);
    rows.push(verdict);
    check();
    return section('Try to break it', rows);
  }

  PROVIDERS.forEach(function (p) {
    var tab = el('button', { 'class': 'tab', role: 'tab', id: 'tab-' + p.id, text: p.label, 'aria-selected': String(p.id === current) });
    tab.addEventListener('click', function () {
      current = p.id;
      Array.prototype.forEach.call(tabs.children, function (t) { t.setAttribute('aria-selected', String(t.id === 'tab-' + p.id)); });
      render();
    });
    tabs.appendChild(tab);
  });

  window.HookScopeDemo = { providers: PROVIDERS, current: function () { return current; } };
  render();
})();
