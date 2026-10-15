/* In-browser webhook signing for the HookScope demo, using Web Crypto only.
 *
 * sign(provider, { body, secret, timestamp, url, msgId }) resolves to
 *   { headers: {name: value}, signedString: "...", signedUrl: "..."? }
 * Each provider mirrors its documented scheme; tests check the output against the providers'
 * published examples and against HookScope's own verifiers.
 *
 * verify(provider, { body, headers, secret, url, now }) resolves to { status, reason } with the same
 * statuses and reasons as HookScope's verifiers, so the demo's verdicts are the server's verdicts.
 *
 * Works in browsers and in Node 18+ (module.exports), so the same file is tested and shipped.
 */
(function (root) {
  'use strict';

  var enc = new TextEncoder();
  var subtle = (root.crypto || require('node:crypto').webcrypto).subtle;

  function toHex(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }
  function toBase64(buffer) {
    var bytes = new Uint8Array(buffer), binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
  function fromBase64(text) {
    var binary = atob(text), bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function hmac(hash, keyBytes, message) {
    return subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: hash }, false, ['sign'])
      .then(function (key) { return subtle.sign('HMAC', key, enc.encode(message)); });
  }
  function hmacText(hash, secret, message) { return hmac(hash, enc.encode(secret), message); }

  function now() { return Math.floor(Date.now() / 1000); }

  /** Form parameters in order. Plus signs are spaces, as in application/x-www-form-urlencoded. */
  function parseForm(body) {
    if (!body) return [];
    return body.split('&').map(function (pair) {
      var i = pair.indexOf('=');
      var name = i < 0 ? pair : pair.slice(0, i), value = i < 0 ? '' : pair.slice(i + 1);
      var decode = function (s) { return decodeURIComponent(s.replace(/\+/g, ' ')); };
      return [decode(name), decode(value)];
    });
  }

  function twilioString(url, body) {
    var params = parseForm(body).sort(function (a, b) {
      return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0;
    });
    return url + params.map(function (p) { return p[0] + p[1]; }).join('');
  }

  var PROVIDERS = {
    github: function (o) {
      return hmacText('SHA-256', o.secret, o.body).then(function (mac) {
        return { headers: { 'X-Hub-Signature-256': 'sha256=' + toHex(mac) }, signedString: o.body };
      });
    },
    stripe: function (o) {
      var ts = o.timestamp, signed = ts + '.' + o.body;
      return hmacText('SHA-256', o.secret, signed).then(function (mac) {
        return { headers: { 'Stripe-Signature': 't=' + ts + ',v1=' + toHex(mac) }, signedString: signed };
      });
    },
    shopify: function (o) {
      return hmacText('SHA-256', o.secret, o.body).then(function (mac) {
        return { headers: { 'X-Shopify-Hmac-Sha256': toBase64(mac) }, signedString: o.body };
      });
    },
    slack: function (o) {
      var signed = 'v0:' + o.timestamp + ':' + o.body;
      return hmacText('SHA-256', o.secret, signed).then(function (mac) {
        return {
          headers: { 'X-Slack-Signature': 'v0=' + toHex(mac), 'X-Slack-Request-Timestamp': String(o.timestamp) },
          signedString: signed
        };
      });
    },
    twilio: function (o) {
      var signed = twilioString(o.url, o.body);
      return hmacText('SHA-1', o.secret, signed).then(function (mac) {
        return { headers: { 'X-Twilio-Signature': toBase64(mac) }, signedString: signed };
      });
    },
    svix: function (o) {
      var signed = o.msgId + '.' + o.timestamp + '.' + o.body;
      var key = fromBase64(o.secret.replace(/^whsec_/, ''));
      var prefix = o.prefix || 'svix';
      return hmac('SHA-256', key, signed).then(function (mac) {
        var headers = {};
        headers[prefix + '-id'] = o.msgId;
        headers[prefix + '-timestamp'] = String(o.timestamp);
        headers[prefix + '-signature'] = 'v1,' + toBase64(mac);
        return { headers: headers, signedString: signed };
      });
    },
    generic: function (o) {
      return hmacText('SHA-256', o.secret, o.body).then(function (mac) {
        return { headers: { 'X-Signature': toHex(mac) }, signedString: o.body };
      });
    }
  };

  /** Sign `body` as `provider` would. `timestamp` (unix seconds) defaults to now. */
  function sign(provider, options) {
    var build = PROVIDERS[provider];
    if (!build) return Promise.reject(new Error('unknown provider: ' + provider));
    var o = Object.assign({ timestamp: now(), msgId: 'msg_demo_0001', url: '' }, options);
    return build(o);
  }

  var TOLERANCE_SECONDS = 300;

  function header(headers, name) {
    var wanted = name.toLowerCase();
    for (var key in headers) if (key.toLowerCase() === wanted) return headers[key];
    return undefined;
  }
  function ok() { return { status: 'valid', reason: '' }; }
  function bad(reason) { return { status: 'invalid', reason: reason }; }
  function unsigned(name) { return { status: 'unsigned', reason: 'missing ' + name + ' header' }; }
  function outsideTolerance(timestamp, now) { return Math.abs(now - Number(timestamp)) > TOLERANCE_SECONDS; }
  var REPLAY = 'timestamp outside tolerance (possible replay)';

  var VERIFIERS = {
    github: function (o) {
      var received = header(o.headers, 'X-Hub-Signature-256');
      if (!received) return Promise.resolve(unsigned('X-Hub-Signature-256'));
      return sign('github', o).then(function (r) {
        return received === r.headers['X-Hub-Signature-256'] ? ok() : bad('signature mismatch');
      });
    },
    stripe: function (o) {
      var received = header(o.headers, 'Stripe-Signature');
      if (!received) return Promise.resolve(unsigned('Stripe-Signature'));
      var t = null, sigs = [];
      received.split(',').forEach(function (part) {
        var i = part.indexOf('='), k = part.slice(0, i).trim(), v = part.slice(i + 1);
        if (k === 't') t = v; else if (k === 'v1') sigs.push(v);
      });
      if (!t || !/^\d+$/.test(t) || !sigs.length) return Promise.resolve(bad('expected format t=<ts>,v1=<hex>'));
      if (outsideTolerance(t, o.now)) return Promise.resolve(bad(REPLAY));
      return sign('stripe', Object.assign({}, o, { timestamp: t })).then(function (r) {
        var expected = r.headers['Stripe-Signature'].split('v1=')[1];
        return sigs.indexOf(expected) >= 0 ? ok() : bad('signature mismatch');
      });
    },
    shopify: function (o) {
      var received = header(o.headers, 'X-Shopify-Hmac-Sha256');
      if (!received) return Promise.resolve(unsigned('X-Shopify-Hmac-Sha256'));
      return sign('shopify', o).then(function (r) {
        return received === r.headers['X-Shopify-Hmac-Sha256'] ? ok() : bad('signature mismatch');
      });
    },
    slack: function (o) {
      var received = header(o.headers, 'X-Slack-Signature');
      var t = header(o.headers, 'X-Slack-Request-Timestamp');
      if (!received) return Promise.resolve(unsigned('X-Slack-Signature'));
      if (received.indexOf('v0=') !== 0) return Promise.resolve(bad('expected format v0=<hex>'));
      if (!t || !/^\d+$/.test(t)) return Promise.resolve(bad('missing or malformed X-Slack-Request-Timestamp header'));
      if (outsideTolerance(t, o.now)) return Promise.resolve(bad(REPLAY));
      return sign('slack', Object.assign({}, o, { timestamp: t })).then(function (r) {
        return received === r.headers['X-Slack-Signature'] ? ok() : bad('signature mismatch');
      });
    },
    twilio: function (o) {
      var received = header(o.headers, 'X-Twilio-Signature');
      if (!received) return Promise.resolve(unsigned('X-Twilio-Signature'));
      if (!o.url) return Promise.resolve(bad('request URL unknown'));
      return sign('twilio', o).then(function (r) {
        return received === r.headers['X-Twilio-Signature']
          ? ok() : bad('signature mismatch (check the public URL Twilio calls)');
      });
    },
    svix: function (o) {
      var prefix = header(o.headers, 'svix-signature') ? 'svix' : 'webhook';
      var received = header(o.headers, prefix + '-signature');
      var id = header(o.headers, prefix + '-id'), t = header(o.headers, prefix + '-timestamp');
      if (!received) return Promise.resolve(unsigned('svix-signature'));
      if (!id || !t || !/^\d+$/.test(t)) {
        return Promise.resolve(bad('missing or malformed ' + prefix + '-id / ' + prefix + '-timestamp header'));
      }
      try { fromBase64(o.secret.replace(/^whsec_/, '')); } catch (e) {
        return Promise.resolve(bad('configured secret is not a valid whsec_ key'));
      }
      if (outsideTolerance(t, o.now)) return Promise.resolve(bad(REPLAY));
      return sign('svix', Object.assign({}, o, { timestamp: t, msgId: id })).then(function (r) {
        var expected = r.headers['svix-signature'].slice(3);
        var candidates = received.split(/\s+/).map(function (part) { return part.split(','); })
          .filter(function (pair) { return pair[0] === 'v1'; }).map(function (pair) { return pair[1]; });
        return candidates.indexOf(expected) >= 0 ? ok() : bad('signature mismatch');
      });
    },
    generic: function (o) {
      var received = header(o.headers, 'X-Signature');
      if (!received) return Promise.resolve(unsigned('X-Signature'));
      return sign('generic', o).then(function (r) {
        return received === r.headers['X-Signature'] ? ok() : bad('signature mismatch');
      });
    }
  };

  /** Check a received request the way HookScope would. `now` (unix seconds) defaults to the current time. */
  function verify(provider, options) {
    var check = VERIFIERS[provider];
    if (!check) return Promise.reject(new Error('unknown provider: ' + provider));
    return check(Object.assign({ now: now(), url: '', headers: {} }, options));
  }

  var api = { sign: sign, verify: verify, TOLERANCE_SECONDS: TOLERANCE_SECONDS, providers: Object.keys(PROVIDERS), parseForm: parseForm, twilioString: twilioString };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.HookScopeSigning = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
