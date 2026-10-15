/* In-browser webhook signing for the HookScope demo, using Web Crypto only.
 *
 * sign(provider, { body, secret, timestamp, url, msgId }) resolves to
 *   { headers: {name: value}, signedString: "...", signedUrl: "..."? }
 * Each provider mirrors its documented scheme; tests check the output against the providers'
 * published examples and against HookScope's own verifiers.
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

  var api = { sign: sign, providers: Object.keys(PROVIDERS), parseForm: parseForm, twilioString: twilioString };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.HookScopeSigning = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
