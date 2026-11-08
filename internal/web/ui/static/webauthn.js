// dbgateway passkey ceremonies (WebAuthn). Served from 'self'; no inline
// scripts. A button with data-webauthn runs one ceremony:
//
//   data-webauthn="create" | "get"
//   data-begin   URL returning the options (POST)
//   data-finish  URL receiving the credential (POST); responds {redirect}
//   data-csrf    CSRF token, sent as X-CSRF-Token
//   data-name    optional id of an <input> with the passkey's name
//   data-status  id of the element showing progress and errors
//   data-msg-*   localized messages (working, error, unsupported)
(function () {
  'use strict';

  function toBuf(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function toB64(buf) {
    if (!buf) return null;
    var bytes = new Uint8Array(buf), s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function creationOptions(o) {
    var pk = o.publicKey;
    pk.challenge = toBuf(pk.challenge);
    pk.user.id = toBuf(pk.user.id);
    (pk.excludeCredentials || []).forEach(function (c) { c.id = toBuf(c.id); });
    return { publicKey: pk };
  }

  function requestOptions(o) {
    var pk = o.publicKey;
    pk.challenge = toBuf(pk.challenge);
    (pk.allowCredentials || []).forEach(function (c) { c.id = toBuf(c.id); });
    var opts = { publicKey: pk };
    if (o.mediation) opts.mediation = o.mediation;
    return opts;
  }

  function serialize(cred) {
    var r = cred.response, out = {
      id: cred.id,
      rawId: toB64(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: { clientDataJSON: toB64(r.clientDataJSON) }
    };
    if (r.attestationObject) {
      out.response.attestationObject = toB64(r.attestationObject);
      if (r.getTransports) out.response.transports = r.getTransports();
    } else {
      out.response.authenticatorData = toB64(r.authenticatorData);
      out.response.signature = toB64(r.signature);
      out.response.userHandle = toB64(r.userHandle);
    }
    return out;
  }

  function post(url, csrf, body) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf || '' },
      body: JSON.stringify(body || {})
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) throw new Error(data.error || res.statusText);
        return data;
      });
    });
  }

  function run(btn) {
    var status = document.getElementById(btn.dataset.status || '');
    var say = function (msg, isError) {
      if (!status) return;
      status.textContent = msg || '';
      status.classList.toggle('error', !!isError);
    };
    var finish = btn.dataset.finish;
    if (btn.dataset.name) {
      var input = document.getElementById(btn.dataset.name);
      if (input) finish += (finish.indexOf('?') < 0 ? '?' : '&') + 'name=' + encodeURIComponent(input.value || '');
    }
    var create = btn.dataset.webauthn === 'create';
    btn.disabled = true;
    say(btn.dataset.msgWorking);
    post(btn.dataset.begin, btn.dataset.csrf).then(function (opts) {
      return create
        ? navigator.credentials.create(creationOptions(opts))
        : navigator.credentials.get(requestOptions(opts));
    }).then(function (cred) {
      if (!cred) throw new Error(btn.dataset.msgError);
      return post(finish, btn.dataset.csrf, serialize(cred));
    }).then(function (data) {
      window.location.assign(data.redirect || window.location.href);
    }).catch(function (err) {
      btn.disabled = false;
      var msg = btn.dataset.msgError || '';
      if (err && err.message && err.name !== 'NotAllowedError') msg = err.message;
      say(msg, true);
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    var supported = !!(window.PublicKeyCredential && navigator.credentials);
    document.querySelectorAll('[data-webauthn]').forEach(function (btn) {
      var wrap = btn.closest('.webauthn') || btn;
      if (!supported) {
        var status = document.getElementById(btn.dataset.status || '');
        if (status) status.textContent = btn.dataset.msgUnsupported || '';
        return;
      }
      wrap.hidden = false;
      btn.hidden = false;
      btn.addEventListener('click', function (ev) { ev.preventDefault(); run(btn); });
    });
  });
})();
