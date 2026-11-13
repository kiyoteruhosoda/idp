// Passkey registration from an account setup link (ADR-0062).
//
// The user is not logged in yet (may never even have had a password). The only proof of identity is
// **the link's token**; no session is used. The token is received via a data attribute on the page and
// sent to the server as is every time.
//
// ⚠ **Wording shown on screen is taken from data attributes** (same reason as SEC12). Showing api result codes or
// a browser exception's `message` as is would put identifiers and English on the user's screen.
(function () {
  const section = document.getElementById('passkey-section');
  const button = document.getElementById('passkey-register');
  const error = document.getElementById('passkey-error');
  const texts = document.getElementById('account-setup-messages');
  if (!section || !button || !texts) { return; }

  const tenantPrefix = section.dataset.tenant || '';
  const token = section.dataset.token || '';
  const messages = texts.dataset;
  const pending = window.idpButtonPending || { mark: function () {}, clear: function () {} };

  // Where passkeys cannot be created, don't put a button that can be pressed but always fails.
  if (!window.PublicKeyCredential || !navigator.credentials) {
    button.disabled = true;
    show(messages.unsupported);
    return;
  }

  function show(text) {
    if (!error || !text) { return; }
    error.textContent = text;
    error.classList.remove('d-none');
  }

  function hide() {
    if (error) { error.classList.add('d-none'); }
  }

  const fromB64 = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  async function register() {
    hide();
    const beginRes = await fetch(tenantPrefix + '/account-setup/passkey/begin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    if (!beginRes.ok) { show(messages.failed); return; }
    const begin = await beginRes.json();
    if (begin.result !== 'ok') { show(messages.failed); return; }

    let credential;
    try {
      const options = begin.options;
      options.publicKey.challenge = fromB64(options.publicKey.challenge);
      options.publicKey.user.id = fromB64(options.publicKey.user.id);
      if (options.publicKey.excludeCredentials) {
        options.publicKey.excludeCredentials = options.publicKey.excludeCredentials
          .map((c) => ({ ...c, id: fromB64(c.id) }));
      }
      credential = await navigator.credentials.create(options);
    } catch (e) {
      // When the user merely cancelled, return silently (not a failure).
      if (e && (e.name === 'NotAllowedError' || e.name === 'AbortError')) { return; }
      show(messages.failed);
      return;
    }

    const payload = {
      id: credential.id,
      rawId: toB64(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: toB64(credential.response.attestationObject),
        clientDataJSON: toB64(credential.response.clientDataJSON),
      },
    };
    if (credential.response.getTransports) {
      payload.response.transports = credential.response.getTransports();
    }

    const completeRes = await fetch(tenantPrefix + '/account-setup/passkey/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        challenge_id: begin.challenge_id,
        name: messages.authenticatorName || 'Passkey',
        credential: payload,
      }),
    });
    if (!completeRes.ok) { show(messages.failed); return; }
    const done = await completeRes.json();
    if (done.result !== 'ok') { show(messages.failed); return; }

    // On success the link is consumed. ⚠ **Don't stay on the same screen** -- nothing there could be pressed,
    // and pressing again ends with "the link is invalid". Go to the completion view.
    window.location.assign(tenantPrefix + '/account-setup/done');
  }

  button.addEventListener('click', async () => {
    pending.mark(button);
    try {
      await register();
    } catch (e) {
      show(messages.failed);
    }
    pending.clear(button);
  });
})();
