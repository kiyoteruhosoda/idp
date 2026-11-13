// Passkey (WebAuthn) self-registration screen (split out of the inline script in `passkey_register.html` by SEC12).
// The tenant prefix and displayed wording are read from the data attributes of `#passkey-register`.
//
// **Wording shown on screen always comes from data attributes.** Showing api result codes (`duplicate_credential` etc.)
// as is puts identifiers on screen, and showing a browser exception's `message` as is shows English regardless of
// the user's language. Both are mapped to the translated wording the template passes.
//
// When the session has expired (401), send the user to the login screen. Staying here would only repeat the same
// failure on every retry with no way out.
(function () {
  const root = document.getElementById('passkey-register');
  const btnRegister = document.getElementById('btn-register');
  const btnRetry = document.getElementById('btn-retry');
  const nameInput = document.getElementById('passkey-name');
  if (!root || !btnRegister || !btnRetry || !nameInput) { return; }
  const messages = root.dataset;
  const tenantPrefix = messages.tenantPrefix || '';
  // Registration itself proceeds even without the mark (when the `button-pending.js` load order is broken).
  const pending = window.idpButtonPending || { mark: function () {}, clear: function () {} };

  // There is a server round trip between pressing and the WebAuthn dialog appearing, during which the button doesn't change.
  // Mark it busy right after the press and remove the mark when the result is in. **Keep the mark on paths that leave
  // the screen** -- reverting to the pressable look just before navigating flickers and lets it be pressed.
  async function doRegister() {
    pending.mark(btnRegister);
    try {
      if (await register()) { return; }
    } catch (e) {
      // fetch failures (offline, api down) land here. If not caught, the Promise ends
      // rejected and the button freezes, spinning forever.
      showError(messages.msgServer, e);
    }
    pending.clear(btnRegister);
  }

  // Proceeds with registration. Returns true only when leaving the screen (the caller handles the mark differently).
  async function register() {
    document.getElementById('step-begin').style.display = '';
    document.getElementById('step-success').style.display = 'none';
    document.getElementById('step-error').style.display = 'none';

    const name = nameInput.value.trim() || 'My Passkey';

    // 1. begin
    const beginRes = await fetch(tenantPrefix + '/passkey/register/begin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name })
    });
    // If identity verification has expired the server returns where to go (403). fetch silently follows
    // redirects, so navigation is done here.
    if (beginRes.status === 403 && await goToStepUp(beginRes)) { return true; }
    if (beginRes.status === 401) { return goToLogin(); }
    if (!beginRes.ok) { showError(messages.msgServer, beginRes.status); return false; }
    const { challenge_id, options } = await beginRes.json();

    // 2. Browser authenticator
    let credential;
    try {
      // base64url decode helper
      const fromB64 = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
      options.publicKey.challenge = fromB64(options.publicKey.challenge);
      options.publicKey.user.id = fromB64(options.publicKey.user.id);
      if (options.publicKey.excludeCredentials) {
        options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(c => ({ ...c, id: fromB64(c.id) }));
      }
      credential = await navigator.credentials.create(options);
    } catch (e) { showError(ceremonyMessage(e), e); return false; }

    // 3. complete
    const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const credJson = {
      id: credential.id,
      rawId: toB64(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: toB64(credential.response.attestationObject),
        clientDataJSON: toB64(credential.response.clientDataJSON),
      }
    };
    if (credential.response.getTransports) {
      credJson.response.transports = credential.response.getTransports();
    }

    const completeRes = await fetch(tenantPrefix + '/passkey/register/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge_id, name, credential: credJson })
    });
    if (completeRes.status === 403 && await goToStepUp(completeRes)) { return true; }
    if (completeRes.status === 401) { return goToLogin(); }
    if (!completeRes.ok) { showError(messages.msgServer, completeRes.status); return false; }
    const result = await completeRes.json();
    if (result.result === 'ok') {
      document.getElementById('step-begin').style.display = 'none';
      document.getElementById('step-success').style.display = '';
    } else {
      // Map api result codes to translated wording (codes not in the table fall back to the default wording).
      showError({
        'duplicate_credential': messages.msgDuplicateCredential,
        'invalid_credential': messages.msgInvalidCredential,
        'challenge_not_found': messages.msgChallengeNotFound,
      }[result.result], result.result);
    }
    return false;
  }

  // Map exceptions thrown by the browser ceremony to wording. Cancel/timeout are user actions, so they are separate.
  // Calling `create()` with an already-registered authenticator gives `InvalidStateError` (the exclude list at work).
  function ceremonyMessage(e) {
    if (!e) { return messages.msgFailed; }
    if (e.name === 'NotAllowedError' || e.name === 'AbortError') { return messages.msgCancelled; }
    if (e.name === 'InvalidStateError') { return messages.msgDuplicateCredential; }
    return messages.msgFailed;
  }

  // When step-up is required, send to the identity verification screen. Returns true only if navigation happened.
  async function goToStepUp(res) {
    let body;
    try { body = await res.clone().json(); } catch (e) { return false; }
    if (body && body.result === 'step_up_required' && typeof body.location === 'string') {
      window.location.assign(body.location);
      return true;
    }
    return false;
  }

  // The SSO session has expired. Retrying here won't succeed, so make the user start over from login.
  function goToLogin() {
    window.location.assign(tenantPrefix + '/login');
    return true;
  }

  // Only translated wording goes on screen. The cause is not swallowed; it is left in the console for developers.
  function showError(text, cause) {
    if (cause) { console.warn('passkey registration failed', cause); }
    document.getElementById('js-error-msg').textContent = text || messages.msgFailed || 'Registration failed';
    document.getElementById('step-error').style.display = '';
  }

  btnRegister.addEventListener('click', doRegister);
  btnRetry.addEventListener('click', () => {
    document.getElementById('step-error').style.display = 'none';
    doRegister();
  });
})();
