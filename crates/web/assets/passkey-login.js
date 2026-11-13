// Passkey (WebAuthn) login on the login screen (SEC12).
//
// Originally an inline <script> in `login.html`, split out into an external asset to drop `script-src 'unsafe-inline'`
// from the CSP. The values the template used to embed (tenant prefix,
// translated error wording) are read from the data attributes of `#passkey-error` -- receiving the template's
// HTML-escaped values via dataset removes direct embedding into JS string literals.
//
// The 3 login screens (OIDC authorization flow, admin console, portal) and identity verification right before
// sensitive operations (`/settings/verify`, T38) share this one script. Begin/complete paths come from `data-begin-path` /
// `data-complete-path` (the authorization-flow paths if unspecified). Values sent to the complete API also
// come from `data-operation` / `data-next` -- verification needs "which operation it is for" and "where to
// return afterwards", while the login screens pass nothing. Error wording is likewise taken from data
// attributes, so no screen names appear in the script as screens are added.
//
// **Wording shown on screen always comes from data attributes.** Showing an exception's `message` as is shows the
// browser's default English ("The operation either timed out or was not allowed...") regardless of the user's language.
// Ceremony cancel/timeout (`NotAllowedError` / `AbortError`) map to dedicated wording; everything else
// falls back to "could not verify".
(function () {
  const btn = document.getElementById('btn-passkey-login');
  const errorBox = document.getElementById('passkey-error');
  if (!btn || !errorBox) { return; }
  const messages = errorBox.dataset;
  const tenantPrefix = messages.tenantPrefix || '';
  const beginPath = messages.beginPath || '/passkey/login/begin';
  const completePath = messages.completePath || '/passkey/login/complete';
  // Values the screen sends to the complete API. Only those passed are included (login screens pass neither).
  const extraFields = {};
  if (messages.operation) { extraFields.operation = messages.operation; }
  if (messages.next) { extraFields.next = messages.next; }
  // Login itself proceeds even without the mark (when the `button-pending.js` load order is broken).
  const pending = window.idpButtonPending || { mark: function () {}, clear: function () {} };

  // The passkey entry point is hidden by the template. Show it only once it is known to work here
  // (don't line up buttons that do nothing when pressed).
  if (!window.PublicKeyCredential) { return; }
  const block = document.getElementById('passkey-login');
  if (block) { block.hidden = false; }

  // Only translated wording goes on screen. The cause is not swallowed; it is left in the console for developers.
  function fail(text, cause) {
    if (cause) { console.warn('passkey login failed', cause); }
    document.getElementById('passkey-error-msg').textContent =
      text || messages.msgInvalidCredential || 'Authentication failed';
    errorBox.style.display = '';
  }

  // Map exceptions thrown by the browser ceremony to wording. Cancel/timeout are user actions, so they are separate.
  function ceremonyMessage(e) {
    if (e && (e.name === 'NotAllowedError' || e.name === 'AbortError')) {
      return messages.msgCancelled;
    }
    return messages.msgInvalidCredential;
  }

  btn.addEventListener('click', async function () {
    errorBox.style.display = 'none';
    // There is a server round trip between pressing and the WebAuthn dialog appearing, during which the button
    // doesn't change. Mark it busy right after the press and remove the mark once it is clear there is no navigation.
    // **Keep the mark on paths that leave the screen** -- reverting to the pressable look just before navigating
    // flickers and lets it be pressed (`finally` runs even on `return`, so a flag distinguishes them).
    let leaving = false;
    pending.mark(btn);
    try {
      // 1. begin
      let beginRes;
      try {
        beginRes = await fetch(tenantPrefix + beginPath, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({})
        });
      } catch (e) { fail(messages.msgServer, e); return; }
      if (!beginRes.ok) { fail(messages.msgServer, beginRes.status); return; }
      const { challenge_id, options } = await beginRes.json();

      // 2. Browser authenticator
      const fromB64 = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
      options.publicKey.challenge = fromB64(options.publicKey.challenge);
      if (options.publicKey.allowCredentials) {
        options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({ ...c, id: fromB64(c.id) }));
      }
      let credential;
      try {
        credential = await navigator.credentials.get(options);
      } catch (e) { fail(ceremonyMessage(e), e); return; }

      // 3. complete
      const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const credJson = {
        id: credential.id,
        rawId: toB64(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: toB64(credential.response.authenticatorData),
          clientDataJSON: toB64(credential.response.clientDataJSON),
          signature: toB64(credential.response.signature),
        }
      };
      if (credential.response.userHandle) {
        credJson.response.userHandle = toB64(credential.response.userHandle);
      }

      // Only on the device registration screen (task #916), attach the device name the user typed.
      const deviceName = document.getElementById('passkey-device-name');
      const typedFields = deviceName ? { device_name: deviceName.value } : {};

      let completeRes;
      try {
        completeRes = await fetch(tenantPrefix + completePath, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ challenge_id, credential: credJson, ...extraFields, ...typedFields })
        });
      } catch (e) { fail(messages.msgServer, e); return; }
      if (!completeRes.ok) { fail(messages.msgServer, completeRes.status); return; }
      const result = await completeRes.json();
      if (result.redirect_to && result.form_post) {
        // response_mode=form_post (G12): pass the authorization code to the RP in the form body, not the URL.
        // Other paths have the server draw an auto-submit form, but passkeys respond with JSON, so
        // the form is built and submitted here. Navigation follows, so the busy mark stays on.
        const form = document.createElement('form');
        form.method = 'post';
        form.action = result.redirect_to;
        for (const [name, value] of result.form_post) {
          const input = document.createElement('input');
          input.type = 'hidden';
          input.name = name;
          input.value = value;
          form.appendChild(input);
        }
        document.body.appendChild(form);
        leaving = true;
        form.submit();
        return;
      }
      if (result.redirect_to) {
        leaving = true;
        window.location.href = result.redirect_to;
        return;
      }
      // Map api error codes to the data attributes of #passkey-error (translated wording).
      // Codes not in the table (errors that cannot happen on that screen) fall back to the default wording.
      fail({
        'policy_denied': messages.msgPolicyDenied,
        // No assignment (ADR-0054). **Authentication succeeded**, so don't use the same wording as a
        // credential failure. Which app it concerns is shown by this screen's heading.
        'application_not_permitted': messages.msgApplicationNotPermitted,
        'invalid_credential': messages.msgInvalidCredential,
        'challenge_not_found': messages.msgChallengeNotFound,
        'session_expired': messages.msgSessionExpired,
        'forbidden': messages.msgForbidden,
        'email_verification_required': messages.msgEmailVerificationRequired,
        'rate_limited': messages.msgRateLimited,
        // The device registration screen (task #916).
        'ticket_invalid': messages.msgTicketInvalid,
        'invalid_name': messages.msgInvalidName,
        'account_unavailable': messages.msgAccountUnavailable,
      }[result.error], result.error);
    } catch (e) {
      // Reaching here is unexpected (broken response JSON etc.). Fall back to the default wording.
      fail(null, e);
    } finally {
      if (!leaving) { pending.clear(btn); }
    }
  });
})();
