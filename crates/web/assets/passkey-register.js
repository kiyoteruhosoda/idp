// パスキー（WebAuthn）のセルフ登録画面（SEC12 で `passkey_register.html` のインライン script から切り出し）。
// テナントプレフィクスは `#passkey-register` の data 属性から読む。
(function () {
  const root = document.getElementById('passkey-register');
  const btnRegister = document.getElementById('btn-register');
  const btnRetry = document.getElementById('btn-retry');
  const nameInput = document.getElementById('passkey-name');
  if (!root || !btnRegister || !btnRetry || !nameInput) { return; }
  const tenantPrefix = root.dataset.tenantPrefix || '';

  async function doRegister() {
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
    // 本人確認が切れていたらサーバが誘導先を返す（403）。fetch はリダイレクトを黙って追って
    // しまうため、遷移はここで行う。
    if (beginRes.status === 403 && await goToStepUp(beginRes)) { return; }
    if (!beginRes.ok) { return showError('Server error (begin)'); }
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
    } catch (e) { return showError(e.message || 'Authenticator error'); }

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
    if (completeRes.status === 403 && await goToStepUp(completeRes)) { return; }
    if (!completeRes.ok) { return showError('Server error (complete)'); }
    const result = await completeRes.json();
    if (result.result === 'ok') {
      document.getElementById('step-begin').style.display = 'none';
      document.getElementById('step-success').style.display = '';
    } else {
      showError(result.result || 'Registration failed');
    }
  }

  // step-up が要求されたら本人確認画面へ送る。遷移できたときだけ true を返す。
  async function goToStepUp(res) {
    let body;
    try { body = await res.clone().json(); } catch (e) { return false; }
    if (body && body.result === 'step_up_required' && typeof body.location === 'string') {
      window.location.assign(body.location);
      return true;
    }
    return false;
  }

  function showError(msg) {
    document.getElementById('js-error-msg').textContent = msg;
    document.getElementById('step-error').style.display = '';
  }

  btnRegister.addEventListener('click', doRegister);
  btnRetry.addEventListener('click', () => {
    document.getElementById('step-error').style.display = 'none';
    doRegister();
  });
})();
