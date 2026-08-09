// ログイン画面のパスキー（WebAuthn）ログイン（SEC12）。
//
// もともとは `login.html` のインライン <script> だったが、CSP から `script-src 'unsafe-inline'` を
// 外すため外部アセットへ切り出した。テンプレートが持っていた埋め込み値（テナントプレフィクス・
// 翻訳済みのエラー文言）は `#passkey-error` の data 属性から読む —— テンプレートが HTML エスケープ
// した値を dataset 経由で受け取る形にすると、JS 文字列リテラルへの直接埋め込みが無くなる。
(function () {
  const btn = document.getElementById('btn-passkey-login');
  const errorBox = document.getElementById('passkey-error');
  if (!btn || !errorBox) { return; }
  const messages = errorBox.dataset;
  const tenantPrefix = messages.tenantPrefix || '';

  if (!window.PublicKeyCredential) {
    btn.disabled = true;
    btn.title = 'WebAuthn is not supported in this browser';
    return;
  }
  btn.addEventListener('click', async function () {
    errorBox.style.display = 'none';
    try {
      // 1. begin
      const beginRes = await fetch(tenantPrefix + '/passkey/login/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      if (!beginRes.ok) throw new Error('Server error (begin)');
      const { challenge_id, options } = await beginRes.json();

      // 2. Browser authenticator
      const fromB64 = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
      options.publicKey.challenge = fromB64(options.publicKey.challenge);
      if (options.publicKey.allowCredentials) {
        options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({ ...c, id: fromB64(c.id) }));
      }
      const credential = await navigator.credentials.get(options);

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

      const completeRes = await fetch(tenantPrefix + '/passkey/login/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challenge_id, credential: credJson })
      });
      if (!completeRes.ok) throw new Error('Server error (complete)');
      const result = await completeRes.json();
      if (result.redirect_to) {
        window.location.href = result.redirect_to;
      } else {
        // api のエラーコードを #passkey-error の data 属性（翻訳済み文言）へ写す。
        const localized = {
          'policy_denied': messages.msgPolicyDenied,
          'invalid_credential': messages.msgInvalidCredential,
          'challenge_not_found': messages.msgChallengeNotFound,
          'session_expired': messages.msgSessionExpired,
        }[result.error];
        throw new Error(localized || messages.msgInvalidCredential || 'Authentication failed');
      }
    } catch (e) {
      document.getElementById('passkey-error-msg').textContent = e.message;
      errorBox.style.display = '';
    }
  });
})();
