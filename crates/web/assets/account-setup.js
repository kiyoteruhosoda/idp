// アカウント設定リンクからのパスキー登録（ADR-0062）。
//
// 本人はまだログインしていない（パスワードを一度も持っていないことすらある）。本人性の根拠は
// **リンクのトークンだけ**で、セッションは使わない。トークンは画面の data 属性で受け取り、
// サーバへは毎回そのまま送る。
//
// ⚠ **画面に出す文言は data 属性から採る**（SEC12 と同じ理由）。api の結果コードやブラウザの
// 例外の `message` をそのまま出すと、識別子や英語が利用者の画面に並ぶ。
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

  // パスキーを作れない環境では、押せるだけで必ず失敗するボタンを置かない。
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
      // 利用者が中止しただけのときは黙って戻す（失敗ではない）。
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

    // 成功したらリンクは消費済み。⚠ **同じ画面に留めない** —— 残しても押せる操作が無く、
    // もう一度押すと「リンクが無効です」で終わる。完了の表示へ送る。
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
