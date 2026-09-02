// パスキー（WebAuthn）のセルフ登録画面（SEC12 で `passkey_register.html` のインライン script から切り出し）。
// テナントプレフィクスと表示する文言は `#passkey-register` の data 属性から読む。
//
// **画面に出す文言は必ず data 属性から採る。** api の結果コード（`duplicate_credential` 等）を
// そのまま出すと識別子が画面に並び、ブラウザの例外の `message` をそのまま出すと利用者の言語に
// 関係なく英語が並ぶ。どちらもテンプレートが渡す翻訳済みの文言へ写す。
//
// セッションが切れた（401）ときはログイン画面へ送る。この画面に留めても、再試行のたびに同じ
// 失敗を繰り返すだけで抜け道が無い。
(function () {
  const root = document.getElementById('passkey-register');
  const btnRegister = document.getElementById('btn-register');
  const btnRetry = document.getElementById('btn-retry');
  const nameInput = document.getElementById('passkey-name');
  if (!root || !btnRegister || !btnRetry || !nameInput) { return; }
  const messages = root.dataset;
  const tenantPrefix = messages.tenantPrefix || '';
  // 印が付かなくても登録そのものは通す（`button-pending.js` の読み込み順が崩れたとき）。
  const pending = window.idpButtonPending || { mark: function () {}, clear: function () {} };

  // 押してから WebAuthn のダイアログが出るまでにはサーバ往復があり、その間ボタンは何も変わらない。
  // 押した直後に処理中の印を付け、結果が出たところで外す。**画面を離れる経路では付けたまま
  // にする** —— 遷移の直前に押せる見た目へ戻すと、一瞬ちらついたうえに押せてしまう。
  async function doRegister() {
    pending.mark(btnRegister);
    try {
      if (await register()) { return; }
    } catch (e) {
      // fetch の失敗（オフライン・api 停止）はここへ来る。捕まえないと Promise が
      // 拒否されたまま終わり、ボタンが回りっぱなしで固まる。
      showError(messages.msgServer, e);
    }
    pending.clear(btnRegister);
  }

  // 登録を進める。画面を離れたときだけ true を返す（呼び出し元が印の扱いを変える）。
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
    // 本人確認が切れていたらサーバが誘導先を返す（403）。fetch はリダイレクトを黙って追って
    // しまうため、遷移はここで行う。
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
      // api の結果コードを翻訳済みの文言へ写す（対応表に無いコードは既定の文言に落ちる）。
      showError({
        'duplicate_credential': messages.msgDuplicateCredential,
        'invalid_credential': messages.msgInvalidCredential,
        'challenge_not_found': messages.msgChallengeNotFound,
      }[result.result], result.result);
    }
    return false;
  }

  // ブラウザのセレモニーが投げた例外を文言へ写す。中止・時間切れは利用者の操作なので分ける。
  // 既に登録済みの認証器で `create()` を呼ぶと `InvalidStateError` になる（除外リストの働き）。
  function ceremonyMessage(e) {
    if (!e) { return messages.msgFailed; }
    if (e.name === 'NotAllowedError' || e.name === 'AbortError') { return messages.msgCancelled; }
    if (e.name === 'InvalidStateError') { return messages.msgDuplicateCredential; }
    return messages.msgFailed;
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

  // SSO セッションが切れている。この画面で再試行しても通らないのでログインからやり直させる。
  function goToLogin() {
    window.location.assign(tenantPrefix + '/login');
    return true;
  }

  // 画面に出すのは翻訳済みの文言だけ。原因は握り潰さず、開発者向けにコンソールへ残す。
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
