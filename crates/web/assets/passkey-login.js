// ログイン画面のパスキー（WebAuthn）ログイン（SEC12）。
//
// もともとは `login.html` のインライン <script> だったが、CSP から `script-src 'unsafe-inline'` を
// 外すため外部アセットへ切り出した。テンプレートが持っていた埋め込み値（テナントプレフィクス・
// 翻訳済みのエラー文言）は `#passkey-error` の data 属性から読む —— テンプレートが HTML エスケープ
// した値を dataset 経由で受け取る形にすると、JS 文字列リテラルへの直接埋め込みが無くなる。
//
// 3 つのログイン画面（OIDC 認可フロー・管理コンソール・ポータル）と、重要操作の直前の本人確認
// （`/settings/verify`。T38）がこの 1 本を共有する。開始・完了のパスは `data-begin-path` /
// `data-complete-path` で受け取る（未指定なら認可フローの経路）。完了 API へ添える値も
// `data-operation` / `data-next` で受け取る —— 本人確認は「どの操作のための確認か」「終わったら
// どこへ戻すか」を要るが、ログイン画面は何も渡さない。表示するエラー文言も同じく data 属性から
// 引くので、画面が増えてもスクリプト側に画面名は現れない。
//
// **画面に出す文言は必ず data 属性から採る。** 例外の `message` をそのまま出すと、利用者の言語に
// 関係なくブラウザ既定の英語（"The operation either timed out or was not allowed..."）が並ぶ。
// セレモニーの中止・時間切れ（`NotAllowedError` / `AbortError`）は独立した文言に当て、それ以外は
// 「検証できなかった」に倒す。
(function () {
  const btn = document.getElementById('btn-passkey-login');
  const errorBox = document.getElementById('passkey-error');
  if (!btn || !errorBox) { return; }
  const messages = errorBox.dataset;
  const tenantPrefix = messages.tenantPrefix || '';
  const beginPath = messages.beginPath || '/passkey/login/begin';
  const completePath = messages.completePath || '/passkey/login/complete';
  // 画面が完了 API へ添える値。渡されたものだけを載せる（ログイン画面はどちらも渡さない）。
  const extraFields = {};
  if (messages.operation) { extraFields.operation = messages.operation; }
  if (messages.next) { extraFields.next = messages.next; }
  // 印が付かなくてもログインそのものは通す（`button-pending.js` の読み込み順が崩れたとき）。
  const pending = window.idpButtonPending || { mark: function () {}, clear: function () {} };

  // パスキーの導線はテンプレートで隠してある。この環境で使えると分かってから出す
  // （押しても何も起きないボタンを並べない）。
  if (!window.PublicKeyCredential) { return; }
  const block = document.getElementById('passkey-login');
  if (block) { block.hidden = false; }

  // 画面に出すのは翻訳済みの文言だけ。原因は握り潰さず、開発者向けにコンソールへ残す。
  function fail(text, cause) {
    if (cause) { console.warn('passkey login failed', cause); }
    document.getElementById('passkey-error-msg').textContent =
      text || messages.msgInvalidCredential || 'Authentication failed';
    errorBox.style.display = '';
  }

  // ブラウザのセレモニーが投げた例外を文言へ写す。中止・時間切れは利用者の操作なので分ける。
  function ceremonyMessage(e) {
    if (e && (e.name === 'NotAllowedError' || e.name === 'AbortError')) {
      return messages.msgCancelled;
    }
    return messages.msgInvalidCredential;
  }

  btn.addEventListener('click', async function () {
    errorBox.style.display = 'none';
    // 押してから WebAuthn のダイアログが出るまでにはサーバ往復があり、その間ボタンは何も
    // 変わらない。押した直後に処理中の印を付け、遷移しないと決まったところで外す。
    // **画面を離れる経路では付けたままにする** —— 遷移の直前に押せる見た目へ戻すと、一瞬
    // ちらついたうえに押せてしまう（`finally` は `return` でも走るので旗で分ける）。
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

      let completeRes;
      try {
        completeRes = await fetch(tenantPrefix + completePath, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ challenge_id, credential: credJson, ...extraFields })
        });
      } catch (e) { fail(messages.msgServer, e); return; }
      if (!completeRes.ok) { fail(messages.msgServer, completeRes.status); return; }
      const result = await completeRes.json();
      if (result.redirect_to && result.form_post) {
        // response_mode=form_post（G12）: 認可コードを URL ではなくフォーム本文で RP へ渡す。
        // 他の経路はサーバ側で自動送信フォームを描くが、パスキーだけは応答が JSON なので
        // ここで組み立てて送る。遷移するので処理中の印は付けたままにする。
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
      // api のエラーコードを #passkey-error の data 属性（翻訳済み文言）へ写す。
      // 対応表に無いコード（その画面では起こらないエラー）は既定文言に落ちる。
      fail({
        'policy_denied': messages.msgPolicyDenied,
        'invalid_credential': messages.msgInvalidCredential,
        'challenge_not_found': messages.msgChallengeNotFound,
        'session_expired': messages.msgSessionExpired,
        'forbidden': messages.msgForbidden,
        'email_verification_required': messages.msgEmailVerificationRequired,
        'rate_limited': messages.msgRateLimited,
      }[result.error], result.error);
    } catch (e) {
      // ここへ来るのは想定外（応答の JSON が壊れている等）。文言は既定へ落とす。
      fail(null, e);
    } finally {
      if (!leaving) { pending.clear(btn); }
    }
  });
})();
