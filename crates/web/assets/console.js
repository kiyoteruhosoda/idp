// 破壊的操作の確認ダイアログ（管理コンソール共通）。
//
// 文言はテンプレートが form の `data-confirm` 属性へ出力する。`onsubmit="return confirm('...')"`
// のようにインライン JS の文字列リテラルへ埋め込んではいけない: Askama の HTML エスケープは
// アポストロフィを `&#39;` にするが、ブラウザは属性値を解釈する際にこれを `'` へ戻すため、
// 文言に含まれるアポストロフィ（英語の "user's" など）が JS 文字列を終端させ、ハンドラ全体が
// 構文エラーになる。結果として**確認なしで送信される**（静かに壊れる）。属性値として渡せば
// HTML エスケープがそのまま正しい防御になる。
(function () {
  'use strict';
  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (!form || form.nodeName !== 'FORM') {
      return;
    }
    var message = form.getAttribute('data-confirm');
    if (!message) {
      return;
    }
    // 選んだ値によってだけ確認したい場合は `data-confirm-if="<name>=<値>"` を添える。
    // （例: 利用できる人を「個別」へ倒すときだけ、名簿が空であることを確かめる）。
    // 当たらない値を選んでいるときに毎回ダイアログを出すと、読まずに OK を押すようになる。
    var condition = form.getAttribute('data-confirm-if');
    if (condition) {
      var separator = condition.indexOf('=');
      var field = form.elements[condition.slice(0, separator)];
      if (!field || field.value !== condition.slice(separator + 1)) {
        return;
      }
    }
    if (!window.confirm(message)) {
      event.preventDefault();
    }
  });
})();

// SAML メタデータの取り込みフォーム（SEC12 で `console/saml_service_providers.html` の
// インライン script から移設）。ファイルを選んだ瞬間に取り込みを実行する（別途「取り込み」ボタンを
// 押さなくてよい）。JS 無効時はボタン送信の従来動作にフォールバックする。
//
// SP（クライアント）の取り込みと外部 IdP の取り込みで同じ挙動なので、id ではなく
// `data-metadata-import` 属性で拾う（画面が増えるたびに id を足さない）。
(function () {
  var forms = document.querySelectorAll("form[data-metadata-import]");
  Array.prototype.forEach.call(forms, function (form) {
    var fileInput = form.querySelector('input[type="file"]');
    if (!fileInput) {
      return;
    }
    fileInput.addEventListener("change", function () {
      if (!fileInput.files || fileInput.files.length === 0) {
        return;
      }
      if (typeof form.requestSubmit === "function") {
        form.requestSubmit();
      } else {
        form.submit();
      }
    });
  });
})();

// 外部 IdP 登録フォームのプロトコル出し分けは JS から外した。プロトコルは画面に入る前に決まり
// （URL か登録済みの値）、サーバが選ばれた側の欄だけを描くので、隠すものが無い。

// 管理コンソールのヘッダの言語ドロップダウン（`console/layout.html`）の戻り先。ログイン中は
// 言語を `POST /{tenant_id}/settings/display` で保存し、いまの画面へ戻る（task #79）。いまの画面の
// URL はサーバから各画面のテンプレートへ渡していないので、ここで埋める。検証（このテナント配下の
// パスだけを受ける）はサーバ側が行う。
(function () {
  var fields = document.querySelectorAll("input[data-return-to-current]");
  Array.prototype.forEach.call(fields, function (field) {
    field.value = window.location.pathname + window.location.search;
  });
})();


// 新しいバージョンの知らせ（`console/layout.html` の `[data-update-notice]`）。
//
// 画面を描いたビルド（`data-build`）と、いま稼働しているビルド（`data-build-check` の口が返す
// 文字列）を比べ、違えば知らせを出す。管理コンソールは service worker を持たないので、開いたままの
// 画面はこうして問い合わせないと、配られたことに気付けない。
//
// 問い合わせるのは、画面が見えているときだけ —— 別のタブから戻ったときと、5 分おき。直前の
// 問い合わせから 1 分は空ける。未ログイン（302）・通信の失敗・前段の停止ページ（200 以外）では
// 何もしない。出した知らせは押すまで消さない（数秒で消えると気付けない）。
(function () {
  var notice = document.querySelector("[data-update-notice]");
  if (!notice || typeof window.fetch !== "function") {
    return;
  }
  var current = notice.getAttribute("data-build");
  var url = notice.getAttribute("data-build-check");
  var MIN_GAP_MS = 60 * 1000;
  var INTERVAL_MS = 5 * 60 * 1000;
  var lastChecked = Date.now();

  function check() {
    if (!notice.hidden || document.visibilityState !== "visible") {
      return;
    }
    var now = Date.now();
    if (now - lastChecked < MIN_GAP_MS) {
      return;
    }
    lastChecked = now;
    window
      .fetch(url, { credentials: "same-origin", cache: "no-store", redirect: "manual" })
      .then(function (response) {
        return response.ok ? response.text() : null;
      })
      .then(function (running) {
        if (running !== null && running.trim() !== "" && running.trim() !== current) {
          notice.hidden = false;
        }
      })
      .catch(function () {});
  }

  var reload = notice.querySelector("[data-update-reload]");
  if (reload) {
    reload.addEventListener("click", function () {
      window.location.reload();
    });
  }
  document.addEventListener("visibilitychange", check);
  // 戻る・進むで復元された画面（bfcache）は、描いたときのビルドのまま出てくる。
  window.addEventListener("pageshow", function (event) {
    if (event.persisted) {
      check();
    }
  });
  window.setInterval(check, INTERVAL_MS);
})();
