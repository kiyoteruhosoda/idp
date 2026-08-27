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
    if (message && !window.confirm(message)) {
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
