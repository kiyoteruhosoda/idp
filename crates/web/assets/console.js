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
