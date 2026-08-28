// フォーム送信中であることをボタンで示す（全画面共通）。
//
// サーバレンダリングのフォームは、押してから次のページが描かれるまで画面が変わらない。
// 押せたのかどうかが分からないと利用者は同じボタンを続けて押すので、押した直後に
// 押したボタンへ処理中の印を付ける（見た目と DOM 操作は `button-pending.js`）。同じフォームの
// 2 度目の送信も止める（登録・削除が二重に走るのを防ぐ）。
//
// 注意点:
//
// - **確認ダイアログで取り消された送信には印を付けない。** 破壊的操作の確認（console.js）は
//   `preventDefault()` で送信を止めるため、`defaultPrevented` を見てから印を付ける。
//   そのためこのスクリプトは console.js より後に読み込む（同じ要素のリスナは登録順に走る）。
// - **戻るボタンで復元されたページは送信中ではない。** bfcache から戻ると DOM が
//   そのまま復元されるので、`pageshow` で印を落とす（回りっぱなしのボタンを残さない）。
(function () {
  'use strict';

  var pending = window.idpButtonPending;
  if (!pending) {
    // `button-pending.js` より先に読み込まれている（テンプレートの script 順が崩れた）。
    // 印が付かないだけで送信自体は動くため、記録して黙って降りる。
    if (window.console) {
      window.console.error('button-pending.js must be loaded before submit-feedback.js');
    }
    return;
  }

  function submitButtonOf(form, submitter) {
    if (submitter) {
      return submitter;
    }
    return form.querySelector('button[type="submit"], button:not([type]), input[type="submit"]');
  }

  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (!form || form.nodeName !== 'FORM') {
      return;
    }
    if (form.getAttribute('data-submitting') === 'true') {
      event.preventDefault();
      return;
    }
    if (event.defaultPrevented) {
      return;
    }
    form.setAttribute('data-submitting', 'true');
    pending.mark(submitButtonOf(form, event.submitter));
  });

  window.addEventListener('pageshow', function () {
    var forms = document.querySelectorAll('form[data-submitting="true"]');
    Array.prototype.forEach.call(forms, function (form) {
      form.removeAttribute('data-submitting');
    });
    pending.clearAll();
  });
})();
