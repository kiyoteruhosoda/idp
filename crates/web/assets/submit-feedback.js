// 送信中であることをボタンで示す（全画面共通）。
//
// サーバレンダリングのフォームは、押してから次のページが描かれるまで画面が変わらない。
// 押せたのかどうかが分からないと利用者は同じボタンを続けて押すので、押した直後に
// 押したボタンへスピナーを出し、送信が終わるまで押せなくする。同じフォームの 2 度目の
// 送信も止める（登録・削除が二重に走るのを防ぐ）。
//
// 注意点:
//
// - **`disabled` は送信データが確定してから付ける。** submit ボタンを同期的に無効化すると
//   そのボタンの name/value が送信されない（どのボタンを押したかで分岐するフォームが壊れる）。
//   `setTimeout(..., 0)` で送信開始後に回す。
// - **確認ダイアログで取り消された送信には印を付けない。** 破壊的操作の確認（console.js）は
//   `preventDefault()` で送信を止めるため、`defaultPrevented` を見てから印を付ける。
//   そのためこのスクリプトは console.js より後に読み込む（同じ要素のリスナは登録順に走る）。
// - **戻るボタンで復元されたページは送信中ではない。** bfcache から戻ると DOM が
//   そのまま復元されるので、`pageshow` で印を落とす（回りっぱなしのボタンを残さない）。
(function () {
  'use strict';

  var SPINNER_CLASS = 'js-submit-spinner';

  function submitButtonOf(form, submitter) {
    if (submitter) {
      return submitter;
    }
    return form.querySelector('button[type="submit"], button:not([type]), input[type="submit"]');
  }

  function markPending(form, button) {
    form.setAttribute('data-submitting', 'true');
    if (!button) {
      return;
    }
    button.setAttribute('aria-busy', 'true');
    // <input type="submit"> は子要素を持てないため、スピナーは <button> にだけ足す
    if (button.nodeName === 'BUTTON') {
      var spinner = document.createElement('span');
      spinner.className = 'spinner-border spinner-border-sm me-2 ' + SPINNER_CLASS;
      spinner.setAttribute('aria-hidden', 'true');
      button.insertBefore(spinner, button.firstChild);
    }
    window.setTimeout(function () {
      button.disabled = true;
    }, 0);
  }

  function clearPending() {
    var forms = document.querySelectorAll('form[data-submitting="true"]');
    Array.prototype.forEach.call(forms, function (form) {
      form.removeAttribute('data-submitting');
    });
    var buttons = document.querySelectorAll('[aria-busy="true"]');
    Array.prototype.forEach.call(buttons, function (button) {
      button.removeAttribute('aria-busy');
      button.disabled = false;
    });
    var spinners = document.querySelectorAll('.' + SPINNER_CLASS);
    Array.prototype.forEach.call(spinners, function (spinner) {
      spinner.parentNode.removeChild(spinner);
    });
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
    markPending(form, submitButtonOf(form, event.submitter));
  });

  window.addEventListener('pageshow', clearPending);
})();
