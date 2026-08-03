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
// - **ボタンの幅を変えない。** スピナーをラベルの前に足すとボタンが横に伸び、隣のボタン
//   （同意画面の承認／拒否など）が動いて押し間違いの元になる。ラベルを包んで場所ごと
//   隠し、スピナーはその上に重ねる（見た目の指定は `app.css`）。
(function () {
  'use strict';

  var SPINNER_CLASS = 'js-submit-spinner';
  var LABEL_CLASS = 'js-submit-label';

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
      // ラベルを包んでから隠す（要素ごと消すのではなく場所を残すことで幅を保つ）
      var label = document.createElement('span');
      label.className = LABEL_CLASS;
      while (button.firstChild) {
        label.appendChild(button.firstChild);
      }
      button.appendChild(label);
      var spinner = document.createElement('span');
      spinner.className = 'spinner-border spinner-border-sm ' + SPINNER_CLASS;
      spinner.setAttribute('aria-hidden', 'true');
      button.appendChild(spinner);
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
    // 包んだラベルを元に戻す（次に押したときに二重に包まないため）
    var labels = document.querySelectorAll('.' + LABEL_CLASS);
    Array.prototype.forEach.call(labels, function (label) {
      var button = label.parentNode;
      while (label.firstChild) {
        button.insertBefore(label.firstChild, label);
      }
      button.removeChild(label);
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
