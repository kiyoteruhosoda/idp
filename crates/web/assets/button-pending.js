// ボタンが「押されて処理中」であることを示す（フォーム送信と fetch 駆動のボタンで共有する）。
//
// 押してから画面が変わるまでの間、何も起きないと利用者は押せたのか分からず同じボタンを続けて
// 押す。押した直後にそのボタンへスピナーを出し、処理が終わるまで押せなくする。
//
// 使い分け:
//
// - サーバレンダリングのフォーム → `submit-feedback.js` が submit を捕まえて自動で呼ぶ。
// - fetch でサーバと話すボタン（パスキー登録など）→ 画面のスクリプトが `mark` / `clear` を呼ぶ。
//   終わりを知っているのは呼び出し側だけなので、解除は呼び出し側の責務になる。
//
// 注意点:
//
// - **`disabled` は送信データが確定してから付ける。** submit ボタンを同期的に無効化すると
//   そのボタンの name/value が送信されない（どのボタンを押したかで分岐するフォームが壊れる）。
//   `setTimeout(..., 0)` で送信開始後に回す。fetch 経路にこの事情は無いが、次のクリックは
//   必ずこのタイマより後に届くため二重押しは同じように止まる。
// - **ボタンの幅を変えない。** スピナーをラベルの前に足すとボタンが横に伸び、隣のボタン
//   （同意画面の承認／拒否など）が動いて押し間違いの元になる。ラベルを包んで場所ごと
//   隠し、スピナーはその上に重ねる（見た目の指定は `app.css`）。
(function () {
  'use strict';

  var SPINNER_CLASS = 'js-pending-spinner';
  var LABEL_CLASS = 'js-pending-label';

  // 処理中の印を付ける。`<input type="submit">` は子要素を持てないためスピナーは出さず、
  // 無効化だけ行う。
  function mark(button) {
    if (!button || button.getAttribute('aria-busy') === 'true') {
      return;
    }
    button.setAttribute('aria-busy', 'true');
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
    // タイマ ID を持っておく。`clear` がこれを取り消さないと、印を付けた直後に終わった処理
    // （fetch の同期的な失敗など）で「解除 → その後にタイマが発火して無効化」の順になり、
    // ボタンが押せないまま固まる。
    button.dataset.pendingTimer = String(window.setTimeout(function () {
      button.disabled = true;
    }, 0));
  }

  // 印を外して押せる状態に戻す。印が付いていないボタンに対しては何もしない。
  function clear(button) {
    if (!button || button.getAttribute('aria-busy') !== 'true') {
      return;
    }
    button.removeAttribute('aria-busy');
    if (button.dataset.pendingTimer) {
      window.clearTimeout(Number(button.dataset.pendingTimer));
      delete button.dataset.pendingTimer;
    }
    button.disabled = false;
    var spinner = button.querySelector('.' + SPINNER_CLASS);
    if (spinner) {
      spinner.parentNode.removeChild(spinner);
    }
    // 包んだラベルを元に戻す（次に押したときに二重に包まないため）
    var label = button.querySelector('.' + LABEL_CLASS);
    if (label) {
      while (label.firstChild) {
        button.insertBefore(label.firstChild, label);
      }
      button.removeChild(label);
    }
  }

  // 画面上の印をすべて外す（戻るボタンで bfcache から復元されたページ用）。
  function clearAll() {
    var buttons = document.querySelectorAll('[aria-busy="true"]');
    Array.prototype.forEach.call(buttons, clear);
  }

  window.idpButtonPending = { mark: mark, clear: clear, clearAll: clearAll };
})();
