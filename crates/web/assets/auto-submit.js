// 読み込み直後にフォームを自動送信する（SAML HTTP-POST binding の中継ページ。
// SEC12 で `saml_post.html` のインライン script から切り出し）。
// 対象は `data-auto-submit` を持つ <form>（JS 無効時は同ページの送信ボタンにフォールバックする）。
(function () {
  var form = document.querySelector('form[data-auto-submit]');
  if (form) { form.submit(); }
})();
