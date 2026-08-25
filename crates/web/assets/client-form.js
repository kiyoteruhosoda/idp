// クライアント登録・編集フォームの入力欄の出し分け（ADR-0032）。
//
// 初期状態はサーバ側のテンプレートが決めている（JS が無くても正しい形で出る）。ここが担うのは
// 「選択を変えた瞬間に追随させる」ことだけで、送信内容の正しさは api 側の検証が担保する。
(function () {
  "use strict";

  var usage = document.getElementById("client-usage");
  var clientType = document.getElementById("client-type");
  var authMethod = document.getElementById("client-auth-method");

  function row(name) {
    return document.querySelector('[data-client-form-row="' + name + '"]');
  }

  function show(element, visible) {
    if (element) {
      element.hidden = !visible;
    }
  }

  function apply() {
    // システム用はブラウザのリダイレクト先を持たず、confidential 以外あり得ない。
    var system = usage && usage.value === "system";
    show(row("redirect-uris"), !system);
    show(row("client-type"), !system);
    // 欄を隠すだけでは選択値は送られ続ける。サーバが confidential へ寄せる値と、画面が
    // 持っている値をここで合わせておく（食い違うと、再表示時に別の欄が消える）。
    if (system && clientType) {
      clientType.value = "confidential";
    }

    // 認証方式・検証鍵は confidential にしか無い（public は常に none）。
    var confidential = !clientType || clientType.value === "confidential";
    show(row("auth-method"), confidential);
    // 検証鍵は private_key_jwt でだけ受け付ける。他の方式で送ると api が拒否する。
    show(
      row("jwks"),
      confidential && authMethod && authMethod.value === "private_key_jwt"
    );
  }

  if (usage) {
    usage.addEventListener("change", apply);
  }
  if (clientType) {
    clientType.addEventListener("change", apply);
  }
  if (authMethod) {
    authMethod.addEventListener("change", apply);
  }
  apply();
})();
