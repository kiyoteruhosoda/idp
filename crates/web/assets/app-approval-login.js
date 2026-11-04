// 「アプリで続ける」（task #892・ADR-0075）を Android のブラウザでだけ見せる。
//
// ⚠ 見た目だけの切り替え。User-Agent は自己申告なので、長さや判定には一切使わない
// （承認は登録した認証アプリの鍵の署名と、依頼を始めたブラウザの印で確かめる）。
// PC で押しても、開いたリンクを受け取るアプリが無いので案内のページになるだけである。
(function () {
  "use strict";
  var block = document.getElementById("app-approval-login");
  if (block && /Android/i.test(navigator.userAgent || "")) {
    block.hidden = false;
  }
})();
