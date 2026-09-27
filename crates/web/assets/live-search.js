// 検索欄を打つだけで一覧を絞り込む（「絞り込み」ボタンを押さなくてよい）。
//
// 絞り込み・ページングはサーバ（api → DB）が行う一覧のためのもの。入力が止まって少し経ったら
// 同じ URL をフォームの値で取り直し、印を付けた領域だけを差し替える ——ページごと読み直すと
// 入力欄のフォーカスとカーソル位置が失われるため。アドレスバーも同じ URL に書き換えるので、
// 再読み込み・共有・戻る（1 件の画面から）で同じ絞り込みに戻れる。
//
// 使い方（テンプレート側）:
//   <form method="get" data-live-search>
//     <input type="search" name="q">
//     <a data-live-search-clear hidden>…</a>        （語が空なら隠す）
//   </form>
//   <div data-live-search-region="results">…</div> （差し替える領域。名前で対応させる。複数可）
//
// ⚠ **日本語の変換中は送らない。** 変換を確定するまでの読み（「あかうんと」）で一覧が
//   揺れないよう、compositionend で初めて数える。
// ⚠ **古い応答で新しい表示を上書きしない。** 打つたびに前の要求を取り消し、最後の要求の応答
//   だけを当てる。
// スクリプトが動かない環境では、今までどおりボタンで送れる（何も変えないのが既定）。
(function () {
  "use strict";

  var DELAY_MS = 300;

  function setup(form) {
    var input = form.querySelector('input[type="search"]');
    if (!input || !window.fetch || !window.DOMParser) return;
    var clear = form.querySelector("[data-live-search-clear]");
    var timer = null;
    var composing = false;
    var controller = null;
    var lastUrl = null;

    function targetUrl() {
      var params = new URLSearchParams();
      var data = new FormData(form);
      data.forEach(function (value, key) {
        var v = String(value).trim();
        // 空の語は送らない（`?q=` が残ると「絞り込み中」に見える）。ページ位置は先頭へ戻す。
        if (v !== "" && key !== "offset") params.append(key, v);
      });
      var action = form.getAttribute("action") || window.location.pathname;
      var query = params.toString();
      return query ? action + "?" + query : action;
    }

    function run() {
      var url = targetUrl();
      if (url === lastUrl) return;
      lastUrl = url;
      if (controller) controller.abort();
      controller = window.AbortController ? new AbortController() : null;
      form.setAttribute("aria-busy", "true");
      window
        .fetch(url, {
          credentials: "same-origin",
          headers: { accept: "text/html" },
          signal: controller ? controller.signal : undefined,
        })
        .then(function (res) {
          // ログインが切れた等でサインイン画面へ飛ばされたときは、ページごと移る。
          if (!res.ok || res.redirected) {
            window.location.assign(url);
            return null;
          }
          return res.text();
        })
        .then(function (html) {
          if (html === null || url !== lastUrl) return;
          var doc = new DOMParser().parseFromString(html, "text/html");
          var regions = document.querySelectorAll("[data-live-search-region]");
          for (var i = 0; i < regions.length; i++) {
            var name = regions[i].getAttribute("data-live-search-region");
            var fresh = doc.querySelector('[data-live-search-region="' + name + '"]');
            if (fresh) regions[i].innerHTML = fresh.innerHTML;
          }
          if (clear) clear.hidden = input.value.trim() === "";
          if (window.history && window.history.replaceState) {
            window.history.replaceState(null, "", url);
          }
        })
        .catch(function (err) {
          if (err && err.name === "AbortError") return;
          // 通信に失敗したら、ページごと送る（ボタンを押したのと同じ結果にする）。
          window.location.assign(url);
        })
        .then(function () {
          if (url === lastUrl) form.removeAttribute("aria-busy");
        });
    }

    function schedule() {
      if (composing) return;
      if (timer) window.clearTimeout(timer);
      timer = window.setTimeout(run, DELAY_MS);
    }

    lastUrl = targetUrl();
    input.addEventListener("compositionstart", function () { composing = true; });
    input.addEventListener("compositionend", function () { composing = false; schedule(); });
    input.addEventListener("input", schedule);
    // Enter やボタンでも、ページを読み直さずに同じ差し替えで済ませる。
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      if (timer) window.clearTimeout(timer);
      lastUrl = null;
      run();
    });
  }

  var forms = document.querySelectorAll("form[data-live-search]");
  for (var i = 0; i < forms.length; i++) setup(forms[i]);
})();
