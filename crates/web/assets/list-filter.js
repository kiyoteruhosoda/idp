// 一覧をその場で絞り込む（入力のたびに。サーバへは送らない）。
//
// 使い方（テンプレート側）:
//   <div data-list-filter>
//     <input type="search" data-list-filter-input>
//     <button type="button" data-list-filter-state="">すべて</button>
//     <button type="button" data-list-filter-state="allowed">使える</button>
//     <p data-list-filter-empty hidden>該当なし</p>
//     <li data-filter-item data-filter-text="表示名 など" data-filter-state="allowed">…</li>
//   </div>
//
// ⚠ 絞り込みは**見せ方だけ**を変える。消した行も DOM には残り、フォーム（割り当て・外す）は
//   そのまま動く。スクリプトが動かない環境では全件が出たままになる（何も隠さないのが既定）。
(function () {
  "use strict";

  function normalize(s) {
    // 全角・半角と大文字小文字の違いで取りこぼさない（「Ｗｉｋｉ」でも wiki に当たる）。
    return (s || "").normalize("NFKC").toLowerCase().trim();
  }

  function setup(root) {
    var input = root.querySelector("[data-list-filter-input]");
    var stateButtons = root.querySelectorAll("[data-list-filter-state]");
    var items = root.querySelectorAll("[data-filter-item]");
    var empty = root.querySelector("[data-list-filter-empty]");
    var state = "";

    function apply() {
      var words = normalize(input ? input.value : "").split(/\s+/).filter(Boolean);
      var shown = 0;
      for (var i = 0; i < items.length; i++) {
        var item = items[i];
        var text = normalize(item.getAttribute("data-filter-text"));
        var matchesText = words.every(function (w) { return text.indexOf(w) !== -1; });
        var matchesState = !state || item.getAttribute("data-filter-state") === state;
        var visible = matchesText && matchesState;
        item.hidden = !visible;
        // Bootstrap の `.d-flex` は `display:flex !important` なので `hidden` だけでは消えない。
        item.classList.toggle("d-none", !visible);
        if (visible) shown++;
      }
      if (empty) empty.hidden = shown !== 0;
    }

    if (input) input.addEventListener("input", apply);
    for (var i = 0; i < stateButtons.length; i++) {
      stateButtons[i].addEventListener("click", function (event) {
        state = event.currentTarget.getAttribute("data-list-filter-state") || "";
        for (var j = 0; j < stateButtons.length; j++) {
          var active = stateButtons[j] === event.currentTarget;
          stateButtons[j].classList.toggle("active", active);
          stateButtons[j].setAttribute("aria-pressed", active ? "true" : "false");
        }
        apply();
      });
    }
    apply();
  }

  var roots = document.querySelectorAll("[data-list-filter]");
  for (var i = 0; i < roots.length; i++) setup(roots[i]);
})();
