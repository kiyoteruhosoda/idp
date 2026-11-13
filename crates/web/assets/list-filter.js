// Filters a list in place (on every keystroke; nothing is sent to the server).
//
// Usage (template side):
//   <div data-list-filter>
//     <input type="search" data-list-filter-input>
//     <button type="button" data-list-filter-state="">All</button>
//     <button type="button" data-list-filter-state="allowed">Allowed</button>
//     <p data-list-filter-empty hidden>No matches</p>
//     <li data-filter-item data-filter-text="display name etc." data-filter-state="allowed">…</li>
//   </div>
//
// ⚠ Filtering changes **only the presentation**. Hidden rows stay in the DOM and forms (assign/remove)
//   keep working. Where the script does not run, all rows stay visible (hiding nothing is the default).
(function () {
  "use strict";

  function normalize(s) {
    // Don't miss matches due to full-width/half-width or case differences ("Ｗｉｋｉ" also matches wiki).
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
        // Bootstrap's `.d-flex` is `display:flex !important`, so `hidden` alone does not hide it.
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
