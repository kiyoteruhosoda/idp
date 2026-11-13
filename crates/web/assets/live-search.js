// Filters a list just by typing in the search box (no need to press the "Filter" button).
//
// For lists whose filtering and paging are done by the server (api -> DB). Shortly after typing stops,
// the same URL is fetched again with the form values and only the marked regions are replaced -- reloading
// the whole page would lose the input's focus and cursor position. The address bar is rewritten to the same URL,
// so reload, share and back (from a single item's screen) return to the same filter.
//
// Usage (template side):
//   <form method="get" data-live-search>
//     <input type="search" name="q">
//     <a data-live-search-clear hidden>…</a>        (hidden when the term is empty)
//   </form>
//   <div data-live-search-region="results">…</div> (region to replace; matched by name; may be several)
//
// ⚠ **Nothing is sent during Japanese IME composition.** So the list does not jitter on the reading before
//   conversion is committed ("あかうんと"), counting starts only at compositionend.
// ⚠ **Stale responses never overwrite a newer view.** Each keystroke aborts the previous request and only
//   the last request's response is applied.
// Where the script does not run, the button still submits as before (changing nothing is the default).
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
        // Don't send an empty term (a leftover `?q=` looks like "filtering"). Reset the page position to the first.
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
          // When redirected to the sign-in screen (e.g. the login expired), navigate the whole page.
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
          // If the request fails, submit the whole page (same result as pressing the button).
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
    // Enter and the button also use the same replacement without reloading the page.
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
