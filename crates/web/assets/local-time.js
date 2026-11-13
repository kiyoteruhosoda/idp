// Re-renders times on the screen in the viewer's time zone (ADR-0048).
//
// The server returns UTC as is, and the template emits
//   <time class="local-time" datetime="2026-09-09T11:20:04.512345Z">2026-09-09 11:20 UTC</time>
// The inner text is "the value left when the script does not run"; when this runs it is
// replaced with the viewer's time. The `datetime` attribute is not touched, so machine-read values
// (copying, assistive technology) stay in UTC.
//
// ⚠ The language comes from <html lang>, not the browser language -- the user chose the screen's
// language (ADR-0011 decision chain), and dates in a different language would confuse readers.
(function () {
  "use strict";

  var nodes = document.querySelectorAll("time.local-time[datetime]");
  if (!nodes.length || typeof Intl === "undefined" || !Intl.DateTimeFormat) {
    return;
  }

  var lang = document.documentElement.lang || undefined;
  var format;
  try {
    format = new Intl.DateTimeFormat(lang, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  } catch (e) {
    return; // Keep the server's rendering where formatting is unavailable
  }

  for (var i = 0; i < nodes.length; i++) {
    var node = nodes[i];
    var parsed = new Date(node.getAttribute("datetime"));
    if (isNaN(parsed.getTime())) {
      continue; // Leave unreadable values alone
    }
    node.textContent = format.format(parsed);
  }
})();
