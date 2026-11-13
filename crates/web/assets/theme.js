// Decides the color scheme (light / dark) before the first paint and sets `<html data-bs-theme>`.
//
// Bootstrap 5.3 switches colors via CSS variables under `[data-bs-theme=dark]`, so as long as this attribute
// is right the whole screen follows. It is set here rather than on the server because the common layout does
// not receive values from every screen's template struct (see `web::theme` for details).
//
// **Load in `<head>` without defer.** Delaying it paints a white screen and then repaints it black.
//
// The choice is carried by the `theme` cookie (`light` / `dark` / `system`). Only this cookie lacks `HttpOnly`
// (see `assay_contracts::cookies::set_preference` for why). Unset or invalid values are treated like `system`
// and follow the OS setting.
(function () {
  'use strict';

  var DARK_QUERY = '(prefers-color-scheme: dark)';

  function choice() {
    var match = document.cookie.match(/(?:^|;\s*)theme=(light|dark|system)(?:;|$)/);
    return match ? match[1] : 'system';
  }

  function apply() {
    var selected = choice();
    var dark = selected === 'dark'
      || (selected === 'system' && window.matchMedia && window.matchMedia(DARK_QUERY).matches);
    document.documentElement.setAttribute('data-bs-theme', dark ? 'dark' : 'light');
  }

  apply();

  // Keep up with OS-side switches (including automatic switching by time). When `system` is not chosen,
  // `apply` does not look at the OS, so calling it as is is fine.
  if (window.matchMedia) {
    var media = window.matchMedia(DARK_QUERY);
    if (media.addEventListener) {
      media.addEventListener('change', apply);
    } else if (media.addListener) {
      media.addListener(apply);
    }
  }
})();
