// Copy button (common to the admin console). Copies the value of `data-copy-text` to the clipboard.
//
// ⚠ The value is received via an attribute (CSP is `script-src 'self'`, so no inline JS).
// On success, shows the wording of `data-copied-text` in the screen's `[data-copy-status]` (for screen readers).
// If the clipboard is refused, selects the `<code>` before the button (the user can copy with Ctrl+C).
(function () {
  'use strict';
  document.addEventListener('click', function (event) {
    var button = event.target && event.target.closest ? event.target.closest('[data-copy-text]') : null;
    if (!button) {
      return;
    }
    var text = button.getAttribute('data-copy-text') || '';
    var status = document.querySelector('[data-copy-status]');
    var selectSource = function () {
      var source = button.previousElementSibling;
      if (!source) {
        return;
      }
      var range = document.createRange();
      range.selectNodeContents(source);
      var selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
    };
    if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') {
      selectSource();
      return;
    }
    navigator.clipboard.writeText(text).then(
      function () {
        if (status) {
          status.textContent = '';
          status.textContent = status.getAttribute('data-copied-text') || '';
        }
      },
      selectSource
    );
  });
})();

// Confirmation dialog for destructive actions (common to the admin console).
//
// The wording is output by the template into the form's `data-confirm` attribute. Do not embed it in an inline JS
// string literal like `onsubmit="return confirm('...')"`: Askama's HTML escaping turns
// apostrophes into `&#39;`, but the browser turns that back into `'` when parsing the attribute value, so
// an apostrophe in the wording (e.g. English "user's") terminates the JS string and the whole handler
// becomes a syntax error. As a result **it submits without confirmation** (fails silently). Passed as an
// attribute value, HTML escaping is itself the correct defense.
(function () {
  'use strict';
  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (!form || form.nodeName !== 'FORM') {
      return;
    }
    var message = form.getAttribute('data-confirm');
    if (!message) {
      return;
    }
    // To confirm only for a particular selected value, add `data-confirm-if="<name>=<value>"`.
    // (e.g. check that the roster is empty only when switching who can use it to "individual").
    // Showing the dialog every time a non-matching value is selected trains people to press OK without reading.
    var condition = form.getAttribute('data-confirm-if');
    if (condition) {
      var separator = condition.indexOf('=');
      var field = form.elements[condition.slice(0, separator)];
      if (!field || field.value !== condition.slice(separator + 1)) {
        return;
      }
    }
    if (!window.confirm(message)) {
      event.preventDefault();
    }
  });
})();

// SAML metadata import form (moved from the inline script in `console/saml_service_providers.html`
// by SEC12). Runs the import as soon as a file is chosen (no need to press a separate "Import" button).
// With JS disabled, falls back to the traditional button submission.
//
// SP (client) import and external IdP import behave the same, so they are picked up by the
// `data-metadata-import` attribute rather than by id (no new id each time a screen is added).
(function () {
  var forms = document.querySelectorAll("form[data-metadata-import]");
  Array.prototype.forEach.call(forms, function (form) {
    var fileInput = form.querySelector('input[type="file"]');
    if (!fileInput) {
      return;
    }
    fileInput.addEventListener("change", function () {
      if (!fileInput.files || fileInput.files.length === 0) {
        return;
      }
      if (typeof form.requestSubmit === "function") {
        form.requestSubmit();
      } else {
        form.submit();
      }
    });
  });
})();

// Protocol show/hide on the external IdP registration form was removed from JS. The protocol is decided before
// entering the screen (the URL or the registered value) and the server draws only the chosen side's fields, so nothing needs hiding.

// Return target for the language dropdown in the admin console header (`console/layout.html`). While logged in,
// the language is saved via `POST /{tenant_id}/settings/display` and the user returns to the current screen (task #79).
// The server does not pass the current screen's URL to each template, so it is filled in here. Validation
// (accepting only paths under this tenant) is done server-side.
(function () {
  var fields = document.querySelectorAll("input[data-return-to-current]");
  Array.prototype.forEach.call(fields, function (field) {
    field.value = window.location.pathname + window.location.search;
  });
})();


// New version notice (`[data-update-notice]` in `console/layout.html`).
//
// Compares the build that drew the screen (`data-build`) with the build currently running (the string returned by
// the `data-build-check` endpoint) and shows the notice if they differ. The admin console has no service worker,
// so an open screen cannot notice a rollout unless it asks like this.
//
// It only asks while the screen is visible -- when returning from another tab, and every 5 minutes, with at least
// 1 minute since the previous check. It does nothing when not logged in (302), on network failure, or for an upstream
// maintenance page (non-200). A shown notice stays until pressed (one that vanishes in seconds goes unnoticed).
(function () {
  var notice = document.querySelector("[data-update-notice]");
  if (!notice || typeof window.fetch !== "function") {
    return;
  }
  var current = notice.getAttribute("data-build");
  var url = notice.getAttribute("data-build-check");
  var MIN_GAP_MS = 60 * 1000;
  var INTERVAL_MS = 5 * 60 * 1000;
  var lastChecked = Date.now();

  function check() {
    if (!notice.hidden || document.visibilityState !== "visible") {
      return;
    }
    var now = Date.now();
    if (now - lastChecked < MIN_GAP_MS) {
      return;
    }
    lastChecked = now;
    window
      .fetch(url, { credentials: "same-origin", cache: "no-store", redirect: "manual" })
      .then(function (response) {
        return response.ok ? response.text() : null;
      })
      .then(function (running) {
        if (running !== null && running.trim() !== "" && running.trim() !== current) {
          notice.hidden = false;
        }
      })
      .catch(function () {});
  }

  var reload = notice.querySelector("[data-update-reload]");
  if (reload) {
    reload.addEventListener("click", function () {
      window.location.reload();
    });
  }
  document.addEventListener("visibilitychange", check);
  // A screen restored by back/forward (bfcache) comes back with the build it was drawn with.
  window.addEventListener("pageshow", function (event) {
    if (event.persisted) {
      check();
    }
  });
  window.setInterval(check, INTERVAL_MS);
})();
