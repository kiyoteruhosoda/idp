// Indicates that a button is "pressed and processing" (shared by form submissions and fetch-driven buttons).
//
// If nothing happens between the press and the screen changing, users can't tell whether it registered and keep
// pressing. Right after the press the button shows a spinner and cannot be pressed until processing ends.
//
// When to use what:
//
// - Server-rendered forms -> `submit-feedback.js` catches submit and calls this automatically.
// - Buttons talking to the server via fetch (passkey registration etc.) -> the screen's script calls `mark` / `clear`.
//   Only the caller knows when it ends, so clearing is the caller's responsibility.
//
// Notes:
//
// - **Set `disabled` only after the submitted data is fixed.** Disabling a submit button synchronously
//   drops that button's name/value from the submission (breaks forms that branch on which button was pressed).
//   It is deferred with `setTimeout(..., 0)` until submission has started. The fetch path has no such issue, but the next
//   click always arrives after this timer, so double presses are stopped the same way.
// - **Don't change the button's width.** Adding a spinner before the label widens the button, moving the adjacent
//   button (approve/deny on the consent screen etc.) and causing mis-presses. Wrap the label and hide it in place,
//   overlaying the spinner on top (styling lives in `app.css`).
(function () {
  'use strict';

  var SPINNER_CLASS = 'js-pending-spinner';
  var LABEL_CLASS = 'js-pending-label';

  // Applies the busy mark. `<input type="submit">` cannot have children, so no spinner is shown;
  // it is only disabled.
  function mark(button) {
    if (!button || button.getAttribute('aria-busy') === 'true') {
      return;
    }
    button.setAttribute('aria-busy', 'true');
    if (button.nodeName === 'BUTTON') {
      // Wrap the label, then hide it (keep its space rather than removing the element, to preserve width)
      var label = document.createElement('span');
      label.className = LABEL_CLASS;
      while (button.firstChild) {
        label.appendChild(button.firstChild);
      }
      button.appendChild(label);
      var spinner = document.createElement('span');
      spinner.className = 'spinner-border spinner-border-sm ' + SPINNER_CLASS;
      spinner.setAttribute('aria-hidden', 'true');
      button.appendChild(spinner);
    }
    // Keep the timer ID. If `clear` does not cancel it, processing that ends right after marking
    // (e.g. a synchronous fetch failure) gives the order "clear -> timer fires and disables",
    // leaving the button stuck unpressable.
    button.dataset.pendingTimer = String(window.setTimeout(function () {
      button.disabled = true;
    }, 0));
  }

  // Removes the mark and makes the button pressable again. Does nothing for a button without the mark.
  function clear(button) {
    if (!button || button.getAttribute('aria-busy') !== 'true') {
      return;
    }
    button.removeAttribute('aria-busy');
    if (button.dataset.pendingTimer) {
      window.clearTimeout(Number(button.dataset.pendingTimer));
      delete button.dataset.pendingTimer;
    }
    button.disabled = false;
    var spinner = button.querySelector('.' + SPINNER_CLASS);
    if (spinner) {
      spinner.parentNode.removeChild(spinner);
    }
    // Unwrap the label (so the next press doesn't wrap it twice)
    var label = button.querySelector('.' + LABEL_CLASS);
    if (label) {
      while (label.firstChild) {
        button.insertBefore(label.firstChild, label);
      }
      button.removeChild(label);
    }
  }

  // Removes every mark on the screen (for pages restored from bfcache via the back button).
  function clearAll() {
    var buttons = document.querySelectorAll('[aria-busy="true"]');
    Array.prototype.forEach.call(buttons, clear);
  }

  window.idpButtonPending = { mark: mark, clear: clear, clearAll: clearAll };
})();
