// Indicates on the button that a form is being submitted (common to all screens).
//
// With server-rendered forms the screen does not change between pressing and the next page being drawn.
// If users can't tell whether the press registered they keep pressing the same button, so right after
// a press the pressed button gets a busy mark (look and DOM handling live in `button-pending.js`). A second
// submission of the same form is also stopped (prevents registrations/deletions from running twice).
//
// Notes:
//
// - **Submissions cancelled in a confirmation dialog get no mark.** The destructive-action confirmation (console.js)
//   stops submission with `preventDefault()`, so the mark is applied only after checking `defaultPrevented`.
//   Hence this script is loaded after console.js (listeners on the same element run in registration order).
// - **A page restored by the back button is not submitting.** Coming back from bfcache restores the DOM
//   as is, so the mark is dropped on `pageshow` (no button left spinning forever).
(function () {
  'use strict';

  var pending = window.idpButtonPending;
  if (!pending) {
    // Loaded before `button-pending.js` (the template's script order is broken).
    // Only the mark is missing and submission itself still works, so log it and bail out quietly.
    if (window.console) {
      window.console.error('button-pending.js must be loaded before submit-feedback.js');
    }
    return;
  }

  function submitButtonOf(form, submitter) {
    if (submitter) {
      return submitter;
    }
    return form.querySelector('button[type="submit"], button:not([type]), input[type="submit"]');
  }

  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (!form || form.nodeName !== 'FORM') {
      return;
    }
    if (form.getAttribute('data-submitting') === 'true') {
      event.preventDefault();
      return;
    }
    if (event.defaultPrevented) {
      return;
    }
    form.setAttribute('data-submitting', 'true');
    pending.mark(submitButtonOf(form, event.submitter));
  });

  window.addEventListener('pageshow', function () {
    var forms = document.querySelectorAll('form[data-submitting="true"]');
    Array.prototype.forEach.call(forms, function (form) {
      form.removeAttribute('data-submitting');
    });
    pending.clearAll();
  });
})();
