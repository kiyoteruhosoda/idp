// Shows "Continue with the app" (task #892, ADR-0077) only in browsers on Android.
//
// ⚠ A purely visual toggle. User-Agent is self-declared, so it is never used for anything beyond that
// (approval is verified by the signature of the registered authenticator app's key and the mark of the browser that started the request).
// Pressing it on a PC just leads to a guidance page, since no app receives the opened link.
(function () {
  "use strict";
  var block = document.getElementById("app-approval-login");
  if (block && /Android/i.test(navigator.userAgent || "")) {
    block.hidden = false;
  }
})();
