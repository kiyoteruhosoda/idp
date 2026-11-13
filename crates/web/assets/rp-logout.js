// Front-channel notification page for RP-initiated logout (split out of the inline script in `rp_logout.html` by SEC12).
// Redirects once all iframes have loaded, or after 5 seconds.
(function () {
  var holder = document.getElementById('logout-redirect');
  if (!holder) { return; }
  var target = holder.dataset.url;
  var frames = document.querySelectorAll('iframe');
  var loaded = 0;
  var moved = false;
  function done() { if (!moved) { moved = true; window.location.href = target; } }
  if (frames.length === 0) { done(); return; }
  frames.forEach(function (f) {
    f.onload = function () { loaded++; if (loaded >= frames.length) { done(); } };
  });
  /* Redirect after 5 seconds even if an RP iframe never fires load. */
  setTimeout(done, 5000);
})();
