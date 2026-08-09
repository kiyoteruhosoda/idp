// RP-initiated logout の front-channel 通知ページ（SEC12 で `rp_logout.html` のインライン script から切り出し）。
// 全 iframe の読み込み完了、または 5 秒経過でリダイレクトする。
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
  /* RP 側 iframe が load を発火しない場合でも 5 秒でリダイレクトする。 */
  setTimeout(done, 5000);
})();
