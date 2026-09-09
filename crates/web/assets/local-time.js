// 画面の時刻を閲覧者のタイムゾーンで描き直す（ADR-0048）。
//
// サーバは UTC のまま返し、テンプレートは
//   <time class="local-time" datetime="2026-09-09T11:20:04.512345Z">2026-09-09 11:20 UTC</time>
// の形で出す。中身の文字は「スクリプトが動かなかったときに残る値」で、ここが動けば
// 閲覧者の時刻へ差し替わる。差し替えても `datetime` 属性は触らないので、機械が読む値
// （コピー・支援技術）は UTC のまま残る。
//
// ⚠ 言語は <html lang> から取る。ブラウザの言語ではない —— 画面の言語を利用者が
// 選んでいる（ADR-0011 の決定チェーン）のに、日付だけ別の言語で出ると読み手が混乱する。
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
    return; // 整形できない環境ではサーバの表記をそのまま残す
  }

  for (var i = 0; i < nodes.length; i++) {
    var node = nodes[i];
    var parsed = new Date(node.getAttribute("datetime"));
    if (isNaN(parsed.getTime())) {
      continue; // 読めない値には触らない
    }
    node.textContent = format.format(parsed);
  }
})();
