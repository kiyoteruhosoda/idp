// 配色（ライト / ダーク）を最初の描画より前に決めて `<html data-bs-theme>` へ立てる。
//
// Bootstrap 5.3 の配色は `[data-bs-theme=dark]` の CSS 変数で切り替わるので、この属性さえ
// 正しければ画面全体が追随する。サーバではなくここで立てるのは、共通レイアウトが全画面の
// テンプレート構造体から値を受け取る形になっていないためである（詳細は `web::theme`）。
//
// **`<head>` で defer 無しに読み込むこと。** 遅らせると、白い画面が描かれてから黒へ塗り替わる。
//
// 選択は `theme` Cookie が運ぶ（`light` / `dark` / `system`）。この Cookie だけ `HttpOnly` を
// 付けていない（理由は `assay_contracts::cookies::set_preference`）。未設定・不正値は `system`
// と同じ扱いにし、OS の設定に従う。
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

  // OS 側の切り替え（時刻による自動切替を含む）に追いつく。`system` を選んでいないときは
  // `apply` が OS を見ないので、そのまま呼んでよい。
  if (window.matchMedia) {
    var media = window.matchMedia(DARK_QUERY);
    if (media.addEventListener) {
      media.addEventListener('change', apply);
    } else if (media.addListener) {
      media.addListener(apply);
    }
  }
})();
