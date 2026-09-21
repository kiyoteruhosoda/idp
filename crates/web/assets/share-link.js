// ワンタイムリンクの受け渡し（ADR-0062）。
//
// 端末の共有シート（`navigator.share`）を開き、無い環境ではクリップボードへ写す。
// ⚠ **共有シートは利用者の操作の中でしか開けない**ので、ボタンの click から直に呼ぶ。
// ⚠ CSP が `script-src 'self'` なので、値は data 属性で受け取る（インライン JS は使えない）。
(() => {
  const box = document.querySelector('[data-setup-link]');
  if (!box) return;

  const url = box.getAttribute('data-setup-link') || '';
  const title = box.getAttribute('data-share-title') || '';
  const copiedText = box.getAttribute('data-copied-text') || '';
  const shareButton = box.querySelector('[data-share-button]');
  const copyButton = box.querySelector('[data-copy-button]');
  const status = box.querySelector('[data-share-status]');
  const say = (text) => {
    if (status) status.textContent = text;
  };

  // 共有シートを持つ端末でだけ出す（持たない環境で押せるボタンを置かない）。
  if (shareButton && typeof navigator.share === 'function') {
    shareButton.hidden = false;
    shareButton.addEventListener('click', async () => {
      try {
        await navigator.share({ title, url });
      } catch (error) {
        // 利用者が共有シートを閉じただけのときは何も言わない（失敗ではない）。
        if (error && error.name === 'AbortError') return;
        // 共有できなかったときは写し取りへ倒す（本人は次の手を探さずに済む）。
        if (copyButton) copyButton.focus();
      }
    });
  }

  if (copyButton) {
    copyButton.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(url);
        if (copiedText) say(copiedText);
      } catch {
        // クリップボードを断られたら、選択だけしてやる（本人が Ctrl+C で写せる）。
        const target = box.querySelector('[data-setup-link-text]');
        if (!target) return;
        const range = document.createRange();
        range.selectNodeContents(target);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
      }
    });
  }
})();
