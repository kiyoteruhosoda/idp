// Handing over a one-time link (ADR-0062).
//
// Opens the device share sheet (`navigator.share`), or copies to the clipboard where it is unavailable.
// ⚠ **The share sheet can only be opened within a user action**, so call it directly from the button's click.
// ⚠ CSP is `script-src 'self'`, so values are received via data attributes (no inline JS).
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

  // Show it only on devices with a share sheet (don't put a button that can be pressed where there is none).
  if (shareButton && typeof navigator.share === 'function') {
    shareButton.hidden = false;
    shareButton.addEventListener('click', async () => {
      try {
        await navigator.share({ title, url });
      } catch (error) {
        // Say nothing when the user simply closed the share sheet (not a failure).
        if (error && error.name === 'AbortError') return;
        // If sharing failed, fall back to copying (the user doesn't have to look for the next step).
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
        // If the clipboard is refused, just select the text (the user can copy it with Ctrl+C).
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
