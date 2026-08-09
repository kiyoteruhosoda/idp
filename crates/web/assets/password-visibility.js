// パスワード入力欄の表示切り替え（SEC12 で `password_visibility.html` のインライン script から切り出し）。
// 文言は `#password-visibility-labels` の data 属性から読む（翻訳はテンプレートが埋め込む）。
(function () {
  if (window.__idpPasswordVisibilityReady) return;
  window.__idpPasswordVisibilityReady = true;
  const labels = document.getElementById('password-visibility-labels');
  const showLabel = (labels && labels.dataset.show) || 'Show password';
  const hideLabel = (labels && labels.dataset.hide) || 'Hide password';
  const enhance = function () {
    document.querySelectorAll('input[type="password"]').forEach(function (input, index) {
      if (input.dataset.passwordVisibility === 'ready') return;
      input.dataset.passwordVisibility = 'ready';
      if (!input.id) input.id = 'password-field-' + index;
      // photonest と同じ入力欄+目アイコンのフォーマット（Bootstrap の input-group）に組み替える
      const group = document.createElement('div');
      group.className = 'input-group';
      input.insertAdjacentElement('beforebegin', group);
      group.appendChild(input);
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'btn btn-outline-secondary password-toggle';
      button.setAttribute('aria-controls', input.id);
      button.setAttribute('aria-label', showLabel);
      const icon = document.createElement('i');
      icon.className = 'fa-solid fa-eye';
      icon.setAttribute('aria-hidden', 'true');
      button.appendChild(icon);
      button.addEventListener('click', function () {
        const hidden = input.type === 'password';
        input.type = hidden ? 'text' : 'password';
        icon.className = hidden ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
        button.setAttribute('aria-label', hidden ? hideLabel : showLabel);
      });
      group.appendChild(button);
    });
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', enhance);
  } else {
    enhance();
  }
})();
