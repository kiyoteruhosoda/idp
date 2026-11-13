// Password field visibility toggle (split out of the inline script in `password_visibility.html` by SEC12).
// Wording is read from the data attributes of `#password-visibility-labels` (the template embeds translations).
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
      // Rearrange into the same input + eye icon layout as photonest (Bootstrap input-group)
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
