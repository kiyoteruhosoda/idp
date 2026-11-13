// Auto-submits the form right after load (relay page for the SAML HTTP-POST binding;
// split out of the inline script in `saml_post.html` by SEC12).
// Targets <form> elements with `data-auto-submit` (with JS disabled, falls back to the page's submit button).
(function () {
  var form = document.querySelector('form[data-auto-submit]');
  if (form) { form.submit(); }
})();
