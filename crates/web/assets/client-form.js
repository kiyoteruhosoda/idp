// Shows/hides input fields of the client registration/edit form (ADR-0032).
//
// The initial state is decided by the server-side template (it renders correctly without JS). This script only
// "follows a changed selection immediately"; correctness of what is submitted is guaranteed by api-side validation.
(function () {
  "use strict";

  var usage = document.getElementById("client-usage");
  var clientType = document.getElementById("client-type");
  var authMethod = document.getElementById("client-auth-method");

  function row(name) {
    return document.querySelector('[data-client-form-row="' + name + '"]');
  }

  function show(element, visible) {
    if (element) {
      element.hidden = !visible;
    }
  }

  function apply() {
    // System clients have no browser redirect target and can only be confidential.
    var system = usage && usage.value === "system";
    show(row("redirect-uris"), !system);
    show(row("client-type"), !system);
    // Merely hiding the field keeps the selected value being submitted. Align the value the server forces to
    // confidential with the value the screen holds (if they diverge, a different field disappears on re-render).
    if (system && clientType) {
      clientType.value = "confidential";
    }

    // The auth method and verification key exist only for confidential (public is always none).
    var confidential = !clientType || clientType.value === "confidential";
    show(row("auth-method"), confidential);
    // The verification key is accepted only with private_key_jwt. Sending it with another method makes the api reject it.
    show(
      row("jwks"),
      confidential && authMethod && authMethod.value === "private_key_jwt"
    );
  }

  if (usage) {
    usage.addEventListener("change", apply);
  }
  if (clientType) {
    clientType.addEventListener("change", apply);
  }
  if (authMethod) {
    authMethod.addEventListener("change", apply);
  }
  apply();
})();
