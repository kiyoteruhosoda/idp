# Login screen messages (English is the source of truth; keys are shared across locales).
login-title = Sign in
login-username = Username or email
login-password = Password
login-submit = Sign in
login-error-invalid-credentials = The username or password is incorrect.
login-error-locked = This account is temporarily locked. Please try again later.
login-error-session-expired = Your sign-in session has expired. Please start over from the application.
login-error-csrf = The form has expired. Please reload the page and try again.
login-error-rate-limited = Too many attempts. Please wait a moment and try again.

# Admin console (A2). Server-rendered pages protected by the idp.admin permission.
admin-console-title = Admin console
admin-login-title = Admin sign in
admin-login-error-forbidden = This account does not have administrator access.
admin-signed-in-as = Signed in as
admin-logout = Sign out
admin-home-intro = Welcome to the admin console. Choose a management area.
admin-nav-clients = Clients (relying parties)
admin-nav-audit = Login and audit logs
admin-nav-permissions = User permissions
admin-forbidden-title = Access denied
admin-forbidden-message = Your account does not have permission to view this page.

# Shared admin form messages.
admin-form-save = Save
admin-form-cancel = Cancel
admin-error-csrf = The form has expired. Please reload the page and try again.
admin-error-internal = Something went wrong. Please try again.

# Client (relying party) management screens (A1).
admin-clients-title = Clients (relying parties)
admin-clients-new = Register a new client
admin-clients-none = No clients are registered yet.
admin-client-col-name = Name
admin-client-col-id = Client ID
admin-client-col-type = Type
admin-client-col-status = Status
admin-client-col-scopes = Scopes
admin-client-field-name = Application name
admin-client-field-type = Client type
admin-client-field-uris = Redirect URIs
admin-client-field-uris-hint = One URI per line. Exact match; no fragments or wildcards.
admin-client-field-scopes = Scopes
admin-client-field-scopes-hint = Space-separated OIDC scopes. Must include openid.
admin-client-field-status = Status
admin-client-field-pkce = Require PKCE
admin-client-field-pkce-hint = Public clients always require PKCE.
admin-client-field-auth-method = Token endpoint auth method
admin-client-field-grants = Grant types
admin-client-field-created = Created at
admin-client-field-updated = Updated at
admin-client-edit = Edit client
admin-client-detail = View client
admin-client-back = Back to clients
admin-client-rotate-secret = Rotate client secret
admin-client-created-title = Client registered
admin-client-secret-rotated-title = Client secret rotated
admin-client-secret-warning = Copy this client secret now. It will not be shown again.
admin-client-secret-label = Client secret
admin-client-no-secret = This client is public and has no secret.
admin-client-not-found-title = Client not found
admin-client-not-found-message = The client you requested does not exist.
admin-client-error-type = Invalid client type. Choose public or confidential.
admin-client-error-status = Invalid status. Choose ACTIVE or DISABLED.
