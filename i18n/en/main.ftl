# Login screen messages (English is the source of truth; keys are shared across locales).
login-title = Sign in
login-username = Username or email
login-password = Password
login-forgot-password = Forgot your password?
login-submit = Sign in
login-error-invalid-credentials = The username or password is incorrect.
login-error-locked = This account is temporarily locked. Please try again later.
login-error-email-not-verified = Please verify your email address before signing in. Check your inbox for the verification link.
login-error-session-expired = Your sign-in session has expired. Please start over from the application.
login-error-csrf = The form has expired. Please reload the page and try again.
login-error-rate-limited = Too many attempts. Please wait a moment and try again.

# End-user portal login (standalone sign-in to the IdP account page, without an OIDC app).
portal-login-title = Sign in to your account
portal-login-lead = Sign in to manage your account settings.
portal-login-password-change-required = Your password must be changed before you can sign in here. Please use the "Forgot your password?" link to reset it, or contact your administrator.

# Forced password change (ADR-0009 §5). Shown after signing in with an auto-generated password.
password-change-title = Change your password
password-change-forced-intro = Your password was generated automatically. Please set a new password before continuing.
password-change-current-label = Current password
password-change-new-label = New password
password-change-confirm-label = Confirm new password
password-change-submit = Change password
password-change-error-mismatch = The new password and confirmation do not match.
password-change-error-invalid-current = The current password is incorrect.
password-change-error-weak = The new password must be at least 8 characters.

# Admin console (A2). Server-rendered pages protected by the idp.admin permission.
admin-console-title = Admin console
admin-login-title = Admin sign in
admin-login-error-forbidden = This account does not have administrator access.
admin-signed-in-as = Signed in as
admin-logout = Sign out
admin-home-intro = Welcome to the admin console. Choose a management area.
admin-nav-home = Back to console home
admin-nav-clients = Clients (relying parties)
admin-nav-status = Client status
admin-nav-audit = Login and audit logs
admin-nav-permissions = User permissions
admin-nav-signing-keys = Signing keys
admin-nav-users-new = Create user
admin-nav-members = Members
admin-nav-invitations = Invite a guest
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

# User permission management screens (A2).
admin-users-title = User permissions
admin-users-search-label = Find a user by email or username
admin-users-search-hint = Enter the exact email address or username.
admin-users-search-button = Search
admin-users-search-none = No user matches that email or username.
admin-users-back = Back to user search
admin-user-col-email = Email
admin-user-col-username = Username
admin-user-col-id = User ID
admin-user-col-status = Status
admin-user-manage-permissions = Manage permissions
admin-user-not-found-title = User not found
admin-user-not-found-message = The user you requested does not exist.
admin-permissions-current = Current permissions
admin-permissions-none = This user has no permissions.
admin-permissions-grant-title = Grant a permission
admin-permissions-grant-label = Permission code
admin-permissions-grant-button = Grant
admin-permissions-revoke-button = Revoke
admin-permission-error-unknown = Unknown permission code. Choose one of the available codes.

# User creation (ADR-0009 §5). Password is auto-generated and shown once.
admin-users-new-title = Create a user
admin-users-field-name = Display name
admin-users-created-title = User created
admin-users-created-warning = This password is shown only once. Record it and share it with the user through a secure channel.
admin-users-generated-password-label = Generated password

# Members (HOME/GUEST) and guest invitations (ADR-0009 §3).
admin-members-title = Members
admin-members-none = No members yet.
admin-members-col-type = Type
admin-members-col-status = Status
admin-members-revoke-confirm = Remove this guest from the tenant?
admin-members-revoke-button = Remove
admin-members-error-home = The home member of this tenant cannot be removed.
admin-members-error-notfound = That membership no longer exists.
admin-invitations-title = Invite a guest
admin-invitations-intro = Enter the internal user ID (UUID) of an existing user from another tenant. A one-time invitation token will be issued.
admin-invitations-field-user-id = User ID (UUID)
admin-invitations-submit = Send invitation
admin-invitations-created-title = Invitation created
admin-invitations-created-warning = This token is shown only once. Record it and share it with the invited user through a secure channel.
admin-invitations-token-label = Invitation token
admin-invitations-expires-label = Expires at
admin-invitations-error-notfound = No such user was found.
admin-settings-self-registration = Allow user self sign-up
admin-settings-self-registration-hint = When enabled, users can create their own accounts at the sign-up page. When disabled (default), accounts can only be created by an administrator or through an invitation.
admin-invitations-email-sent = An invitation email with the acceptance link was sent to
admin-invitations-email-not-sent = No invitation email was sent (SMTP is not configured or delivery failed). Share the token with the invited user through a secure channel.

# Guest invitation acceptance page (opened from the invitation email link).
invitation-accept-title = Accept guest invitation
invitation-accept-intro = You are about to join this tenant as a guest.
invitation-accept-login-required = Sign in at your home tenant first, then open the invitation link again. If the link is incomplete, check the invitation email.
invitation-accept-submit = Accept invitation
invitation-accept-success = You have joined the tenant as a guest.
invitation-accept-error-invalid = The invitation is invalid or has expired. Ask the administrator to issue a new invitation.
invitation-accept-error-forbidden = This invitation was issued to a different user. Sign in as the invited user and try again.

# Email verification page (opened from the sign-up verification email link). SEC6b.
verify-email-title = Verify your email
verify-email-intro = Click the button below to verify your email address and activate sign-in.
verify-email-submit = Verify email
verify-email-success = Your email address has been verified. You can now sign in.
verify-email-missing-token = The verification link is incomplete. Please open the link from the email again.
verify-email-error-invalid = This verification link is invalid or has expired. Please register again or request a new link.

# Status screens (A3): audit/login log list and client status list.
admin-audit-title = Login and audit logs
admin-audit-none = No audit log entries match the filter.
admin-audit-error-datetime = Invalid date-time. Use RFC 3339, e.g. 2026-07-06T00:00:00Z.
admin-audit-filter-event = Event type
admin-audit-filter-result = Result
admin-audit-filter-result-all = All
admin-audit-filter-client = Client ID
admin-audit-filter-correlation = Correlation ID
admin-audit-filter-from = From
admin-audit-filter-to = To
admin-audit-filter-datetime-hint = RFC 3339 (UTC), e.g. 2026-07-06T00:00:00Z.
admin-audit-search = Search
admin-audit-reset = Reset
admin-audit-prev = Previous
admin-audit-next = Next
admin-audit-col-time = Time (UTC)
admin-audit-col-event = Event
admin-audit-col-result = Result
admin-audit-col-client = Client
admin-audit-col-correlation = Correlation ID
admin-audit-col-ip = IP address
admin-audit-col-reason = Reason
admin-status-title = Client status
admin-status-intro = Registered clients with their status, scopes, and last use.
admin-status-none = No clients are registered yet.
admin-status-col-name = Name
admin-status-col-id = Client ID
admin-status-col-status = Status
admin-status-col-scopes = Scopes
admin-status-col-last-used = Last used (UTC)

# Signing key management screens (K1).
admin-signing-keys-title = Signing keys
admin-signing-keys-none = No signing keys found.
admin-signing-keys-col-kid = Key ID (kid)
admin-signing-keys-col-alg = Algorithm
admin-signing-keys-col-status = Status
admin-signing-keys-col-not-before = Valid from (UTC)
admin-signing-keys-col-not-after = Valid until (UTC)
admin-signing-keys-col-created = Created (UTC)
admin-signing-keys-col-actions = Actions
admin-signing-keys-retire = Retire
admin-signing-keys-delete = Delete
admin-signing-keys-generate-heading = Generate a new signing key
admin-signing-keys-alg-label = Algorithm
admin-signing-keys-generate-button = Generate
admin-signing-keys-not-found-title = Signing key not found
admin-signing-keys-not-found-message = The signing key you requested does not exist.

# Consent screen (F3).
consent-title = Allow access
consent-intro = The following application is requesting access to your account:
consent-approve = Allow
consent-deny = Deny
consent-error-session-expired = Your authorization session has expired. Please start over from the application.
consent-error-csrf = The form has expired. Please reload the page and try again.
consent-scope-profile = Profile information (name, picture)
consent-scope-email = Email address
consent-scope-offline_access = Keep you signed in (refresh tokens)

# MFA / TOTP screens.
mfa-title = Two-factor authentication
mfa-setup-title = Set up two-factor authentication
mfa-setup-intro = Scan the QR code below with your authenticator app (e.g. Google Authenticator, Authy).
mfa-setup-qr-alt = QR code for authenticator app setup
mfa-setup-manual-label = Can't scan the QR code?
mfa-setup-manual-hint = Enter this code manually in your authenticator app:
mfa-setup-code-label = Enter the 6-digit code from your app
mfa-setup-confirm-button = Verify and activate
mfa-setup-confirmed-title = Two-factor authentication enabled
mfa-setup-confirmed-message = Your account is now protected with two-factor authentication.
mfa-deleted-title = Two-factor authentication removed
mfa-deleted-message = Two-factor authentication has been removed from your account.
mfa-verify-title = Two-factor authentication
mfa-verify-intro = Enter the 6-digit code from your authenticator app.
mfa-verify-code-label = Authentication code
mfa-verify-submit = Continue
mfa-error-invalid-code = The code is incorrect or has expired. Please try again.
mfa-error-session-expired = Your session has expired. Please start over.
mfa-error-not-signed-in = You must be signed in to perform this action.
mfa-error-already-configured = Two-factor authentication is already configured. Remove it before setting up again.
mfa-error-not-configured = Two-factor authentication is not configured.
mfa-error-mfa-not-pending = This page is not available in the current state. Please sign in again.

# ── Passkey（WebAuthn） ──────────────────────────────────────────────────────
passkey-title = Passkeys
passkey-list-title = Your Passkeys
passkey-list-empty = You have no passkeys registered yet.
passkey-register-title = Register a Passkey
passkey-register-intro = Use a passkey to sign in without a password using your device's biometrics or security key.
passkey-register-name-label = Passkey name
passkey-register-name-placeholder = e.g. MacBook Touch ID
passkey-register-button = Add passkey
passkey-register-success = Passkey registered successfully!
passkey-back-to-list = Back to passkey list
passkey-retry = Try again
passkey-delete-button = Delete
passkey-delete-confirm = Are you sure you want to delete this passkey?
passkey-deleted-title = Passkey deleted
passkey-deleted-message = Your passkey has been deleted.
passkey-last-used = Last used
login-passkey-or = Or
login-passkey-button = Sign in with Passkey
passkey-error-not-signed-in = You must be signed in to manage passkeys.
passkey-error-session-expired = Your session has expired. Please sign in again.
passkey-error-not-found = Passkey not found.

# 設定画面（MT14・MT15）
admin-nav-settings = Settings
admin-settings-title = Settings
admin-settings-saved = Saved.
admin-settings-back = Back to console home
admin-settings-save = Save
admin-settings-error-forbidden = You do not have permission to change this setting.
admin-settings-error-validation = Please check your input.
admin-settings-tenant-heading = Tenant settings
admin-settings-tenant-id = Tenant ID
admin-settings-tenant-status = Status
admin-settings-tenant-name = Display name
admin-settings-system-heading = System settings (SMTP)
admin-settings-system-note = These settings apply to the whole IdP and are only editable by the root system administrator.
admin-settings-smtp-host = SMTP host
admin-settings-smtp-port = SMTP port
admin-settings-smtp-username = SMTP username
admin-settings-smtp-password = SMTP password
admin-settings-smtp-password-set = A password is currently set.
admin-settings-smtp-password-unset = No password is set.
admin-settings-smtp-password-hint = Leave blank to keep the current password.
admin-settings-smtp-from = From address
admin-settings-smtp-tls = Use TLS
user-settings-title = Account settings
user-settings-password-heading = Change password
user-settings-current-password = Current password
user-settings-new-password = New password
user-settings-new-password-confirm = Confirm new password
user-settings-password-submit = Change password
user-settings-password-saved = Your password has been changed.
user-settings-language-heading = Language
user-settings-language-current = Current language
user-settings-mfa-heading = Multi-factor authentication
user-settings-mfa-totp = Set up an authenticator app (TOTP)
user-settings-mfa-passkey = Manage passkeys
user-settings-error-mismatch = The new passwords do not match.
user-settings-error-invalid-current = The current password is incorrect.
user-settings-error-weak = The new password does not meet the strength requirements.
user-settings-error-session = Your session has expired. Please sign in again.
user-settings-error-internal = Something went wrong. Please try again.

# Self-service password reset (MT18).
forgot-password-title = Reset your password
forgot-password-intro = Enter the email address of your account. If the account exists, a password reset link will be sent to it.
forgot-password-email = Email address
forgot-password-submit = Send reset link
forgot-password-accepted = If the account exists, a password reset link has been sent. Check your inbox.
forgot-password-error-unavailable = Password reset by email is not available. Contact your administrator.
forgot-password-error-rate-limited = Too many requests. Wait a while and try again.
password-reset-title = Set a new password
password-reset-intro = Enter a new password for your account.
password-reset-new-label = New password
password-reset-confirm-label = New password (confirm)
password-reset-submit = Set password
password-reset-success = Your password has been updated. All existing sessions have been signed out.
password-reset-to-login = Go to sign-in
password-reset-error-missing-token = The reset link is incomplete. Check the link in the email.
password-reset-error-invalid = The reset link is invalid or has expired. Request a new one from the sign-in page.
password-reset-error-weak = The new password does not meet the strength requirements.
password-reset-error-mismatch = The passwords do not match.

# API error messages (MT19). Used by admin API endpoints; translated based on Accept-Language.
# Error codes are language-invariant; only the message field is translated.
api-user-not-found = User not found.
api-user-email-conflict = This email address is already registered.
api-user-username-conflict = This username is already taken.
api-permission-unknown = Unknown permission code. Choose one of the available codes.
api-permission-forbidden = You do not have permission to perform this action.
api-member-home-cannot-remove = The home member of this tenant cannot be removed.
api-member-not-found = That membership no longer exists.
api-client-not-found = Client not found.
api-client-type-invalid = Invalid client type. Choose public or confidential.
api-client-status-invalid = Invalid status. Choose ACTIVE or DISABLED.
api-invitation-user-not-found = No such user was found.
api-signing-key-not-found = Signing key not found.
api-signing-key-retire-failed = Only ACTIVE keys can be retired.
api-signing-key-delete-failed = Only RETIRED keys can be deleted.
api-tenant-not-found = Tenant not found.
api-audit-invalid-datetime = Invalid date-time. Use RFC 3339, e.g. 2026-07-06T00:00:00Z.
api-invalid-request = Invalid request.
api-internal-error = An internal error occurred.
admin-nav-tenants = Tenant registration
admin-tenants-title = Tenant registration
admin-tenants-intro = Only root administrators can register child tenants. An initial administrator and temporary password are generated on creation.
admin-tenants-create-title = New tenant
admin-tenants-add = Add a tenant
admin-tenants-add-close = Close
admin-tenants-name = Tenant name
admin-tenants-admin-email = Initial administrator email
admin-tenants-create = Register
admin-tenants-list-title = Registered tenants
admin-tenants-list-empty = No tenants have been registered yet. Use "Add a tenant" to create the first one.
admin-tenants-self-registration = User self sign-up
admin-tenants-self-registration-hint = Whether users can create their own accounts. When "Allowed", anyone can sign up at the sign-up page; when "Invite only", accounts are created only by an administrator or via invitation.
admin-tenants-self-registration-on = Allowed
admin-tenants-self-registration-off = Invite only
admin-tenants-login = Login page
admin-tenants-login-user = User login
admin-tenants-login-admin = Admin login
admin-tenants-created-title = Tenant registered
admin-tenants-created-intro = The initial administrator password is shown only once on this screen. Share it through a secure channel.
admin-tenants-admin-user-id = Initial administrator ID
admin-tenants-generated-password = Initial password
admin-tenants-back = Back to tenant registration
admin-tenants-error-forbidden = Tenant registration requires the idp.system.admin permission.
admin-tenants-error-validation = Check the input values.
admin-tenants-error-conflict = The initial administrator email is already in use.
admin-home-heading = Administration menu
admin-home-groups-label = Administration menu grouped by category
admin-home-group-operations = Operations and audit
admin-home-group-operations-desc = Review runtime status and logs.
admin-home-group-access = User and access management
admin-home-group-access-desc = Manage users, permissions, members, and invitations.
admin-home-group-integration = Integrations and keys
admin-home-group-integration-desc = Manage relying-party clients and signing keys.
admin-home-group-settings = System and tenant settings
admin-home-group-settings-desc = Adjust tenant, registration, and delivery settings.
admin-nav-status-desc = Check client runtime status
admin-nav-audit-desc = Search login history and audit trails
admin-nav-permissions-desc = Change permissions per user
admin-nav-users-new-desc = Create a new user
admin-nav-members-desc = Review administrative members
admin-nav-invitations-desc = Create and review guest invitations
admin-nav-clients-desc = Manage OIDC clients
admin-nav-signing-keys-desc = Rotate signing keys
admin-nav-settings-desc = Configure tenant and SMTP
admin-nav-tenants-desc = Register a new tenant
admin-settings-lead = Settings are grouped by type so you can jump directly to the section you need.
admin-settings-nav-label = Settings categories
admin-settings-runtime-heading = Runtime setting sources
admin-settings-runtime-note = Values are not displayed; the table shows owner, current source, status, reason, and restart requirement per key. Secret values and fingerprints are hidden.
user-settings-kicker = Self service
user-settings-lead = Manage language, password, and multi-factor authentication from one place.
user-settings-logout = Sign out
user-settings-nav-label = Account setting categories
user-settings-security-heading = Security
user-settings-language-help = Your selection is saved to a cookie and, when signed in, to your user profile.
user-settings-language-submit = Save language
user-settings-password-help = Confirm your current password before changing it.
user-settings-mfa-help = Add or manage authenticator apps and passkeys.

# SAML federation registration (admin console).
admin-nav-saml = SAML federation
admin-nav-saml-desc = Register the external SAML IdP entity ID, SSO URL, and certificate.
admin-saml-title = Register SAML federation
admin-saml-lead = Register external identity provider metadata and prepare SAML sign-in federation for this tenant.
admin-saml-saved = SAML federation settings were accepted.
admin-saml-field-display-name = Display name
admin-saml-field-entity-id = IdP Entity ID
admin-saml-field-sso-url = SSO URL
admin-saml-field-certificate = X.509 certificate
admin-saml-certificate-hint = Paste a PEM encoded certificate.
admin-saml-field-enabled = Enable this provider
admin-saml-submit = Register SAML federation
admin-saml-error-validation = Fill in all required fields.
admin-saml-error-sso-url = SSO URL must use HTTPS or localhost.

# Password visibility toggle.
password-visibility-show = Show password
password-visibility-hide = Hide password

# Profile navigation.
admin-profile-settings = Open profile settings
admin-saml-error-conflict = A SAML federation with the same Entity ID already exists.
