# ログイン画面の文言（キーは en/main.ftl と共通。日本語訳は手動で追記する）。
login-title = サインイン
login-username = ユーザー名またはメールアドレス
login-password = パスワード
login-forgot-password = パスワードをお忘れですか？
login-submit = サインイン
login-error-invalid-credentials = ユーザー名またはパスワードが正しくありません。
login-error-locked = このアカウントは一時的にロックされています。しばらくしてからお試しください。
login-error-session-expired = サインインのセッションが期限切れです。アプリケーションからやり直してください。
login-error-csrf = フォームの有効期限が切れました。ページを再読み込みしてやり直してください。
login-error-rate-limited = 試行回数が多すぎます。しばらく待ってからお試しください。

# 強制パスワード変更（ADR-0009 §5）。自動生成パスワードでのサインイン直後に表示する。
password-change-title = パスワードを変更してください
password-change-forced-intro = パスワードは自動生成されています。続行する前に新しいパスワードを設定してください。
password-change-current-label = 現在のパスワード
password-change-new-label = 新しいパスワード
password-change-confirm-label = 新しいパスワード（確認）
password-change-submit = パスワードを変更
password-change-error-mismatch = 新しいパスワードと確認用の入力が一致しません。
password-change-error-invalid-current = 現在のパスワードが正しくありません。
password-change-error-weak = 新しいパスワードは 8 文字以上にしてください。

# 管理コンソール（A2）。idp.admin 権限で保護するサーバレンダリング画面。
admin-console-title = 管理コンソール
admin-login-title = 管理者サインイン
admin-login-error-forbidden = このアカウントには管理者権限がありません。
admin-signed-in-as = サインイン中
admin-logout = サインアウト
admin-home-intro = 管理コンソールへようこそ。管理する項目を選択してください。
admin-nav-home = コンソールホームへ戻る
admin-nav-clients = クライアント（RP）
admin-nav-status = クライアント状況
admin-nav-audit = ログイン・監査ログ
admin-nav-permissions = 利用者権限
admin-nav-signing-keys = 署名鍵
admin-nav-users-new = 利用者を作成
admin-nav-members = メンバー
admin-nav-invitations = ゲストを招待
admin-forbidden-title = アクセスできません
admin-forbidden-message = このアカウントにはこのページを表示する権限がありません。

# 管理フォーム共通の文言。
admin-form-save = 保存
admin-form-cancel = キャンセル
admin-error-csrf = フォームの有効期限が切れました。ページを再読み込みしてやり直してください。
admin-error-internal = エラーが発生しました。もう一度お試しください。

# クライアント（RP）管理画面（A1）。
admin-clients-title = クライアント（RP）
admin-clients-new = クライアントを新規登録
admin-clients-none = 登録済みのクライアントはありません。
admin-client-col-name = 名前
admin-client-col-id = クライアント ID
admin-client-col-type = 種別
admin-client-col-status = 状態
admin-client-col-scopes = スコープ
admin-client-field-name = アプリケーション名
admin-client-field-type = クライアント種別
admin-client-field-uris = リダイレクト URI
admin-client-field-uris-hint = 1 行に 1 つ。完全一致。フラグメント・ワイルドカードは不可。
admin-client-field-scopes = スコープ
admin-client-field-scopes-hint = 空白区切りの OIDC スコープ。openid を含めること。
admin-client-field-status = 状態
admin-client-field-pkce = PKCE を必須にする
admin-client-field-pkce-hint = public クライアントは常に PKCE 必須です。
admin-client-field-auth-method = トークンエンドポイント認証方式
admin-client-field-grants = グラント種別
admin-client-field-created = 作成日時
admin-client-field-updated = 更新日時
admin-client-edit = クライアントを編集
admin-client-detail = クライアントを表示
admin-client-back = クライアント一覧へ戻る
admin-client-rotate-secret = クライアントシークレットを再発行
admin-client-created-title = クライアントを登録しました
admin-client-secret-rotated-title = クライアントシークレットを再発行しました
admin-client-secret-warning = このクライアントシークレットを今すぐ控えてください。再表示されません。
admin-client-secret-label = クライアントシークレット
admin-client-no-secret = このクライアントは public のためシークレットはありません。
admin-client-not-found-title = クライアントが見つかりません
admin-client-not-found-message = 指定されたクライアントは存在しません。
admin-client-error-type = クライアント種別が不正です。public または confidential を選んでください。
admin-client-error-status = 状態が不正です。ACTIVE または DISABLED を選んでください。

# 利用者権限の管理画面（A2）。
admin-users-title = 利用者権限
admin-users-search-label = メールアドレスまたはユーザー名で利用者を検索
admin-users-search-hint = 正確なメールアドレスまたはユーザー名を入力してください。
admin-users-search-button = 検索
admin-users-search-none = 該当する利用者が見つかりません。
admin-users-back = 利用者検索へ戻る
admin-user-col-email = メールアドレス
admin-user-col-username = ユーザー名
admin-user-col-id = 利用者 ID
admin-user-col-status = 状態
admin-user-manage-permissions = 権限を管理
admin-user-not-found-title = 利用者が見つかりません
admin-user-not-found-message = 指定された利用者は存在しません。
admin-permissions-current = 保有権限
admin-permissions-none = この利用者は権限を保有していません。
admin-permissions-grant-title = 権限を付与
admin-permissions-grant-label = 権限コード
admin-permissions-grant-button = 付与
admin-permissions-revoke-button = 剥奪
admin-permission-error-unknown = 未知の権限コードです。付与可能なコードから選んでください。

# 利用者作成（ADR-0009 §5）。パスワードは自動生成され、一度だけ表示する。
admin-users-new-title = 利用者を作成
admin-users-field-name = 表示名
admin-users-created-title = 利用者を作成しました
admin-users-created-warning = このパスワードは一度だけ表示されます。控えたうえで、安全な方法で本人へ伝えてください。
admin-users-generated-password-label = 生成されたパスワード

# メンバー（HOME/GUEST）・ゲスト招待（ADR-0009 §3）。
admin-members-title = メンバー
admin-members-none = メンバーはまだいません。
admin-members-col-type = 種別
admin-members-col-status = 状態
admin-members-revoke-confirm = このゲストをテナントから解除しますか？
admin-members-revoke-button = 解除
admin-members-error-home = このテナントの HOME メンバーは解除できません。
admin-members-error-notfound = 指定されたメンバーシップは存在しません。
admin-invitations-title = ゲストを招待
admin-invitations-intro = 他テナント所属の既存利用者の内部 ID（UUID）を入力してください。一度限りの招待トークンが発行されます。
admin-invitations-field-user-id = 利用者 ID（UUID）
admin-invitations-submit = 招待を送信
admin-invitations-created-title = 招待を作成しました
admin-invitations-created-warning = このトークンは一度だけ表示されます。控えたうえで、安全な方法で被招待者へ伝えてください。
admin-invitations-token-label = 招待トークン
admin-invitations-expires-label = 有効期限
admin-invitations-error-notfound = 該当する利用者が見つかりません。
admin-settings-self-registration = 自己登録（/auth/register）を許可する
admin-settings-self-registration-hint = 無効（既定）の間は、アカウントは管理者による作成または招待経由でのみ作られます。
admin-invitations-email-sent = 承諾リンクを記載した招待メールを次の宛先へ送信しました
admin-invitations-email-not-sent = 招待メールは送信されていません（SMTP 未設定または送信失敗）。トークンを安全な方法で被招待者へ伝えてください。

# 招待承諾画面（招待メールのリンクから開く）。
invitation-accept-title = ゲスト招待の承諾
invitation-accept-intro = このテナントにゲストとして参加しようとしています。
invitation-accept-login-required = 先に所属元テナントでログインしてから、招待リンクを開き直してください。リンクが不完全な場合は招待メールを確認してください。
invitation-accept-submit = 招待を承諾する
invitation-accept-success = テナントにゲストとして参加しました。
invitation-accept-error-invalid = 招待が無効か、有効期限が切れています。管理者に再発行を依頼してください。
invitation-accept-error-forbidden = この招待は別の利用者宛です。被招待者本人でログインし直してください。

# 状況確認画面（A3）: 監査／ログインログ一覧・クライアント状況一覧。
admin-audit-title = ログイン・監査ログ
admin-audit-none = 条件に一致する監査ログはありません。
admin-audit-error-datetime = 日時の形式が不正です。RFC 3339 で入力してください（例: 2026-07-06T00:00:00Z）。
admin-audit-filter-event = イベント種別
admin-audit-filter-result = 結果
admin-audit-filter-result-all = すべて
admin-audit-filter-client = クライアント ID
admin-audit-filter-correlation = Correlation ID
admin-audit-filter-from = 開始
admin-audit-filter-to = 終了
admin-audit-filter-datetime-hint = RFC 3339（UTC）。例: 2026-07-06T00:00:00Z。
admin-audit-search = 検索
admin-audit-reset = リセット
admin-audit-prev = 前へ
admin-audit-next = 次へ
admin-audit-col-time = 時刻（UTC）
admin-audit-col-event = イベント
admin-audit-col-result = 結果
admin-audit-col-client = クライアント
admin-audit-col-correlation = Correlation ID
admin-audit-col-ip = IP アドレス
admin-audit-col-reason = 理由
admin-status-title = クライアント状況
admin-status-intro = 登録済みクライアントの状態・スコープ・最終利用時刻の一覧。
admin-status-none = 登録済みのクライアントはありません。
admin-status-col-name = 名前
admin-status-col-id = クライアント ID
admin-status-col-status = 状態
admin-status-col-scopes = スコープ
admin-status-col-last-used = 最終利用時刻（UTC）
admin-nav-signing-keys = 署名鍵管理

# 署名鍵管理画面（K1）。
admin-signing-keys-title = 署名鍵管理
admin-signing-keys-none = 署名鍵が登録されていません。
admin-signing-keys-col-kid = 鍵 ID（kid）
admin-signing-keys-col-alg = アルゴリズム
admin-signing-keys-col-status = 状態
admin-signing-keys-col-not-before = 有効開始（UTC）
admin-signing-keys-col-not-after = 有効終了（UTC）
admin-signing-keys-col-created = 作成日時（UTC）
admin-signing-keys-col-actions = 操作
admin-signing-keys-retire = 退役
admin-signing-keys-delete = 削除
admin-signing-keys-generate-heading = 新規署名鍵の生成
admin-signing-keys-alg-label = アルゴリズム
admin-signing-keys-generate-button = 生成
admin-signing-keys-not-found-title = 署名鍵が見つかりません
admin-signing-keys-not-found-message = 指定された署名鍵は存在しません。

# 同意画面（F3）。
consent-title = アクセスの許可
consent-intro = 次のアプリケーションがあなたのアカウントへのアクセスを求めています：
consent-approve = 許可する
consent-deny = 拒否する
consent-error-session-expired = 認可セッションの有効期限が切れました。アプリケーションから最初からやり直してください。
consent-error-csrf = フォームの有効期限が切れました。ページを再読み込みして再試行してください。
consent-scope-profile = プロフィール情報（名前・画像）
consent-scope-email = メールアドレス
consent-scope-offline_access = サインイン状態を維持する（リフレッシュトークン）

# MFA / TOTP 画面。
mfa-title = 二段階認証
mfa-setup-title = 二段階認証の設定
mfa-setup-intro = 認証アプリ（Google Authenticator、Authy など）でQRコードをスキャンしてください。
mfa-setup-qr-alt = 認証アプリ登録用QRコード
mfa-setup-manual-label = QRコードをスキャンできない場合
mfa-setup-manual-hint = 認証アプリに以下のコードを手動で入力してください：
mfa-setup-code-label = アプリに表示された6桁のコードを入力
mfa-setup-confirm-button = 確認して有効化する
mfa-setup-confirmed-title = 二段階認証が有効になりました
mfa-setup-confirmed-message = アカウントに二段階認証が設定されました。
mfa-deleted-title = 二段階認証を無効にしました
mfa-deleted-message = アカウントから二段階認証が削除されました。
mfa-verify-title = 二段階認証
mfa-verify-intro = 認証アプリに表示された6桁のコードを入力してください。
mfa-verify-code-label = 認証コード
mfa-verify-submit = 続行
mfa-error-invalid-code = コードが正しくないか有効期限が切れています。再度お試しください。
mfa-error-session-expired = セッションの有効期限が切れました。最初からやり直してください。
mfa-error-not-signed-in = この操作を行うにはサインインが必要です。
mfa-error-already-configured = 二段階認証はすでに設定されています。再設定するには先に削除してください。
mfa-error-not-configured = 二段階認証が設定されていません。
mfa-error-mfa-not-pending = 現在の状態ではこのページは利用できません。再度サインインしてください。

# ── Passkey（WebAuthn） ──────────────────────────────────────────────────────
passkey-title = パスキー
passkey-list-title = 登録済みパスキー
passkey-list-empty = パスキーはまだ登録されていません。
passkey-register-title = パスキーを登録する
passkey-register-intro = デバイスの生体認証またはセキュリティキーを使って、パスワードなしでサインインできます。
passkey-register-name-label = パスキーの名前
passkey-register-name-placeholder = 例: MacBook Touch ID
passkey-register-button = パスキーを追加
passkey-register-success = パスキーを登録しました！
passkey-back-to-list = パスキー一覧に戻る
passkey-retry = 再試行
passkey-delete-button = 削除
passkey-delete-confirm = このパスキーを削除してもよいですか？
passkey-deleted-title = 削除完了
passkey-deleted-message = パスキーを削除しました。
passkey-last-used = 最終使用
login-passkey-or = または
login-passkey-button = パスキーでサインイン
passkey-error-not-signed-in = パスキーを管理するにはサインインが必要です。
passkey-error-session-expired = セッションの有効期限が切れました。再度サインインしてください。
passkey-error-not-found = パスキーが見つかりません。

# 設定画面（MT14・MT15）
admin-nav-settings = 設定
admin-settings-title = 設定
admin-settings-saved = 保存しました。
admin-settings-back = コンソールホームへ戻る
admin-settings-save = 保存
admin-settings-error-forbidden = この設定を変更する権限がありません。
admin-settings-error-validation = 入力内容を確認してください。
admin-settings-tenant-heading = テナント設定
admin-settings-tenant-id = テナント ID
admin-settings-tenant-status = 状態
admin-settings-tenant-name = 表示名
admin-settings-system-heading = システム設定（SMTP）
admin-settings-system-note = これらの設定は IdP 全体に適用され、root システム管理者のみが変更できます。
admin-settings-smtp-host = SMTP ホスト
admin-settings-smtp-port = SMTP ポート
admin-settings-smtp-username = SMTP ユーザー名
admin-settings-smtp-password = SMTP パスワード
admin-settings-smtp-password-set = パスワードは設定済みです。
admin-settings-smtp-password-unset = パスワードは未設定です。
admin-settings-smtp-password-hint = 空欄のままにすると現在のパスワードを維持します。
admin-settings-smtp-from = 送信元アドレス
admin-settings-smtp-tls = TLS を使用する
user-settings-title = アカウント設定
user-settings-password-heading = パスワード変更
user-settings-current-password = 現在のパスワード
user-settings-new-password = 新しいパスワード
user-settings-new-password-confirm = 新しいパスワード（確認）
user-settings-password-submit = パスワードを変更
user-settings-password-saved = パスワードを変更しました。
user-settings-language-heading = 言語
user-settings-language-current = 現在の言語
user-settings-mfa-heading = 多要素認証
user-settings-mfa-totp = 認証アプリ（TOTP）を設定する
user-settings-mfa-passkey = パスキーを管理する
user-settings-error-mismatch = 新しいパスワードが一致しません。
user-settings-error-invalid-current = 現在のパスワードが正しくありません。
user-settings-error-weak = 新しいパスワードが強度要件を満たしていません。
user-settings-error-session = セッションの有効期限が切れました。再度サインインしてください。
user-settings-error-internal = エラーが発生しました。もう一度お試しください。

# セルフサービス・パスワードリセット（MT18）。
forgot-password-title = パスワードの再設定
forgot-password-intro = アカウントのメールアドレスを入力してください。アカウントが存在する場合、再設定用のリンクを送信します。
forgot-password-email = メールアドレス
forgot-password-submit = 再設定リンクを送信
forgot-password-accepted = アカウントが存在する場合、再設定用のリンクを送信しました。受信トレイを確認してください。
forgot-password-error-unavailable = メールによるパスワード再設定は現在利用できません。管理者にお問い合わせください。
forgot-password-error-rate-limited = 試行回数が多すぎます。しばらく待ってからやり直してください。
password-reset-title = 新しいパスワードの設定
password-reset-intro = アカウントの新しいパスワードを入力してください。
password-reset-new-label = 新しいパスワード
password-reset-confirm-label = 新しいパスワード（確認）
password-reset-submit = パスワードを設定
password-reset-success = パスワードを更新しました。既存のセッションはすべてサインアウトされています。
password-reset-to-login = ログイン画面へ
password-reset-error-missing-token = 再設定リンクが不完全です。メールのリンクを確認してください。
password-reset-error-invalid = 再設定リンクが無効か、有効期限が切れています。ログイン画面から再度要求してください。
password-reset-error-weak = 新しいパスワードが強度要件を満たしていません。
password-reset-error-mismatch = パスワードが一致しません。
