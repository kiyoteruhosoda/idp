# ログイン画面の文言（キーは en/main.ftl と共通。日本語訳は手動で追記する）。
login-title = サインイン
login-username = ユーザー名またはメールアドレス
login-password = パスワード
login-submit = サインイン
login-error-invalid-credentials = ユーザー名またはパスワードが正しくありません。
login-error-locked = このアカウントは一時的にロックされています。しばらくしてからお試しください。
login-error-session-expired = サインインのセッションが期限切れです。アプリケーションからやり直してください。
login-error-csrf = フォームの有効期限が切れました。ページを再読み込みしてやり直してください。
login-error-rate-limited = 試行回数が多すぎます。しばらく待ってからお試しください。

# 管理コンソール（A2）。idp.admin 権限で保護するサーバレンダリング画面。
admin-console-title = 管理コンソール
admin-login-title = 管理者サインイン
admin-login-error-forbidden = このアカウントには管理者権限がありません。
admin-signed-in-as = サインイン中
admin-logout = サインアウト
admin-home-intro = 管理コンソールへようこそ。管理する項目を選択してください。
admin-nav-clients = クライアント（RP）
admin-nav-audit = ログイン・監査ログ
admin-nav-permissions = 利用者権限
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
