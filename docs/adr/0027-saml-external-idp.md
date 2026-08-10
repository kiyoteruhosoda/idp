# ADR-0027: SAML 外部 IdP（SP 側）

- Status: Accepted
- Date: 2026-08-10
- 関連: ADR-0023（外部 IdP の信頼モデル）、AP10（OIDC 外部 IdP）、AP12

## Context

AP10 で入れた外部 IdP は **OIDC のみ**である。`external_identity_providers` は
`issuer` / `authorization_endpoint` / `token_endpoint` / `jwks_uri` / `client_id` という OIDC 前提の
列構成で、SAML の IdP メタデータ（`SingleSignOnService` URL・署名証明書・`NameID` 形式）を
表現できない。

本 IdP を **SAML の IdP として**振る舞わせる側（`/{tenant}/saml/metadata`・`saml_sso_requests`）は
既に在る。ここで決めるのは**向きが逆**の話——外部の SAML IdP を利用者の認証元として使う（SP 側）。

決めることは 2 つある。

1. プロトコル固有の設定をどこに置くか。
2. SAML アサーションの署名検証をどう実装するか。

## Decision

### 1. プロトコル固有の設定は同じ表の列に置き、Rust 側は enum で 1 つに絞る

`external_identity_providers` に `protocol`（`oidc` / `saml`）列を足し、**両プロトコルの設定列を
同じ表に置く**（使わない側は NULL）。ドメインは

```rust
pub enum ExternalIdpConfig { Oidc(OidcProviderConfig), Saml(SamlProviderConfig) }
```

を持ち、`ExternalIdentityProvider` は共通項（`provider_code` / `display_name` / `issuer` /
`enabled` / `allow_auto_link`）＋ `config` で構成する。

**JSON 列に寄せない。** MariaDB の JSON では列ごとの NOT NULL・CHECK・長さ制限を掛けられず、
「SSO URL が空のまま登録された SAML プロバイダ」が登録時ではなく**ログイン時**に落ちる。設定の
誤りは管理者が直せる時点（登録・更新）で弾きたい。

**別表にも分けない。** プロバイダは認証のたびに読む。1 プロトコルにつき 1 行しか無い付随表を
join するか 2 回引くかの選択が、共通項だけを読みたい一覧（ログイン画面のボタン）にも掛かる。
列の NULL は「この行では使わない」を表すのに十分で、どの組み合わせが妥当かは Rust の enum が
単一の出所として持つ。リポジトリは行 → enum の変換でしか値を作らないので、
`protocol = 'saml'` なのに SSO URL が NULL という行は**読み出しで失敗する**（黙って既定に
落ちない）。

### 2. `issuer` は両プロトコル共通の信頼の起点にする

- OIDC: ID Token の `iss`。
- SAML: Response / Assertion の `<Issuer>`（IdP の entityID）。

どちらも「その主張を出した発行者の識別子」で、`user_external_identities.external_issuer` は
そのまま使える。同一性の根拠を `iss` + `sub` に限る ADR-0023 の判断は SAML でも変えない
（`sub` に当たるのが `NameID`）。**メール一致による自動連携は SAML でも `allow_auto_link` の
明示設定を要求する。**

### 3. XML 署名の検証は自前で実装する

保守されている純 Rust の SAML SP ライブラリが無い。一方、IdP 側（`domain::saml_response`）で
既に XMLDSIG の**生成**を自前で持っており、そこでは「最初から排他的正準形で XML を組み立てる」
ことで正準化器を持たずに済ませていた。**検証側では同じ手は使えない**——受け取る XML は相手が
作るものなので、本物の排他的正準化（exclusive C14N）が要る。

そこで次の 2 モジュールを足す。

- `domain::xml_c14n` — 排他的正準化（`http://www.w3.org/2001/10/xml-exc-c14n#`）。
- `domain::xml_signature` — enveloped signature の検証（RSA-SHA256 / ECDSA-SHA256）。

対応するのは SAML SP に必要な組み合わせだけに絞る（exc-c14n・SHA-256・enveloped）。
未対応のアルゴリズムは**既定へ丸めずエラー**にする。SHA-1 系は受け付けない。

### 4. 署名ラッピング（XSW）への防御を検証の入口で固定する

SAML SP の典型的な破れ方は、署名そのものではなく「署名された要素と**読む**要素が違う」ことで
起きる。次を検証の前提条件として `xml_signature` / `saml_external_idp` に置く:

- `Assertion` は**ちょうど 1 つ**。0 個・2 個以上は拒否する。
- 署名は Response か Assertion のいずれかに掛かっていること。**Response だけに署名がある場合は、
  その Assertion が署名対象の部分木に含まれていること**を ID の一致で確認する。
- `Reference URI` は `#ID` 形式に限る（空 URI = 文書全体・外部参照は拒否）。
- 参照先 ID を持つ要素が**ちょうど 1 つ**であること（複数一致は拒否）。
- 検証済みの要素から**取り出し直した**値だけを使う（検証と読み出しで別の木を歩かない）。

## Consequences

- 管理 API・管理画面は `protocol` で入力項目が変わる。SAML では IdP メタデータ XML の貼り付けから
  `entityID` / SSO URL / 証明書を取り込める（既にある `domain::saml_metadata` を
  `IDPSSODescriptor` の解析まで広げる）。
- 署名証明書は**配列**で持つ（`saml_certificates`）。IdP の証明書更新期間は新旧の 2 枚が同時に
  有効なので、1 枚しか持てないと更新のたびにログインが止まる。
- SP 側の PKCE・`nonce` に当たるものが SAML には無い。リプレイ防止は
  `InResponseTo` と `RelayState` の単回消費（既存の `external_login_requests` を流用）＋
  `NotOnOrAfter` / `NotBefore` の時刻検証で行う。
- 外部 IdP との通信はブラウザ経由（HTTP-Redirect / HTTP-POST バインディング）だけで、サーバ間
  通信は無い。OIDC の `ExternalOidcClient` に当たるポートは**要らない**（検証はすべて手元で完結
  する）ので、SAML 用のポートは足さない。
- **署名付き AuthnRequest は出さない。** 出すには SP 側の鍵と、IdP 側での鍵登録・更新の運用が
  要る一方、得られるのは「AuthnRequest の出所の保証」で、アサーションの真正性は Response の
  署名検証で担保されている。必要になった時点で足す。
