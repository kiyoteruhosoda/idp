# ADR-0012: api と web を別ドメイン（別オリジン）で公開する

- Status: Accepted
- Date: 2026-07-25
- 関連: `docs/adr/0007-api-web-service-split.md`（§2 で「サブドメイン分割」を代替として保留していた決定を本 ADR で採用する）、
  `docs/adr/0010-zero-touch-deployment-and-configuration-provenance.md`（設定キーの出所区分）、
  `docs/Progress.md`（MT29）

## Context

ADR-0007 で api（OIDC protocol・JSON 管理 API）と web（HTML 画面）をサービス分割した際、デプロイ位置づけは
**単一オリジン・パスルーティング**（1 ドメインをリバースプロキシがパスで振り分け）を既定とし、
サブドメイン分割は「CORS/CSRF の考慮が増えるため既定にしない（将来必要になれば選択可能）」の代替扱いだった。

その「将来」が来た。次を実現するため、api と web を**別ドメイン（別オリジン）で公開する構成**を正式に採用する。

- **公開範囲の分離**: protocol（api）は外部公開しつつ、ログイン画面・管理コンソール（web）のドメインを
  社内 DNS・別のアクセス制御下に置ける。
- **TLS・証明書・WAF ポリシーの独立運用**: ドメイン単位で設定を分けられる。
- **プロキシ構成の単純化**: パスの振り分け表を保守する代わりに、ドメイン → サービスの 1:1 対応にできる。

一方、現状の実装は単一オリジンを前提にしている箇所がある。

| 箇所 | 現状 | 別ドメインでの問題 |
|---|---|---|
| `/authorize` → ログイン画面 | `/{tenant}/login` へ**相対** 302（`crates/api/src/presentation/handlers/authorize.rs`） | api ドメイン上の存在しないパスへ飛ぶ |
| Cookie（`sso_session_id`・`auth_session_id`） | `Domain` 属性なし＝**host-only**（`crates/{api,web}/src/{presentation/,}cookies.rs`） | web が Set-Cookie した SSO Cookie が api の `/authorize` に送信されない（逆も同様） |
| web の Cookie `Secure` 判定 | `ISSUER`（= api の公開オリジン）のスキームで判定 | web 自身の公開オリジンと乖離しうる |

## Decision

### 1. トポロジ: 同一親ドメイン配下のサブドメイン分割のみをサポートする

- 例: api = `https://api.example.com`、web = `https://id.example.com`。
- **api と web は同一の登録可能ドメイン（eTLD+1、例 `example.com`）のサブドメインであることを必須制約とする。**
  SSO/auth_session Cookie の共有（決定 3）と `SameSite=Lax` の維持は「same-site（同一 eTLD+1）」であることに
  依存する。全く無関係なドメイン間（cross-site）の分割は、サードパーティ Cookie 遮断により成立しないため
  **サポートしない**。
- 従来の単一オリジン・パスルーティング構成は**引き続きサポートする**（ローカル開発・小規模配置の既定。
  決定 2 のキーが未設定なら従来挙動のまま）。コードは両構成を同一バイナリで扱う。
  → **既定は ADR-0016 で本 ADR の別ドメイン構成（`domain-split`）へ変更した**。単一オリジンは
  `PUBLISH_TOPOLOGY=single-origin` の明示指定で継続サポートする（同一バイナリで両対応する点は不変）。

### 2. お互いのドメインの定義場所（SSOT は config。DNS・プロキシ設定ではない）

各サービスが「自分」と「相手」の公開オリジンを知る場所は、ADR-0010 の設定機構（`config` モジュール）に
一元化する。リバースプロキシや DNS の設定はこれに**追従する側**であり、出所にしない。

| キー | 読む側 | 意味 | 出所区分（ADR-0010） |
|---|---|---|---|
| `ISSUER` | api / web | **api の公開オリジン**（OIDC issuer。ID Token `iss` と完全一致）。web はブラウザを api へ向けるリダイレクトの基点として参照する | EnvLocked（既存） |
| `PUBLIC_WEB_BASE_URL` | api / web | **web の公開オリジン**。api は `/authorize` からログイン/同意画面への 302 とメールリンク生成に使う（既存）。web は**自オリジン**として Cookie `Secure` 判定・絶対 URL 生成に使う（新規参照） | **EnvLocked へ変更**（下記） |
| `API_BASE_URL` | web | web→api の**サーバ間内部到達先**（reqwest）。公開ドメインとは独立（内部ネットワークのアドレスでよい） | EnvLocked 相当（web は DB を持たない。既存） |
| `COOKIE_DOMAIN` | api / web | **新設**。サービス横断 Cookie に付与する `Domain` 属性（例 `.example.com`）。**未設定 = host-only**（単一オリジン構成の従来挙動） | **EnvLocked**（api/web で一致必須のため DB 上書き不可） |

- `PUBLIC_WEB_BASE_URL` は api（相手の URL としてリダイレクト先に使う）と web（自分の URL として
  Secure 判定・絶対 URL 生成に使う）が**同一の公開オリジンを指す前提の値**であり、不一致は全ログイン
  フローを壊す（api が `id-a` へ 302、web は `id-b` として振る舞う、など）。ADR-0010 の
  「api/web で値を一致させる必要があるキーは EnvLocked」の規則に従い、**DbManaged から EnvLocked へ
  変更する**（DB 側だけの変更や片側の typo が検出されないまま効いてしまう事態を防ぐ。実装は MT29）。
- web の Cookie `Secure` 判定は `ISSUER` のスキームではなく**自オリジン（`PUBLIC_WEB_BASE_URL`）のスキーム**
  で行うよう改める（`COOKIE_SECURE` による明示上書きは従来どおり）。
- 新設キーは CLAUDE.md「設定管理」の手順どおり `RUNTIME_SETTING_DEFINITIONS`（`domain/system_setting.rs`）へ
  定義を追加し、api（`crates/core/src/config.rs`）・web（`crates/web/src/config.rs`）双方に getter を設ける。

### 3. Cookie 共有: サービス横断 Cookie に `Domain=COOKIE_DOMAIN` を付与する

- 対象は **api と web の双方が読み書きする Cookie のみ**: `sso_session_id`（SSO セッション）と
  `auth_session_id`（`/authorize`〜`/login` の短命セッション）。
- `COOKIE_DOMAIN` 設定時は両サービスの Cookie 組み立て（`cookies::build`）が同一の `Domain` 属性を出力する。
  削除 Cookie（`Max-Age=0`）も同じ `Domain` で出さないと消えないため、build/clear の両方に適用する。
- **既存デプロイからの移行（host-only Cookie の残留対策）**: Cookie の識別子は名前だけでなく `Domain` を
  含むため、単一オリジン構成から `COOKIE_DOMAIN` を有効化しても、ブラウザに残った旧 host-only の
  `sso_session_id` / `auth_session_id` は上書き・失効されず、同名 Cookie が二重送信されて古いセッションが
  新しいセッションを覆い隠しうる（ログインループ・セッション取り違え）。これを防ぐため、
  `COOKIE_DOMAIN` 設定時の Set-Cookie は**ドメイン付き Cookie の発行と同時に、`Domain` 属性なしの
  同名削除 Cookie（`Max-Age=0`）を併送する**（build/clear 共通。host-only 残留を能動的に掃除する）。
- `SameSite=Lax` / `HttpOnly` / `Secure` / `Path=/` は現行のまま変更しない（same-site サブドメイン間の
  トップレベル遷移・フォーム POST では Lax でも Cookie が送信される）。
- web ローカルの Cookie（`lang`・CSRF 関連等、api が読まないもの）は host-only のまま広げない。

### 4. ブラウザ向けクロスサービス遷移は絶対 URL にする

- api の `AuthorizeOutcome::LoginRequired` / `ConsentRequired` の 302 先を、相対パスから
  `{PUBLIC_WEB_BASE_URL}/{tenant}/login`・`{PUBLIC_WEB_BASE_URL}/{tenant}/consent` の絶対 URL へ変更する
  （単一オリジン構成では `PUBLIC_WEB_BASE_URL`＝`ISSUER` なので挙動は実質不変）。
- web がブラウザを api へ向ける経路（あれば）は `ISSUER` 基点の絶対 URL とする。web→api のサーバ間呼び出しは
  従来どおり `API_BASE_URL` で、公開ドメインを経由しない。
- ログイン成功時の RP への `redirect_to` は api が生成する絶対 URL であり、変更不要。

### 5. CORS は導入しない

ブラウザとサービス間のクロスオリジン相互作用は**トップレベル遷移（302・フォーム POST）のみ**に保つ。
管理コンソールのデータ取得・操作は従来どおり web がサーバ側で api を呼ぶ（ADR-0007 §4）ため、
ブラウザから api への cross-origin XHR/fetch は存在しない。よって api に CORS ヘッダを追加しない
（追加しないことが公開面の縮小として機能する）。

### 6. リバースプロキシ・公開範囲

- パスルーティング表に代えて、**ドメインごとの vhost**（api ドメイン → api、web ドメイン → web）とする。
  > **本項は ADR-0015 で置き換えられた。** 実装では vhost（`server_name`）ではなく
  > **リッスンポート分割**（同梱 nginx の `:8080` → web、`:8081` → api）を採る。前段プロキシが既に
  > ドメインで振り分けているため、同梱 nginx にもドメイン名を持たせると二重管理になるという理由。
  > 決定と手順は `docs/adr/0015-domain-split-by-listen-port.md` を参照。
- `/internal/*` は**どちらのドメインでも公開しない**（ADR-0007 §5 のとおり内部ネットワーク限定＋
  サービス認証トークン）。
- HSTS（`HSTS_MAX_AGE`）・`X-Forwarded-*` の信頼（`TRUST_FORWARDED_HEADERS`）は両ドメインに同様に適用する。

## Consequences

**Positive**

- 画面（web）と protocol（api）の公開範囲・TLS・WAF をドメイン単位で独立に制御できる。
  管理コンソールを内部 DNS 限定にする、といった運用が可能になる。
- ドメイン → サービスの 1:1 対応でプロキシ設定が単純になり、パス振り分け表の保守が消える。
- 単一オリジン構成と同一コードで両対応（`COOKIE_DOMAIN` 未設定なら従来挙動）のため、退行リスクが小さい。

**Negative / コスト**

- `Domain=.example.com` の Cookie は**同一親ドメイン配下の全サブドメインへ送信される**。同じ親ドメインに
  信頼できない他サービスを同居させない、という運用上の前提が新たに生じる（OPERATIONS に明記する）。
- 設定不整合時の障害モードが増える（`COOKIE_DOMAIN` 片側未設定 → ログインループ、`PUBLIC_WEB_BASE_URL`
  誤設定 → 誤ドメインへの 302）。起動時検証で fail-fast にする。検証内容は次の 2 点:
  1. `COOKIE_DOMAIN` が `ISSUER`・`PUBLIC_WEB_BASE_URL` 双方のホストの親ドメイン（または同一）であること。
  2. `COOKIE_DOMAIN` が **public suffix（eTLD。例 `.co.uk`・`.com`）そのものでないこと**。public suffix は
     `api.example.co.uk` / `id.example.co.uk` 双方の親として検証 1 を通過してしまうが、ブラウザは
     public suffix への `Domain` Cookie を拒否するため、起動は成功するのに Cookie が一切共有されない
     ログインループになる。Public Suffix List に基づく判定（例: `psl` クレート）で起動時に拒否する。
- `PUBLIC_WEB_BASE_URL` の EnvLocked 化（決定 2）は既存の DbManaged 運用からの**破壊的変更**:
  DB（system_settings）で上書きしていた環境は、同じ値を ENV へ移す必要がある（OPERATIONS に移行手順を記載）。
- ローカル開発（`localhost` ポート違い）は same-site だが `Domain` 属性を使えないため、開発は従来どおり
  単一オリジン（または host-only のまま同一ホスト名）で行う。

**Alternatives considered**

- **全く別ドメイン間の分割（cross-site）＋トークンリレー**: サードパーティ Cookie 遮断下で SSO Cookie を
  共有できず、ワンタイムトークンの受け渡し機構が必要になる → 複雑さに見合わず却下。
- **ブラウザから api への直接 XHR ＋ CORS 開放**: 管理コンソールを SPA 化する前提がなく、公開面が広がるだけ
  → 却下（決定 5）。
- **単一オリジン・パスルーティングの継続**: 公開範囲・TLS の独立制御ができない → 既定としては残すが、
  本番公開の目標構成にはしない。

### 7. テスト戦略: Cookie 越境を実際に検証する web→api E2E を必須とする

現状のテストは本 ADR の挙動を**検証できない**。web には `crates/web/tests/`（統合テスト）が存在せず、
api の `tests/oidc_flow.rs` は web の役をテストコードが代行して `/internal/*` を直接呼び、Cookie も
ヘッダ文字列を手で組み立てている（ブラウザの `Domain` 属性・same-site・host-only 同名競合の規則を
エミュレートしていない）。このままでは Cookie 共有が壊れてもテストが通る。

MT29 の実装には次の E2E テストを含める（受け入れ条件）。

- **構成**: api と web を実プロセス（またはローカルポートに bind した実サーバ）として同時起動し、
  Cookie jar 有効の HTTP クライアント（reqwest `cookie_store` + `resolve()` で
  `api.example.test` / `id.example.test` → `127.0.0.1` を上書き）でブラウザ相当の遷移を辿る。
  Cookie jar が `Domain` 属性・ホスト一致を解釈するため、越境可否を実挙動で検証できる。
- **ケース**:
  1. 別ドメイン構成: `/authorize`（api ドメイン）→ 302 → `/login`（web ドメイン）→ POST → SSO Cookie が
     `Domain=COOKIE_DOMAIN` で保存され、**再度の `/authorize`（api ドメイン）に SSO Cookie が送信されて**
     即時 code 発行される（ログイン→API 連携の本丸）。
  2. `auth_session_id` の逆方向: api（Set-Cookie）→ web（`/login` で読む）に届く。
  3. host-only 残留の掃除: 事前に host-only の同名 Cookie を仕込んだ状態でログインし、削除併送により
     二重 Cookie が解消される。
  4. 回帰: `COOKIE_DOMAIN` 未設定（単一オリジン構成）で従来挙動が変わらない。
- 起動時検証（親ドメイン整合・public suffix 拒否）はユニットテストで網羅する。

## Follow-ups

- 実装は `docs/Progress.md` の **MT29** で追う（`COOKIE_DOMAIN` 新設・絶対 URL 化・web 自オリジン設定・
  起動時検証・web→api E2E テスト）。
- `docs/OPERATIONS.md` に別ドメイン構成の設定手順（環境変数一覧・vhost 例・親ドメイン同居の注意）を追記する。
- 完了時に ADR-0007 §2 へ「別ドメイン構成は ADR-0012 で正式サポート化」の注記を入れる。
