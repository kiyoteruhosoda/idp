# ADR-0018: api↔web の状態受け渡しから Cookie を外し、ホスト名を入れ子にして Cookie スコープを閉じる

- Status: Accepted（決定 2〜4 は実装済み。**決定 1 はワイルドカード証明書の 1 ラベル制約により
  適用不能と判明し、ADR-0019 で撤回した** — 兄弟サブドメイン + `COOKIE_DOMAIN` 恒久未設定へ）
- Date: 2026-07-27
- 関連: `docs/adr/0012-api-web-domain-split.md`（**§Decision 1 のホスト名前提と §Decision 3「サービス横断
  Cookie に `Domain` を付与する」を本 ADR で置き換える**）、`docs/adr/0007-api-web-service-split.md`（§3 内部認証 API）、
  `docs/adr/0015-domain-split-by-listen-port.md`・`docs/adr/0016-domain-split-as-default-topology.md`（配置）

## Context

ADR-0012 は、api（OIDC protocol）と web（HTML 画面）を別サブドメインで公開するにあたり、両者が読み書きする
`sso_session_id` / `auth_session_id` に `Domain=COOKIE_DOMAIN` を付与して**ブラウザ経由で共有する**ことを決めた。

その後 stg / prod の公開ドメインを確定した（`idp.nolumia.com` / `idpapi.nolumia.com`、
`idpstg.nolumia.com` / `idpapistg.nolumia.com`）ところ、この決定が破綻していることが判明した。

- api と web は**兄弟サブドメイン**であり、両方を覆う `Domain` は共通の親 `nolumia.com` しかない。
- `Domain=nolumia.com` の Cookie は `nolumia.com` 配下の**全ホスト**へ送信される。stg も同じ配下に
  あるため、**prod にログイン済みのブラウザが stg のホストへアクセスすると prod の
  `sso_session_id` / `auth_session_id` が stg サービスへ渡る**。
- これらは平文がそのまま bearer credential である（api は受け取った値の SHA-256 で DB を引く。
  `crates/core/src/application/admin_access.rs`）。stg 側で観測・記録できれば prod セッションを再生できる。
- `COOKIE_DOMAIN` の起動時検証（`crates/contracts/src/cookie_domain.rs`）は「双方の公開オリジンの親」
  「public suffix でない」しか要求しないため、この構成は検証を通過してしまう。

原因は独立した 2 つである。

1. **ホスト名が兄弟**なので `Domain` が apex まで広がる。
2. **api↔web の状態受け渡し手段に Cookie を選んでいる**（ADR-0012 §3）。

2 について実装を確認すると、api がブラウザ Cookie を必要としているのは**ブラウザ経路の 2 エンドポイントだけ**で
あり、protocol・JSON 管理 API は Cookie を必要としていない。

| api の箇所 | Cookie の用途 | ブラウザ由来か |
|---|---|---|
| `handlers/authorize.rs`（読み） | `/authorize` の SSO 成立判定（`prompt` / `max_age` 含む） | はい |
| `handlers/authorize.rs`（書き） | `auth_session_id` を Set-Cookie し、web の `/login`・`/consent` が読む | はい |
| `handlers/logout.rs` | RP-initiated logout で SSO Cookie を読み失効させる | はい |
| `presentation/admin.rs` | 管理 JSON API の認証 extractor | **いいえ**（web の `api_client` が `Cookie:` ヘッダを明示付与するサーバ間呼び出し） |
| `/token`・`/userinfo`・`/jwks`・`/introspect`・`/.well-known` | 使わない | — |

さらに、**ログイン完了経路は既に Cookie 非依存**である。web は `auth_session_id` を
`/internal/authenticate` のリクエストボディで渡し、api は `redirect_to`（code 付き RP URL）と
`sso_session_id` を応答で返す（`crates/contracts/src/auth.rs`）。つまり「api↔web をボディで繋ぐ」形は
既にこのコードベースの確立パターンであり、残りの経路だけが Cookie に依存している。

## Decision

### 1. ホスト名を入れ子にする（api を web の子サブドメインにする）〔ADR-0019 で撤回〕

> **撤回（2026-07-29・ADR-0019）**: ワイルドカード証明書は左 1 ラベルしか覆えず、
> サブサブドメイン（`api.idp.nolumia.com`）には別証明書が必要になるため適用できなかった。
> 決定 2〜4 の実装完了により Domain 付きセッション Cookie 自体が存在しなくなったので、
> 兄弟サブドメイン（`idpapi.nolumia.com` 等）+ `COOKIE_DOMAIN` 未設定の維持で置き換える。

| 環境 | web（HTML 画面） | api（protocol・JSON） | Cookie スコープ |
|---|---|---|---|
| prod | `idp.nolumia.com` | `api.idp.nolumia.com` | `idp.nolumia.com` 配下に閉じる |
| stg | `idpstg.nolumia.com` | `api.idpstg.nolumia.com` | `idpstg.nolumia.com` 配下に閉じる |

- api が web の**子**になるため、`Domain` を apex ではなく web のホスト名まで絞れる。prod の Cookie は
  stg のホストへ送信されず、逆も同様になる。
- 公開ポート（prod `10000` / `10001`、stg `10010` / `10011`）と同梱プロキシの構成は変えない。
  変わるのは `.env` の `ISSUER`・`PUBLIC_WEB_BASE_URL`・`COOKIE_DOMAIN` と DNS・証明書だけで、
  **コード変更を伴わない**。
- ADR-0012 §Decision 1 の「同一の登録可能ドメイン配下のサブドメイン」という制約は維持したうえで、
  **api と web を兄弟にしない**ことを追加の制約とする。

### 2. api↔web の状態受け渡しから Cookie を外す

**api はブラウザ Cookie を読み書きしない。** api が受け取るセッション値は、`/internal/*` のリクエスト
ボディか、web がサーバ間呼び出しで明示的に付与した `Cookie:` ヘッダに限る。

- **`auth_session_id`**: `/authorize` は Set-Cookie をやめ、web へのリダイレクト URL に**単回・短命の
  ハンドル**として載せる（`{web}/{tenant}/login?auth_session=...`）。web は受領後ただちに自ドメインの
  host-only Cookie（またはフロー内の受け渡し）へ移し、URL からは除去する（303 で自 URL へ）。
  以降 api へ返すのは従来どおり `/internal/*` のボディ。
- **SSO 判定**: `/authorize` は SSO Cookie を読まない。web が**自ドメインの host-only**
  `sso_session_id` を読み、`/internal/*` の新エンドポイントへ `auth_session_id` とともに渡す。
  api は SSO 有効なら `redirect_to`（code 付き）を、無効ならログイン継続を返す（`/internal/authenticate`
  と同じ応答パターン）。
- **ログアウト**: 起点を web にする。api の `/logout` は `id_token_hint` 検証・back-channel 通知・
  `post_logout_redirect_uri` の組み立てを担い、**SSO Cookie の破棄は web が自ドメインで行う**。

### 3. 認可コードフロー + PKCE は不変（アクセストークン発行経路に手を入れない）

アクセストークンの発行は従来どおり **Authorization Code Flow + PKCE（S256）** のみとし、本 ADR は
**フロントチャネル（`/authorize` → ログイン画面 → `/authorize` 完了）の状態受け渡し手段だけ**を変える。

- `code_challenge` / `code_challenge_method` はブラウザではなく**サーバ側の `auth_session` が保持**し、
  code 発行時に `authorization_code` へ引き継がれる（`crates/core/src/domain/{auth_session,authorization_code}.rs`）。
  URL に載せるのはその `auth_session` を指す**単回ハンドルだけ**で、PKCE の値そのものは載せない。
- `/token` の code 交換（`code_verifier` の検証）は RP↔api のバックチャネルであり、元から Cookie に
  依存していない。本 ADR で**変更しない**。
- したがって「ハンドルを奪われても PKCE が破れない」性質は維持される。逆にハンドルは
  `auth_session`（＝その `code_challenge`）に固定的に束ねられ、他の認可要求へ付け替えられないこと
  （単回・短命・固定束縛）を実装の受け入れ条件とする。
- 暗黙フロー・パスワードグラント等は引き続き採用しない。

### 4. `COOKIE_DOMAIN` は設定しないことを既定とする

決定 2 の完了後、api と web が同一 Cookie を共有する必要は無くなる。`COOKIE_DOMAIN` は
**未設定（host-only）を既定**とし、設定キー自体は互換のため残すが `domain-split` でも設定しない。

### 適用順序

決定 1 と 2 は独立に効く。**1 だけでも本 ADR の Context にある露出は塞がる**（安価・コード変更なし）ため、
先に 1 を適用し、続けて 2 を実装する（多層防御。2 の完了後も 1 の入れ子構成は維持する）。

## Consequences

**良くなる点**

- prod と stg の Cookie スコープが交わらない（決定 1）。api がブラウザから bearer credential を
  受け取らなくなる（決定 2）。どちらか一方が崩れても、もう一方が露出を防ぐ。
- CSRF・`SameSite`・Cookie 属性の考慮が web に集約され、api は「ボディで受けてボディで返す」だけになる。
- 単一オリジン構成（`single-origin`）との差分が減る（どちらも `COOKIE_DOMAIN` 未設定で動く）。

**コスト・注意点**

- **`ISSUER` が変わる**（api のホスト名変更）。discovery・ID Token の `iss` が変わるため、
  **RP 側の再設定が必要**。移行はメンテナンス枠で行う。
- 証明書は **web・api 両方のホスト名を SAN に含める**必要がある。`*.idp.nolumia.com` の
  ワイルドカードは `api.idp.nolumia.com` には一致するが、**bare な `idp.nolumia.com` には一致しない**
  （ワイルドカードは左 1 ラベルのみを覆う）。1 枚にまとめるなら SAN = `idp.nolumia.com` +
  `api.idp.nolumia.com`（または `*.idp.nolumia.com` + `idp.nolumia.com`）とし、2 枚に分けてもよい。stg も同様。
- `/authorize` から web への往復が 1 回増える。`prompt=none`（サイレント認証）もリダイレクトで
  完結するためユーザー操作は不要だが、iframe 経路の挙動はテストで確認する。
- URL に載せる `auth_session` ハンドルは**単回使用・短命・高エントロピー**とし、`Referrer-Policy` を
  設定したうえで web が即座に URL から除去する。ログにクエリ文字列を残さないことも合わせて確認する。
- 既存ブラウザに残る `Domain` 付き Cookie は、ADR-0012 §3 と同じ要領で削除 Cookie を併送して掃除する
  （今度は「ドメイン付きを消して host-only へ戻す」向き）。
