# ADR-0013: web の共有ランタイム設定を api 経由で解決する

- Status: Accepted
- Date: 2026-07-25
- 関連: `docs/adr/0007-api-web-service-split.md`（web は sqlx/DB に依存しない）、
  `docs/adr/0010-zero-touch-deployment-and-configuration-provenance.md`（設定キーの出所区分。
  本 ADR は §2「`.env` への materialize」の代替手段を定める）、
  `docs/adr/0012-api-web-domain-split.md`（api/web で一致必須のキー）、
  `docs/Progress.md`（MT26）

## Context

ADR-0010 は設定キーの出所を `BUILTIN` / `ENV_LOCKED` / `DB_MANAGED` の 3 状態で管理すると決めた。
DB で上書きできる（＝設定画面から変えられる）ことが運用上の価値であり、既定は `DB_MANAGED` にしたい。

しかし ADR-0007 で **web は DB（sqlx）に依存しない**と決めているため、web は `system_settings` を読めない。
その結果、api と web の**両方が消費する**次のキーは「値がずれると壊れる」ことを理由に `ENV_LOCKED` へ
退避したまま残っていた。

| キー | api での用途 | web での用途 | ずれたときの壊れ方 |
|---|---|---|---|
| `COOKIE_SECURE` | `Set-Cookie` の `Secure` 属性 | 同左（web も同じ Cookie を発行する） | 片側が `Secure` を落とすと平文経路へ Cookie が出る／https 側で Cookie が保存されない |
| `HSTS_MAX_AGE` | `Strict-Transport-Security` | 同左 | 片方のドメインだけ HSTS が付かない |
| `AUTH_SESSION_TTL_SECS` | `auth_session` レコードの寿命 | `auth_session_id` Cookie の `Max-Age` | Cookie だけ先に切れる／DB だけ先に切れる。どちらもログインが進まない |

いずれも**壊れ方が静か**である（500 が出るのではなく、ログインが通らない・保護が外れる）。
そのため「片方だけ DB で変えられる」状態は許容できず、ENV_LOCKED のまま設定画面から触れなかった。

ADR-0010 §2 は `DB_MANAGED` かつ再起動が必要な値を「DB を正として `.env` の marker 内へ materialize する」
としていた。しかしこれはホスト上のファイル書き換えを伴い、原子的更新・排他・permission 検証・障害復旧を
デプロイスクリプト側に要求する（ADR-0010 §Consequences が挙げた負債そのもの）。api がすでに DB の唯一の
所有者であり、web→api の内部 API（`/internal/*`）も存在する以上、ファイルを経由する必要はない。

## Decision

### 1. api を共有ランタイム設定の唯一の出所（SSOT）とし、web は起動時に HTTP で受け取る

- 設定定義（`domain/system_setting.rs` の `RUNTIME_SETTING_DEFINITIONS`）に
  **`shared_with_web` フラグ**を追加する。「api と web の両方が消費する DB 管理キー」であることを
  定義側に持たせ、キー一覧をコードの複数箇所へ散らさない。
- api は `GET /internal/runtime-settings` で、`shared_with_web` かつ非 secret のキーの
  **DB 上書き値だけ**を返す。`/internal/*` 共通のサービス認証トークンで保護する。
- web は起動時に 1 度だけこれを呼び、`既定値 < ENV < api 経由の DB 値` の順で設定を解決する。
- 上記 3 キーを `ENV_LOCKED` から `DB_MANAGED` へ変更する（＝ root 設定画面から変更できるようになる）。

`.env` の materialize（ADR-0010 §2）は本用途では採らない。ファイル書き換えを伴わないため、
`deploy.sh` は `.env` の生成・保持に専念でき、DB reset で DB 管理値が消えるという寿命の扱いも変わらない。

### 2. 返すのは「DB 上書き値」であり「api の有効値」ではない

api が自分の有効値（ENV・既定値まで解決した結果）を返すと、web の既定値の導き方を api が上書きしてしまう。
とくに `COOKIE_SECURE` の既定は**各サービスが自分の公開オリジンのスキームから導く**（ADR-0012 §2:
web は `PUBLIC_WEB_BASE_URL`、api は `ISSUER`）。したがって api は DB に明示的に保存された値だけを返し、
そこに無いキーは web が自分の ENV → 自分の既定値へフォールバックする。

上書き解除（`system_settings` に空文字列を保存する）は応答へ含めない。「空文字列という値」ではなく
「キーが無い」として渡すことで、web 側の未設定判定と一致する。

### 3. secret は共有しない

`shared_with_web` は非 secret キーにのみ立てる（`domain/system_setting.rs` のテストで強制する）。
web が必要とする bootstrap secret（`INTERNAL_SERVICE_TOKEN`・`CSRF_SECRET`）は ADR-0010 の方針どおり
`ENV_LOCKED` のままで、web 自身の環境変数から読む。api が secret を配る経路は作らない。

### 4. 取得に失敗したら web は起動しない（fail-fast）

api へ到達できない場合は指数バックオフで再試行し（5 回・500ms 起点）、全試行が失敗したら起動を失敗させる。
ENV だけで起動する fail-soft は採らない。共有キーはいずれも壊れ方が静かで、設定画面の表示と実挙動が
食い違ったまま動く方が原因に辿り着けないためである。Compose では web が
`depends_on: api (service_healthy)` と `restart: unless-stopped` を持つため、api 復旧後に自動で回復する。

同じ理由で、DB 上書き値のパースに失敗した場合も既定値へ黙って落とさず起動を失敗させる。

### 5. 反映タイミングは「両サービスの再起動」

これらのキーは `restart_required: true` のままとする。設定画面で変更した値は **api と web の両方を
再起動して**初めて有効になる（web は起動時にしか取得しない）。ホットリロードは Progress MT27 で扱う。

## Consequences

- `COOKIE_SECURE`・`HSTS_MAX_AGE`・`AUTH_SESSION_TTL_SECS` を root 設定画面から変更できるようになり、
  ADR-0010 の「あとから DB で上書きできる」という思想が web を含む全体へ及ぶ。
- 値の一致は「同じ値を 2 箇所へ書く」ではなく「同じ出所から 2 サービスが読む」ことで保証される。
  片側だけ typo する事故が構造的に無くなる。
- web の起動が api の可用性に依存するようになる（従来は独立に起動できた）。Compose の依存関係は
  すでにこの順序であり、readiness も api 到達性で判定していた（`/readyz`）ため運用上の変化は小さい。
- 設定変更後に web を再起動し忘れると、api と web で値がずれた状態が生じる。起動ログへ
  「api から受け取って適用したキー名」を出し、切り分けできるようにする（値は出さない）。
- 新しい共有キーを増やすときは、定義へ `shared_with_web: true` を立て、web の `config.rs` で
  `SharedSettingResolver` 経由に読み替えるだけでよい（エンドポイント・クライアントは変更不要）。

## Rejected alternatives

### `.env` の marker 内へ materialize する（ADR-0010 §2 の原案）

DB を正として `.env` を書き換え、両サービスが同じファイルから読む。値の一致は保証できるが、ホスト上の
ファイルの原子的更新・排他・permission 検証・失敗時のロールバックをデプロイスクリプトが負う。
api がすでに DB の唯一の所有者であり内部 API も存在するため、この複雑さに見合わない。

### web にも DB 接続を持たせる

最も単純だが、ADR-0007 の「web は sqlx/infrastructure に依存しない」という crate 境界を壊す。
web の攻撃面に DB 資格情報が加わり、分割の主目的（DB へ触れるサービスを api だけに限定する）を失う。

### リクエストごとに api から取得する

設定変更が再起動なしで反映される利点はあるが、Cookie 発行のたびに api 呼び出しが増え、api 障害時の
挙動（前回値を使うのか失敗させるのか）を全ハンドラで決める必要がある。ホットリロードの是非は
共有設定に限らない論点のため、MT27 で設定機構全体として扱う。

### `ENV_LOCKED` のまま据え置く

現状維持。運用者は設定画面で値を見られるのに変更はできず、変更するにはホストの `.env` を編集して
再デプロイする必要がある。ADR-0010 が解こうとした問題がそのまま残る。
