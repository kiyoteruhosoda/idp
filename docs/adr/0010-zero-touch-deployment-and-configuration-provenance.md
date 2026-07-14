# ADR-0010: ゼロタッチ配置と設定値の出所管理

- Status: Proposed
- Date: 2026-07-13
- Related: ADR-0004, ADR-0007, ADR-0009, Progress CFG1/OPS1/UI1

## Context

初期配置では、利用者が `.env` を手作業で作らなくても DB、migration、api、web、proxy が起動し、
ログイン画面へ到達できる必要がある。一方、設定には次の異なる寿命がある。

1. 未設定でも起動するための組み込み既定値。
2. STG/PROD 等のサイト差を表し、初期化や通常 deploy で上書きしてはいけない `.env` の固定値。
3. 設定画面から変更し、DB reset では消えてよいサイト固有値。コンテナ再作成が必要な値は `.env` へ反映する。

現在は api/web の `Config`、Compose、`.env.example`、DB の `system_settings` が別々に設定キーを管理している。
Compose が注入しないキーがあり、コメント上の「環境変数 > DB > 既定値」と実装も一致しない。また、固定 `.env`
と DB 反映による `.env` 更新を区別しなければ、通常 deploy による意図しない上書きや reset 後の値残留が起こる。

## Decision

### 1. 設定レジストリを単一の出所にする

各設定キーについて、型、既定値、secret 区分、利用サービス、再起動要否、許可する出所、危険判定を定義する。
api/web の構成読み込み、設定 API、Compose への注入一覧、設定画面はこの定義と整合させる。

設定の状態は次のいずれかとする。

| 状態 | 意味 | 通常 deploy | reset |
|---|---|---|---|
| `BUILTIN` | リポジトリ組み込み既定値 | 変更なし | 組み込み値へ戻る |
| `ENV_LOCKED` | オペレーターが `.env` 固定領域で指定 | 上書きしない | 保持する |
| `DB_MANAGED` | 設定画面/API で DB 管理を明示 | DB 値を自動生成領域へ反映 | DB と自動生成領域から削除 |

有効値は、キーに選択された状態の値を使う。異なる状態を暗黙の優先順位だけで競合させず、設定画面と API は
現在の状態と出所を返す。`ENV_LOCKED` から `DB_MANAGED` への変更は root 管理者の明示操作と監査ログを必須にする。

### 2. `.env` を固定領域と自動生成領域に分ける

`.env` 内にスクリプト管理の開始・終了 marker を設ける。marker 外はオペレーター固定領域であり、通常 deploy、
DB 反映、初期化で変更しない。marker 内だけを原子的に再生成し、更新前の構文・permission を検証する。

- 初回で `.env` が無い場合はテンプレートから作成し、bootstrap secret を CSPRNG で生成する。
- `DB_MANAGED` かつ再起動が必要な値は、DB を正として marker 内へ materialize する。
- `reset` は DB と marker 内の DB 管理値を削除する。marker 外の STG/PROD 固定値は保持する。
- secret はログ、API、画面、差分へ平文出力しない。

DB 接続情報、DB root password、`KEY_ENCRYPTION_KEY`、サービス間認証 token など、DB を読む前または DB 内の
secret を復号するために必要な bootstrap secret は `DB_MANAGED` にしない。これらは初回自動生成後
`ENV_LOCKED` として扱い、専用の rotation 手順を持つ。

### 3. deploy の入口を一本化する

ホスト側の標準入口は `deploy.sh` とし、モードは `app`（デプロイ）、`migrate`、`reset` の 3 つに
限定する。`.env` が無い初回デプロイは、自動生成、DB 起動、migrate、アプリ起動、readiness 確認まで
実行する。旧 `init.sh` は削除済み（`deploy.sh app` が初回・更新を兼ねる）。

`reset` はデータ破壊操作（DB volume 削除）だが、運用上の摩擦を避けるため確認フラグは要求せず
即実行する。通常デプロイと `migrate` は DB volume や `ENV_LOCKED` を削除しない。

### 4. 危険な既定値を可視化する

起動を優先して組み込み既定値を許すが、設定レジストリの危険判定を root 設定画面へ表示する。
secret は値ではなく、生成済み、既定値使用、未設定、不一致だけを表示する。HTTPS の有無だけを
「本番判定」に使わず、明示した deployment profile と実際の cookie/HSTS/issuer 等を個別評価する。

## Consequences

- 初期配置の手順が一つになり、STG/PROD 固定値を保持したまま DB 管理設定と reset の寿命を分けられる。
- 設定値の出所と危険な初期状態を UI、API、ログで説明できる。
- `.env` の部分更新、DB との materialize、再起動を跨ぐため、原子的更新、排他、障害復旧テストが必要になる。
- bootstrap secret は DB 設定画面だけでは変更できず、専用 rotation が引き続き必要になる。

## Rejected alternatives

### 常に `環境変数 > DB > 既定値` とする

`.env` が存在する限り DB 変更を反映できず、「DB 反映でサイト独自値にする」という要件を満たさない。

### DB 値で `.env` 全体を上書きする

STG/PROD の固定値や bootstrap secret を失い、DB reset 後にもどの値を復元すべきか判断できない。

### すべて DB だけで管理する

DB 接続前に必要な認証情報や、DB 内 secret の復号鍵を同じ DB から安全に取得できない。
