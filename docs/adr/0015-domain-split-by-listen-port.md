# ADR-0015: 別ドメイン公開はリッスンポート分割で実現する

- Status: Accepted
- Date: 2026-07-25
- 関連: `docs/adr/0012-api-web-domain-split.md`（§6 の「ドメインごとの vhost」を本 ADR で置き換える）、
  `docs/adr/0007-api-web-service-split.md`（§2 単一オリジン・パスルーティング）

## Context

ADR-0012 で api（OIDC protocol・JSON 管理 API）と web（HTML 画面）を別サブドメインで公開する構成を
採用し、アプリ側の実装（`COOKIE_DOMAIN` によるサービス横断 Cookie の共有、`/authorize` の絶対 URL 化、
web 自オリジンの設定、起動時検証）は完了した。残っていたのは**デプロイ構成**である。

ADR-0012 §6 は「パス振り分け表に代えて、ドメインごとの vhost（api ドメイン → api、web ドメイン → web）
とする」と決めていた。しかし実際の配置（Synology DSM 等）では、**前段にリバースプロキシが必ず存在し、
そこで既にドメイン単位の振り分けと TLS 終端を行っている**。この状況で同梱 nginx にも `server_name` を
書くと、次の問題が生じる。

- **ドメイン名の二重管理**: 公開ドメインを変更するたび、前段プロキシと `docker/nginx.conf` の両方を
  直す必要がある。片方だけ直すと、Host が一致せず既定 vhost へ落ちて誤ったサービスへ流れる
  （404 ではなく「別サービスの応答が返る」ため気づきにくい）。
- **前段プロキシの Host 保持への依存**: 前段が Host ヘッダを書き換える設定だと成立しない。
- **証明書・DNS の変更が nginx.conf に波及する**: 本来デプロイ設定と無関係な関心事が持ち込まれる。

一方、同梱 nginx を使わず api・web コンテナをホストへ直接 publish する案もあるが、これは
`/internal/*` の遮断点（ADR-0007 §5 の多層防御）を前段プロキシへ移すことになり、公開面が広がる。

## Decision

**同梱リバースプロキシを維持したまま、リッスンポートでサービスを分ける。**

```
前段プロキシ（DSM 等。TLS 終端・ドメイン振り分け）
  https://id.example.com  → ${WEB_BIND_HOST}:${WEB_PORT} → 同梱 nginx :8080 → web
  https://api.example.com → ${API_BIND_HOST}:${API_PORT} → 同梱 nginx :8081 → api
```

1. **同梱 nginx はドメイン名を持たない。** `docker/nginx.domain-split.conf` は
   `listen 8080` → `web`、`listen 8081` → `api` の 2 つの `server` ブロックだけで構成し、
   `server_name` を書かない。ドメインの知識は前段プロキシと `config`（`ISSUER` /
   `PUBLIC_WEB_BASE_URL`）にのみ存在する（ADR-0012 §2 の「SSOT は config」と整合）。
2. **api・web コンテナはホストへ publish しない。** 公開点は常に proxy だけであり、
   `/internal/*` の 404 遮断は単一オリジン構成と同じく 1 か所で担保される。
3. **単一オリジン・パスルーティング構成は既定として残す**（ADR-0012 §1）。切替は `.env` の
   `PUBLISH_TOPOLOGY`（`single-origin` 既定 / `domain-split`）のみ。`domain-split` のとき
   `scripts/deploy.sh` が `docker-compose.domain-split.yml` を重ねる。未知の値は起動を止める。
4. **コンテナ内 8080 を web に割り当てる。** proxy のヘルスチェック（`127.0.0.1:8080/readyz`）と
   ベース Compose のポート公開定義（`${WEB_BIND_HOST}:${WEB_PORT}:8080`）を無変更で流用でき、
   `WEB_PORT` の意味（＝ブラウザ向け HTML の公開ポート）が両構成で一貫する。新設は `API_PORT` /
   `API_BIND_HOST` のみで、既存 stg/prod の `.env` はそのまま動く。
5. **publish 先の既定はループバック**（`127.0.0.1`）。前段プロキシが同一ホストで動く前提とする。
   別ホストの前段プロキシから届かせる場合のみ `WEB_BIND_HOST` / `API_BIND_HOST` を広げる。

## Consequences

**Positive**

- 公開ドメインの変更が `.env`（`ISSUER` / `PUBLIC_WEB_BASE_URL`）と前段プロキシだけで完結し、
  同梱 nginx を触らない。二重管理と Host 不一致による誤振り分けが消える。
- `/internal/*` の遮断点が両トポロジで同じ 1 か所に留まり、公開面が広がらない。
- パス振り分け（`Accept` ヘッダによる `/{tenant_id}/admin` の分岐、`/assets/`・`/version` の
  個別指定）が domain-split では**丸ごと不要**になる。ポートとサービスが 1:1 のため。
- 単一オリジン構成は無変更のまま残るため、既存デプロイの後戻りが可能。

**Negative / コスト**

- ホストの公開ポートが 1 つ増える（`API_PORT`）。同一ホストに stg/prod を併置する場合、
  `WEB_PORT` と同様に `API_PORT` も環境ごとに分ける必要がある。
- 前段プロキシが**別ホスト**にある構成では bind を広げる必要があり、その場合は
  `/internal/*` の遮断とアクセス制御を前段・ファイアウォールでも担保する運用前提が生じる
  （同梱 nginx が 404 を返すため多層防御は残るが、公開面は広がる）。
- トポロジという分岐が 1 つ増える。設定不整合（`PUBLISH_TOPOLOGY=domain-split` なのに
  `ISSUER` と `PUBLIC_WEB_BASE_URL` が同一オリジン、など）は ADR-0012 の起動時検証と
  `deploy.sh` の fail-fast で拾う。

**Alternatives considered**

- **ドメインごとの vhost（ADR-0012 §6 の当初案）**: 上記のとおりドメイン名の二重管理と
  Host 保持への依存が生じる → 却下。
- **同梱 nginx を廃止し api・web を直接 publish**: `/internal/*` の遮断責務が前段プロキシへ移り、
  公開面が広がる。X-Forwarded-* の付与も前段任せになる → 却下。
- **1 ポートのまま前段でパスを振り分ける**: 前段プロキシ側にパス振り分け表（`Accept` ヘッダ分岐を
  含む）を複製することになり、最も保守しにくい → 却下。

## Follow-ups

- 手順は `docs/OPERATIONS.md`「api と web を別ドメイン（サブドメイン）で公開したいとき」に記載する。
- ADR-0012 §6 に本 ADR への参照を追記済み。
