# ADR-0016: 公開トポロジの既定を domain-split にする

- Status: Accepted
- Date: 2026-07-25
- 関連: `docs/adr/0015-domain-split-by-listen-port.md`（§Decision 3 の「単一オリジンを既定として残す」を
  本 ADR で置き換える）、`docs/adr/0012-api-web-domain-split.md`、
  `docs/adr/0007-api-web-service-split.md`

## Context

ADR-0007 で api（OIDC protocol・JSON 管理 API）と web（HTML 画面）をサービス分割し、ADR-0012 で
別サブドメイン公開に必要なアプリ側の実装を、ADR-0015 でそのデプロイ構成（リッスンポート分割）を
それぞれ決めた。ADR-0015 §Decision 3 では移行期の後戻り余地として **単一オリジン・パスルーティングを
既定のまま残す**とし、`PUBLISH_TOPOLOGY` の既定値を `single-origin` にしていた。

その後 domain-split 構成が `scripts/test_deploy.sh` のトポロジ試験まで含めて一巡し、実運用でも
使える状態になった。この時点で既定を据え置くと、次の不都合が残る。

- **既定の構成の方が仕組みが複雑**。単一オリジンは `/{tenant_id}/admin/...` を `Accept` ヘッダで、
  `/{tenant_id}/logout` を HTTP メソッドで振り分ける（`docker/nginx.conf`）。web の画面 URL と api の
  JSON 管理 API が同じパス名前空間を共有するために必要な分岐だが、**パスと Accept の対応表が
  サービス分割の実態から独立して増えていく**。新しい画面・エンドポイントを足すたびに
  nginx.conf の振り分け表を更新する必要があり、更新漏れは「別サービスの応答が返る」という
  気づきにくい壊れ方をする。domain-split ではポートとサービスが 1:1 のため、この表が丸ごと不要になる。
- **既定の構成の方がサービス境界を曖昧にする**。単一オリジンでは api と web が同一オリジンに見えるため、
  ブラウザから見た両者の境界（Cookie・CORS・CSP）を意識せずに実装できてしまう。境界を跨ぐ不整合は
  別オリジンにした瞬間に初めて露見する。既定を domain-split にすれば、日常の開発が常に本番と同じ
  オリジン境界の上で行われる。
- **推奨構成と既定値が食い違う**。ドキュメント上は別ドメイン公開を前提に据えつつ、`.env.example` は
  `single-origin` を出力するため、新規配置は必ず一度「既定で起動 → トポロジを切り替えて再デプロイ」を
  踏む。ゼロタッチ配置（ADR-0010）の趣旨と噛み合わない。

## Decision

**`PUBLISH_TOPOLOGY` の既定値を `domain-split` にする。** `single-origin` は明示指定で選ぶ構成として
残す（削除はしない）。

1. **既定値の変更点は 2 か所**。`scripts/deploy.sh` の未設定時フォールバックと、`.env*.example` の
   `PUBLISH_TOPOLOGY` 行。`.env` に値がある既存配置は**その値のまま動く**（`single-origin` を
   明記済みの環境は無変更で単一オリジンを維持する）。
2. **`.env*.example` は `ISSUER` と `PUBLIC_WEB_BASE_URL` を別オリジンで出力する**。ローカル既定は
   `http://localhost:8070`（api＝`API_PORT`）と `http://localhost:8060`（web＝`WEB_PORT`）。
   `PUBLIC_WEB_BASE_URL` はこれまで既定でコメントアウトだったが、既定トポロジで必須になるため
   有効な行として出す。
3. **ローカル既定では `COOKIE_DOMAIN` を設定しない。** Cookie はポートを区別しないため、
   host-only Cookie（`localhost`）のままで web:8060 と api:8070 の双方に届く。`COOKIE_DOMAIN` が
   要るのは実ドメインのサブドメイン分割時だけであり、既定値を空のまま保てる。
4. **不正値は従来どおり fail-fast**。未設定は既定（`domain-split`）に落ちるが、`single-origin` /
   `domain-split` 以外の値は起動を止める（ADR-0015 §Decision 3 の挙動を維持）。
5. **`single-origin` は明示指定でサポートを継続する。** `docker/nginx.conf` とパス振り分け表、
   `scripts/test_deploy.sh` のトポロジ試験は残す。単一オリジンへ戻す手順は `docs/OPERATIONS.md` に置く。

## Consequences

**Positive**

- 新規配置が既定のまま本番想定の構成（api / web が別オリジン）で立ち上がる。トポロジ切替のための
  再デプロイが不要になる。
- 開発・stg・prod が同じオリジン境界で動くため、Cookie・リダイレクト・絶対 URL 化の不整合が
  本番投入前に露見する。
- 既定経路から `Accept` ヘッダ・HTTP メソッドによる振り分けが外れ、公開経路の説明が
  「ポートとサービスが 1:1」だけで済む。

**Negative / コスト**

- **ホストの公開ポートが既定で 2 つになる**（`WEB_PORT` / `API_PORT`）。同一ホストに stg/prod を
  併置する場合、分ける必要があるポートも 2 つずつになる。
- 既定の `.env` で確認すべき値が 1 つ増える（`ISSUER` に加えて `PUBLIC_WEB_BASE_URL`）。
- 単一オリジンを前提に「1 ポートだけ開ける」運用をしていた読み手にとって、既定の意味が変わる。
  `.env` に `PUBLISH_TOPOLOGY` を明記済みの環境は影響を受けないが、**未設定のまま運用していた
  環境は再デプロイでトポロジが変わる**（`.env.example` 由来の `.env` には常に値が入るため、
  実際に該当するのは手書き `.env` の場合のみ）。

**Alternatives considered**

- **既定を据え置き、ドキュメントで domain-split を推奨する**: 推奨と既定の食い違いが残り、新規配置は
  切替のための再デプロイを踏み続ける → 却下。
- **`single-origin` を廃止して分岐そのものを消す**: 前段プロキシを持たない最小構成（1 ポートだけ
  開ける配置）の受け皿が無くなる。分岐の維持コストは nginx.conf 1 ファイルと試験 1 本に留まるため、
  廃止に見合わない → 却下。

## Follow-ups

- 待ち受けポートの一覧と単一オリジンへ戻す手順は `docs/OPERATIONS.md` に記載する。
- ADR-0015 §Decision 3 に本 ADR への参照を追記済み。
