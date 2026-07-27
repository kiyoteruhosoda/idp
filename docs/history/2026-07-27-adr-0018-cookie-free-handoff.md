# ADR-0018 実装: api↔web の状態受け渡しから Cookie を外す（2026-07-27）

背景・決定の経緯は `docs/adr/0018-cookie-free-api-web-handoff.md` を参照。本書は実装の構造と
移行時の注意だけを記録する。

## 変更後のフロントチャネルフロー

```
RP → api GET /{tenant}/authorize
       検証 → AuthSession 作成（prompt / max_age / handle を保存）
       302 → {web}/{tenant}/login?auth_session=<単回ハンドル>     ← Set-Cookie なし
web GET /login?auth_session=...
       POST api /internal/authorize/resume { handle, sso_session_id(web の host-only Cookie) }
       api: ハンドルを単回消費 → SSO 復元 / max_age / 同意チェック
         ├ 同意済み SSO      → { redirect: code 付き RP URL }   → web が 302（auth Cookie 掃除）
         ├ prompt=none 失敗  → { error_redirect: RP URL }        → web が 302
         ├ 同意が必要        → { consent_required, auth_session_id } → Cookie 化して 303 /consent
         └ 認証が必要        → { login_required, auth_session_id }   → Cookie 化して 303 /login（クエリ除去）
以降（POST /login・/consent・MFA・passkey）は従来どおり /internal/* のボディ渡し
```

RP-initiated Logout は `end_session_endpoint = {web}/{tenant}/logout` になった。web が
`POST /internal/logout/rp` を呼び、api が SSO 失効・back-channel 通知・`post_logout_redirect_uri`
検証（`state` 付与済み URL の組み立て）を行う。SSO Cookie の破棄と front-channel iframe ページ
（`crates/web/templates/rp_logout.html`。通知先オリジンだけ `frame-src` を許可する CSP を付与）は
web が担う。api の公開 `GET /{tenant}/logout` は削除した。

## 単回ハンドルの性質（受け入れ条件）

- **固定束縛**: ハンドルは `auth_sessions.handle_hash`（SHA-256）として当該行に保存され、
  その行の `code_challenge` に固定的に束ねられる。他の認可要求への付け替えは構造上できない。
- **単回使用**: `/internal/authorize/resume` の交換時に `UPDATE ... WHERE handle_hash = ?` で
  原子的に NULL 化する。並行交換・再利用は 0 行更新となり `expired_handle` で拒否される。
- **短命**: `handle_expires_at` は発行から 60 秒（`/authorize` → web → resume の片道のみを覆う）。
- web は受領後ただちに host-only Cookie へ移し、303 で自 URL へ付け替えて URL から除去する。

## Cookie の扱い（決定 2・4）

- `sso_session_id` / `auth_session_id` は **web だけが発行・読取する host-only Cookie** になった。
  `CookiePolicy::set_shared/expire_shared` は `set_session/expire_session` へ改名し、`Domain` 属性を
  一切付けない。
- `COOKIE_DOMAIN` は互換のため残るが、意味が「旧 ADR-0012 構成でブラウザに残った `Domain` 付き
  Cookie を掃除する削除 Cookie の併送」へ変わった。既定は未設定。移行が済んだ環境では設定しない。
- api が受け取るセッション値は `/internal/*` のボディ、または web の `api_client` がサーバ間呼び出しで
  明示付与する `Cookie:` ヘッダ（管理 JSON API の extractor）に限る。

## スキーマ変更

`migrations/0016_authorize_web_handoff.up.sql`: `auth_sessions` に `prompt`（CHECK: none/login/consent）・
`max_age`・`handle_hash`（UNIQUE）・`handle_expires_at` を追加（expand のみ・NULL 許容）。

## 移行時の注意

- **`ISSUER` が変わる**（api を web の子サブドメインへ。決定 1）。RP の再設定（discovery・`iss`・
  `end_session_endpoint`）が必要。デプロイ作業は `docs/Progress.md` T1。
- 旧バイナリと新バイナリの混在中、旧 api が発行した `auth_session_id` Cookie は新 web でも読める
  （Cookie 名は不変）が、旧 `/authorize` の Set-Cookie 経路は新 web では発生しない。ローリング中の
  進行中フローは `/authorize` からやり直しになる場合がある（AuthSession は短命の一時状態）。
