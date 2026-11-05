# ADR-0076: 画面を出さずに試す往復（prompt=none）の 302 だけを、設定した親の枠に入れてよくする

- Status: Accepted
- Date: 2026-11-04
- 関連: task #888（親 #875）、ADR-0074（DBSC）、ADR-0071（自分の端末・取り消しでログイン状態を終える）、
  fastapitemplate の ADR-0104（各アプリはリフレッシュトークンを持たず、切れたら見えない枠で問い合わせる）

## 背景

各アプリ（RP）は SSO で入ったあと自分のリフレッシュトークン（14 日）を持っていた。Cookie を盗まれると、assay の
ログイン状態が終わっても（端末の登録の取り消し・DBSC の検知）アプリのほうは使われ続ける。task #888 で各アプリは
リフレッシュトークンをやめ、アクセストークン（5 分）が切れたら**見えない枠（iframe）**で
`/authorize?prompt=none` へ問い合わせ、assay のログイン状態が生きていればそのまま続けることにした。

assay の応答は全部 `X-Frame-Options: DENY`（web は加えて `frame-ancestors 'none'`）で、枠に入れられない。
`prompt=none` の往復は `/authorize`（api）→ `/login?auth_session=`（web）→ RP の `redirect_uri` と 302 だけで進むので、
ブラウザが 302 の XFO を見ない限り通るが、それに頼らず、許す範囲を明示する。

## 決定

1. **環境変数 `SILENT_AUTH_FRAME_ANCESTORS`（空白区切りの origin。例 `https://*.nolumia.com`）を足す。** 既定は空で、
   枠を許さない。画面・DB からは変えられない（`EnvLocked`）。api と web が同じ値を読み、同じ検査
   （`assay_contracts::frame_ancestors`）を通す。書けるのは `https://<名前>` と `https://*.<2 段以上の名前>`
   （ポート可）、開発用の `http://localhost` だけ。`*`・キーワード・パス付きは起動を止める。
2. **枠を許すのは 302 だけ。** api の `/authorize` は `prompt=none` のときの 302、web の `/login?auth_session=` の
   引き継ぎ（と開き直し）は RP へ返す 302（成功・エラー）に、`Content-Security-Policy: frame-ancestors <親>` を付け、
   `X-Frame-Options` を付けない。
3. **描く応答は今までどおり枠に入れない。** 自動送信フォーム（`response_mode=form_post`）・ログイン画面・同意画面・
   「許可されていません」の画面・400 の本文は `DENY`・`'none'` のまま。`prompt=none` の往復で描く画面は出ない
   （出るとすれば失敗で、枠の中では止まって RP は時間切れで全画面へ移る）。
4. **端末の登録の取り消しは今の作りのまま。** 取り消すとその端末で作られたログイン状態と refresh token を消す
   （ADR-0071）。次の `prompt=none` は `login_required` になり、RP は 5 分以内にログイン画面へ移る。

## 理由

- **302 は描かれない。** 枠に入れても押させるもの・読ませるものが無いので、クリックジャッキングの的にならない。
  描く画面を許すと的になる。
- **`prompt=none` のときだけ（api）。** web の 302 は `prompt` を知らずに返すが、描かれないので同じ理由で安全。
  契約（`/internal/authorize/resume` の応答）を変えずに済む。
- **DBSC との関係。** W3C の草案（2026-09-08 版 §8.3・§8.5）では、枠の中からの要求でも更新される。ただし
  要求を出したオリジンが assay と同じか、登録の設定の `allowed_refresh_initiators` に合うときだけ。各アプリの
  画面から始まる往復は全画面でも枠でも同じ扱いになる（task #887 へ伝えた）。

| 採らなかった案 | 捨てた理由 |
|---|---|
| 何もしない（302 の XFO はブラウザが見ないことに頼る） | 仕様の細部に頼る。許す範囲がコードに残らない |
| 画面ごと（ログイン画面も）枠を許す | クリックジャッキングの的になる |
| `prompt=none` 専用の別の口を作る | OIDC の `/authorize` の外になり、RP の作りが変わる |
| 親を DB の設定にする | 画面から枠の許可を広げられる。通信先と同じく環境変数だけにする |

## 影響

- 本番・stg の api と web の両方に `SILENT_AUTH_FRAME_ANCESTORS=https://*.nolumia.com` を入れる（deploy-repo）。
- `*.nolumia.com` のどれか 1 つの頁でスクリプトを動かせる人は、その頁の枠で `prompt=none` を通せる。返るのは
  その頁の RP の `redirect_uri` への 302 だけで、コードは登録済みの `redirect_uri` にしか届かない（今までの全画面の
  `prompt=none` と同じ）。
