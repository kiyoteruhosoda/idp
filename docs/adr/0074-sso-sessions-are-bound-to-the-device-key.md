# ADR-0074: SSO セッションを端末の鍵へ結び付け（DBSC）、長さを結び付けの有無で変える

- Status: Accepted
- Date: 2026-11-04
- 関連: task #887（親 #875「ログイン状態を端末の鍵に結び付け、長さを結び付けの有無で変える」・#867）、
  ADR-0071（自分の端末）、ADR-0058（テナントが決める設定）、ADR-0044（セッションの失効で refresh token も落とす）

## 背景

assay のログイン状態は Cookie（`__Host-sso_session_id`）だけで成り立っていた。ブラウザの Cookie をまとめて持ち出す
ウイルスに盗まれると、別の PC からそのまま使える。Chrome（Windows・Chrome 145 以降）は Device Bound Session
Credentials（DBSC。W3C WebAppSec の草案 2026-09-08 版）を既定で有効にしており、サイトが求めればログイン状態を
TPM の中の鍵へ結び付けられる。Android の Chrome はまだ対応していない。

持ち主の決定（task #875・11/04）: 長さは「端末の鍵に結び付いたものは 30 日、結び付いていないものは 7 日」。30 日には
ADR-0071 の「自分の端末」に登録済みであることも求める。使わなかったときの期限も同じ長さにする。

## 決定

1. **DBSC は assay の web（画面のオリジン）だけで扱う。** ログイン状態の Cookie を置いた応答（ADR-0071 の middleware と
   同じ所）に `Secure-Session-Registration: (ES256 RS256);path="/dbsc/register";challenge="…"` を付ける。範囲は assay の
   オリジンだけ（`include_site: false`）。各アプリ（RP）の Cookie には付けない（RP は task #888 で assay に問い合わせる）。
2. **Cookie は 2 本。** 長い Cookie（今の `__Host-sso_session_id`）はそのまま残し、結び付けたログイン状態には短い Cookie
   `__Host-sso_bound`（10 分）を足す。短い Cookie は「SSO セッション（の SHA-256）と期限」の HMAC で、DB に置かない。
   Chrome は TPM の都合で短い Cookie を付けずに要求を送ることがある（`Secure-Session-Skipped`）ので、長い Cookie を
   消す作りにはしない。
3. **確かめは web の入口の 1 か所で行う。** 長い Cookie があって、合う短い Cookie が無い要求は、そのログイン状態が
   結び付いているかを api に聞き（`POST /internal/sso/key-binding`。結果は web が 60 秒覚える）、結び付いていれば
   **長い Cookie を要求から外す**（どの画面にも「ログインしていない」に見える）。ログインの経路・画面ごとには足さない
   （api の 36 か所の `find_by_hash` を触らない）。`/dbsc/*` だけは外さない。
4. **鍵と challenge の確かめは api。** challenge は「SSO セッション・発行時刻」の HMAC（`CSRF_SECRET` から用途を分けて
   導く。DB に置かない。5 分）。署名（JWT・`typ: dbsc+jwt`・ES256 か RS256・`jti` が challenge）は登録のときは JWT の
   `jwk` で、更新のときは登録した公開鍵で確かめる。結び付けは `sso_session_contexts` に置く（`sso_sessions` に列を
   足さない。ADR-0071 と同じ理由）。1 つのログイン状態に結び付けは 1 回だけ。
5. **違う鍵の署名が来たら、そのログイン状態を終わらせる**（refresh token も。ADR-0044）。監査に残し、ADR-0071 の送り先へ
   「ログイン状態の持ち出しの疑い」を知らせ、Chrome には `{"continue": false}` を返す。短い Cookie が無いだけでは
   知らせない（TPM の都合で起きる）。
6. **長さ。** 始まりは常に `SSO_ABSOLUTE_TTL_SECS`。結び付けの登録と更新のたびに、「結び付きあり かつ そのログイン
   状態の端末（ADR-0071 の端末の印）が登録済み」なら `SSO_BOUND_TTL_SECS`（既定 30 日・組織ごと）を作った時刻から
   数えて当てる。そうでなければ `SSO_ABSOLUTE_TTL_SECS` に戻す（端末の登録を取り消した後も 30 日のまま残さない）。
   使わなかったときの期限（idle）は**延長で短くしない**（`GREATEST`）。結び付いた 30 日のログイン状態は、7 日使わなくても
   切れない。User-Agent は見ない。
7. **この配備の 7 日は deploy-repo の環境変数で決める。** 組み込みの既定（idle 8 時間・absolute 24 時間）は変えない
   （配布物の既定。ADR-0056 の考え方）。
8. **各アプリから始まった要求でも短い Cookie を取り直させる（2026-11-09 追記・task #934）。** 範囲が assay のオリジンだけ
   なので、草案（2026-09-08 版 §8.3・§8.5）では、要求を出したオリジンが assay でないとき（各アプリの見えない枠の
   `prompt=none`。task #888）Chrome は短い Cookie を取り直さない。短い Cookie が切れたまま往復が assay に着くと 3. で
   長い Cookie が外れ、アプリはログイン待ちになっていた（assay を直に開くと取り直されて戻る）。
   登録と更新の応答の本文のいちばん外側に `allowed_refresh_initiators` を置き、値は環境変数
   `DBSC_ALLOWED_REFRESH_INITIATORS`（空白区切りのホストの型。この配備は `*.nolumia.com`）から入れる。草案の照合は
   要求元のホストの文字列（§8.4）なので、スキーム・ポートは書けない。`*.nolumia.com` は `nolumia.com` 自身には当たらない。
   範囲（`include_site`）は広げない（各アプリへ短い Cookie を送らない・送る先は assay のまま）。
   **更新の応答にも同じ本文を返す。** 草案（§8.8・§8.9）では本文のある更新の応答で結び付けの設定が置き換わるので、
   この設定の前に結び付いたログイン状態にも、次の更新（10 分以内に assay を開いたときなど）で届く。本文の
   `session_identifier` は今の結び付けのもの（違うと Chrome は結び付けを終わらせる）。
   ⚠ 届く前のログイン状態は、一度 assay で短い Cookie が取り直されるまで、アプリの往復ではまだ取り直されない。

## 結果

- Windows の Chrome で結び付いたログイン状態は、Cookie を盗まれても別の PC では 10 分で使えなくなる。
- ⚠ **防げないこと**: PC そのものの乗っ取り（その PC の TPM で署名できる）・結び付けの無いブラウザ（Android の
  Chrome・Edge 以外の多く・Mac は未確認）の Cookie の持ち出し・各アプリ（RP）が自分で持つログイン状態（task #888）。
- DBSC の鍵が TPM の中にあるかは assay から確かめられない。まねをした Chrome でも結び付けは作れるので、30 日には
  「自分の端末」への登録（パスキーが要る）を求める。
- `CSRF_SECRET` を入れ替えると、短い Cookie と challenge が全部無効になる（Chrome は次の要求で更新し直す。結び付いた
  ログイン状態は更新の 403 → 署名で戻る）。
