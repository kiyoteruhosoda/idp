# ADR-0071: 利用者の端末を登録させ、登録していない端末でのログインを知らせる

- Status: Accepted
- Date: 2026-11-04
- 関連: task #872（親 #867「宅内への侵入に気付けるようにする」）、ADR-0044（セッションの失効で refresh token も落とす）、
  ADR-0058（テナントが決める設定）

## 背景

一般によく起きる乗っ取りは「パスワード・パスキーを盗まれて、別の端末で新しくログインされる」形である。assay はログインを
監査ログに残していたが、**それが本人のいつもの端末からか**を判断する材料を持たず、運用者が気付く手段も無かった。

## 決定

1. **端末はブラウザの Cookie（端末の印）で見分ける。** web がログインの応答で `assay_device`（64 文字の乱数・HttpOnly・
   400 日）を置き、assay は SHA-256 だけを持つ。User-Agent と国は表示と知らせに使うだけで、判定には使わない（自己申告のため）。
2. **ログインの経路ごとに処理を足さない。** web の middleware が「応答が SSO セッションの Cookie を新しく置いた」ことを
   見て `/internal/devices/observe` を呼ぶ。api は作られて 2 分以内のセッションにだけ、1 度だけ端末を結び付ける
   （`sso_session_contexts`。`sso_sessions` に列を足さない）。結び付けや知らせの失敗でログインは止めない。
3. **登録はパスキーで確かめてから 5 分以内だけ。** step-up の操作 `register_device` は**パスキーでしか通らない**
   （`SensitiveOperation::passkey_only`）。新しさは `step_up_at` ではなく、パスキーでログインした時刻か、パスキーで
   step-up した時刻（`sso_session_contexts.passkey_verified_at`）で測る。`step_up_at` はパスワードの再確認でも進むため。
4. **取り消すと、その端末で作られたログイン状態を切る**（refresh token も。ADR-0044 と同じ理由）。今の画面のセッションは残す。
5. **180 日使われなかった端末は登録が切れる**（1 日 1 回）。
6. **知らせは Webhook で送り、宛先と鍵は環境変数だけ**（`SECURITY_ALERT_WEBHOOK_URL`・`SECURITY_ALERT_WEBHOOK_TOKEN_FILE`）。
   形は nolumia notice の受け口と同じ JSON。送るのは利用者の所属元テナントの `UNREGISTERED_DEVICE_ALERTS_ENABLED` が
   有効なときだけ（既定は無効）。監査ログ（`login.unregistered_device`・`device.registered`・`device.revoked`・
   `device.expired`）には設定にかかわらず残す。
7. **知らせに黙らせる口を付けない。** いつも使う端末は登録すれば鳴らなくなる。

## 結果

- パスワードやパスキーを盗まれて別の端末でログインされたとき、運用者に届く。
- ⚠ **防げないこと**: 端末そのものの乗っ取り（その端末は登録済み）・端末の印そのものを盗まれた場合・各アプリ（RP）が
  自分で持つログイン状態の不正利用。印を端末の鍵へ結び付ける（DBSC）・アプリのトークンを結び付ける（DPoP）は task #875。
- Cookie を消した・シークレットウィンドウ・別のブラウザは毎回「登録していない端末」になる。
