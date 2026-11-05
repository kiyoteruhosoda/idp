# ADR-0077: Android の Chrome のログインを認証アプリで承認し、30 日にする（「アプリで続ける」）

- Status: Accepted
- Date: 2026-11-04
- 関連: task #892・#891（親 #875）、ADR-0074（DBSC と長さ）、ADR-0071（自分の端末）、ADR-0044（セッションの失効で refresh token も落とす）

## 背景

Android の Chrome は DBSC に対応していない（ADR-0074）。持ち主の決定（#875・11/04）: 登録したスマホのアプリで承認して
作ったログイン状態は 30 日。承認は人にコードを見せない形で、User-Agent は信用しない。承認の口は nolumia notice ではなく
認証用の新しいアプリ（`com.nolumia.auth`・deck 配布だけ・Play には載せない）に載せる。

調べると、assay には利用者がトークンで呼ぶ API が無く（アクセストークンに `sid`・`auth_time` も無い）、戻り先は https
だけ、`assetlinks.json` も無かった。

## 決定

1. **アプリはトークンを持たない。** 鍵の登録・承認・断り・取り消しのたびに、Keystore の鍵で次の文に署名する
   （ECDSA P-256・SHA-256）。操作・組織・対象を入れて、署名を別の操作・依頼・組織へ使い回させない。
   ```
   assay-app-approver-v1\n<activate|approve|deny|revoke>\n<組織>\n<対象>\n<使い捨ての値>
   ```
   OIDC の client も refresh token もアプリには作らない。
2. **鍵の登録は 3 段。** ① 受付（10 分）と challenge → ② Keystore が出した証明書の鎖を送り、Key Attestation を確かめる →
   ③ アプリが Auth Tab で assay の確認の画面を開き、利用者がログイン＋パスキー（5 分以内。ADR-0071 と同じ確かめ）で
   「登録する」→ 2 分・1 回のコードが Auth Tab の戻り先（`https://<発行者>/app/enrolled`）でアプリへ届き、アプリがコードへ
   署名して有効にする。確認の画面のリンクを他人に踏ませても、コードは踏んだ人の側へ返るので、送った人の鍵は有効にならない。
3. **Key Attestation で確かめること**（`domain::key_attestation`。依存を足さず、DER を読む部品は自前）:
   鎖が Google の根（RSA 4096・ECDSA P-384「Key Attestation CA1」。同梱）まで署名でつながる・上の証明書は CA で鍵の証明を
   持たない（鍵の証明書の鍵で偽の証明書に署名して足す形を断る）・置き場が TEE か StrongBox・challenge・EC P-256・署名用・
   Keystore の中で作った・生体だけで解け使うたびに求める（`noAuthRequired` 無し・`userAuthType` が指紋のみ・`authTimeout` 無し）・
   起動が Verified でロック済み・パッケージ名と署名の証明書の SHA-256。
4. **「アプリで続ける」は、依頼を始めたブラウザの印でしか完了しない。** ログイン画面の「アプリで続ける」→ 依頼（5 分）と
   ブラウザの印（`__Host-app_approval_binding`・HttpOnly・`SameSite=Lax`。DB は SHA-256）→ 発行者のホストの App Link
   （`/app/approve`。ログイン画面とは別のホストなので Chrome がアプリへ渡す）→ アプリが鍵で承認 → 30 秒・1 回のコード →
   アプリが同じスマホのブラウザで `/{t}/login/app/complete` を開く → コードと印が揃えばログイン。
   **依頼を始めたタブが待って完了する口は作らない**（作ると、別の端末で始めた依頼をだまされて承認したときに通ってしまう）。
   印の合わないブラウザで完了しようとしたら、ログインさせず、依頼を終わらせ、監査（`app_approval.refused`）と知らせ
   （ADR-0071 の送り先）に残す。
5. **長さ。** `lifetime_for` に結び付けの種類（なし・DBSC・アプリで承認）を渡す形にした。アプリで承認したログイン状態は
   確立のときから `SSO_BOUND_TTL_SECS`（30 日・使わなかったときの期限も同じ）。ブラウザの端末の登録は問わない（承認した鍵が
   パスキーで登録した端末の鍵なので）。認証方式は `app_approval`（`amr` は `hwk`・第二要素）。認証ポリシーの「方式の指定」は満たさない。
6. **取り消し。** 鍵は「自分の端末」の欄に「認証アプリ」として並ぶ。取り消し（画面・アプリのどちらからでも）は、その鍵で承認した
   ログイン状態と refresh token を終わらせる（`sso_session_contexts.approver_key_id` で引く）。
7. **設定は環境変数だけ**（組織ごとにしない）: `APP_APPROVER_PACKAGE_NAME`（空なら口を全部閉じる）・
   `APP_APPROVER_SIGNING_CERT_SHA256`・stg の確かめ用の `APP_APPROVER_EXTRA_ATTESTATION_ROOTS_FILE` と
   `APP_APPROVER_ALLOW_SOFTWARE_ATTESTATION`。`assetlinks.json` も同じ値から答える。
8. **ボタンは Android のブラウザでだけ見せる。** User-Agent はこの見た目の切り替えにだけ使い、判定にも長さにも使わない。

## 結果

- Android の Chrome でも 30 日ログインが続き、承認は指紋 1 回で済む。別の端末で始めた依頼は、承認しても完了しない。
- ⚠ **防げないこと**: Android の Chrome の Cookie そのものの持ち出し（結び付けが無いので 30 日の間は使われうる）・
  root 化された持ち主の電話・Google の失効一覧に載った端末の鍵（`attestation/status` の照会は外への通信が要るので入れていない）・
  証明書の有効期間（端末によって当てにならないので見ない）。
- 承認の口は OIDC のログイン画面（認可の途中）にだけある。assay 自身の画面へのポータルログインには出さない。
- stg では Claude の確かめの台本がアプリの役をするため、試験用の根とソフトウェアの鍵を受ける（本番は Google の根だけ）。
