# ADR-0017: `ISSUER` を DB 管理にし、反映のための再起動を設定画面から実行できるようにする

- Status: Accepted
- Date: 2026-07-27
- 関連: `docs/adr/0010-zero-touch-deployment-and-configuration-provenance.md`（設定キーの出所区分）、
  `docs/adr/0013-web-shared-runtime-settings.md`（web の共有ランタイム設定は api 経由）、
  `docs/adr/0014-runtime-setting-rollout.md`（反映は再起動。未反映を画面で可視化する。本 ADR は
  §Rejected alternatives「設定保存時にサービスを自動再起動する」を**手動操作として**採り直す）、
  `docs/adr/0012-api-web-domain-split.md`（api/web で一致必須のキー）

## Context

`ISSUER` はディスカバリ文書（`/.well-known/openid-configuration`）の各エンドポイント URL と、発行する
ID Token の `iss` の基底になる。デプロイ先の公開 URL に一致していなければ RP はトークンを検証できない。

その `ISSUER` が `ENV_LOCKED` だった。設定画面には行が出るのに `editable` は false で、値は組み込み
既定の `http://localhost:8080` のまま。直すには `.env` を編集して再デプロイするしかなく、**画面から
見えているのに画面からは直せない**。ADR-0010 が「DB で上書きできることが運用上の価値」と決めた
方針からも外れている。

`ENV_LOCKED` だった理由は 2 つある。

1. **web も `ISSUER` を消費する。** web は自オリジン（`PUBLIC_WEB_BASE_URL` 未設定時）と
   `COOKIE_DOMAIN` の検証に使う。web は DB を持たないので自力では DB 値を読めない。
2. **`ISSUER` のスキームが起動可否を決める。** `https://` のとき、api も web も開発用の既定
   secret（`KEY_ENCRYPTION_KEY`・`INTERNAL_SERVICE_TOKEN`・`CSRF_SECRET`）では起動を拒否する。

もう 1 つ、`ISSUER` に限らない問題がある。ADR-0014 で反映は再起動と決めたが、**その再起動を行う手段が
画面に無い**。設定は画面から変えられるのに、反映だけはシェルへ入って `docker compose restart` を打つ
必要がある。設定画面は「保存済み・未反映」の警告を出せるようになった（ADR-0014）が、その警告を消す
操作だけが画面の外にある。

## Decision

### 1. `ISSUER` を `DB_MANAGED` かつ `shared_with_web` にする

理由 1 は ADR-0013 が既に解いている。web は起動時に api の `GET /internal/runtime-settings` から
DB 上書き値を受け取る。`ISSUER` をその共有キーに加えるだけで、api と web は同じ値で動く
（`COOKIE_SECURE` 等と同じ経路で、新しい仕組みは要らない）。反映には api → web 両方の再起動が要る。

`PUBLIC_WEB_BASE_URL` と `COOKIE_DOMAIN` は `ENV_LOCKED` のまま残す（ADR-0012）。これらは
「api と web が**同じ値**を持つ」だけでなく、web が api へ問い合わせる前（bootstrap）に確定して
いなければならない値である。`ISSUER` にその制約は無い。

### 2. 値の検証を強くする（書式 ＋ 起動可否）

DB 上書きは起動時にしか読まれないので、**壊れた値を保存できると、それが露見するのは次の再起動である**。
そのときには api も web も落ちていて、設定画面ごと消えている。復旧手段は DB の直接編集しか残らない。
そこで保存の時点で 2 段階に検査する。

- **書式**（`SettingKind::PublicBaseUrl`）: スキーム（http/https）とホストを持つ絶対 URL であること。
  資格情報・クエリ・フラグメントを含まないこと。→ 400。
- **起動可否**（`ensure_override_is_bootable`）: 書式が正しくても起動時 fail-fast に掛かる値を
  保存させない。→ **409**。検査するのは、起動時の fail-fast のうち **`ISSUER` の値で成否が
  変わるもの**すべてである。

  | 条件 | 起動時に落ちる場所 | 落ちるサービス |
  |---|---|---|
  | `https://` の `ISSUER` × 開発用の既定 secret | `config::ensure_production_secrets` | api・web |
  | `COOKIE_DOMAIN` 設定時に、その配下から外れる `ISSUER` | `contracts::cookie_domain::validate_cookie_domain` | api・web |
  | `COOKIE_DOMAIN` 設定時に、明示された `PUBLIC_WEB_BASE_URL` とスキームがずれる `ISSUER` | 同上 | api・web |

  いずれも相手側（secret・`COOKIE_DOMAIN`・`PUBLIC_WEB_BASE_URL`）が `ENV_LOCKED` で DB からは
  直せないため、**`ISSUER` 側を保存させないことでしか防げない**。判定に要る配置状態は
  `DeploymentState` にまとめ、`Config::deployment_state()` から Application 層へ渡す。

400 と 409 を分けるのは、画面に出す文言が違うからである。前者は「URL を直せ」、後者は「URL は正しい。
先に配置側（secret・`COOKIE_DOMAIN` 周り）を直せ」であり、同じ「保存できません」に潰すと運用者は
正しい URL を疑い続けて本当の原因に辿り着けない。409 の応答本文は翻訳済みの一般的な案内なので、
**どの条件で落ちたか**は運用ログ（運用言語）へ出す。

起動可否の判定は、起動時 fail-fast と**同じ述語・同じ関数**を使う
（`domain::system_setting::requires_production_secrets` と
`idp_contracts::cookie_domain::validate_cookie_domain`）。片方だけが判定規則を変えると、
保存はできるのに起動できない値がまた生まれる。

`PUBLIC_WEB_BASE_URL` は「明示設定されたか」を区別して保持する（`Config::public_web_base_url_override`）。
未設定なら web の自オリジンは issuer に追従するのでスキームはずれないが、明示設定なら `ISSUER` を
変えた瞬間にずれ得る。解決後の値だけでは両者を区別できない。

### 3. 設定画面から api → web を再起動できるようにする

`POST /{tenant_id}/admin/restart`（api・`idp.system.admin` 必須）と、それを呼ぶ web の同名エンドポイント
を追加する。web の設定画面には確認ダイアログ付きのボタンを置く。

**アプリは自分を起動し直せない。** できるのは自分を綺麗に終わらせることだけで、新しいプロセスを起こす
のは配置側の再起動ポリシー（Compose の `restart: unless-stopped`、systemd の `Restart=always`、k8s の
`restartPolicy: Always`）である。終了コードは 0 なので `on-failure` 系のポリシーでは再起動されない。
この前提は画面と `docs/OPERATIONS.md` の両方に明記する。

順序と応答は次のように決める。

- **api を先に止める。** web は起動時に api から共有設定を受け取る（ADR-0013）ため、web が先に
  立ち上がると再起動前の api が配る古い値を掴む。
- **応答を返してから停止する。** 先に止めると要求自身が接続ごと切れ、「押したが何も起きなかった」
  ように見える。api は 202 を返してから約 0.5 秒後に graceful shutdown を起こす。
- **api の受理を確認できなければ web は止めない。** web だけ落ちると、api は動いているのに画面が
  消えて、再起動を指示する手段そのものが無くなる。
- web は待機画面（`<meta http-equiv="refresh">` で設定画面へ戻る 1 枚もの）を返してから停止する。
  この画面は共通レイアウトを継承しない。数秒間どのリンクもつながらないため、押せる導線を持たせると
  「壊れた」ように見える。

ADR-0014 は「設定保存時にサービスを自動再起動する」を退けた。本 ADR が採るのは**保存とは分離した
運用者の明示操作**であり、退けた案とは別物である。保存が無停止であることは変わらず、再起動は
運用者がタイミングを選んで実行する。プロセス管理へ介入しない（停止するだけ）ので配置形態ごとの
仕組みも要らない。

## Consequences

- 既定の `http://localhost:8080` のまま配置された IdP を、シェルへ入らずに設定画面だけで正しい
  公開 URL へ直せる。ディスカバリ文書と `iss` が実際の公開 URL に揃う。
- ADR-0014 の「保存済み・未反映」警告を、同じ画面のボタンで解消できるようになった。警告 → 再起動 →
  警告が消えることの確認、が 1 画面で完結する。
- **`ISSUER` の DB 上書きは api・web 双方の再起動で反映される。** api だけ再起動した状態は
  ADR-0014 の「web に未反映」として警告に出る（`shared_with_web` を立てたことで自動的にそうなる）。
- 再起動要求は監査ログ（`service.restart_requested`）に残る。稼働中の全リクエストを打ち切る操作で
  あり、誰がいつ行ったかが残らないと後から追えない。
- **再起動ポリシーの無い環境では、押すとサービスが停止したままになる。** ボタンの説明文と確認
  ダイアログでこれを明示するが、仕組みとして防いではいない。アプリからは配置側のポリシーを知る
  手段が無いためである。
- **単一インスタンス配置を前提にする。** このボタンが止めるのは要求を受け取ったプロセスだけで、
  複数レプリカ配置では他のレプリカが起動時スナップショットのまま残る。実装が悪いのではなく、
  多重化した瞬間に「設定を反映する」という操作がデプロイ全体のロールアウトになり、アプリ内の
  仕組みでは担えなくなる（k8s なら `kubectl rollout restart`、Compose のスケール構成なら
  `docker compose restart <service>` が本来の手段である）。本リポジトリの配置形態は ADR-0007・
  ADR-0015・ADR-0016 のとおり api 1・web 1 の Compose であり、`InMemoryLoginRateLimiter` や
  権限キャッシュも同じ前提に立っている。多重化を扱うなら、まずそれらと ADR-0013 のスナップショット
  モデルごと設計し直すことになるため、本 ADR の範囲外とする。
- `ISSUER` を https にする配置では、先に 3 つの secret を環境変数で設定して再起動しておく必要がある
  （順序が逆だと保存が 409 で拒否される）。これは起動時 fail-fast と同じ制約を保存時へ前倒しした
  ものであり、新しい制約ではない。
- **`ISSUER` のホスト名を変えると、登録済みの Passkey が使えなくなる。** WebAuthn の RP ID は
  issuer のホスト名から導出する（`infrastructure::webauthn`）ため、ホストが変わると別 RP として
  扱われる。RP 側の issuer 設定の更新と、ホスト単位の Cookie が失われることによる再ログインも
  同時に必要になる。これは `.env` で変えていたときも同じで本 ADR が作った制約ではないが、画面から
  手軽に変えられるようになった分だけ踏みやすい。設定項目の説明文と `docs/OPERATIONS.md` に明記する。
  → **ADR-0019 決定 2 で RP ID の導出元は `PUBLIC_WEB_BASE_URL`（web の公開ベース URL。未設定時は
  issuer に追従）へ変更した。** この注意が付くキーも `PUBLIC_WEB_BASE_URL` へ移っている。

## Rejected alternatives

### `ISSUER` を `ENV_LOCKED` のまま残し、`.env` 編集を案内する

現状維持。設定画面に「変えられない値」が並ぶこと自体が、どれが変えられるのかを分かりにくくする。
ADR-0013 が web への配布経路を用意した以上、`ISSUER` を除外し続ける技術的な理由はもう無い。

### 保存時に自動で再起動する

ADR-0014 が退けたとおり。保存が無停止でなくなる副作用が大きく、複数キーを続けて直す通常の運用と
噛み合わない。再起動のタイミングは運用者が選べる方がよい。

### `Config` をホットリロードする

ADR-0014 §1 のとおり、ADR-0013 の不変条件（web は api より新しい値を先取りしない）と Cookie の
発行/失効の対称性を壊す。`ISSUER` はさらに悪く、発行済みトークンの `iss` と検証時の `iss` が
リロードを境に食い違う。

### web の再起動も api に指示させる（api → web の順序を api 側で担保する）

api から web を止める経路（内部エンドポイント）が必要になり、api → web の依存が生まれる。
ADR-0007 の依存の向き（web → api）を逆流させてまで得るものが無い。順序は web 側のハンドラが
「api の受理を待ってから自分を止める」だけで担保できる。
