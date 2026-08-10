## 2026-08-10（G6: Prometheus メトリクス）

- **`GET /internal/metrics`（Prometheus 形式）を追加した（G6）。** 可観測性が JSON ログと
  `log` / `audit_log` テーブルだけで、ログイン成功率・トークン発行レート・エンドポイント別
  レイテンシ・sqlx プールの枯渇といった SLO を見るのに要る値が取れなかった。
  - **公開面ではなく内部面に置く。** `/internal/*` はプロキシで遮断する前提の面で、多層防御として
    サービストークンも要る。メトリクスは「誰がいつ何回失敗したか」を集約した情報である。
  - **監査イベントの計測は `AuditService` の 1 か所だけ**にした（`idp_audit_events_total`）。
    ログイン成功率・トークン発行レート・鍵ローテーションの成否はすべてこの 1 本から導ける。
    計測器を各ユースケースへ散らすと、片方だけ増えて静かにずれる。
  - **ラベルは有限の enum に限る。** `route` はマッチしたルートの雛形（`/{tenant_id}/admin/clients`）で、
    実 URL ではない。テナント ID・利用者 ID・クライアント ID は入れない——入れると監視側の時系列が
    利用者数に比例して増え、Prometheus が落ちる形で初めて気づくことになる。統合テストで固定した。
  - プール接続数は使用時ではなく定期的に観測する（枯渇は「何も起きていない間」にこそ見たい値で、
    枯渇して要求が待たされているときは記録する側も待たされている）。
  - 所要時間のバケットは 1ms〜10s を対数的に刻む。既定のバケットでは、数ミリ秒（discovery）から
    数百ミリ秒（Argon2 を伴うトークン発行）までの帯域が 1〜2 バケットに潰れて p95 が読めない。

## 2026-08-10（AP6: アカウントロックの管理者解除と段階的ロック）

- **アカウントロックを管理者が即時解除できるようにした（AP6。仕様 §17.1・§24.6）。** 従来はロック
  期限の経過を待つしかなく、ヘルプデスクに戻す手段が無かった。
  - `POST /{tenant_id}/admin/users/{user_id}/unlock` と、メンバー一覧の「ロック解除」ボタン。
  - **ロック期限のクリアと失敗回数のリセットを必ず同時に行う。** 期限だけ消すと失敗回数は閾値を
    超えたままなので、次の 1 回の失敗で即座に再ロックされ、しかも段が 1 つ進んで前より長くなる
    ——「解除したつもりが悪化する」。
  - 冪等（ロックされていなくても成功。応答の `was_locked` で区別）。自分自身にも実行できる
    （他のライフサイクル操作の自己禁止はロックアウト防止が目的で、解除はその逆向きの操作）。
  - メンバー一覧に**ロック状態**を出すようにした。ロックは `users.status` ではなく `locked_until` で
    表されるため、これまで画面からは誰がロックされているか分からなかった。期限切れ判定は api 側で
    行い、web には真偽値だけを渡す（web は時計を持たない）。
- **ロック時間を段階的にした（AP6）。** 固定時間だと、攻撃者は「ロック時間だけ待ってまた閾値まで
  試す」を無限に繰り返せ、単位時間あたりの試行数を一定に保てる。逆に初回を長くすると打ち間違いを
  重ねただけの利用者が長時間締め出される。
  - 初回は `LOGIN_LOCK_DURATION_SECS`、以降は失敗のたびに倍で `LOGIN_MAX_LOCK_DURATION_SECS`
    （新設。既定 24 時間）で頭打ち。上限を初回以下にすると従来どおりの固定時間になる。
  - 段数は `failed_login_count` をそのまま使う（ログイン成功でのみ 0 に戻るため、ロック期限切れ後の
    1 回目の失敗が自動的に次の段になる）。追加の状態列は持たない。
  - 失敗の記録とロック判定は 1 文の `UPDATE` で行う必要があり（SEC13）、ロック時間の選択が SQL に
    落ちる。計算式を SQL へ写して二重化させないため、**段の一覧をドメイン（`escalation_ladder`）から
    渡して SQL は選ぶだけ**にした。両者の一致は DB 統合テストで固定している。

## 2026-08-10（SEC10: トークン系エンドポイントの負荷ゲート）

- **`/token`・`/introspect`・`/revoke` に負荷ゲートを入れた（SEC10）。** この 3 つは confidential
  クライアントの `client_secret` を Argon2id（19 MiB・2 反復）で照合する。総当たりは非現実的だが、
  メモリハード関数はそれ自体が増幅器で、数百バイトのリクエストがサーバ側に 19 MiB の確保と数十
  ミリ秒の CPU を強制できる。照合は同期関数で tokio のワーカースレッド上を走るため、バーストは
  トークン発行だけでなく**全エンドポイントの応答を止める**。
  - **同時実行数の上限**（`TOKEN_ENDPOINT_MAX_CONCURRENCY`、既定 8）を主たる防御線にした。
    ピークメモリを「上限 × 19 MiB」に抑え、**接続元が分からなくても効く**。`TRUST_FORWARDED_HEADERS`
    は既定 `false`（api が接続元 IP を知らない構成）なので、IP 単位のレート制限だけでは既定構成で
    何も守れない。溢れた要求は**待たせず** 503 で落とす（待ち行列は CPU の飽和をメモリの飽和に
    変えるだけ）。
  - **接続元 IP 単位のレート制限**（`TOKEN_ENDPOINT_RATE_LIMIT_MAX_REQUESTS`、既定 300 回/分）を
    重ねた。単一の送信元が同時実行枠を占有して正規の RP を締め出すのを防ぐ。ログインの制限器とは
    別にする（RP のトークン取得がログイン試行の枠を食い合わないため）。
  - 判定はレート制限 → 枠取得の順。枠を取ってから弾くと、弾かれる要求が一瞬でも枠を占有して
    攻撃者が枠を空にできる。枠切れで落とした要求も送信元の回数には数える（数えないと、枠が
    埋まっている間は無制限に叩ける）。
  - 応答は `temporarily_unavailable`（RFC 6749 §5.2 に「混雑」のコードが無いため §4.1.2.1 のものを
    使う）＋ `Retry-After`。文言は翻訳しない（RP 向けの固定値）。
  - 残る課題: Argon2 照合が同期関数のまま tokio ワーカーを占有する点は変えていない
    （`spawn_blocking` 化は `PasswordHasher` トレイトの非同期化を伴うため別途）。

## 2026-08-10（G8: `audit_log` の絞り込み索引と保持期間）

- **`audit_log` の索引を管理コンソールの絞り込みへ合わせた（G8。migration 0033）。** 索引は
  `event_type` / `correlation_id` / `occurred_at` / `tenant_id` の**単一列 4 本**だけで、コンソールの
  絞り込み（「テナント × 期間 × event_type × result × client_id」）と噛み合っていなかった。単一列
  `tenant_id` ではテナント内の全期間を読んでから期間で絞ることになり、行が増え続ける表では期間検索が
  事実上の全表走査になる。`client_id` と `user_id` には索引すら無かった。
  - `(tenant_id, occurred_at)` を土台に、`event_type` / `result` / `client_id` / `user_id` を挟んだ
    複合索引を張った。末尾を `occurred_at` にするのは、範囲条件（`from`/`to`）と
    `ORDER BY occurred_at DESC` を同じ索引で賄うため。
  - 単一列の `result` 索引は作らない（値が 2 種類しかなく選択性が無い）。`(tenant_id, result, occurred_at)`
    が「このテナントの、失敗だけを、この期間で」というエラー絞り込みを索引だけで完結させる。
  - 重複する単一列索引（`tenant_id`・`event_type`）は落とした。`occurred_at` 単独と `correlation_id` は
    残す（保持期間削除と追跡はテナントを跨いで引くため）。
- **保持期間 `AUDIT_LOG_RETENTION_DAYS` を追加した（G8）。** `log` には `APP_LOG_RETENTION_DAYS` が
  あるのに `audit_log` には削除の仕組みが無く、際限なく伸び続けていた。
  - **既定は `0` ＝ 削除しない。** 監査ログの保存期間は法令・契約で決まる運用側の判断であり、
    既定値で消し始めてよいものではない。日数を設定したときだけ 1 時間ごとに削除する。
  - 削除は 1 万行ずつのバッチで行い、消し切るまで 1 秒間隔で続ける。保持期間を後から有効化した
    環境では対象が一度に数百万行になり得るため、無制限の `DELETE` は認可フローの `INSERT` を
    長時間止めてしまう。

## 2026-08-10（G7: 一覧 API のページング）

- **`GET /admin/clients`・`GET /admin/tenants` をページング応答にした（G7）。** どちらも `Vec` を
  全件返しており、テナント内のクライアントが数百件になると管理コンソールの一覧がその数に比例して
  重くなった（`/admin/members`・`/admin/audit-logs` には `limit`/`offset` があり非対称でもあった）。
  - 応答を `{ clients | tenants, total, limit, offset }` に変えた。`total` を返すのは、次ページの
    有無を**受信件数では判定できない**ため（最終ページがちょうど `limit` 件で埋まると空ページへの
    リンクが出る）。`limit`/`offset` は要求値ではなく**実際に適用した値**を返す。
  - ページングは DB 側（`LIMIT`/`OFFSET` + 同条件の `COUNT(*)`）で行う。並びはページ間で安定させる
    ため副キー（`client_id` / `id`）を足した。
  - 取得範囲の語彙を `domain::paging`（`PageRequest` / `Page` / `PagedResult`）に、web のページャ組み立てを
    `web::pagination` に集約し、MT22 でメンバー一覧に入れた実装をそちらへ寄せた。ページャの HTML も
    `console/pagination.html` の共有部品にした（翻訳キーも `admin-pagination-*` に一本化）。
  - **権限一覧（`GET /admin/permissions`・利用者の保有権限）はページングしない。** どちらも
    `permissions` マスタの語彙で件数が上限づけられ、テナントのデータ量では増えない。付与フォームの
    選択肢を分割すると、選べない権限が出るという別の不具合になる。

## 2026-08-10（G12: `prompt=select_account` と複数値の `prompt`）

- **`prompt=select_account` を受け付けるようにした（G12。OIDC Core §3.1.2.1）。** これまで
  `Prompt::parse` は `none`/`login`/`consent` のみで、`select_account` は**未知の値として捨てられ**、
  有効な SSO があれば黙って現在のアカウントで続いていた。要求した RP から見ると「アカウントを
  選ばせてほしい」という指定が無言で無視される形になる。
  - **`login` と同じ扱い（SSO 復元を止めてログイン画面へ戻す）にした。** 本 IdP はブラウザごとに
    SSO セッションを 1 つしか持たないため、複数アカウントの一覧は出せない。ただし要求の本質は
    「黙って現在のアカウントで続けないこと」であり、ログイン画面へ戻せば利用者は同じアカウントで
    入り直すことも別のアカウントへ切り替えることもできる。
  - **`prompt` を空白区切りの集合として扱うようにした（migration 0032）。** `prompt` は単一値では
    なく、`prompt=select_account consent` のように複数指定できる。値をひとつしか持てない形だと
    複数指定の要求はどれかを取りこぼし、しかも取りこぼしは**無言**で起きる。DB 列も単一値の
    CHECK 付きだったため、`select_account` 単体すら保存できなかった（保存に失敗して認可フローが
    開始できない）。
  - Discovery の `prompt_values_supported` に加えた（未対応と広告したままにしない）。
  - 残件: `response_mode=form_post`（`docs/Progress.md` G12）。

## 2026-08-10（AP1: 認証ポリシーの管理画面）

- **認証ポリシーを管理コンソールから設定できるようにした（AP1。`/{tenant_id}/admin/authentication-policies`）。**
  これまで「誰がどの要素でログインできるか」を決める設定は API からしか触れず、**ログインを止める
  設定**の確認も切り戻しも運用者に curl を強いていた。AP3 で増えた条件（ネットワークゾーン・
  時間帯・`acr_values`）と効果（`require_specific_method`）も画面から扱える。
  - **可変長の条件はテキスト領域で往復させる。** api の更新は全項目置換なので、画面に出せなかった
    項目は保存の瞬間に消える。時間帯を「1 つだけの入力欄」にすると、2 つ設定されたポリシーを開いて
    保存しただけで片方が失われる。時間帯は `曜日 開始-終了 オフセット` の 1 行 1 帯で読み書きし、
    **1 行でも読めなければ保存を拒否する**（読めた行だけ保存すると、書いたはずの条件が黙って消える）。
  - **一覧に「一致しないときの既定動作」を必ず出す。** 同じ `deny` 1 件でも、既定が `allow` か `deny` かで
    「その 1 件だけ止まる」のか「その 1 件以外も止まっている」のかが変わる。表示のため
    `AUTH_POLICY_DEFAULT_EFFECT` を `shared_with_web` にした（判定は従来どおり api）。
  - **web と api の DTO の食い違いをテストで固定した。** 管理 API の DTO は api（OpenAPI の出所）と
    contracts（web の client 契約）に分かれるため、JSON を往復させて形の一致を検査する。認証方式の
    コード一覧も `AuthenticationMethod` との一致を検査する（選んだ方式が api に弾かれる形にしない）。
  - 残件: AP10 の外部 IdP 設定と AP8 のログイン識別子の管理画面は未実装（`docs/Progress.md` AP16）。

## 2026-08-10（G11: web crate の統合テスト）

- **`crates/web/tests/` を新設し、ルータ経由の統合テストを入れた（G11）。** これまで web 側の
  自動検証はハンドラ内の `#[test]`（純関数・テンプレート描画）だけで、**Cookie の発行と読み出し・
  CSRF 同期トークンの往復・リダイレクトの行き先・api クライアントのエラー処理**という
  「ハンドラの外側」は `scripts/e2e.sh` のシェルスクリプトしか通していなかった。
  - **api は `wiremock` でスタブする。** web は DB を持たずデータ操作がすべて api への HTTP
    呼び出しである（ADR-0007）ため、api を HTTP で置き換えれば DB 無しでブラウザ経路を通せる。
  - **api 不通の検証には「閉じたポート」を使う。** スタブサーバを drop して落とす方法は、停止が
    完了する前に届いた要求へ 404 が返り「api 不通」ではなく「テナントが無い」として扱われて
    偽陰性になる。実際にこの取り違えでテストが緑にならず、原因がテスト側だと分かった。
  - 入れた検証: ログイン画面の CSRF 種 Cookie（属性・使い回し）・ログイン成功時の SSO Cookie 発行と
    RP へのリダイレクト・資格情報エラーでセッションを発行しないこと・CSRF 不一致の PRG・
    api 不通時に 5xx へ倒すこと・管理コンソールの入口ガード（未ログイン→ログイン画面、権限不足→403、
    api 不通→502 の弾き分け）・共通セキュリティヘッダ・`/healthz` が api に依存しないこと。

## 2026-08-10（AP7: パスワードポリシーの拡張）

- **パスワード要件に「漏えい済みの拒否」「過去パスワードの再利用禁止」「有効期限」を足した
  （AP7。仕様 §11.2。migration 0031）。** これまでの要件は最小・最大文字数だけで、
  それは入力そのものの形しか見ていない。文字数を満たしていても、公開済みの資格情報リストに
  載っている値・変更を強制した直後に戻された値・何年も同じままの値は止められなかった。
  - **判定と記録を 1 本にまとめた。** パスワードを設定する経路は 7 つある（自己登録・OIDC の強制変更・
    管理コンソールの強制変更・ポータルの強制変更・セルフサービス変更・パスワードリセット・管理者に
    よる再発行）。各経路に条件を書くと**書き忘れた経路がそのまま抜け穴**になるため、
    `PasswordPolicyService` を通す形にして各経路はこれを呼ぶだけにした。
  - **有効期限はログインを拒否しない。** 期限切れは `must_change_password` と同じ「変更画面へ誘導する
    状態」として扱う（判定は `password_change_required` の 1 本で、ログイン経路と変更経路が同じ規則を
    見る）。拒否にすると利用者が自力で復旧できず、管理者による再発行を毎回挟むことになる。
    期限切れフラグを DB に書かないのは、期限が設定変更で**過去にさかのぼって変わる**ため。
  - **履歴には退役したハッシュだけを積む**（`user_password_history`）。現行は `users.password_hash` に
    あり、写しを持つと更新漏れで履歴と現行がずれる。保持するのは判定に使う件数までで、
    平文も可逆な値も持たない（保存形式は現行パスワードと同じ argon2 の PHC 文字列）。
  - **パスワードの書き込みを現行ハッシュ条件の compare-and-swap にした。** 履歴は「実際に置き換えた」
    ハッシュでなければ意味を持たない。無条件の UPDATE では、同時に届いた 2 つの変更要求が同じ現行
    ハッシュを読み、後勝ちで上書きしたうえで両方が同じ古いハッシュを積む（先に書かれたパスワードが
    現行にも履歴にも残らない）。負けた要求は書き込まずにやり直させる。
  - **漏えい照合は k-匿名性のレンジ API へ SHA-1 の先頭 5 桁だけを送る**（既定は無効。
    外向き通信を前提にしない）。**到達できないときは拒否せず通す** —— 外部サービスの不調で
    パスワード変更が一切できなくなると、資格情報が漏れたまさにその状況で交換ができない。
    一方で履歴の読み取り失敗は fail-open にしない（自前 DB の異常は見せる）。
  - **拒否理由を利用者へ返すようにした。** 「弱い」の一語にまとめると、再利用を拒否された利用者は
    同じ値を何度も試すことになる。api は理由コード（`policy` / `breached` / `reused`）を返し、
    訳出は従来どおり web が行う。
  - 設定は `PASSWORD_MIN_LENGTH` / `PASSWORD_HISTORY_COUNT`（既定 5）/ `PASSWORD_MAX_AGE_DAYS`
    （既定 0 = 無期限）/ `PASSWORD_BREACH_CHECK_ENABLED`（既定 false）ほか。手順は
    `docs/OPERATIONS.md`「パスワードの要件を強くしたいとき」。

## 2026-08-09（G12: RP-initiated logout の `id_token_hint`）

- **`id_token_hint` を RP-initiated logout で検証・利用するようにした（G12。OIDC RP-Initiated
  Logout 1.0 §2）。** これまで web はクエリを受け取るだけで api へ渡しておらず、`/logout` は
  「誰の・どの RP のログアウト要求か」を確かめる手掛かりを一つも持っていなかった。web が hint を
  api へ転送し、api が署名（退役済みを含む署名鍵の `kid` 引き）と `iss`（要求テナントの合成
  issuer）を検証する。
  - **`exp` は見ない。** hint は過去に発行した ID Token を指すもので、期限切れが普通である
    （同 §2 が明示的に許している）。代わりに `typ` が `JWT` であることを確かめ、Access Token
    （`at+jwt`）が hint として通らないようにした。
  - **`aud` が `post_logout_redirect_uri` の照合先になる。** 署名検証を通った hint は「本 IdP が
    実際にその RP へ発行した ID Token」であり、自己申告の `client_id` パラメータより強い根拠に
    なる。両方あって食い違う場合はどちらも信用しない。検証を通らない hint では**リダイレクトを
    返さない**（確かめられない相手へブラウザを送り返さない）。`client_id` も hint も無い従来の
    要求は、これまでどおりテナント内のいずれかの登録 URI で通す。
  - **`sub` が現在ログイン中の利用者と違うならセッションを終了しない。** hint は「この利用者を
    ログアウトさせたい」という指定であり、別人のセッションを落とすのは指定に反する。同じ
    ブラウザで別の人がログインし直した後に、前の利用者ぶんのログアウト要求が届く経路が現実に
    存在する。このとき api は通常の成功ではなく `subject_mismatch` を返し、**web は SSO Cookie も
    破棄しない** —— DB にセッションを残したまま Cookie だけ消すと、ブラウザからそこへ戻れない
    宙ぶらりんの状態になり、守ろうとした別利用者のログイン状態を結局は壊してしまう。
  - 検証を通らない hint でも**セッションの終了自体は続ける**（ログアウトは冪等で、止めると
    「ログアウトしたのにログインしたまま」という利用者側の不利益になる）。
  - **付随して `/revoke` の種別フォールバックを直した。** `token_type_hint` を伴わない
    access_token の失効要求が、refresh_token としての UPDATE が 0 行でも「失効させた」と
    判定され、access_token 側の失効を一度も試さないまま 200 を返していた（RFC 7009 §2.1 は
    hint が外れたら他の種別も試すことを求めている）。`RefreshTokenRepository::revoke` が
    失効行数を返すようにして判定を実体に合わせた。

## 2026-08-09（G3: `client_secret_post` に対応）

- **トークン系エンドポイントのクライアント認証に `client_secret_post` を追加した（G3。migration 0030）。**
  従来は `Authorization: Basic`（`client_secret_basic`）だけを受け付けていた。RFC 6749 §2.3.1 は
  Basic を推奨しつつ body での提示も認めており、実際の RP ライブラリ・SaaS 連携には
  `client_secret_post` を既定にするものが多い。方式が合わないだけで連携できない状態を解消した。
  - **どちらを使うかはクライアントの登録値（`token_endpoint_auth_method`）が決める。** 両方を常時
    受け付ける実装にはしない —— そうすると `token_endpoint_auth_method` が「設定できるが効かない
    値」になり、Basic 前提で登録した RP の secret が body 経由でも通ってしまう。confidential
    クライアントの登録・編集（管理 API・管理コンソール）で選べるようにし、既定は
    `client_secret_basic` のまま。`none` は confidential では選べない（secret を持ったまま
    認証が外れるため）。
  - **1 リクエストで両方を提示したら `invalid_request`**（§2.3.1）。片方だけ照合すると「Basic には
    誤った secret、body には正しい secret」のような要求で、どちらが検証されたのかリクエストから
    決められなくなる。
  - **`/token` だけでなく `/introspect`・`/revoke` も同じ方式**（RFC 7009 §2.1・RFC 7662 §2.1）。
    3 経路に散っていた Basic ヘッダの復号と方式判定を、`presentation::client_auth`（取り出し）と
    `application::client_authentication`（どの secret を照合するかの選択）へ集約した。方式を
    増やしたときに取りこぼす経路が出ないようにするため。
  - Discovery に `token_endpoint_auth_methods_supported` の更新と、
    `revocation_endpoint_auth_methods_supported`・`introspection_endpoint_auth_methods_supported`
    を追加した。

## 2026-08-09（G12: `login_hint` / `ui_locales` を web が消費する）

- **認可要求の `login_hint` / `ui_locales` をログイン画面へ反映した（G12）。** どちらも
  `/authorize` が受け取って `auth_sessions` へ保存済みだったが、web は resume の 303
  （単回ハンドルを URL から外す付け替え）で状態を落とすため画面の描画時には手元に無く、
  保存されるだけで誰も読んでいなかった。api に読み出し専用の
  `POST /internal/authorize/login-context` を足し、web が `auth_session_id` から引き直す。
  - **取得は middleware 1 本（`web::login_context`）に寄せる。** 消費者が
    「表示言語の決定（`ui_locales`）」と「ログイン画面のハンドラ（`login_hint`）」に分かれており、
    ハンドラ側で取ると言語決定より後になって画面と文言の言語が食い違うか、同じ文脈を 2 度
    取りに行くことになる。api を呼ぶのは `auth_session_id` Cookie を持つリクエスト
    （＝OIDC フロー中）だけで、管理コンソール・ポータルには増分が無い。
  - **`ui_locales` は Cookie より下・ブラウザ言語より上**（`CLAUDE.md`「国際化」の決定順に追記）。
    RP の希望であって利用者自身の選択ではないため、一度でも言語を選んだ利用者の画面を RP の
    都合で切り替えず、何も選んでいない利用者にはブラウザ既定より優先する。採用しても `lang`
    Cookie には保存しない（RP の希望を利用者の選択として残さない）。対応言語を含まない要求は
    次順位へ落とす（既定 `ja` へ丸めると `Accept-Language` を追い越してしまう）。
  - **`login_hint` はユーザー名欄の初期値にするだけ**で、認証・認可の判断には使わない
    （RP が指定した任意の文字列であり、実在するアカウントを意味しない）。ログイン失敗後の
    再表示では入れ直さない（利用者が別の識別子を入れて失敗したのに、RP の指定へ黙って戻ると
    入力し直しに気付けない）。

## 2026-08-09（AP8: ログイン識別子の複数化 — expand フェーズ）

- **ログイン識別子の登録簿を導入した（AP8。ADR-0025・migration 0029）。** ログイン欄に入力できる
  値は `users.preferred_username` の 1 本きりで、電話番号・社員番号のように組織がすでに配っている
  識別子を使えず、改姓時に旧いユーザー名を残す猶予も作れず、識別子を 1 本だけ止めることも
  できなかった（列が 1 つしか無いので、止めるにはアカウントごと無効化するしかない）。
  `user_login_identifiers` に種別（`username` / `email` / `phone_number` / `employee_number`）・
  **表示値と正規化値**・有効/無効を持たせ、テナント管理者が
  `/{tenant_id}/admin/users/{user_id}/login-identifiers` から割り当てられるようにした。
  - **照合は正規化値、表示は登録どおり。** `090-1234-5678` と `+81 90 1234 5678` は同じ番号を
    指すが、利用者が自分の登録内容だと分かるのは前者である。正規化を表示にも使うと「登録した
    覚えのない値が並ぶ」ことになり、同一性を確認できない。種別は「正規化のしかた」を決めるために
    あり、同じ文字列でもユーザー名としてなら大小を、電話番号としてなら区切り記号を無視する。
  - **無効化は行を消さずに行う。** 一意制約は `is_active` を見ないため、止めた値は他の利用者が
    登録できないままになる。削除にすると同じ値を別人が取れ、止めた識別子の宛先が黙って変わる。
  - **既存の値は登録簿へ写さない。** 解決は「登録簿の有効な行 → `users.preferred_username`」の順で、
    登録簿には**追加の識別子だけ**が入る。写しを取ると同じ値が 2 か所にでき、同期が漏れた瞬間に
    「変更前のユーザー名でログインできる」「無効化したのに認証が通る」が生まれる ——
    どちらも経路ごとに同期を足す形では塞ぎきれない。主識別子の移送は contract フェーズ
    （AP15）でまとめて行う（AP9 / ADR-0022 と同じ分け方）。管理画面のために、一覧 API は
    `preferred_username` から**読み出し時に合成した行**（`id` が `null`）を先頭に足す。
  - ログイン 4 経路は `UserRepository::find_by_login_identifier` の 1 本に寄せ、どこを引いたかは
    実装に閉じた。利用者作成・プロフィール編集の一意性チェックも同じ引き方に揃えた
    （`users` だけを見ると、別名として登録済みの値を素通しにする）。
  - **`users.email` も取り込まない。** 取り込むとマイグレーションを当てた瞬間からメールで
    ログインできてしまい、認証の入り口が黙って広がる。`email` 種別を明示的に足したときだけ有効。
  - 追加できる値かは**実際の解決経路で引いてみて**判定し、**すでにログインに使える値を拒否**する。
    他人に解決される値だけでなく**自分の主識別子と同じ値も拒む**（登録できると、その行を
    無効化しても `preferred_username` へのフォールバックで認証が通ってしまう）。メール種別は
    加えて `users.email` も見る（他人の連絡先でなりすませるため。本人のアドレスは通す）。
  - **候補生成と登録時検証は同じ「その種別として読めるか」判定を使う**（`accepts`）。電話番号の
    正規化を任意の入力に掛けると、ユーザー名 `alice123456` から抜いた `123456` が他人の電話番号に
    一致し得る。加えて、種別をまたいで**複数の利用者に当たったら誰も返さない**（fail-closed。
    `LIMIT 1` で選ぶと索引の都合で解決先が決まってしまう）。
  - 監査（`user.login_identifier_added` / `.updated` / `.removed`）には**種別のみ**残す
    （電話番号・メールアドレスは PII）。

## 2026-08-09（優先度 8・5 の対応: SEC6・SEC12・SEC13・G1・G2・G9・AP3）

- **進行状態テーブルの秘密値をハッシュ保存にした（SEC6）。** `auth_sessions.id` は web の
  `auth_session_id` Cookie **そのもの**でありながら平文で主キーに置かれており、他の bearer
  credential（`sso_sessions.session_hash`・`authorization_codes.code_hash`・`refresh_tokens.token_hash`・
  同じ表の `handle_hash`）が全てハッシュ保存なのと非対称だった。DB 読取を得た者は TTL の間、
  同意待ち・MFA 待ちの認可セッションを乗っ取れる。`id_hash`（SHA-256）へ移し、同じ構造だった
  `saml_sso_requests.id`、平文の写しを持っていた `passkey_challenges.auth_session_id` /
  `external_login_requests.auth_session_id` も揃えた（1 か所でも残るとハッシュ化の意味が無い）。
  リポジトリのトレイトが平文を受け取らない形にして、生値を保存する経路を型の上で塞いだ。
  ハンドル交換は平文 id が手元に無いため、消費と同じ UPDATE で id を再生成する。
- **ログイン失敗カウンタの加算を原子的にした（SEC13）。** 「読む → +1 して上書き」だったため、
  並行して届いた N 件の試行が同じ値を読むと N 回失敗しても行が 1 しか進まず、ロック閾値に
  届かないことがあった。加算とロック判定を 1 文の UPDATE で行う `record_login_failure` を追加し、
  失敗経路 5 つ（OIDC パスワード / MFA / ポータル ×2 / 管理コンソール）を寄せた。
- **期限切れレコードの GC を 1 本のタスクに集約した（G2）。** 定期削除は `log` にしか無く、
  `auth_sessions`・`authorization_codes`・`refresh_tokens`・`sso_sessions`・`revoked_access_tokens`・
  `passkey_challenges`・各種一時トークン表は誰も消していなかった（`passkey_challenges` は
  `delete_expired` を実装済みなのに呼び出し元が無かった）。`ExpiringRecordStore` ポートで掃除口を
  1 ファイルに単一定義し、`EXPIRED_RECORD_PURGE_INTERVAL_SECS`（既定 3600）で回す。
  `expires_at` を持つのに掃除対象へ載っていない表は統合テストが検出する。
- **CORS を実装した（G1）。** 既定トポロジ（api と web が別ホスト名）では SPA からの `/token`・
  `/userinfo` が常にクロスオリジンで、`Access-Control-Allow-Origin` が無いためブラウザが
  レスポンスを読めなかった。公開メタデータは `*`、`/token`・`/revoke`・`/introspect`・`/userinfo` は
  テナント内 public client の `redirect_uris` 由来のオリジン + `CORS_ALLOWED_ORIGINS` に限る。
  管理 API・`/internal/*` には開けず、どの経路でも `Allow-Credentials` は付けない（ADR-0018）。
- **api のシングルインスタンス前提を明文化した（G9）。** レートリミッタ・キャッシュがプロセス内
  メモリ、鍵ローテーションが排他制御なし。README に「何が壊れるか」の一覧を、OPERATIONS に
  `--scale api=N` を使わない旨を書いた。
- **低リスク改善のまとめ（SEC12）。** CSP から `script-src 'unsafe-inline'` を外した（インライン
  script を自オリジンのアセットへ切り出し、埋め込み値は `data-*` で渡す）。Swagger UI を
  `API_DOCS_ENABLED`（既定 false）で制御。死に設定だった `clients.require_pkce` を列ごと削除
  （PKCE S256 は無条件必須で、画面が「切れる」と誤解させていた）。同意 POST を Cookie の
  `auth_session_id` に束縛。argon2 のパラメータを明示（19MiB/2/1）。CSRF 比較を定数時間に統一。
  `/authorize` の redirect_uri 組み立てから `expect()` を除去。
- **認証ポリシーの条件種別を拡張し `require_specific_method` を追加した（AP3）。** 条件に
  `ip_cidrs`（ネットワークゾーン）・`time_windows`（時間帯）・`requested_acr` を追加し、効果に
  「その方式でなければ通さない」を追加した（`require_mfa` に丸めると TOTP 登録済みの利用者が
  WebAuthn 必須をすり抜ける）。判定は実際に使われた方式が確定した時点で行い、MFA 経路は
  `MfaLoginService` が `[password, 第二要素]` に対して再評価する。`/authorize` は `acr_values`・
  `login_hint`・`ui_locales` を受け付けて保存し、Discovery に対応状況を広告する。
  国・端末信頼の条件は判定材料（GeoIP・デバイス登録簿）が無いため未実装（ADR-0020 追補・Progress AP14）。
  一致した方式指定は**全件**を満たす必要があり（1 件目だけ見ると「AND はポリシー 2 本で表す」が
  壊れる）、判定は各経路が SSO を発行する直前に置く。**復元した SSO セッションにも掛ける** ——
  掛けないと、RP が `acr_values` で起動したポリシーをパスワードだけの既存セッションが素通りする。

## 2026-08-08（セキュリティレビューの高優先度対応: SEC1・SEC5・SEC7・SEC8・SEC9）

- **web の `X-Forwarded-For` 無条件信頼をやめた（SEC1）。** api と同じ `TRUST_FORWARDED_HEADERS`
  （既定 `false`。`shared_with_web` へ変更）でゲートし、非信頼時は TCP 接続元（`ConnectInfo`）へ
  フォールバックする。ADR-0018 以降ログインの入口は web で、web が組み立てた IP が api の
  レートリミッタ・監査ログの IP になるため、web だけが素通しだと api 側のゲートがログイン経路で
  迂回されていた（ヘッダを変え続ければ IP レート制限を回避、送らなければ判定自体をスキップ）。
  判定は `client_ip` middleware 1 箇所に集約し、ハンドラは `Extension<ClientIp>` で結果だけを受ける。
  信頼する場合でも採るのは **最右**の値（信頼するプロキシが追記した接続元）にした。プロキシは
  クライアント申告を消さずに追記する（nginx の `$proxy_add_x_forwarded_for`）ため、先頭を採ると
  ゲートを通したうえで偽装がそのまま通る。同梱の nginx も `$remote_addr` で**上書き**するようにし、
  導出は api と共有（`idp_contracts::forwarded`）にした。信頼するホップは 1 段と仮定する
  （多段構成では前段プロキシの IP が記録される＝精度は落ちるが偽装はされない）。
- **未認証フォームの CSRF 種を `__Host-` でオリジンへ束縛した（SEC5）。** `admin_csrf_id` /
  `portal_csrf_id` に加え、`portal_mfa_ticket` / `saml_request_id` も対象。Cookie はサブドメイン間で
  分離されないため、同一親ドメインの別サブドメインを奪った攻撃者が `Domain=親` の種を強制して
  CSRF トークンを偽造できた。平文 HTTP（開発環境）ではブラウザが `__Host-` を拒否するため前置しない。
- **認証成功時に `auth_session_id` を再生成するようにした（SEC7）。** `set_password_verified` /
  `set_authenticated_user` が記録と同じ UPDATE で id を差し替える（別文に分けると認証済みなのに
  旧 id が引ける瞬間ができる）。`sso_session_id` はログインのたびに再生成していたのに、認証前に
  発行した `auth_session_id` だけ使い回していた非対称を解消した。パスワード・MFA・パスキー・
  外部 IdP・強制パスワード変更・SSO 復元の 6 経路すべてが対象。
- **再利用検知でトークンファミリを一括失効するようにした（SEC8）。** `refresh_tokens.grant_hash`
  （元の authorization code の SHA-256。rotation で引き継ぐ）を追加し（0025。
  既存行は再帰 CTE でチェーン全体を根から埋め戻す）、refresh token の
  再利用検知では提示されたトークンだけでなく**同一グラント由来の子孫すべて**を失効させる
  （従来は親 1 本のみで、攻撃者が先に交換して得た子トークンが生き残った）。authorization code の
  再利用も同じ鍵でトークンを失効させ、監査 reason を「本当の再利用」と「不存在・期限切れ」に
  切り分けた（従来は 1 文字列に丸めていて攻撃を拾えなかった）。RFC 6819 §5.2.2.3 / OAuth 2.1 準拠。
- **アクセスログにクエリ文字列を残さないようにした（SEC9）。** `TraceLayer` の既定スパンは `uri` を
  クエリ込みで持ち、`RUST_LOG=debug` で `?auth_session=`（単回ハンドル）・`code_challenge`・`code` が
  stdout へ落ちた。api / web とも `make_span_with` でパスのみを記録する（組み立ては
  `idp_contracts::http_trace` に単一定義。片方だけ既定へ戻る事故を防ぐ）。

## 2026-08-08（優先度 14・15 の実装: 認証コンテキスト・Step-up・認証器統合・外部 IdP・M2M・ログアウト信頼性・セルフサービス）

- **認証セッションへ認証コンテキストを記録するようにした（AP4）。** `sso_sessions` に
  `authentication_methods` / `authentication_strength` / `mfa_completed_at` を追加し（0020）、
  ログイン経路 5 つすべてが `SsoSession::establish` 経由で記録する。強度と MFA 完了時刻の導出は
  ドメイン 1 箇所に閉じた（経路ごとに計算すると Step-up・再認証の判定が食い違う）。
- **認証ポリシーをポータル・管理コンソールのログインへも適用した（AP2）。** これまで OIDC フロー
  だけが評価対象で、`deny` されたはずの利用者がポータル経由で SSO セッションを得られた。
  クライアント文脈が無いため `client_id` は `None`。管理コンソールは第二要素の入力ステップを
  持たないため、`require_mfa` が掛かる利用者はいずれの案内でも SSO を発行しない。
- **Step-up 認証を追加した（AP5）。** パスワード変更・認証器の追加削除・セッション失効・外部 IdP の
  紐付けは、直近の本人確認から `STEP_UP_MAX_AGE_SECS`（既定 300 秒）を超えていれば確認をやり直させる。
  認証器を登録済みの利用者が認証器を触る操作では第二要素まで求める。判定基準は AP4 の記録と、
  新設した `sso_sessions.step_up_at`（0022）。
- **認証器を統合管理するようにした（AP9）。** 種別ごとに別テーブルだった認証器を、状態
  （pending/active/suspended/revoked）を持つ登録簿 `user_authenticators` へ集約した（0023。既存の
  TOTP・パスキーは冪等に取り込む）。**リカバリーコード**（10 本の束・1 回きり・ハッシュ保存）と
  **email OTP** を追加し、どちらも MFA 入力欄で TOTP と同じ欄から使える。SMS OTP は種別として
  持つが送信手段がスタックに無いため発行経路は無い。秘密（TOTP 共有鍵・パスキー公開鍵）は元の表に
  残す expand フェーズまで（判断と残作業は ADR-0022）。
- **外部 IdP（OpenID Provider）認証を追加した（AP10）。** `iss` + `sub` だけを同一性の根拠とし、
  メール一致の自動連携はプロバイダ単位の opt-in かつ外部 IdP が `email_verified` を主張する場合に
  限る（0024）。ID Token の検証（JWKS 署名・`iss`・`aud`・`exp`・`nonce`）は `ExternalOidcClient` の
  実装に閉じ、検証を通ったクレームだけがポートから出る契約にした（信頼モデルは ADR-0023）。
- **`client_credentials` grant を追加した（G4）。** confidential かつ管理者が明示的に許可した
  クライアントのみ。ID Token も Refresh Token も発行せず、`sub` はクライアント自身（`sub_type`
  クレームで利用者主体のトークンと区別する）。これまで死んでいた `clients.grant_types` を許可の
  出所として使う。
- **back-channel logout に `sid`・`exp` を付け、送信を永続キュー＋再試行にした（G5）。**
  RP がセッション単位で失効できるようになり（Discovery で `backchannel_logout_session_supported`
  を広告）、`tokio::spawn` の撃ちっぱなしをやめて `backchannel_logout_deliveries` へ積み、
  指数バックオフで再試行する（0021）。署名済み logout_token は保存せず送信直前に署名する
  （`sid` の運び方とキューの設計は ADR-0024）。
- **利用者セルフサービスにセッション一覧・失効と連携アプリの解除を追加した（G10）。**
  `SsoSessionRepository::list_for_user` が trait にも実装にも無かったため追加。連携解除では
  同意行だけでなく**解除したクライアントの** refresh token も失効させる。
- **上記のレビュー指摘を反映した。** 認証器の一時停止・失効を認証経路（TOTP・パスキー）でも
  見るようにし（AP9。登録簿にしか状態が無いため、見なければ「止めたはずの認証器」で入れた）、
  step-up のゲートを画面だけでなく**更新系エンドポイント自体**（パスキー登録の JSON API・
  TOTP 有効化の POST）へ移した。外部 IdP は連携の照合に `iss` を含め（プロバイダの issuer 差し替えで
  別人に化けるのを防ぐ）、認可フローの途中から来た場合の続き（同意確認・code 発行）を api 側で
  実装した（従来は存在しないルートへ 302 していた）。

## 2026-08-08（レビュー指摘の反映: ロック回避経路と送信時の宛先検査）

- **MFA 待ちのパスワード成功では失敗カウンタをリセットしないようにした（SEC3 の追補）。**
  `LoginService` はパスワード検証直後に `failed_login_count` を 0 に戻していたため、パスワードを
  知っている攻撃者が「TOTP を上限手前まで失敗 → 正しいパスワードで再ログイン → カウンタが 0」を
  繰り返してロックを永久に回避できた。リセットは認証が最後まで通った時点（単一要素で成立する経路、
  または `MfaLoginService` の TOTP 成功時）だけで行う。
- **back-channel logout の送信直前にも宛先を検査するようにした（SEC2 の追補）。** 登録時の検証だけでは、
  検証導入より前に登録された行や DB を直接編集された行が素通りし、SSRF が残っていた。判定は
  `domain/outbound_uri.rs` に単一定義し、登録時（`client_management`）と送信時（`logout` ハンドラ）が
  同じ規則を使う。内部宛先はスキップして WARN を出す。
- ドキュメント用レンジ（192.0.2.0/24 等）は拒否対象から外した。経路が無いだけで「内部」ではなく、
  検証環境が RP の代用に使うことがあるため。

## 2026-08-08（`INTERNAL_SERVICE_TOKEN` の検証と本番判定の見直し（SEC11））

- **`INTERNAL_SERVICE_TOKEN` に最低要件（32 文字以上・`CHANGE-ME` 検出）を課した。**
  `/internal/*`（認証・パスワード変更・MFA 検証）を守る唯一の資格情報でありながら、
  `KEY_ENCRYPTION_KEY` / `CSRF_SECRET` と違って無検証で 1 文字でも起動できていた。
- **開発用既定 secret の fail-fast を「https のとき」から「ループバック以外を公開しているとき」へ
  広げた。** 前段で TLS を終端して `ISSUER=http://id.example.com` とした配置では判定が効かず、
  ソースに埋め込まれた既知トークンのまま `/internal/*` が開いていた（防御が前段プロキシの
  `/internal/` 404 一枚だけになる）。`ISSUER` の DB 上書きを保存してよいかの判定（ADR-0017）も
  同じ述語を使うため同時に厳しくなる。
- 判定と検証は `idp-contracts` の `deployment` モジュールへ単一定義した。api と web が別々に
  持っていると「api は起動するが web は起動しない」がおきるため。

## 2026-08-08（ログアウト系 URI の検証と管理 API の Origin 検証を追加した（SEC2・SEC4））

- **クライアントのログアウト系 URI を検証するようにした（SEC2）。** `redirect_uris` は
  絶対 http(s)・フラグメント禁止・ワイルドカード禁止を課していたのに、
  `post_logout_redirect_uris` / `frontchannel_logout_uri` / `backchannel_logout_uri` は
  無検証で保存していた。3 種とも同じ検査を通し、登録時・更新時の両方で適用する。
- **`backchannel_logout_uri` はさらに内部宛先を拒否する。** api がサーバ側から POST する唯一の
  外向き URI であり、テナント管理者権限で `http://169.254.169.254/...` 等を登録できると
  認証済み blind SSRF になる。ループバック・プライベート・リンクローカル・CGNAT・
  unique local のアドレスリテラルと `localhost` を拒否する（名前解決の結果までは見ないため、
  閉じた配置では前段プロキシの egress 制御を併用する）。
- **Cookie 認証の変更系リクエストに Origin / Referer 検証を追加した（SEC4）。**
  `single-origin` トポロジでは `Accept: application/json` を付けた same-site スクリプトから
  api の管理 API へ Cookie 付きで到達でき、body を取らない POST（`restart`・secret 再発行・
  password/MFA reset）はプリフライトも発生しないため CSRF が成立していた。`RequirePerms` /
  `AuthenticatedUser` extractor が、変更系メソッドで許可オリジン（`PUBLIC_WEB_BASE_URL` と
  `ISSUER`）との一致を要求する。ヘッダを持たないリクエスト（`curl` 等）は従来どおり通す。

## 2026-08-08（OIDC ログインの TOTP 検証に総当たり対策を入れた（SEC3））

- **OIDC ログインフローの TOTP 検証（`/internal/mfa/totp/verify`）に、IP 単位のレート制限と
  ユーザー単位の失敗カウント・期限付きロックを追加した。** それまで失敗は監査記録だけで、
  auth_session の生存中（既定 600 秒）は 6 桁コードを無制限に試せた。ポータル側 MFA には
  レート制限があり非対称だった。
- レート制限はパスワード認証と**同じ limiter インスタンス**、ロックはパスワード認証と同じ
  `LockoutPolicy` / `users.failed_login_count` / `locked_until` を共有する。別枠にすると
  「パスワードで上限手前まで、TOTP でさらに上限手前まで」と配分してロックを免れられるため。
- ロック中のアカウントは TOTP 照合の前に拒否し、検証成功時は失敗カウンタとロックを解除する
  （パスワード認証の成功時と同じ扱い）。監査には `ip_rate_limited` / `invalid_totp` /
  `account_locked` / `too_many_failures` を記録する。
- 応答に `RateLimited`（429）・`Locked`（403）を追加し、web は再試行できないため
  フォームではなく案内ページを返す（`mfa-error-rate-limited` / `mfa-error-locked`）。

## 2026-08-03（フォームの送信中を押したボタンで示す（ADR-0021））

- **押した送信ボタンにスピナーが出て、送信が終わるまで押せなくなった。** サーバレンダリングの
  画面は次のページが返るまで表示が変わらず、押せたのか分からないまま同じボタンを続けて押せた。
  共通スクリプト `/assets/submit-feedback.js` を認証系画面（`page.html`）と管理コンソール
  （`console/layout.html`）の両方のレイアウトへ入れ、テンプレートの記述なしで全フォームに効かせる。
- スピナーはラベルの上に重ね、ラベルは場所を占めたまま隠す。ラベルの前に足すとボタンが
  横に伸び、隣のボタン（同意画面の承認／拒否など）が動いて押し間違いの元になるため。
- 同じフォームの 2 度目の送信は止める（無効化が反映される前に届いた分をボタンの `disabled` では
  止められないため）。無効化自体は送信データが確定してから行う（同意画面の approve / deny や
  言語切替のように、押したボタンの `name`/`value` で分岐するフォームが壊れるため）。
- 確認ダイアログ（`console.js`）で取り消された送信には印を付けない。読み込み順への依存は
  `templates.rs` のテストで固定した。
## 2026-08-03（テナント管理画面に混入していた React のデバッグ表示を除去した）

- **テナント管理画面（`/admin/tenants`）に「React: テナント名を入力してください」が
  表示され、レイアウトが崩れていた問題を修正した。** 原因は 2 つ。(1) React island の
  `TenantRegistrationConsole` strategy が開発用のステータス文言を日本語直書きで描画していた
  （画面の表示言語に追従せず、スタイルも当たっていない）。(2) `hydrateAll` が
  `document.body` も描画先にしていたため、同じ文言が `</footer>` の後ろ（レイアウトの外）にも
  差し込まれていた。デバッグ表示を削除し、描画先をテンプレートが宣言した
  `[data-react-surface]` の領域だけに限定した。フォーム状態の `data-*` 反映は従来どおり。

## 2026-08-01（認証ポリシーを導入し、アカウントロックを設定化した（ADR-0020））

- **テナント単位の認証ポリシー（`authentication_policies`）を導入した。** 効果は
  `allow` / `deny` / `require_mfa`、適用条件は `client_ids` / `user_ids`（空 = 制限しない、AND）。
  評価は優先順位昇順・**拒否優先**のドメイン純粋関数で、パスワード／パスキー検証成功後に行う
  （資格情報を知らない攻撃者へポリシーの存在を観測させない）。`require_mfa` 一致時、TOTP 設定済みは
  既存 MFA ステップへ、未設定は単一要素での成立を拒否する。パスキーは `require_mfa` を満たす。
  拒否は `login.policy_denied` として監査記録する。一致ポリシー無しの既定動作は
  `AUTH_POLICY_DEFAULT_EFFECT`（既定 `allow`、`deny` へ切替可）。
- **管理 API（`/{tenant_id}/admin/authentication-policies`、CRUD、`idp.tenant.admin` 必須）を追加した。**
  変更は `authentication_policy.created` / `.updated` / `.deleted` として監査記録する。
- **アカウントロックの閾値を設定化した。** 3 つのログインサービスにハードコードされていた
  「10 回失敗 / 15 分ロック」を `LOGIN_MAX_FAILED_ATTEMPTS` / `LOGIN_LOCK_DURATION_SECS`
  （DbManaged）からの注入（`LockoutPolicy`）に一本化した（既定値は従来と同じ）。

## 2026-07-29（api を兄弟サブドメインへ戻し、WebAuthn RP ID を web オリジン由来にした（ADR-0019））

- **ADR-0018 決定 1（入れ子ホスト名）を撤回した（ADR-0019 決定 1）。** ワイルドカード証明書は
  左 1 ラベルしか覆えず、サブサブドメイン（`api.idp.nolumia.com`）には別証明書が必要になるため。
  `.env.production.example` / `.env.staging.example` と `docs/OPERATIONS.md` の公開ホスト名を
  兄弟命名（`identity.nolumia.com` / `identitystg.nolumia.com`）へ戻した。決定 2〜4（api の Cookie
  非依存・host-only）は実装済みのため、兄弟命名でも stg/prod の Cookie スコープは交わらない。
  成立条件として **`COOKIE_DOMAIN` は掃除用途以外で設定禁止**を明記した。Progress.md 旧 T1
  （入れ子ホスト名の適用作業）は不要になり削除した。
- **WebAuthn の RP ID・origin の導出元を `ISSUER` から `PUBLIC_WEB_BASE_URL` へ変更した
  （ADR-0019 決定 2）。** Passkey のセレモニーは web のページ上で実行されるため、issuer
  （api のオリジン）由来だと domain-split では RP ID が呼び出し元オリジンのサフィックスに
  ならず常に失敗していた。single-origin（`PUBLIC_WEB_BASE_URL` 未設定 = issuer 追従）では
  従来と同値で挙動不変。「ホスト名を変えると登録済み Passkey が使えなくなる」注意の対象キーも
  `PUBLIC_WEB_BASE_URL` へ移した（設定説明・`docs/OPERATIONS.md`・ADR-0017 追記）。

## 2026-07-28（SAML SSO エンドポイントを実装した）

- **メタデータが広告していた SingleSignOnService（`{issuer}/{tenant_id}/saml/sso`）を実装した。**
  SP-initiated SSO（HTTP-Redirect / HTTP-POST 両バインディング）で AuthnRequest を受け、登録済み SP
  （entity_id 照合・ACS URL の完全一致・enabled）を検証したうえで、署名付き SAML Response
  （Assertion への enveloped XML 署名。RS256 / ES256、OIDC と同じ ACTIVE 署名鍵）を SP の ACS へ
  自動 POST するフォームで返す。NameID は SP 登録の Format に従う（emailAddress → メール、それ以外 →
  OIDC と同じ `sub`）。発行・拒否は `saml_response.issued` として監査記録する。
- **認証は OIDC と同じ web ハンドオフ方式（ADR-0018 決定 2）。** api はブラウザ Cookie を読まず、
  進行状態（`saml_sso_requests` 表。0018）を作って単回・短命ハンドルで web の
  `/{tenant_id}/saml/continue` へ 302 する。web が SSO Cookie とともに `/internal/saml/resume` を呼び、
  SSO 未確立ならポータルログインへ誘導して成功後にフローへ復帰する（TOTP・強制パスワード変更を含む）。
  SSO 復元の判定（有効期限・ユーザー有効性・テナントメンバーシップ・idle 延長）は
  `application::sso_restore::SsoRestorer` へ切り出し、OIDC の authorize と共有する。
- **XML 署名は排他的 C14N 正準形で直接生成する方式。** 生成 XML を最初から正準形（全closeタグ・
  正準属性順・正準エスケープ）で出力し、そのバイト列へ署名する（`domain::saml_response`）。

## 2026-07-28（IdP メタデータのダウンロードリンクが 404 になるのを修正した）

- **管理コンソールの「IdP メタデータをダウンロード」を web オリジンのダウンロード URL にした。**
  `/{tenant_id}/admin/saml-clients/idp-metadata` が api から XML を取得して添付ファイルとして中継するため、
  別ドメイン公開でも 404 にならず、管理画面に api への直接リンクを露出しない。
- **取得処理は Application 境界の `ApiClient::fetch_saml_idp_metadata` へ委譲した。** web ハンドラは
  管理者セッションの検証と HTTP レスポンスへの変換に専念し、web→api の内部到達先と通信処理を持たない。
- **web の設定に `issuer()` を追加した。** ブラウザへ出す api の URL は公開オリジン（`ISSUER`）を基点に
  する。`api_base_url()`（web→api のサーバ間到達先。Compose 内部アドレスになりうる）とは用途が別。
- **この経路の退行検出を追加した。** 描画テストと URL の単体テストで、リンクが api オリジンではなく
  web のダウンロードルートを指すことを検証する。
- **同種の「経路とサービスの取り違え」を構造テストで塞いだ。** 個別の画面ごとにテストを書いても
  次に足したリンクは素通りするため、ルート一覧（`router.rs` の宣言）を単一の出所として突き合わせる。
  - テンプレートに直書きした `href` / `action` のパスが web 自身のルートであること（api だけが持つ
    パスを web オリジン相対で書けなくなる）。
  - web の画面のパスが単一オリジン構成のリバースプロキシ（`docker/nginx.conf`）に列挙されていること
    （列挙漏れは catch-all で api へ流れて 404 になる。ルートを足して振り分けを足し忘れる退行を検出）。

## 2026-07-28（DB パスワード不一致でデプロイが止まらないようにした）

- **`.env` の `MARIADB_PASSWORD` と既存 DB volume の不一致を、`deploy.sh` が自動で解消するようにした。**
  MariaDB は data volume 初回作成時のパスワードを固定し以後の `.env` 変更を反映しないため、パスワードを
  変えると `Access denied for user 'idp'` でデプロイが停止していた（対処は手動の `ALTER USER` か、
  データを消す `reset` のみ）。プリフライトで不一致を検出したら `.env` を正とし、`MARIADB_ROOT_PASSWORD`
  で root 認証できる場合は DB 側のユーザーを `.env` の値へ同期して続行する（データは保持される）。
- **root でも認証できない場合（`.env` ごと別物）を別の診断に分けた。** この状態では
  `KEY_ENCRYPTION_KEY` も変わっており既存 DB の署名鍵を復号できないため、「元の `.env` を戻す」か
  「`reset`」を提示して停止する。
- **DB 資格情報を `.env` の字面ではなく Compose が解決した実効値（`mariadb` コンテナの環境変数）から
  読むようにした。** 引用符・インラインコメント・変数展開といった dotenv 構文の解釈は Compose が唯一の
  正で、`deploy.sh` が再実装すると api / migrate へ渡る値と食い違う（プリフライトの偽陽性に加え、
  パスワード同期が誤った値を DB へ書き込みかねない）。
- **パスワード不一致の判定をエラーコード 1045 に限定した。** 資格情報が正しくても DB へのアクセス権が
  無ければ MariaDB は同じ「Access denied for user …」の文言で 1044 を返すため、文字列判定では権限不足を
  drift と誤認し、`GRANT` で意図的に絞った権限を広げてしまう。

## 2026-07-27（エラー・警告ログを管理コンソールから参照できるようにした）

- **アプリケーションログ（`log` テーブル）を追加し、管理コンソールに「エラー・警告ログ」画面
  （`/{tenant_id}/admin/logs`）を新設した。** これまで api・web の WARN / ERROR はコンテナの標準出力に
  出るだけで、画面からは追えなかった（`CLAUDE.md`「ログ」が定める `log` テーブルが未実装だった）。
  レベル・サービス（api / web）・出力元モジュール（前方一致）・correlation ID・期間で絞り込める。
  `correlation_id` は監査ログと同じ値なので、同じリクエストの監査イベントと内部エラーを突き合わせられる。
  マイグレーション 0017 で `log` テーブルを追加。
- **取り込みは `tracing` の層で行い、WARN / ERROR だけを DB へ非同期書き込みする。** 取り込み層と
  レコードの形は `idp-contracts`（`application_log`）に単一定義し、api・web が同じ導出を使う。api は
  チャネル経由でバックグラウンドタスクが書き、DB を持たない web は `POST /internal/logs`（サービス
  トークン保護）へまとめて送って api に書いてもらう。どちらもリクエスト処理はブロックせず、queue が
  詰まったら捨てる（捨てた件数は 1 行の WARN として記録に残す）。書き込み経路自身のログは取り込まない
  （失敗ログが書き込みを誘発する再帰を断つ）。
- **閲覧は `idp.system.admin`（root）に限定した。** 全テナントの記録が同じテーブルに載るため、テナント
  管理者には開かない（テナント単位の追跡は従来どおり監査ログ `/admin/audit-logs` が担う）。
- **保持期間の設定 `APP_LOG_RETENTION_DAYS`（既定 30 日・DB 管理）を追加した。** これより古い行は
  1 時間ごとに削除する。`0` で削除を止められる。
- **correlation_id を `tracing` スパンに載せた（api・web）。** ハンドラが出す WARN / ERROR は囲っている
  リクエストスパンから追跡キーを拾い、`log.correlation_id` に入る。

## 2026-07-27（ログイン・強制パスワード変更の自己回復と失敗ログの拡充）

- **CSRF 不一致のフォームを PRG（Post/Redirect/Get）で自動復帰させた。** 従来は POST 応答として
  「フォームの有効期限が切れました」ページを返すだけだった（リロードすると POST が再送されて同じ
  エラーが続く。ポータル/管理ログインは空の CSRF を埋めたフォームを再描画するため再送信でも復帰不能）。
  OIDC/ポータル/管理ログイン・強制パスワード変更・TOTP 入力・同意画面の CSRF 不一致はすべて 303 で
  GET へ付け替え、新しいトークンのフォームを自動再表示する（`?error=csrf` でバナー表示。翻訳キー
  `login-error-csrf-retry`）。
- **ポータル/管理ログインの CSRF 種 Cookie を GET ごとに回転させるのをやめた。** 有効な種 Cookie が
  あれば使い回して TTL を延長する（複数タブでログイン画面を開くと古いタブのフォームが必ず CSRF
  不一致になっていた）。
- **強制パスワード変更（ポータル/管理）の多重送信を冪等にした。** 変更成功直後の再送（ダブルクリック・
  POST 応答のリロード）は `must_change_password` 解除後に届くため「現在のパスワードが正しくありません」
  と誤表示されていた。`new_password` が現行ハッシュに一致する再送は同じ変更の再送とみなし、成功時と
  同じ後続（メール検証 → TOTP/権限ゲート → SSO 発行）へ進める。
- **ログイン系の失敗を監査・ログへ残すようにした。** CSRF 不一致（`csrf_mismatch` /
  `password_change_csrf_mismatch`）・現行パスワード不一致（`invalid_current_password`）・変更不要状態への
  再送（`password_change_not_required`）を `audit_log` へ記録し、AuthSession 期限切れ等は
  correlation_id 付きの WARN ログを出す（従来は何も残らず原因調査ができなかった）。

## 2026-07-27（ADR-0018 を実装した: api はブラウザ Cookie を読み書きしない）

- **`/authorize` の Set-Cookie を廃止した（ADR-0018 決定 2・3）。** 検証成功時は AuthSession に
  束ねた**単回・短命（60 秒）のハンドル**を発行し、`{web}/{tenant}/login?auth_session=...` へ 302 する。
  web はハンドルを新設の `POST /internal/authorize/resume` で即座に交換（交換時に消費 = 単回使用）し、
  `auth_session_id` を自ドメインの host-only Cookie へ移して 303 で URL から除去する。SSO 判定・
  `prompt` / `max_age` の評価・同意チェック・code 発行も resume（web が SSO Cookie の値をボディで
  渡す）へ移した。マイグレーション 0016 で `auth_sessions` に `prompt` / `max_age` /
  `handle_hash` / `handle_expires_at` を追加。
- **RP-initiated Logout の起点を web へ移した。** `end_session_endpoint` は
  `{web}/{tenant}/logout`（discovery も変更）。api は新設の `POST /internal/logout/rp` で SSO 失効・
  back-channel 通知・`post_logout_redirect_uri` の検証と `state` 付与を担い、SSO Cookie の破棄と
  front-channel iframe ページの描画（Askama テンプレート化）は web が行う。api の公開
  `GET /{tenant}/logout` は削除した。
- **セッション Cookie（`sso_session_id`・`auth_session_id`）は常に host-only になった（決定 4）。**
  `CookiePolicy` の `set_shared`/`expire_shared` を `set_session`/`expire_session` へ改め、
  `COOKIE_DOMAIN` は「旧 ADR-0012 構成でブラウザに残った `Domain` 付き Cookie を掃除する削除 Cookie の
  併送」にだけ使う（既定は未設定）。
- **`.env` テンプレートを入れ子ホスト名へ変更した（決定 1）。** prod は `api.idp.nolumia.com`（api）/
  `idp.nolumia.com`（web）、stg は `api.idpstg.nolumia.com` / `idpstg.nolumia.com`。`COOKIE_DOMAIN` は
  既定で未設定。**`ISSUER` が変わるため RP 再設定と DNS・証明書（web/api 両ホストを SAN に含める）の
  デプロイ作業が別途必要**（`docs/Progress.md` T1）。

## 2026-07-27（api↔web の Cookie 共有をやめる方針を決定した。ADR-0018）

- **ADR-0018 を追加した。** api と web を**兄弟**サブドメインで公開すると、両方を覆う `COOKIE_DOMAIN` が
  apex（`nolumia.com`）しか無くなり、prod のセッション Cookie（平文がそのまま bearer credential）が
  stg のホストへも送信される。これを解消するため次の 2 つを決定した。
  1. **api を web の子サブドメインへ移す**（`api.idp.nolumia.com` / `COOKIE_DOMAIN=idp.nolumia.com`）。
     Cookie スコープが環境内に閉じる。コード変更は不要（`.env` の 3 キーと DNS・証明書のみ）。
  2. **api↔web の状態受け渡しから Cookie を外す**。`/authorize` は `auth_session_id` を Set-Cookie
     せず単回ハンドルとして URL で渡し、SSO 判定と `/logout` の Cookie 破棄は web が自ドメインで行う。
     完了後は `COOKIE_DOMAIN` 未設定（host-only）が既定になる。
- ADR-0012 の §Decision 1（ホスト名前提）・§Decision 3（サービス横断 Cookie の `Domain` 付与）は
  ADR-0018 で置き換えた。`docs/OPERATIONS.md` の別ドメイン公開手順も入れ子の例へ改めた。
- 実装は `docs/Progress.md` の T1（ホスト名入れ子）・T2（Cookie 非依存化）。

## 2026-07-27（stg/prod の公開ポート・公開ドメインを実運用値に確定した）

- **デプロイ用 `.env` テンプレートの公開ポートを実運用値へ変更した。** prod = `10000`（web）/
  `10001`（api）、stg = `10010`（web）/ `10011`（api）。同一ホストで stg/prod が衝突しない割り当て。
  Compose の組み込みフォールバック（`8060` / `8070`）と汎用 `.env.example`（ローカル開発）は不変。
- **公開オリジンを実ドメインへ設定した**（前段プロキシで TLS 終端する前提）。prod は
  `https://idp.nolumia.com`（web）/ `https://idpapi.nolumia.com`（api）、stg は
  `https://idpstg.nolumia.com` / `https://idpapistg.nolumia.com`。あわせて domain-split で必須の
  `COOKIE_DOMAIN=nolumia.com` と `COOKIE_SECURE=true` / `TRUST_FORWARDED_HEADERS=true`（prod は
  `HSTS_MAX_AGE=31536000`）をテンプレートに入れた。
- 既知のリスク（受容して運用する）: stg と prod が同じ登録可能ドメイン（`nolumia.com`）配下のため
  `COOKIE_DOMAIN` が一致し、prod のサービス横断 Cookie（平文がそのまま bearer credential）が stg の
  ホストへも送信される。当面は stg を prod と同等の信頼境界で扱う。恒久的なドメイン分離は
  `docs/Progress.md` の T1 で管理する。
- `docs/OPERATIONS.md`（stg/prod 併置表・待ち受けポート一覧）・`scripts/README.md`・`test_deploy.sh`
  の期待値を新ポートへ更新した。

## 2026-07-27（`ISSUER` を DB 管理にし、設定画面から api・web を再起動できるようにした。ADR-0017）

- **`ISSUER` を `ENV_LOCKED` → `DB_MANAGED`（`shared_with_web`）へ移した。** ディスカバリ文書の各 URL と
  ID Token の `iss` が既定の `http://localhost:8080` のまま、設定画面からは直せない状態を解消した。
  web は ADR-0013 の共有ランタイム設定経路（`GET /internal/runtime-settings`）で同じ値を受け取る。
  反映には api → web 両方の再起動が必要（未反映は既存の警告に出る）。
- **`ISSUER` の保存時検証を追加した。** 書式（スキーム＋ホストを持つ絶対 URL。資格情報・クエリ・
  フラグメント不可）は 400、**起動時 fail-fast に掛かる値**は 409 で拒否する。後者を通すと再起動で
  api・web が起動しなくなり、直す画面ごと消えるため保存の時点で止める。対象は
  「`https://` × 開発用の既定 secret」と「`COOKIE_DOMAIN` 設定時にその配下から外れる／明示された
  `PUBLIC_WEB_BASE_URL` とスキームがずれる」の両方で、判定には起動時と同じ述語・同じ関数
  （`requires_production_secrets`・`contracts::cookie_domain::validate_cookie_domain`）を使う。
  どの条件で落ちたかは運用ログへ出す。
- **設定画面から api → web を再起動できるようにした。** `POST /{tenant_id}/admin/restart`
  （api・web の双方。`idp.system.admin` 必須）と設定画面のボタンを追加した。api の受理（202）を
  確認してから web を停止する。停止するだけで、起動し直すのは配置側の再起動ポリシー
  （`restart: unless-stopped` 等）に委ねる。要求は監査ログ（`service.restart_requested`）に残る。
- 再起動中は待機画面（自動で設定画面へ戻る）を返す。共通レイアウトは継承しない（数秒間どの導線も
  つながらないため）。

## 2026-07-25（公開トポロジの既定を domain-split にし、待ち受けポートとシステム構成図を整備した。ADR-0016）

- **`PUBLISH_TOPOLOGY` の既定を `single-origin` → `domain-split` へ変更した**（ADR-0016）。
  `deploy.sh` の未設定時フォールバックと `.env*.example` の 2 か所のみの変更で、`.env` に値がある
  既存配置は挙動不変（`single-origin` を明記済みの環境はそのまま単一オリジンを維持する）。
  単一オリジンは明示指定で継続サポートする（`docker/nginx.conf`・トポロジ試験とも維持）。
- `.env*.example` は `ISSUER`（api）と `PUBLIC_WEB_BASE_URL`（web）を**別オリジンで出力**するように
  した（ローカル既定は `http://localhost:8070` / `http://localhost:8060`）。`PUBLIC_WEB_BASE_URL` は
  既定トポロジで必須になるためコメントアウトをやめた。ローカル既定では Cookie がポートを区別しない
  ため `COOKIE_DOMAIN` は不要（未設定のままで両サービスに届く）。
- `deploy.sh`: 既定変更が**稼働中の `.env` へ波及しない**ようにした（`migration_value_for`）。
  バージョン更新時の不足キー追記に `.env.example` の新既定をそのまま流すと公開先が黙って変わるため、
  `PUBLISH_TOPOLOGY` が無い `.env` には `single-origin` を追記し（本 ADR 以前の配置＝単一オリジン）、
  `PUBLIC_WEB_BASE_URL` は追記しない（未設定＝`ISSUER` フォールバック＝従来挙動）。
- README・OPERATIONS のローカル開発手順（プロキシなしで api・web をホスト実行）で
  `PUBLIC_WEB_BASE_URL=http://localhost:8081` を**両プロセスに**渡すようにした。未設定だと
  `ISSUER`（api の `:8080`）へフォールバックし、`/authorize` がログイン画面へ飛ばす先が web ではなく
  api になっていた。
- **待ち受けポートの記載を新設した。** `docs/OPERATIONS.md`「待ち受けポート一覧」に、前段プロキシ →
  ホスト公開ポート（`.env`）→ コンテナ内ポート（固定）の 3 段を表で整理し、ローカル開発時の待ち受けも
  併記した。README にも要約表を置いた。「単一オリジンで公開したいとき」の手順も追加した。
- **README のシステム構成図を現行構成へ更新した。** 単一サービス（`web` が IdP 本体）のままだった図を、
  proxy / api / web / mariadb ＋ migrate の 4 サービス構成と待ち受けポートを含む図へ差し替え、
  認可コードフローの図も api（`/authorize`・`/token`）と web（ログイン画面 → `/internal/authenticate`）の
  分担を反映した形に更新した。
- ADR-0007 §2・ADR-0012 §1・ADR-0015 §Decision 3 の「単一オリジンを既定とする」記述に ADR-0016 への
  参照を追記した。

## 2026-07-25（api/web の別ドメイン公開をデプロイ構成として実装した。ADR-0015）

- **`PUBLISH_TOPOLOGY` を新設**（`single-origin` 既定 / `domain-split`）。`domain-split` では
  `docker-compose.domain-split.yml` と `docker/nginx.domain-split.conf` を重ね、同梱プロキシが
  **リッスンポートでサービスを分ける**（`:8080` → web、`:8081` → api）。前段のリバースプロキシが
  `id.example.com` / `api.example.com` を各ポートへ振り分ける。ADR-0012 §6 の「ドメインごとの
  vhost」に代わる決定（同梱 nginx にドメイン名を持たせると前段プロキシと二重管理になるため）。
- api・web コンテナは**両構成でホストへ publish しない**ため、`/internal/*` の 404 遮断点は
  1 か所（同梱プロキシ）のままで公開面が広がらない。公開ポートは `WEB_PORT`（web）と
  新設 `API_PORT`（api）で、`WEB_PORT` の意味は両構成で変わらない（既存 `.env` はそのまま動く）。
- `deploy.sh`: トポロジに応じて override を重ね、`domain-split` では web・api **両方**の
  `/readyz` を待つようにした。未知のトポロジ値は fail-fast。
- `deploy.sh`（既存不具合の修正）: 完了時に表示する root テナント URL の基点を `ISSUER` から
  **`PUBLIC_WEB_BASE_URL`**（未設定なら `ISSUER`）へ変更した。`/{tenant}/login`・`/{tenant}/admin`
  を返すのは web のため、別ドメイン構成では api ホストの誤った URL を表示していた。
- `deploy.sh`（既存不具合の修正）: Compose 定義に無いサービスを待つ場合、120 秒のタイムアウト後に
  「healthy になりませんでした」と誤誘導していたのを、定義の欠落として即座に落とすようにした。
- アプリ（Rust）側は MT29 で実装済みのため無変更。
## 2026-07-25（API エラーの多言語化・web の言語決定順・テナント/プロフィール編集 UI。MT19 / MT20 / MT23 / MT25 / MT28）

- **API のエラーメッセージを多言語化した（MT19）。** Domain / Application は訳文を持たず
  `domain::message::MessageKey`（翻訳キー＋差し込み値）で返し、訳出は Presentation
  （`presentation::i18n::ApiMessages`）が `Accept-Language` に応じて行う。同じエラーを
  「応答では利用者の言語」「内部ログでは運用言語（英語）」の二重の要求に、文言を複製せず応える境界。
  `MessageKey` の `Display` はキーを出すため、ログは言語設定に関係なくグレップできる。
  OAuth/OIDC プロトコルエラー・500 の本文・監査ログは意図的に固定文字列のまま（RP のログ・
  自動処理が文言に依存し得るため）。ソースから `api-*` キーを抽出して両ロケールの充足を検査する
  テストを追加した。
- **web の言語決定順を完全実装し、言語切替 UI を追加した（MT20）。**
  `?lang=` → ユーザー設定 → Cookie → ブラウザ `Accept-Language` → 既定 `ja` の先勝ちで、
  ミドルウェア（`web::language`）が決定言語をリクエストの `lang` Cookie へ正規化するため、
  既存ハンドラの `locale(&headers)` は変更不要。決定言語は `Accept-Language` で api へ引き継ぎ、
  **Cookie・`lang` クエリは api へ送らない**（api がそれらを見ないための境界）。Cookie とユーザー設定
  （`users.language`）への保存は明示的な `?lang=` のときだけ行う。
- **テナント編集 UI を追加した（MT23）。** テナント一覧の各行から表示名と状態（`ACTIVE` /
  `DISABLED`）を変更できる（api の `PATCH /admin/tenants/{id}` は実装済みで画面が未接続だった）。
- **管理者による利用者プロフィール編集を追加した（MT25）。**
  `PATCH /{tenant_id}/admin/users/{user_id}/profile` と権限画面のフォームで、メール・ログイン識別子・
  表示名を変更できる。状態変更と別エンドポイントにしたのは認可の粒度が違うため（プロフィール編集は
  ロックアウトを招かないので自己編集を許す）。email は管理者がメール所有を保証する扱いで
  `email_verified` を維持し、`preferred_username` の解除はパスワードログイン不能を招くため拒否する。
  一意性の事前チェックは対象本人の行を除外する（列が大小無視の照合順序のため、大文字小文字だけを
  直す変更が誤って 409 になる）。監査には変更した**項目名のみ**記録する（値は PII のため出さない）。
- **未使用テーブル `saml_identity_providers` を削除した（MT28。マイグレーション `0015`）。**
  ADR-0004 §6 の expand/contract の contract 側。`down` は 0008 と同一定義で再作成する。
  DROP 済みテーブルが存在しないことをスキーマ整合テストで固定した。
- **管理機能のアクセス判定に ACTIVE メンバーシップの要求を追加した（`AdminAccessService`）。**
  ゲストの一時停止（`SUSPENDED`。MT24）は可逆性のため権限行を残すので、権限行だけを見る判定では
  停止が効かず、**既存の SSO セッションを持つ停止済みゲストが当該テナントの管理 API を使い続けられた**
  （SSO セッションはホスト共有のため意図的に失効させない。ADR-0009 §8）。解除に対する二重防御にもなる。

## 2026-07-25（保存済み・未反映のランタイム設定を設定画面で可視化した。MT27 / ADR-0014）

- ランタイム設定は起動時にしか読まれないため、設定画面で保存しても api・web を再起動するまで
  挙動が変わらない。その事実が画面から見えず、運用者が「保存したのに直らない」と設定値の側を
  疑い続ける状態だった。**ホットリロードは導入せず**（ADR-0014 §1。ADR-0013 の
  「web は api より新しい値を先取りしない」という不変条件と、Cookie の発行/失効で同じ属性値を
  使う前提を壊すため）、代わりに未反映を可視化する方針を採った。
- `GET /{tenant_id}/admin/system-settings` の各項目に **`pending_restart`**（保存済みだが実行中の
  api へ未反映）と **`shared_with_web`**（反映に web の再起動も要る）を追加した。
  判定は `ResolvedSetting::is_pending_restart` を単一の出所とし、**上書きの解除も未反映**に含める
  （解除しても再起動までは既定値に戻らないため）。
- 設定画面に警告バナー（未反映のキー名と api→web の再起動手順）と行ごとのバッジを追加した。
  web が起動時に受け取った共有設定と api が現在配っている共有設定を突き合わせ、
  **api だけ再起動して web を忘れた**状態も検出する（ADR-0013 が構造的には防げないと認めていた
  唯一のずれ方）。突き合わせに失敗した場合は警告を出さずに画面を描画する（補助表示のため）。

## 2026-07-25（メンバー一覧をページング付きにした。MT22）

- **`GET /{tenant_id}/admin/members` に絞り込み（`q`）・ページング（`limit` / `offset`）を追加**した。
  従来は当該テナントのメンバーシップと利用者を**全件**読み込んで web 側で絞り込んでいたため、
  テナントの規模に比例して応答が膨らみ、利用者が増えると破綻する作りだった。絞り込み・並び替え・
  ページングをすべて DB 側（`tenant_memberships` と `users` の結合 1 クエリ）で行うようにした。
- **応答の形が配列からオブジェクト（`{members, total, limit, offset}`）に変わる**破壊的変更。
  `total` は絞り込み後の総件数で、画面が「該当件数」と次ページの有無を確定できる。`limit` は api が
  実際に適用した値（既定 50・上限 200 へ丸めた後）で、呼び出し側がページ送りの刻み幅に使える。
  この API を消費するのは管理コンソール（web）だけで、api と web は同時に配置される。
- 検索語は `LIKE` のワイルドカード（`%` / `_`）をエスケープする（しないと `%` が全件一致になる）。
- 管理コンソールのメンバー一覧に該当件数の表示と前後ページのリンクを追加した。検索は web 内の
  絞り込みから api（DB）側の絞り込みに変わり、**現在のページだけでなく全件が検索対象**になった。
- 読み取り専用の経路として `TenantMemberQuery`（domain）／`MemberDirectoryService`（application）を
  追加し、メンバーシップの変更（`InvitationService`）と関心を分けた。全件取得を前提とした
  `TenantMembershipRepository::list_for_tenant` と `UserRepository::find_by_ids` は用途が無くなったため削除した。

## 2026-07-25（ゲストメンバーシップの一時停止を追加した。MT24）

- **`tenant_memberships.status` に `SUSPENDED` を追加**（マイグレーション `0014_membership_suspended`）。
  従来ゲストのアクセスを止める手段は解除（削除）だけで、解除は当該テナント scope の権限行も消すため
  戻すには招待からやり直しだった。休職・委託の中断のような一時的な措置のために、メンバーシップ行と
  権限行を残したままアクセスだけを止められるようにした。
- **`PATCH /{tenant_id}/admin/members/{user_id}`**（`status` = `SUSPENDED` / `ACTIVE`）を追加し、
  管理コンソールのメンバー一覧にゲスト行の「一時停止」「再開」を追加した。停止できるのは GUEST の
  `ACTIVE` のみ、再開できるのは `SUSPENDED` のみ（HOME は所属元そのもので、止めるとログイン先が
  無くなるため不可。アカウント無効化を使う）。
- `is_active_member`（`/authorize` のメンバーシップ判定）は `status = 'ACTIVE'` を見るため、
  値の追加だけで停止が効く（判定側の変更は不要）。
- **停止時に当該テナントで発行済みの refresh token を失効させる**（`revoke_all_for_user_in_tenant` を
  追加）。既存の refresh token は `/authorize` を通らずトークンを更新し続けられるため、失効させないと
  停止が効くのは最長で refresh token の寿命（既定 30 日）先になる。**他テナント分は失効させない**
  （ゲストの停止は 1 テナントへの措置で、所属元での利用を巻き込んではいけない）。SSO セッションも
  ホスト単位で共有されるため失効させない。
- 監査へ `tenant_membership.suspended` / `tenant_membership.resumed` を記録する。

## 2026-07-25（管理者による MFA 解除を追加した。MT21）

- **`POST /{tenant_id}/admin/users/{user_id}/mfa-reset` を追加**（`idp.tenant.admin` 必須）。
  認証アプリ（TOTP）とパスキーを登録した端末を失った利用者は、自分ではログインできないため
  MFA を解除できない。テナント管理者が代わりに解除する復旧手段を用意した。
  管理コンソールのメンバー一覧（`/admin/members`）に「MFA 解除」を追加した。
- **TOTP とパスキーは同時に外す**。片方でも残ると本人はログインできないままで、復旧手段として
  成立しないため。MFA 未設定の利用者でもエラーにせず、何を外したか（`totp_removed` /
  `passkeys_removed`）を応答で返す（管理者が「効いたのか」を確認できるようにする）。
- **解除と同時に対象利用者のセッション・トークンを失効させる**。この操作の契機は端末の紛失・盗難で
  あり、紛失した端末が生きたログイン状態を保持している可能性があるため（MFA を外すだけでは残る）。
- 対象は所属元（HOME）が要求テナントの利用者のみ、自分自身は不可（既存のライフサイクル操作と同じ
  ガード）。`user.mfa_reset` として監査に残す（外した要素の種別と件数のみ。シークレットは記録しない）。
- `WebAuthnCredentialRepository::delete_all_for_user` を追加（1 件ずつ消して消し残すと復旧が失敗する）。
- **失効に失敗したら MFA 解除は成功を返さない**（fail-closed）。他のライフサイクル操作は失効漏れを
  ログに留めるが（パスワードが変わっている・アカウントが無効という別の防御線が残るため）、MFA 解除は
  失効が唯一の防御線で、「盗まれた端末のセッションは切れた」と伝えたのに生きている取り違えを生む。
- **確認ダイアログの文言をインライン JS から `data-confirm` 属性へ移した**（管理コンソール全 7 箇所）。
  `onsubmit="return confirm('…')"` は、Askama が `'` を `&#39;` にしてもブラウザが属性値の解釈時に
  `'` へ戻すため、アポストロフィを含む文言（英語の "user's" など）でハンドラごと構文エラーになり
  **確認なしで破壊的操作が送信される**。共通スクリプト `/assets/console.js` が属性を読んで確認する。

## 2026-07-25（api/web 共有ランタイム設定を DB 管理へ移した。MT26 / ADR-0013）

- **`COOKIE_SECURE`・`HSTS_MAX_AGE`・`AUTH_SESSION_TTL_SECS` を EnvLocked → DbManaged へ変更**し、
  root 設定画面から変更できるようにした。これらは api と web の両方が消費するため、web が DB を
  読めない（ADR-0007）ことを理由に ENV 固定のまま残っていた。
- **api を共有設定の唯一の出所にした**: `GET /internal/runtime-settings`（サービストークン保護）を
  追加し、web は起動時にここから DB 上書き値を取得して `既定値 < ENV < DB` の順で解決する。
  返すのは **DB 上書き値だけ**で api の有効値ではない（`COOKIE_SECURE` の既定は各サービスが
  自分の公開オリジンのスキームから導くため。ADR-0012 §2）。secret は共有しない。
- 応答は **実行中の api の起動時スナップショット**であり `system_settings` の現在値ではない。
  毎回 DB を読むと「保存したが api を再起動していない」状態で web だけが新しい値を拾えてしまい、
  この仕組みが防ごうとしている不一致が起きる。新しい値の公開は api の再起動が担う。
- web の bootstrap（api への到達に必要な最小設定）は**共有キーをパースしない**。ENV に不正値が
  あっても DB 上書きで復旧できるようにするため。bootstrap secret の fail-fast は従来どおり先に行う。
- **設定定義に `shared_with_web` を追加**（`domain/system_setting.rs`）。「api と web の両方が消費する
  DB 管理キー」を定義側に持たせ、キー一覧が実装の複数箇所へ散らないようにした。`shared_with_web` かつ
  `EnvLocked`／secret の組み合わせはテストで禁止する。
- **取得に失敗した web は起動しない**（指数バックオフ 5 回 → fail-fast）。共有キーはずれても 500 に
  ならず「ログインが通らない」「保護が外れる」という静かな壊れ方をするため、ENV だけで起動する
  fail-soft は採らない。不正な DB 値のパース失敗も同様に起動を失敗させる。
- ADR-0010 §2 が想定していた `.env` marker への materialize は本用途では採用せず、ADR-0013 として
  判断を記録した（ホスト上のファイル書き換えを避ける）。変更の反映には **api と web 両方の再起動**が
  必要（MT27 で扱う）。

## 2026-07-25（Cookie の名前・属性組み立てを `idp-contracts` へ集約し、ログアウトの越境を E2E で固定した）

- **Cookie の契約を `idp_contracts::cookies` へ単一化した**: api（`presentation/cookies.rs`）と
  web（`cookies.rs`）に同一実装・同一テストの複製があり、さらに `api_client.rs` が
  `sso_session_id` の名前を三重に定義していた。名前・`Set-Cookie` 組み立て・`Cookie` ヘッダ解析を
  contracts へ移し、各サービスには axum アダプタ（`HeaderMap` 読み出し・ヘッダ化）だけを残した。
- **`CookiePolicy`（`Secure` + `Domain`）を導入**し、発行箇所が `secure`・`domain` を引数で持ち回る形を
  やめた。web は `WebState::set_cookies()` から `set_shared` / `expire_shared`（api も読むセッション
  Cookie）と `set_local` / `expire_local`（web だけが読む CSRF・言語・MFA チケット）をメソッド名で
  区別する。新しい発行箇所で `Domain` を渡し忘れて別ドメイン構成の SSO が壊れる型の事故を防ぐ。
- **ログアウトの Cookie 越境を E2E テストに追加**（`e2e_domain_split.rs` ケース 2）: api の
  RP-initiated Logout・web のポータルログアウトの双方で、相手ドメインに保存された SSO Cookie が
  jar から消え、再 `/authorize` がログイン画面へ戻ることを実挙動で確認する。削除 Cookie の
  `Domain` 付与漏れ（＝ログアウトしたのにログインしたまま）を検出できるようにした。
- **web の本番シークレット検証を自オリジンにも適用**（fail-fast）: `ISSUER` だけでなく
  `PUBLIC_WEB_BASE_URL` が `https://` の場合も開発用デフォルトの `INTERNAL_SERVICE_TOKEN` /
  `CSRF_SECRET` での起動を拒否する。web を https で公開しつつ `ISSUER` を内部 http URL に取り違えた
  構成で、api と共有する CSRF 鍵が既知の開発用値のまま動く（CSRF トークンを偽造できる）のを防ぐ。
- **公開ベース URL のスキームを正規化時に小文字化**した（api/web 双方）。URI のスキームは大小を
  区別しない（RFC 3986 §3.1）が、`https://` の前方一致で判定していたため `HTTPS://` 表記では
  Cookie の `Secure` 付与と上記の本番シークレット検証がすり抜けていた。ホスト・パスは
  変更しない（issuer は ID Token の `iss` と完全一致させる必要があるため）。
## 2026-07-25（RSA 署名鍵の生成が tokio ワーカースレッドを占有していたのを修正した）

- **鍵ペア生成を `spawn_blocking` で blocking プールへ退避した**（`application/key_service.rs`）:
  RSA-2048 の生成は素数探索のため CPU バウンドで実行時間の裾が長く、非同期タスク内で直接呼ぶと
  tokio のワーカースレッドを占有していた。占有されたスレッド上の他の future は生成完了まで進まないため、
  **advisory lock（`GET_LOCK`）を保持したブートストラップタスクが poll されず、待機側はプール接続を
  握ったまま滞留**する（放置された接続がサーバ側タイムアウトで切断され `got 0 bytes at EOF` になる）。
  並走数がワーカー数を超えると発生するため、並列テストで間欠的に失敗していた。本番でも起動時
  ブートストラップと 1 時間ごとのローテーションが HTTP サーバと同じランタイムで走るため、鍵生成の
  たびにワーカー 1 本がリクエスト処理から抜けていた。回帰テスト（DB 不要）を `key_service` に追加した。
- **起動時の署名鍵ブートストラップに指数バックオフ再試行を追加した**（5 回・500ms 起点）:
  `ensure_active_key` は冪等なので、排他ロック待ちのタイムアウトや一過性の接続断で
  プロセスが落ちないようにした。全試行が失敗したときのみ起動を失敗させる（fail-fast は維持）。
- **並走ブートストラップテストの予算を明示した**（`crates/api/tests/keys.rs`）: 同時実行数・接続プール枠を
  定数で関連付け、ワーカースレッドを 1 本に固定した（鍵生成がランタイムを占有しないことの回帰ガード）。

## 2026-07-25（api/web の別ドメイン（サブドメイン）公開に対応した。MT29 / ADR-0012）

- **`COOKIE_DOMAIN` を新設**（EnvLocked。api/web で同値必須）: 設定時、サービス横断 Cookie
  （`sso_session_id`・`auth_session_id`）に `Domain` 属性を付与し、同一親ドメイン配下のサブドメイン間で
  SSO Cookie を共有できるようにした。発行・削除の両方で host-only の同名削除 Cookie を併送し、
  単一オリジン構成から移行したブラウザに残る旧 Cookie を掃除する（同名二重送信によるログインループ防止）。
  未設定なら従来どおり host-only（単一オリジン構成の挙動は不変）。
- **`/authorize` のログイン・同意リダイレクトを `PUBLIC_WEB_BASE_URL` 基点の絶対 URL 化**
  （単一オリジン構成では issuer と同値のため実質不変）。
- **web に自オリジン設定 `PUBLIC_WEB_BASE_URL` を追加**し、Cookie `Secure` 判定を `ISSUER` から
  自オリジンのスキームへ変更。api 側 `PUBLIC_WEB_BASE_URL` は DbManaged → **EnvLocked へ変更**
  （api/web で同値必須のため。DB 上書き運用からの移行手順は OPERATIONS.md）。
- **起動時検証（fail-fast）**: `COOKIE_DOMAIN` が `ISSUER`・`PUBLIC_WEB_BASE_URL` 双方の親ドメインで
  あること、public suffix（eTLD）そのものでないこと（Public Suffix List 判定）を api/web 共通の
  検証（`idp_contracts::cookie_domain`）で確認する。
- **web→api E2E テストを新設**（`crates/api/tests/e2e_domain_split.rs`）: api/web を実サーバとして
  同時起動し、Cookie jar 有効のクライアントで authorize→login→SSO Cookie 越境→即時 code 発行を
  実挙動で検証（別ドメイン・単一オリジン両構成＋host-only 残留掃除）。

## 2026-07-24（存在しないテナントの管理コンソール URL が 502 になっていたのを 404 にした）

- **web が api の whoami 404 を 502 に化けさせていたのを修正した**: `/{tenant_id}/admin` 系の画面は
  `resolve_admin` が api の `GET /{tenant_id}/admin/whoami` へ SSO を転送して保護しているが、200/401/403 以外を
  一律 `AdminSession::Error` → **502 Bad Gateway** に倒していた。api の `resolve_tenant` は未知・`DISABLED`・
  UUID 不正のテナントをすべて 404 に倒す（web 側は UUID 形式しか検証しない）ため、**存在しないテナントの
  管理コンソール URL を開くとゲートウェイ障害に見え、原因の切り分けを誤らせていた**。`AdminSession::NotFound`
  を追加し、404 は共通エラーページの 404 として返す。502 は api への到達失敗・想定外ステータス（500/503 等）
  本来の意味に限定した。

## 2026-07-24（web の全エラー応答（4xx/5xx）を共通エラーページに揃えた）

- **HTTP エラーページを追加し、エラー応答の HTML 化を 1 箇所へ集約した**: ステータスコードを大きく表示して
  タイトルと説明文を添える共通テンプレート（`error_page.html` / `ErrorPage`）を新設し、描画の入口を
  `crate::error_pages` に集約した。従来 web のエラー応答は、ハンドラが `StatusCode::X.into_response()` や
  `Html(String::new())` で本文なしに返す経路（46 箇所）、axum の extractor 拒否（`Form` デシリアライズ失敗で
  「Failed to deserialize form body: …」という内部詳細がプレーンテキストで露出）、未マッチ経路の 404、
  メソッド不一致の 405 が、いずれも白紙・生テキストのままブラウザへ渡っていた。ハンドラを 1 箇所ずつ
  書き換える方式は新しいエラー経路が増えたときに漏れるため、**ルーティングの外側に置くミドルウェア
  （`error_pages::render_error_pages`）で一括して差し替える**方式にした。差し替えるのは「本文が空」または
  「本文が `text/plain`」のときだけで、ハンドラが文脈に応じて描画した HTML（管理コンソールの権限不足バナー・
  戻るリンク付き告知など）は尊重して素通しする。副次的に extractor 拒否の内部詳細も露出しなくなった。
- **全ステータスコードに対応した**: 文言は `error-<code>-title` / `-message` を引き、IANA 登録済みの 4xx/5xx
  （418 を除く 39 コード）に専用文言を ja/en で用意した。専用文言を持たないコード（標準外の 499 等）は
  クラス既定（`error-4xx-*` / `error-5xx-*`）へフォールバックするため、翻訳キーがそのまま画面に出ることはない。
  宣言した全コードが ja/en 双方で実際に翻訳されていることはテストで検証する。
- JSON を送るブラウザ JS 経路（passkey の登録・認証 API）と `HEAD` は対象外とし、HTML を混ぜない。

## 2026-07-24（migrate チェックサム不一致の案内を「初期化が必要」と明示し埋もれさせないようにした）

- **チェックサム不一致時の対処案内を、結論（DB の初期化が必要）先頭・具体コマンド付きにし、最後に表示するようにした**:
  fail-fast 化はしていたが、案内の直後に MariaDB のコンテナログ（`compose_diagnostics_for`、原因と無関係な
  「Aborted connection …」の羅列）を出していたため、肝心の対処が画面上部へ流れ、operator には最終行の
  「チェックサム不一致」しか見えず「何をすればよいか分からない」状態だった。チェックサム不一致の分岐では
  MariaDB コンテナログを出さず、案内を最後に表示する。案内は「▶ 必要な操作: DB の初期化（再作成）が必要です」を
  先頭に置き、バックアップ（`mariadb-dump` 1 行）と `./deploy.sh reset` の具体コマンドを併記する。`scripts/test_deploy.sh`
  に「初期化の明示」「MariaDB ログで埋もれないこと」の検証を追加。

## 2026-07-24（migrate のチェックサム不一致を fail-fast で明示するようにした）

- **適用済みマイグレーションのチェックサム不一致を検出し、リトライせず対処を提示するようにした**: 既存 DB へ
  適用済みのマイグレーションファイルを後から改訂すると（例: root テナント UUID の固定化＝ADR-0011。`0002` の
  チェックサムが変わる）、`sqlx migrate run` は「migration N was previously applied but has been modified」で
  決定論的に失敗する。従来の `deploy.sh` はこれを一過性の失敗と同様に 3 回リトライして時間を浪費し、最終的に
  「DB migration failed after 3 attempts」としか表示しなかった。MariaDB 側には失敗した migrate プロセスが接続を
  切ったときの「Aborted connection … Got an error reading communication packets」という一見無関係な警告だけが
  残り、真因が埋もれていた。`run_migrations_with_retry` が migrate の出力を検査してチェックサム不一致を判別し、
  リトライせず即停止した上で、原因（適用済みファイルの改変 / イメージと DB 履歴の食い違い）と対処
  （意図的な改訂なら `./deploy.sh reset`、非意図なら該当ファイルを元へ戻す、データ保持なら追記型の新規
  マイグレーション）を案内するようにした。あわせて migrate 出力を `mask_secrets` 経由で表示するようにし、
  接続エラー時に DATABASE_URL 等の機微値が deploy ログへ漏れないようにした。挙動は `scripts/test_deploy.sh` で検証。

## 2026-07-24（管理コンソールの一覧テーブルをモバイルでカード表示にした）

- **一覧テーブルを狭い画面（<768px）でカード表示に変形するようにした**: 管理コンソールの一覧
  （clients / members / tenants / audit-logs / signing-keys / users-permissions / saml-clients /
  admin-settings runtime / client-status の 9 画面）は横スクロール前提の表で、モバイルでは見づらかった。
  各テーブルに `.table-cards` クラスを付け、CSS メディアクエリ（`app.css`）で見出し行を隠して
  「1 行＝1 カード（項目名＋値の縦積み）」へ組み替える。PC（>=768px）は従来どおりの表のまま。
  項目名は各データセルの `data-label` に列見出しと同じ翻訳（`messages.get(...)`）を流用し、翻訳の二重
  管理を避けた。マークアップは 1 系統のまま（表とカードの二重描画はしない）で、DTO・ハンドラ・翻訳
  リソースは変更なし。

## 2026-07-24（SP メタデータをファイル選択した瞬間に取り込むようにした）

- **SAML SP メタデータのファイル選択で自動取り込みするようにした**: 管理コンソールの SP 追加画面で、
  メタデータ XML ファイルを選んでも別途「取り込み」ボタンを押すまで何も起きず「反応しない」ように見えていた。
  ファイル選択（`change`）でその場で取り込みフォームを送信するようにし、選んだ直後に登録フォームへ値が
  反映されるようにした。JS 無効環境では従来どおりボタン送信にフォールバックする。ファイル読み取り
  （multipart）・パーサ自体は正常で、UX 上の導線のみの修正。

## 2026-07-24（root テナントの UUID を固定値にした）

- **root テナントの UUID を固定値 `00000000-0000-7000-8000-000000000001` にした**: 従来 seed が動的採番して
  いたため DB を再初期化するたびに変わり、管理者ログイン URL `/{root}/...` も変わっていた。seed（`0002`）で
  固定リテラルを投入するよう変更し、全環境共通・git 管理とした。root は引き続き `parent_tenant_id IS NULL` の
  唯一行として構造的に識別する（テーブル分割はしない）。設計判断と固定値を秘密にしない理由は ADR-0011。
  既存 DB へ反映するには再初期化が必要（`0002` のチェックサムが変わる。ADR-0009 §11 同様の一度限りの seed 改訂）。

## 2026-07-23（build-remote-container.sh がプロジェクト名をディレクトリから自動取得）

- **プロジェクト名をデプロイ先ディレクトリの親から自動取得するようにした**: ディレクトリ構成
  `/<プロジェクト名>/<環境>`（例 `/volume1/docker/idp/prod`）を前提に、環境（ディレクトリ名）に加えて
  **プロジェクト名を親ディレクトリ名から導出**する（`{PROJECT}` の展開元）。優先順位は
  `IDP_PROJECT` > 設定ファイル `PROJECT` > 親ディレクトリ名 > 既定 `idp`。この構成に従えば `PROJECT` の
  指定は不要になり、`build-remote-container.env` のサンプルからも `PROJECT` 行をコメントアウトした。
  親が取得できない退化ケース（`/prod` 等）は既定 `idp` に安全にフォールバックする。起動ログの
  `PROJECT` 行に出所（環境変数／設定ファイル／ディレクトリ／既定）を併記する。

## 2026-07-23（build-remote-container.sh の起動ログを読みやすく）

- **起動時に配置環境（stg/prod 等）とモードを見やすく表示するようにした**: START ヘッダを罫線で囲み、
  ターゲットディレクトリ名から分類した**環境（`stg`/`prod`/その他はディレクトリ名）とモード（`app`/`migrate`/`reset`）**を
  冒頭で明示する。ログ接頭辞を `[idp:build-remote-container]` から **`[idp:container]`** へ短縮して読みやすくした
  （git 版 `[idp:build-remote]` と区別）。環境分類は初回の既定イメージタグ決定ロジックと共通化した（重複排除）。

## 2026-07-23（build-remote-container.sh の自己更新）

- **`build-remote-container.sh` が古ければ実行のたびに最新版へ自動更新するようにした**: このスクリプトは
  `dist/` に含まれない手置きブートストラップのため `git pull` では更新されず、機能追加（例:
  `build-remote-container.env` の読み込み）が反映されないまま `IDP_DIST_DIR` 未設定エラーで停止する事故があった。
  BUILD ステップを SYNC（`git pull` のみ）→ SELF-UPDATE → BUILD（`build.sh`）へ分割し、SYNC 直後に dev
  コンテナ内の最新 `build-remote-container.sh` と byte 比較して、異なれば最新版へ自分自身を差し替え同じ引数で
  自動再実行する（同一ディレクトリ内 rename でアトミック差し替え、`IDP_SELF_UPDATED` で再実行 1 回に限定）。
  `build-remote-container.env`（サイト固有設定）は対象外。自動更新が働くのは既に self-update 対応版が
  置かれている場合で、未対応の古い版は一度だけ手動差し替えが必要（以後は自動）。

## 2026-07-23（アセット URL のキャッシュバスティング）

- **アセット URL に `?v={バージョン}` を付与し、デプロイ後も旧 CSS/JS が配られる問題を修正**: `app.css` 等は
  安定 URL で配信していたため、中間キャッシュ（Cloudflare が origin の `max-age=0` を上書きして 4 時間キャッシュ）と
  ブラウザキャッシュにより、デプロイしても旧アセットが配られ続けていた（例: テナント一覧の ID 折り返し修正が
  ステージングで反映されない）。テンプレートのアセット参照すべてにビルド時埋め込みバージョン
  （`crate::templates::asset_version()` = パッケージ版-git 版）のクエリを付け、デプロイごとに URL 自体を変える
  ことで TTL に依存せず確実に更新を配る。バージョン値には同梱アセットの内容ダイジェスト（FNV-1a）を必ず含め、
  git バージョンが注入されないビルド経路（`IDP_GIT_VERSION` 未指定の docker-compose ビルド）でもアセットが
  変われば URL が変わるようにした。バージョン付き URL で参照する CSS/JS は `max-age=31536000, immutable`、
  クエリを付けられない webfont（FA CSS 内の相対参照）・source map は `max-age=86400` とした。

## 2026-07-23（管理コンソール: 表示名の表示・変更、テナント切り替え、テナント一覧の折り返し修正、deploy 末尾に root URL）

- **ヘッダに表示名を出す**: 管理コンソール右上（モバイルでは左上）のユーザーメニューが内部 ID（UUID）ではなく
  表示名を出すようにした。`GET /admin/whoami` が `name`／`preferred_username` を返すよう拡張し、web は
  「表示名 → ログイン識別子 → 内部 ID」の順で空でない最初の値を採用する。SSO セッション解決時に読み込む
  ユーザー行から取得するため追加クエリは発生しない（`AuthorizedAdmin` に `name`／`preferred_username` を追加）。
- **プロフィール設定に表示名の変更を追加**: 利用者のセルフサービス設定画面（`/{tenant_id}/settings`）に表示名
  （`users.name`）の編集フォームを追加。空・空白のみは解除（`NULL`）に正規化する。内部 API
  `POST /internal/account/profile`（取得）・`POST /internal/account/update-name`（更新）と
  `AccountProfileService`・`UserRepository::update_name` を追加。
- **テナント切り替え機能を追加**: ユーザーメニューに「テナントを切り替え」を追加し、`ACTIVE` なメンバーシップを
  持つテナントの管理コンソールへ遷移できる画面（`GET /{tenant_id}/admin/switch-tenant`）を新設。SSO はホスト共有の
  ため再ログインは不要（ADR-0009 §8）。内部 API `POST /internal/account/tenants`・`AccountTenantsService`・
  `TenantMembershipRepository::list_active_for_user` を追加。
- **管理コンソールのホーム表示の重複を解消**: ホーム見出し横のテナント名バッジと「現在のテナント: 〜」の二重表示を
  1 箇所（「現在のテナント」行のバッジ）に統一。
- **テナント一覧の折り返し崩れを修正**: 表セル内の識別子（`<code>`）が既定の `word-break: break-all` により
  狭い画面で 1 文字ずつ縦積みになり ID 列が崩れていたのを、表内では折り返さず `.table-responsive` の横スクロールへ
  逃がすよう修正（`.table-responsive td code`）。
- **deploy.sh の末尾に root テナント URL を表示**: デプロイ完了時のまとめとして root テナントの管理コンソール URL・
  ログイン URL を最後に出力するようにした。

## 2026-07-23（バージョン情報画面に DB マイグレーション適用状態を表示）

- **バージョン情報画面（`/version`）に DB スキーマの適用状態を追加**: DB を直接参照できない運用者が、
  適用済みマイグレーション version を画面から確認できるようにした。「適用済みバージョン」（`_sqlx_migrations`
  の最大 version）・「期待バージョン」（稼働中 api に埋め込まれた最大 version）・両者の一致状態を表示する。
  web は DB 非依存のため、api の新規エンドポイント `GET /version/schema`（`{expected, db_readable, applied}` を
  返す。認証不要）から取得する。状態は「最新／DB が遅れています（migrate 未適用）／DB 読み取り不可（運用障害）」を
  区別し（DB 読み取り失敗を「遅れ」と誤表示しないよう `db_readable` で区別し、api はエラーをログに残す）、api 未到達時は
  フェイルソフトで「取得できません（api 未起動の可能性）」を表示。`db.rs` は `embedded_schema_version()`／
  `applied_schema_version()` を切り出し、`verify_schema_version` も同関数を再利用。contracts に `SchemaVersionInfo` を追加。
  なお api は DB が期待 version 未満だと fail-fast で起動を中止する（ADR-0004）ため、遅れている状態では本画面自体が
  配信されないことがある（その場合は api ログの `expected`/`applied` で確認）。

## 2026-07-23（初期管理者のログイン識別子を admin@example.com に統一 + ログイン欄の表記修正 + ルート `/` のリダイレクト廃止）

- **初期管理者のログイン識別子（ユーザー名）を `admin@example.com` に変更**: ログインは email ではなく
  `preferred_username` で照合する（ADR-0009 §8）ため、seed 既定のユーザー名 `admin`（0002）のままの root 管理者行だけを
  `admin@example.com` へ更新するマイグレーション（0013。運用者が別名へ変更した行は上書きしない。追記型で 0002 は
  書き換えない）を追加。これで初期案内どおり「ユーザー名＝`admin@example.com` / パスワード＝`admin@example.com`」で
  ログインできる。
- **ログイン欄の表記を修正**: ログイン識別子欄のラベルを「ユーザー名またはメールアドレス／Username or email」から
  「ユーザー名／Username」へ修正（実装は `preferred_username` 照合のみでメール照合はしないため。i18n `login-username` を更新）。
- **ルート `/` のリダイレクトを廃止（root 露出の抑止）**: 素のドメインアクセスで `/{root_tenant_id}/admin/login` へ
  リダイレクトしていた挙動を廃止。root テナントの UUID と管理ログイン画面を露出させないため、特定テナントに触れない
  汎用の案内ページ（404）を返すよう変更した。これに伴い web の `ROOT_TENANT_ID` 設定・deploy.sh の自動反映・
  docker-compose の受け渡しを撤去（i18n `root-landing-*` を追加）。

## 2026-07-23（テナント作成を「作成者ブートストラップ」方式に変更 + メンバー一覧に絞り込みを追加・利用者検索画面を廃止）

- **テナント作成フローを変更（ADR-0009 §5）**: 従来の「初期管理者メールから管理者ユーザーを自動生成し、
  自動生成パスワードを一度だけ返す」方式を廃止。テナント作成時は**作成者自身**を新テナントのブートストラップ
  管理者として登録する（ACTIVE な GUEST メンバーシップ＋新テナント scope の `idp.tenant.admin`）。作成者は自身の
  SSO セッションのまま新テナントで正式な管理者（HOME 利用者）を作成・付与し、最後に自身のゲストメンバーシップを
  解除して離脱する。作成 API（`POST /{tenant_id}/admin/tenants`）の入力は `name` のみ、応答は作成したテナント
  （`admin_email`・`generated_password`・`admin_user_id` は廃止）。`TenantProvisioningRepository::provision` は
  ユーザー作成を伴わない 3 INSERT（テナント・メンバーシップ・付与）に変更。ブートストラップ中に限り作成者が
  新テナント内部を操作できる点が従来の「作成者は一切操作できない」からの緩和（離脱は運用者の責務）。
- **メンバー一覧に絞り込み（検索）を追加**: `/{tenant_id}/admin/members` にメール・氏名の部分一致（大文字小文字
  無視）で絞り込む検索ボックスを追加（api は全件返し、絞り込みは web 側で実施。api 変更なし）。
- **利用者検索画面を廃止**: 管理コンソールの「利用者を検索」画面（`GET /{tenant_id}/admin/users`）とサイドバー導線を
  削除。利用者一覧・検索の起点はメンバー画面に一本化した（利用者作成・権限画面は従来どおり）。api の
  `GET /admin/users?q=`（検索エンドポイント）は分離テストで使用のため残置。

## 2026-07-23（root テナントの既定表示名を ROOT に + 管理コンソールで現在テナント名を表示）

- **root テナントの既定表示名を `Root` → `ROOT` に変更**: seed（0002）の既定名 `Root` のままの root 行だけを
  `ROOT` へ更新するマイグレーション（0012。運用者が別名へ変更した行は上書きしない。追記型で 0002 は書き換えない）を追加。
- **管理コンソールに現在のテナント名を表示**: ホーム画面（`/{tenant_id}/admin`）の見出しに現在テナント名（root は `ROOT`）を
  バッジ表示する。名前は api の `GET /admin/settings/tenant` から取得し、取得失敗時は名前だけ省いて描画する（フェイルソフト）。
  i18n（ja/en）に `admin-home-current-tenant` を追加。

## 2026-07-23（権限一覧資料 `docs/PERMISSIONS.md` を追加）

- **権限一覧のリファレンスを追加**: 利用者権限コード（`idp.system.admin`＝全体管理者／`idp.tenant.admin`＝
  テナント管理者）と scope・判定ルール・エンドポイント別の要求権限を `docs/PERMISSIONS.md` に一枚化した。
  出所は既存の ADR-0006／ADR-0009 §4・`permission.rs`・`admin.rs`（重複記述はせずリンクで参照）。
  `OPERATIONS.md` の権限付与手順から本資料へリンクを追加。

## 2026-07-23（SAML SP の変更・削除を追加 + 設定値の優先順位を「既定値 < ENV < DB」へ + 設定用途の説明を追加）

- **SAML SP（クライアント）の変更・削除を追加**: 従来は登録・一覧のみだった SAML サービスプロバイダ管理に
  更新（`PUT /{tenant_id}/admin/saml-service-providers/{id}`）と削除（`DELETE …/{id}`。成功時 204）を追加。
  domain（`SamlServiceProvider::apply` による検証付き変更）・repository trait（`find_by_id`／`update`／`delete`）・
  sqlx 実装・application（`update`／`delete`、`NotFound` エラー）・contracts（`SamlServiceProviderUpdateRequest`、
  応答へ `x509_certificate` 追加）・api ハンドラ／ルータ・web（api クライアント・コンソールの行内編集フォーム／
  削除ボタン・ルータ）・i18n（ja/en）を一気通貫で追加。テナント境界内の id のみ操作でき、他テナントの id は 404。
- **設定値の優先順位を「組み込み既定値 < 環境変数（ENV）< DB（system_settings）」へ修正**: 「あとから DB で
  上書きできる」思想に合わせ、`DbManaged` のキーは DB 値が ENV を上書きするようにした（ADR-0010 の decision に整合。
  従来コメントと実装は `ENV > DB` だった）。DB を読む前や DB 内 secret 復号に必要な bootstrap 系・api/web で値を
  一致させたいキーは従来どおり `EnvLocked`（DB を参照せず ENV > 既定値）。`config.rs`・`system_setting.rs`・
  `CLAUDE.md`・設定画面の注記（env-locked-note）を更新。
- **各設定が何に使われるかの説明を追加**: `SettingDefinition` に `description` を追加し、全ランタイム設定キーへ
  用途の一文を付与。`ResolvedSetting` → `RuntimeSettingResponse` → web `RuntimeSettingView` → 設定画面へ透過し、
  ランタイム設定表のキー欄に説明を表示する。

## 2026-07-23（ログイン識別子を preferred_username に確定 + 未指定時は email を既定値化）

- **ログイン識別子を `preferred_username` に確定（ADR-0009 §8）**: 同日先行の「メールアドレスのみ統一」
  （下記エントリ）を反転し、ログイン照合を `find_by_username`（`preferred_username`）に戻した。メール
  アドレスでのログイン（`find_by_email`）は行わない。3 経路（OIDC・ポータル・管理コンソール）の資格情報
  フィールドを `email`→`username` に戻し、ログイン画面テンプレート・i18n（`login-username`）・契約 DTO・
  core コマンド・e2e・統合テストを更新。ポータル初回強制変更の共有画面（`ForcedPasswordChange`）と
  MFA/メール検証ゲートはそのまま維持し、識別子フィールドのみ `username` に揃えた。
- **`preferred_username` 未指定時は `email` を既定値化**: 自己登録（`register`）・管理者作成
  （`user_management`）で `preferred_username` が未指定なら `email` と同値を採用する。採用値は
  `domain::values::validate_preferred_username` でカラム長（`VARCHAR(255)`）超過を永続化前に検証する
  （`email` は `VARCHAR(320)` のため既定値化で超え得る）。既存ユーザー向けに `preferred_username IS NULL`
  を `email` で埋める backfill マイグレーション（`0011_backfill_preferred_username`）を追加。email が別
  ユーザーの `preferred_username` と衝突する行はスキップして UNIQUE 違反によるマイグレーション中断を防ぐ
  （LEFT JOIN + IS NULL。衝突行は NULL のまま残し運用で個別解消）。

## 2026-07-23（ログイン識別子をメールアドレスに統一 + ポータル初回ログインの強制変更誘導を統合）

- **ログインをメールアドレスのみに統一（ADR-0009 §8）**: OIDC ログイン・ポータル（一般）ログイン・
  管理コンソールログインの 3 経路の資格情報フィールドを `username`→`email` にリネームし、利用者検索を
  `find_by_email` 限定にした（従来は「username で検索 → 見つからなければ `@` を含むとき email」の二段構え）。
  `preferred_username` は OIDC `profile` クレーム（任意・NULL 可・テナント内一意の表示ハンドル）としての
  役割に限定し、ログイン識別子には使わない。契約 DTO（`InternalAuthenticateRequest` 等）・core コマンド・
  web フォーム（`LoginForm`）・ログイン画面テンプレート（`type="email"`・`autocomplete="email"`）・
  i18n（`login-email`・エラー文言）を更新。
- **ポータル（一般）ログインの初回強制パスワード変更を admin と統合（ADR-0009 §5）**: 従来ポータル経路のみ
  `must_change_password` を検出しても案内メッセージを出して 403 で拒否するだけで変更手段が無かった不整合を、
  管理コンソールと**同じ強制変更画面を流用**して解消した。web フォーム DTO（`ForcedPasswordChangeForm`）と
  テンプレート（`password_change_forced.html` / `ForcedPasswordChange`。送信先を `action` で切替）を admin と
  共有化（`console/password_change.html` を統合）。core は `PortalLoginService::change_password`（admin と同方式・
  admin 権限は不要）、api は `POST /internal/authenticate/portal/change-password`、web は
  `POST /{tenant_id}/login/password-change` を新設。

## 2026-07-22（設定/デプロイ: .env の CHANGE-ME プレースホルダ残りを fail-fast で明示）

- **crates/core・crates/web — `KEY_ENCRYPTION_KEY`・`CSRF_SECRET` のプレースホルダ検出**: `.env.*.example` を
  手動コピーして `CHANGE-ME` を置換し忘れると、api は `KEY_ENCRYPTION_KEY must be base64: Invalid symbol 45,
  offset 6` という素の base64 エラーで crash-loop し原因に辿り着けなかった（staging で実際に発生。`-` が
  offset 6 = `CHANGE-ME` そのもの）。base64 復号の前に `CHANGE-ME` を検出し、「テンプレートのプレースホルダの
  まま」という原因と対処（`openssl rand -base64 32`）を明示するエラーへ変更。通常の base64 エラーにも生成
  コマンドのヒントを追記（core は `decode_secret_32` へ共通化、web の `CSRF_SECRET` も同様）。
- **scripts/deploy.sh — 既存 .env のプレースホルダ検査**: 秘密キー（`MARIADB_PASSWORD`・`KEY_ENCRYPTION_KEY`・
  `INTERNAL_SERVICE_TOKEN`・`CSRF_SECRET`・`DATABASE_URL` 等）に `CHANGE-ME` が残っていたら、コンテナ起動前に
  該当キー名と生成コマンドを提示して停止する（`ensure_no_placeholder_secrets`）。`test_deploy.sh` にケース追加。

## 2026-07-22（デプロイ: DB 認証プリフライトで既存 volume とのパスワード不一致を fail-fast）

- **scripts/deploy.sh — MariaDB 起動後・migration 前にアプリ用ユーザーの認証を検証**: MariaDB 公式
  イメージは data volume を初回作成時の `MARIADB_PASSWORD` で固定し、その後の `.env` 変更を既存 volume の
  `idp` ユーザーへ反映しない。この不一致（例: `.env` 再生成・汎用→staging テンプレート切替）は healthcheck
  （root/socket でサーバ稼働のみ確認）では検出できず、`migrate` が「Access denied for user 'idp'」で不可解に
  3 回リトライして失敗していた。`start_database` に `preflight_db_auth` を追加し、migration の前にアプリ用
  ユーザーの認証可否を確認する。資格情報は Compose と同じ解決順（エクスポート済みシェル環境変数 > `.env`
  ファイル値）で読み、migrate と同じ TCP 経路（`-h mariadb`＝コンテナ IP から接続し `'%'` ホスト定義に
  マッチ）で試す。認証失敗（パスワード drift）のときだけ原因と対処（`./deploy.sh reset` で volume 再作成、
  または `.env` のパスワードを volume 作成時の値へ戻す）を明示して即断し、認証以外（DB 不在・権限・一時的な
  ネットワーク障害等）は破壊的 reset を勧めず汎用の接続/クエリ失敗として報告する（一過性のみ短く再試行）。
  診断出力の秘密マスクは既存経路を踏襲。`test_deploy.sh` に認証失敗・認証以外失敗の両ケース（fail-fast・
  migrate 未実行・秘密マスク・reset 提案の出し分け）を追加。

## 2026-07-22（SAML: SP 登録メタデータのファイルアップロード対応）

- **crates/web — SP（クライアント）登録のメタデータ取り込みをファイルアップロードにも対応**: 管理コンソール
  （`/{tenant_id}/admin/saml-clients`）の取り込みフォームを `multipart/form-data` にし、`.xml` ファイルの
  アップロード（`metadata_file`）を追加。従来の貼り付け（`metadata_xml`）も維持し、両方あればファイルを優先する。
  ハンドラは multipart を読み、UTF-8・サイズ上限（1 MiB）を検証してから既存の取り込み API へ委譲する。
  axum の `multipart` feature を web crate に追加。i18n（en/ja）にファイル項目のラベル・ヒントを追加。

## 2026-07-22（デプロイ: ディレクトリ名で stg/prod の .env を初回自動選択）

- **scripts — 初回 `.env` 生成をデプロイディレクトリ名から判定**: デプロイ先ディレクトリ名が `stg`/`staging`/
  `*-stg`（または `prod`/`production`/`*-prod`）のとき、`deploy.sh` は初回 `.env` を汎用 `.env.example` ではなく
  `.env.staging.example` / `.env.production.example` から生成し、秘密（`CHANGE-ME`）を乱数化する。DB URL の
  host:port（stg=3307/prod=3306）はテンプレートを保持し `CHANGE-ME` のみ置換。`build-remote-container.sh` も
  同規則で初回ビルドタグ（`stg`/`prod`）を決め、「`latest` でビルド → `.env` は stg を要求 → イメージ不一致」を防ぐ。
  該当しない名前は従来どおり汎用 `.env.example`（8060/latest）へフォールバック。`test_deploy.sh` に stg 選択の
  ケースを追加。

## 2026-07-22（SAML: IdP メタデータの Content-Type を application/xml に変更）

- **crates/api — `GET /{tenant_id}/saml/metadata` の Content-Type を `application/samlmetadata+xml`
  から `application/xml; charset=utf-8` に変更**（`Content-Disposition: attachment` は維持）。
  ほぼ未登録の `application/samlmetadata+xml` では Android の DownloadManager が保存ファイルの MIME を
  焼き付け、開けるアプリが無く「テキストとして認識されない／開けない」状態になっていた。生成 XML 自体は
  整形式で不変（変更は Content-Type ヘッダのみ）。
- **scripts/README.md — 基準ディレクトリ解決の説明を修正**: 「どのディレクトリから実行しても動く」が
  stg/prod の取り違え（`cd stg` しても本番 `.env` が使われる）を招いていた。基準は `$PWD` ではなく
  スクリプト実体の置き場所（または `IDP_TARGET_DIR`）で決まる旨と、stg/prod を同一ホストで分ける手順を明記。

## 2026-07-22（SAML: 外部 IdP 連携（本製品を SP とする機能）を廃止）

- **crates/core・api・web — 外部 SAML IdP 連携を削除**: 本プロダクトは IdP であり、他 IdP に依存
  （identity brokering）しない方針とした。本製品が SP として外部 IdP でログインする機能一式
  （`/admin/saml`「SAML 連携アプリ」・`SamlProviderManagementService`・`parse_idp_metadata` 等）を削除した。
  破壊的 DDL は expand/contract で分割する（ADR-0004 §6）ため、`saml_identity_providers` テーブル自体は
  未使用のまま残置し、DROP は旧アプリが完全にいなくなった後続リリース（contract フェーズ。Progress MT28）で
  行う。SP（クライアント）登録（`/admin/saml-clients`）と IdP メタデータ出力（`/saml/metadata`）は維持する。

## 2026-07-22（SAML: IdP メタデータ出力と SP（クライアント）登録）

- **crates/core・api・web — SAML メタデータ出力を SP → IdP メタデータへ修正**: 本プロダクトは IdP のため、
  `GET /{tenant_id}/saml/metadata` は `SPSSODescriptor` ではなく `IDPSSODescriptor` を返すべきだった。
  `EntityDescriptor`（`IDPSSODescriptor`）を生成する `build_idp_metadata_xml` に置き換え、SSO
  エンドポイント（`{issuer}/saml/sso`）と ACTIVE 署名鍵を `KeyDescriptor` に含める。署名鍵は RS256 を
  `RSAKeyValue`、ES256 を `ECKeyValue`（XMLDSIG11）で埋め込む（JWKS の `n`/`e`・`x`/`y` を変換）。
- **crates/core・api・web — SAML SP（クライアント）登録機能を追加**: 本 IdP を信頼する SP をテナント単位で
  登録する。ドメイン `saml_service_provider`＋マイグレーション `saml_service_providers`（entity_id・
  acs_url・name_id_format・任意の証明書）、`parse_sp_metadata`（`SPSSODescriptor` から entity_id・
  ACS URL（HTTP-POST 優先）・証明書・NameID を抽出）、管理 API `/admin/saml-service-providers`（一覧・
  登録・メタデータ取り込み）、管理コンソール `/admin/saml-clients`（SP メタデータ貼り付けで登録フォーム
  初期化・IdP メタデータのダウンロード導線）を追加。
- 認証フロー（アサーション送受信・ACS・SSO・署名検証）は本変更の対象外（メタデータ出力・取り込みと
  SP 登録のみ）。外部 IdP 連携（`/admin/saml`。本プロダクトが SP として外部 IdP でログインする既存機能）は
  従来どおり別機能として残す。

## 2026-07-22（デプロイ: 一ホスト方式 build-remote.sh を追加）

- **scripts — `build-remote.sh` を追加**: デプロイ先で git 取得 → 自己更新 → `build.sh` →
  `deploy.sh` を 1 本で実行する一ホスト方式。デプロイ先に置くのは最初にこのスクリプト 1 本だけでよく、
  ソースは git から取得するため `dist/` の転送が不要になる。実行のたびにリポジトリ上の
  `build-remote.sh` と自分を比較し、不一致なら自身を上書きして再実行する（自己更新）。取得元・
  ブランチ・取得先は `IDP_REPO_URL` / `IDP_BRANCH` / `IDP_SRC_DIR` で変更できる。従来の二ホスト方式
  （`build.sh` → `dist/` 転送 → `deploy.sh`）はそのまま利用できる。
- **CI — `scripts/test_build_remote.sh` を追加**: 実物の git（ローカル origin を clone）と
  スタブ化した `build.sh` / `deploy.sh` / `docker` で、取得・自己更新・モード委譲・再実行ループ非発生を検証する。

## 2026-07-22（デプロイ: 既定の外部公開ポートを stg 8061 / prod 8060 に統一）

- **env サンプル・OPERATIONS — 同一ホスト運用の既定 WEB_PORT を整理**: staging の外部公開ポートを
  `8081` から `8061` に変更し（`.env.staging.example` の `ISSUER`／`PUBLIC_WEB_BASE_URL`／`WEB_PORT`）、
  production は従来どおり `8060`。`docs/OPERATIONS.md` の stg/prod デプロイ表も stg `8061` / prod `8060` に
  そろえた（コンテナ内ポートは常に `8080` のまま。外部公開ポートのみ変更）。

## 2026-07-22（SAML: SP メタデータ出力・外部 IdP メタデータ取り込み）

- **crates/core — SAML メタデータの解析・生成を追加**: ドメイン `domain::saml_metadata` に、外部 IdP の
  `EntityDescriptor`（`IDPSSODescriptor`）から `entity_id`／`sso_url`（HTTP-Redirect 優先）／署名証明書を
  抽出する `parse_idp_metadata` と、本 IdP を SAML SP として記述する `EntityDescriptor`（`SPSSODescriptor`）を
  生成する `build_sp_metadata_xml` を実装した（`quick-xml`。名前空間接頭辞非依存・属性値は自動エスケープ）。
- **crates/api — SP メタデータ出力と IdP メタデータ取り込みエンドポイントを追加**: 公開の
  `GET /{tenant_id}/saml/metadata`（`application/samlmetadata+xml`。entityID＝テナント issuer）を
  discovery と同じ公開領域へ、管理者向けの `POST /admin/saml-providers/import-metadata`（XML を解析して
  登録候補値を返す。非永続）を追加した。
- **crates/web — 管理コンソールにメタデータ取り込みと SP メタデータ導線を追加**: `/admin/saml` の追加
  パネルにメタデータ XML 貼り付け欄と「メタデータから取り込む」を設け、api の解析結果で登録フォームを
  初期化する。画面ヘッダに SP メタデータのダウンロードリンクを追加。
- 認証フロー（アサーション送受信・ACS・署名検証）は本変更の対象外（メタデータの出力・取り込みのみ）。

## 2026-07-21（web: モバイル表示の崩れ修正・言語設定 Cookie の全画面反映）

- **crates/web — 言語設定が設定画面以外へ反映されない不具合を修正**: 管理コンソール・ログイン等
  16 モジュールがモジュール内 `locale()` で `Accept-Language` のみを見ており、設定画面で保存した
  `lang` Cookie を無視していた。共通ヘルパー `handlers::locale`（`lang` Cookie > `Accept-Language` >
  既定 `ja`）へ一本化した。
- **crates/web — 管理コンソールのユーザーメニューが画面外へはみ出す崩れを修正**: ドロップダウンの
  ヘッダに長いユーザー識別子が折り返し無しで入り、モバイルでビューポート左へはみ出していた。
  メニューへ最大幅・折り返しを設定し、ナビバーのラベルは省略表示にした。
- **crates/web — コンソールのテーブル行がモバイルで縦へ伸びる崩れを修正**: CJK 文言の見出し・
  操作ボタンが 1 文字ずつ縦に折り返されていた。テーブル内の見出し・ボタンを折り返し禁止にし、
  `.table-responsive` の横スクロールへ委ねた。
- **crates/web — 認証系画面がモバイルで「上に余白があるのに下へスクロールが必要」になる問題を修正**:
  `100vh`（アドレスバー込み）＋縦センタリングが原因。高さを `100dvh` 基準にし、<768px は上詰めにした。

## 2026-07-20（deploy.sh: 中断で残った一時コンテナによる名前衝突を自動解消）

- **scripts/deploy.sh — アプリコンテナ入れ替え失敗の修正**: `docker compose up -d --force-recreate` は
  旧コンテナを「`<旧ID先頭12桁>_<コンテナ名>`」へ一時リネームしてから入れ替えるが、前回デプロイが
  中断されるとこのコンテナが残り、次回が「Conflict. The container name ... is already in use」で
  失敗していた。入れ替え前に当該パターンの残存コンテナを検出・削除する事前クリーンアップを追加。

## 2026-07-20（管理コンソール: SAML 連携アプリ一覧化・テナント画面の名称整理）

- **crates/core・api・web — SAML 連携アプリの一覧表示を追加**: `GET /admin/saml-providers`
  （リポジトリ `list_for_tenant` → `SamlProviderManagementService::list` → api ハンドラ）を新設し、
  `/admin/saml` 画面を「登録フォームのみ」から「SAML 連携アプリ一覧＋追加パネル」へ再構成した
  （テナント一覧と同じ collapse パターン。表示名・Entity ID・SSO URL・有効/無効を表示）。
  文言を「SAML 連携登録」→「SAML 連携アプリ一覧」「SAML 連携アプリ追加」へ変更。
- **crates/web — テナント画面の名称を「テナント登録」→「テナント一覧」へ変更**: 画面は従来から
  一覧＋追加の構成だったため、ナビ・タイトル・ホームカードの文言のみ実態に合わせた。

## 2026-07-20（管理コンソール: パスパラメータ抽出の 500 修正・プロフィール画面の戻り導線）

- **crates/web — `{tenant_id}` 配下の ID 付きルートが一律 500 になる不具合を修正**: `.nest("/{tenant_id}", …)`
  配下ではネスト元のパラメータも数えられるため、`/admin/members/{user_id}/reset-password` 等の
  13 ハンドラで `Path<String>` の抽出が「Wrong number of path arguments. Expected 1 but got 2」で
  失敗していた。`Path<(String, String)>` のタプル受けに修正（members の状態変更/PW再発行/削除/解除、
  users の権限参照/付与/剥奪、clients の詳細/編集/secret 再発行、tenants の削除/管理者PW再発行）。
  ルータの回帰テストを追加。
- **crates/web — プロフィール設定に管理コンソールへの戻りリンクを追加**: コンソール右上の
  「プロフィール設定を開く」から `/settings` へ遷移すると戻る手段が無かった。`?from=admin` で文脈を
  引き継ぎ、画面左上に「管理コンソールへ戻る」リンクを表示する（言語変更・パスワード変更の
  PRG 後も維持）。

## 2026-07-18（管理コンソール: 利用者ライフサイクル・テナント削除/PW再発行・設定の DB 上書き）

- **crates/core・api — 利用者ライフサイクル API を新設**: `UserLifecycleService` を追加し、
  `PATCH /admin/users/{id}`（有効化・無効化）・`DELETE /admin/users/{id}`（削除）・
  `POST /admin/users/{id}/password-reset`（一時パスワード再発行。`must_change_password` 付与）を
  実装した。所属元（HOME）が当該テナントの利用者のみ操作でき、自分自身への操作は禁止。再発行・
  無効化時は SSO セッション・refresh token・未消費 authorization code を全失効させる。
- **crates/api・web — 子テナントの削除と管理者パスワード再発行を画面へ接続**: テナント登録画面の
  各行に「削除」（既存 `DELETE /admin/tenants/{child_id}` を接続。配下残存時は 409 を表示）と
  「管理者PW再発行」（新設 `POST /admin/tenants/{child_id}/admin-password-reset`。メール指定で
  一時パスワードを一度だけ表示）を追加した。
- **crates/web — メンバー一覧を利用者管理のハブへ再構成**: 一覧に「利用者を作成」「ゲストを招待」
  ボタンと、メンバーごとの権限参照リンク・アカウント状態（有効/無効/ロック）表示・無効化/有効化・
  パスワード再発行・削除（HOME）／解除（GUEST）を追加。サイドバーの「利用者権限」「利用者を作成」を
  「メンバー」「利用者を検索」へ整理した（権限リンクは HOME メンバーのみ。ゲストの `users`
  レコードへは参加先管理者から到達できない。ADR-0009 §3）。
- **crates/core・api・web — ランタイム設定の DB 上書きと現在値表示**: 設定画面のランタイム設定表に
  有効値・出所バッジ（ENV/DB/既定値）・既定値・DB 上書き入力欄を追加し、`DB_MANAGED` キーを
  `PUT /admin/system-settings/runtime` で上書き・解除できるようにした（値の型検証付き。反映は
  API 再起動後）。
- **docker/nginx.conf — web 画面のルーティング漏れ（404）を修正**: `/{tenant_id}/settings`
  （プロフィール設定）・`forgot-password`・`password-reset`・`verify-email`・`invitations/accept`・
  `/version` が api 側へ流れて 404 になっていたのを web へ振り分けた。`/logout` は POST（ポータル）
  → web、GET（OIDC RP-Initiated Logout）→ api にメソッドで振り分け。
- **crates/web — フッタのバージョン表記に Git バージョンを併記**: `IdP Web v0.1.0 (git describe)`
  形式にした（ビルド時埋め込みが無い場合はパッケージ版のみ）。
- **crates/core — `/introspect` が無効化・削除済み利用者のトークンを active と返す穴を塞いだ**:
  access_token（JWT）・refresh_token の両経路で利用者の現在状態を確認し、非 ACTIVE・不存在は
  `active: false` を返す（`/userinfo` と同じ判定。無効化・削除・パスワード再発行の即時反映）。
- **crates/core — ランタイム設定の整数検証を u32 範囲に強化**: `KEY_ROTATION_LEAD_DAYS` 等の
  u32 消費キーに範囲外の値（u32::MAX 超）を保存すると次回起動が構成エラーで失敗するため、
  保存前に u32 でパース検証する。
- **scripts/e2e.sh — `printf | grep -q` の SIGPIPE 誤検知を解消**: `set -o pipefail` 下で
  `grep -q` の早期終了により `printf` が SIGPIPE(141) となり、マッチ成功でもパイプラインが
  失敗扱いになっていた（テナント登録画面チェックで顕在化）。here-string（`<<<`）方式へ変更。

## 2026-07-18（エンドユーザー・ポータルのログイン新設とテナント登録 UI 改善）

- **crates/core・api・web — エンドユーザー・ポータルの直接ログインを新設**: `/{tenant_id}/login` を
  OIDC の `auth_session_id` を持たない直接アクセスで開くと、IdP 自身のアカウント画面
  （`/{tenant_id}/settings`）へ入るためのポータルログインとして働くようにした（従来は「セッション切れ」
  エラーだった）。管理コンソールのログイン（`AdminLoginService`）と同じくクライアント非依存で SSO を
  直接発行するが、admin 権限は要求せず、**TOTP（MFA）を尊重**する（TOTP 設定済みユーザーは署名付き
  短命チケット `mfa_ticket` 経由で TOTP 入力を挟み、パスワードのみで SSO を得る抜け道を作らない）。
  api に `POST /internal/authenticate/portal[/mfa]` を追加。アカウント画面にサインアウト導線を追加し、
  `POST /{tenant_id}/logout` で SSO を失効する。
- **crates/web — テナント登録コンソールを一覧中心へ再構成**: 登録フォームは常設をやめ「テナントを追加」
  ボタンで開閉する折りたたみに変更、入力欄を `form-control-lg` へ拡大。一覧の各テナント行に利用者
  ログイン（`/{id}/login`）・管理者ログイン（`/{id}/admin/login`）へのリンクを追加した。
- **crates/web・i18n — 「自己登録」の表記を「利用者のセルフ登録」に変更**: 一覧のバッジを
  「許可 / 招待制のみ」に改め、意味の説明（ツールチップ・ヒント文）を追加した（設定画面の同項目も同様）。

## 2026-07-17（マイグレーション 0008 の外部キー不成立を修正）

- **migrations/0008 — `saml_identity_providers` がテーブルオプション未指定で作成不能だった問題を修正**:
  サーバ既定照合（`mariadb:10.11` は `utf8mb4_general_ci`）と `tenants`（`utf8mb4_unicode_ci`）の照合不一致で
  外部キーが errno 150 となり、新規 DB への適用（CI 含む）が必ず失敗していた。他テーブルと同じ
  `ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci` を明示し、時刻列を規約どおり
  `DATETIME(6)` へ変更した（`(tenant_id, entity_id)` の一意制約は索引キー上限を超えるため、
  MariaDB が長キー一意制約 `USING HASH` として作成する）。

## 2026-07-17（web UI を photonest と同じ Bootstrap フォーマットへ全面刷新）

- **crates/web — 全画面を Bootstrap 5 + Font Awesome の photonest フォーマットで書き換え**: 認証系
  画面（ログイン・同意・パスワード関連・MFA・Passkey 等）は中央寄せカード型の共通ベース
  `templates/page.html` を新設して継承、管理コンソールは `console/layout.html` をナビバー＋
  常設サイドバー（<768px はオフキャンバスドロワー）＋フッタ構成へ刷新した。表は `table-hover`、
  通知は `alert`、状態表示は `badge` に統一。フォーム名・hidden 値・JS フック（Passkey/WebAuthn、
  `data-react-surface`）は従来どおり維持。
- **crates/web — Bootstrap 5.3.3 / Font Awesome Free 7.3.0 をベンダリング**: `assets/vendor/` 配下に
  同梱し `handlers/vendor_assets.rs` から `/assets/vendor/...` として自オリジン配信
  （CSP `default-src 'self'` 準拠。外部 CDN 非依存）。`assets/app.css` は DADS パレット一式を廃し、
  サイドバー幅等の最小限の Bootstrap 補完のみに縮小した。

## 2026-07-15（web 共通スタイルシートの導入）

- **crates/web — 全画面へ共通 CSS を適用**: これまで web の各テンプレートは CSS を一切読み込まず
  （`console/layout.html` の `<head>` にスタイルシート指定が無く、`admin-header` 等のクラスに対応する
  ルールも存在しなかった）、ブラウザ既定の素の HTML 表示になっていた。`assets/app.css` を追加し
  `/assets/app.css` として自オリジン配信（CSP `style-src 'self'` 準拠、`react_assets` と同方式）、
  各テンプレートの `<head>` から読み込むことで、ログイン・管理コンソール・セルフサービス各画面へ
  デザイン（DADS パレット）を適用した。

## 2026-07-15（proxy readiness の異常検知強化）

- **docker-compose*.yml — nginx proxy に SETGID/SETUID と healthcheck を追加**: Synology NAS 等で
  `cap_drop: ALL` のまま nginx worker が `setgid(101)` / `setuid(101)` できず、proxy master だけが
  Up に見える状態を避けるため、必要 capability を明示的に戻し、`/readyz` healthcheck で検知する。
- **deploy.sh — proxy の healthy 待機を追加**: api / web の起動後、外部 `readyz` 確認前に proxy 自身の
  healthcheck を待つことで、proxy 起動不良時はタイムアウト後に compose diagnostics / logs を出力する。

## 2026-07-15（Compose project 名の明示化）

- **deploy.sh — `COMPOSE_PROJECT_NAME` を .env から明示適用**: 新規 `.env` では Docker Compose の
  container / network / volume 名が `stg-api-1` のような汎用名にならないよう `idp-<ディレクトリ名>` を使う。
  一方、既存 `.env` に未設定の場合は既存 volume を保護するため従来のディレクトリ名 project を維持する。
- **env サンプル — stg/prod の project 名を分離**: `.env.staging.example` は `COMPOSE_PROJECT_NAME=idp-stg`、
  `.env.production.example` は `COMPOSE_PROJECT_NAME=idp-prod` を持つ。

## 2026-07-15（proxy 起動権限と deploy ログ保存）

- **docker-compose.deploy.yml / docker-compose.yml — nginx proxy の chown 権限を最小追加**: `read_only` + `tmpfs` +
  `cap_drop: ALL` の組み合わせで nginx 起動時の `chown("/var/cache/nginx/client_temp", 101)` が
  `Operation not permitted` になり、proxy が restart して `/readyz` が通らない問題を修正。proxy のみに `CAP_CHOWN` を
  戻し、他 capability は drop したままにする。
- **deploy.sh — 実行ログの日時ミリ秒付き自動保存**: `./deploy.sh ...` の標準出力・標準エラーをコンソールへ出しつつ、
  実行ディレクトリへ `deploy-YYYYMMDDHHmmssmmm.log` として自動保存する。

## 2026-07-15（migrate tar の軽量化）

- **deploy.sh — migrate 失敗時に Docker 診断ログを即時出力**: `docker compose run --rm migrate` が失敗した各 retry で、
  `migrate` / `mariadb` の `compose ps`・container status・image・`docker compose logs --tail=100 --timestamps` を出す。
  これによりスクリプトの実行結果だけで、migration ジョブ自体のエラーと DB 側ログを確認できる。

- **Dockerfile — Rust ビルドステージを bookworm に固定**: `runtime-*` / `migrate` が `debian:bookworm-slim` である一方、
  `rust:slim` が新しい Debian へ追従すると、コピーした `sqlx` やアプリバイナリが `GLIBC_2.39` などを要求して
  NAS 側の bookworm 実行イメージで起動できない。`builder` / `migrate-tool-builder` を `rust:slim-bookworm` に固定し、
  ビルド時と実行時の glibc ABI を揃えた。

- **Dockerfile — migrate 実行イメージから Rust ツールチェインとビルド依存を除外**: `sqlx-cli` の
  `cargo install` を `migrate-tool-builder` ステージへ分離し、最終 `migrate` ステージは `debian:bookworm-slim` に
  `sqlx` バイナリ・証明書・`migrations/` のみを含める構成にした。これにより `idp-migrate.tar` が
  自身のビルド用コンテナ相当（Rust/Cargo/ビルドツール）を内包して肥大化する状態を避ける。

## 2026-07-15（MariaDB 初期化待機の堅牢化）

- **deploy.sh — MariaDB の health 待機を低速 NAS 向けに延長**: reset 直後の fresh volume 初期化が
  120 秒を超えて `unhealthy` 表示のまま進む環境に備え、MariaDB の待機既定値を 600 秒へ延長した。
  `DEPLOY_MARIADB_HEALTH_TIMEOUT_SECS` / `DEPLOY_APP_HEALTH_TIMEOUT_SECS` / `DEPLOY_HEALTH_TIMEOUT_SECS` /
  `DEPLOY_HEALTH_POLL_INTERVAL_SECS` でサービス種別ごとに上書きできる。待機中は 30 秒ごとに状態と残り時間を出す。
- **docker-compose.deploy.yml — MariaDB healthcheck の猶予を拡大**: 初期化中に早期 `unhealthy` へ落ちにくいよう
  `start_period: 120s` と `retries: 120` を設定した。

# CHANGELOG

完了した重要な変更の要約（詳しい経緯は `history/`、設計判断は `adr/`）。

## 2026-07-14（起動しない api コンテナの修正 — スタブ出荷＋旧コンテナ居座り）

- **deploy.sh — 必須 `app|migrate|reset` CLI と全モードのアプリ入れ替えに刷新**: 通常デプロイは
  `./deploy.sh app` に明示化し、`migrate` / `reset` でも DB 処理後に `api`・`web`・`proxy` を
  `--force-recreate` で必ず作り直す。tar 読み込み進捗、CRLF 除去、詳細診断、migration retry を統合。

- **env サンプル — 同一ホスト stg/prod 用テンプレートを追加**: `.env.staging.example` は `WEB_PORT=8081` /
  `IMAGE_TAG=stg`、`.env.production.example` は `WEB_PORT=8080` / `IMAGE_TAG=prod` とし、HTTP 外部接続時の
  `ISSUER` / `PUBLIC_WEB_BASE_URL` の書き換え箇所を明示。

- **deploy.sh — アプリコンテナを `--force-recreate` で確実に置き換え**: 新イメージを load
  （タグ付け替え）しても、旧イメージのまま restart ループしているコンテナが居座ると `up -d` が
  「変更なし」と判断して置き換えず、古い（壊れた）バイナリが動き続ける不具合を修正。
  `$compose up -d --force-recreate api web proxy` で毎回作り直す（mariadb は対象外＝DB は落とさない）。

- **Dockerfile — 依存キャッシュ層のスタブが本体として出荷される不具合を修正**: 依存だけ先にコンパイル
  するため `fn main() {}` のダミーソースでビルドした後、本体ソースを `COPY` して再ビルドしていたが、
  `COPY` が元ファイルの mtime を保持するため本体ソースがダミー成果物より古い mtime になり、cargo の
  鮮度判定（mtime ベース）が再ビルドをスキップしてダミーの空バイナリ（即 exit 0・ログ無し）を出荷して
  いた。これにより stg で `api` コンテナが起動直後に exit 0 で終了し続け（`restart: unless-stopped` で
  再起動ループ）、healthcheck が通らず `unhealthy` になっていた。再ビルド直前に
  `find crates -name '*.rs' -exec touch {} +` でソース mtime を更新して確実に再コンパイルさせる
  （依存クレートのキャッシュには触れないため、キャッシュ高速化は維持）。`api`・`web` 両バイナリに影響。

## 2026-07-14（deploy.sh の CLI 整理・CPU 制限の撤去）

- **deploy.sh — `migration` を `migrate` に改名**: サブコマンド名を compose の `migrate` サービス名と
  揃えた（`./deploy.sh migrate`）。フェーズログも `phase=migrate` に統一。
- **deploy.sh — `reset` から `--yes` 要求を撤廃**: `./deploy.sh reset` は確認フラグなしで即実行される
  破壊的操作になった。
- **docker-compose.deploy.yml — `cpus:` 制限を撤去**: Synology 等 CFS バンド幅制御
  （cgroup `cpu.cfs_quota`）非対応カーネルで `docker compose up` が
  `NanoCPUs can not be set` で失敗する不具合を修正。`mem_limit` / `pids_limit` は維持。

## 2026-07-13（build/deploy スクリプトの簡素化）

- **build.sh — tar バンドル出力を既定化**: 引数なしで Docker イメージ（api/web/migrate）をビルドし、
  tar・デプロイ用 `docker-compose.yml`・`docker/nginx.conf`・`.env.example`・`deploy.sh`・manifest を
  `dist/` へ出力する。ネイティブビルド／`--check`／レジストリ push モードは削除
  （`cargo build --release` や CI の fmt/clippy/test で代替。レジストリ配布は不使用のため廃止）。
- **deploy.sh — 単一入口・3 モードに簡素化**: 引数なし（初回・更新デプロイ）／`migration`（DB 更新のみ）／
  `reset --yes`（DB 初期化）のみ。同梱 tar を自動 `docker load` し manifest（image ID・revision label）と
  照合する。使用する Compose はバンドル同梱の `docker-compose.yml` に固定され、手で `-f` 指定する必要は
  ない。初回は `.env` を自動生成し、確認すべき項目（`ISSUER`・`WEB_PORT`）を出力する。
- `init.sh`（互換ラッパー）と `lib.sh` を削除（deploy.sh に統合・自己完結化）。

## 2026-07-13（DDD1: Application 層の Infrastructure 具象依存除去）

- **DDD1 — Application 層の DIP 境界整理**: Application ユースケースから `infrastructure::crypto` / `infrastructure::jwt` / `WebAuthnService` の直接 import を除去し、暗号・JWT のドメインサービスと `WebAuthnPort` 経由のポリモーフィックな依存へ切り替えた。Infrastructure の WebAuthn 実装は composition root で選択し、Application は port のみに依存する。

## 2026-07-13（UI1・REL1: 設定安全性表示と成果物検証）

- **UI1 — root 設定画面の安全性表示**: ランタイム設定の出所に加え、安全／要対応の状態、判定理由、再起動要否、secret 非露出表示を返すようにした。開発用既知 secret、`COOKIE_SECURE=false`、`HSTS_MAX_AGE=0` などを要対応として表示する。
- **REL1 — stale イメージ再利用防止**: レジストリ配布では `latest` を拒否し、deploy 時に明示 pull する。`build.sh --save` は tar の SHA-256、Git commit、version、image ID を manifest に出力し、deploy は manifest とローカル image ID / revision label を照合する。api/web/migrate が同一 commit 由来であることも検証する。

## 2026-07-12（REF3・SEC7・REF4: リファクタ・セキュリティ強化）

- **REF3 — 認可ホットパスの整理**:
  - 権限コード定数（`idp.tenant.admin`・`idp.system.admin`）を `domain::permission` に集約（各所のローカル `const` を削除）。
  - `UserPermissionRepository` トレイトに `has_any_permission` デフォルト実装を追加。`SqlxUserPermissionRepository` は `IN (?, ?)` の単一クエリでオーバーライド。
  - `AdminAccessService` の SSO セッション解決ロジックを `resolve_session_user` ヘルパーに抽出（`authorize`・`authenticated_user` の重複を排除）。
  - `AdminLoginService::login`・`change_password` の `has_permission` 2 回呼び出しを `has_any_permission` 1 回に統合。

- **SEC7 — CSRF トークンの HMAC 化**:
  - `idp-contracts::csrf` の `login_csrf_token` / `consent_csrf_token` を SHA-256 から HMAC-SHA256 へ変更。関数が `key: &[u8]` を受け取る（破壊的変更）。
  - `web::csrf` の `admin_csrf_token` / `console_csrf_token` も同様に HMAC-SHA256 へ変更。
  - `CSRF_SECRET` 環境変数（base64, 32 バイト）を api・web の両方で読み込む。未設定時は開発用デフォルト（`DEV_CSRF_SECRET`、32 バイト）を使用し、https issuer では fail-fast。
  - `LoginService`・`ChangePasswordService`・`MfaLoginService` の構造体に `csrf_secret: [u8; 32]` フィールドを追加し、コンストラクタ・`AppState::build()` を更新。

- **REF4 — 小粒の重複解消**:
  - `PermissionManagementError→ApiError` マッピング関数 `map_permission_management_error` を `handlers/mod.rs` に集約（`admin_permissions.rs` と `admin_users.rs` の重複を削除）。
  - `validate_email` を `domain::values` に統合。`register.rs`・`user_management.rs` のローカル実装を削除し、`domain_validate_email` を再利用。
  - `InvitationService::list_members` の N+1 を解消: `UserRepository::find_by_ids` トレイトメソッドを追加（デフォルト実装は逐次、`SqlxUserRepository` は `IN` クエリでオーバーライド）。
  - `PermissionManagementService` に `find_user_by_id` プライベートヘルパーを抽出（`get_user` と `ensure_user_in_tenant` の重複 `find_by_id` + エラー変換を統合）。


- **MT19 — API の `Accept-Language` ベース多言語化**: `ApiLocale` extractor（`FromRequestParts`、既定 `ja`）と
  `ApiMessages`（`fluent` ラッパー）を `crates/api/src/presentation/i18n.rs` に追加。全管理系ハンドラ
  （`admin_users`・`admin_permissions`・`admin_clients`・`admin_members`・`admin_invitations`・`admin_signing_keys`）
  が `Accept-Language` を参照して日本語／英語のエラーメッセージを返すように更新した。
  `FluentBundle` が `!Send` のため、エラーマッピング関数で `ApiLocale`（`Copy`）を受け取り、関数内で
  `ApiMessages` を生成するパターンで `Send` 境界を満たした。翻訳キーは `i18n/{en,ja}/main.ftl` に
  `api-*` プレフィックスで追加（18 キー）。

- **MT20 — Web の表示言語決定チェーン全面実装**:
  - **DB 対応**: `migrations/0007_user_language.up/down.sql` で `users.language VARCHAR(5) NULL CHECK (language IN ('ja', 'en'))` を追加。`UserRepository::update_language` トレイトメソッドと sqlx 実装を追加。
  - **AccountLanguageService**: `crates/core/src/application/account_language.rs` に新設。`/internal/account/update-language` エンドポイント（`POST`）をコントラクト・ルータ・ハンドラに追加。
  - **言語決定チェーン**: `Locale::resolve(query, user_language, cookie, accept_language)` を 4 引数に拡張（優先順: `?lang=` → ユーザー DB 設定 → Cookie → `Accept-Language` → 既定 `ja`）。全ハンドラに適用、デフォルトを `En` → `Ja` に統一。
  - **ログイン時 Cookie 設定**: ログイン／MFA 成功時に `LoginOutcome`／`MfaLoginOutcome` が `user_language` を返し、web ハンドラが `lang` Cookie をユーザー設定値で上書き。
  - **設定画面言語変更の DB 保存**: `/settings?lang=` による言語変更時、SSO セッションが存在する場合は `account_update_language` API を呼び出して DB に永続化。


- **SEC6b — 自己登録アカウントのメール検証**: 自己登録（SEC6）で作られる `email_verified = false` の
  アカウントに、確認リンクによるメール検証フローを導入した（配送は MT17 の `Mailer`＋MT14 の SMTP を再利用）。
  - 登録時に検証メールを送出（best-effort。SMTP 未設定・送信失敗でも登録自体は成立）。`RegisterResponse`
    に `email_verification_required` を追加。トークンは 32 バイト・SHA-256 hash のみ保存
    （`email_verification_tokens`。migration 0006）・TTL 既定 24 時間（`EMAIL_VERIFICATION_TTL_SECS`）・
    単回消費・再送で旧トークン失効。
  - **ログインゲート**: `email_verified = false` のアカウントはログイン不可（`LoginService` がパスワード
    検証成功後に判定 → `EmailVerificationRequired`。資格情報を知らない攻撃者からは検証状態を観測できない）。
    確認リンク（web `/{tenant_id}/verify-email` → api `POST /{tenant_id}/auth/verify-email`）で
    `email_verified` を立てるとログイン可能になる。
  - **検証済みで作る経路**: 管理者作成ユーザー（`UserManagementService`。管理者がメール所有を保証）と
    招待ゲスト（招待リンクで所有確認済み）は `email_verified = true` で作られ、ゲートに掛からない。
  - トークン・メールアドレスはログ・監査に出さない（監査は `email_verification.requested/verified`）。



- **UI1 — root 設定画面の安全性表示**: ランタイム設定の出所に加え、安全／要対応の状態、判定理由、再起動要否、secret 非露出表示を返すようにした。開発用既知 secret、`COOKIE_SECURE=false`、`HSTS_MAX_AGE=0` などを要対応として表示する。
- **REL1 — stale イメージ再利用防止**: レジストリ配布では `latest` を拒否し、deploy 時に明示 pull する。`build.sh --save` は tar の SHA-256、Git commit、version、image ID を manifest に出力し、deploy は manifest とローカル image ID / revision label を照合する。api/web/migrate が同一 commit 由来であることも検証する。

## 2026-07-12（GAP1: ゲスト権限付与の ADR 乖離解消）

- **GAP1 — 権限付与対象を「所属元照合」から「ACTIVE メンバーシップ判定」へ**（ADR-0009 §4）:
  `PermissionManagementService::ensure_user_in_tenant` を、対象ユーザーの所属元テナント一致
  （`users.tenant_id`）ではなく「ユーザー現存 + `TenantMembershipRepository::is_active_member`」で
  判定するよう変更（list/grant/revoke の 3 経路すべてに適用）。
  - 付与対象は当該テナントで **ACTIVE なメンバーシップ**（HOME / GUEST）を持つユーザーで、アカウントの
    出自（HOME か GUEST か）では区別しない。`INVITED`（未承諾）ゲスト・テナント外ユーザーは
    ACTIVE メンバーでないため、テナント越しの存在推測を防ぐべく従来どおり 404 に倒す。
  - `find_user_by_identifier`（識別子検索）は所属元限定のまま維持（ゲストの識別子は所属元名前空間にあり
    参加先での検索はホームユーザーと衝突し得るため）。GUEST への付与はメンバー一覧の `user_id` 導線を使う。
  - negative/positive テストを追加（INVITED への付与不可・テナント外 404 維持・別テナント所属の ACTIVE
    ゲストへの付与成功）。統合テストのユーザー生成ヘルパ（`create_plain_user`）も実運用同様に HOME
    メンバーシップを投影するよう修正。


## 2026-07-12（MT18: パスワードリセット / SEC6: 自己登録の制御）

- **MT18 — セルフサービス・パスワードリセット（忘失時）**: ログイン画面の「パスワードをお忘れですか」
  から、メールアドレス入力 → リセットリンク付きメール（MT17 の `Mailer`＋MT14 の SMTP 設定を再利用）→
  リンク先（`/{tenant_id}/password-reset`）で新パスワード設定。
  - 列挙防止: 要求はアカウントの有無・状態・送信結果に関わらず同一応答（`accepted`）。SMTP 未設定のみ
    `unavailable`（アカウント非依存）。IP 単位のレート制限（15 分 5 回）。
  - トークン: 32 バイト・SHA-256 ハッシュのみ保存（`password_reset_tokens`。migration 0005）・
    TTL 既定 1 時間（`PASSWORD_RESET_TTL_SECS`）・単回消費・再要求で旧トークン失効。
  - リセット成功時は SSO セッション・refresh token・未消費 authorization code をユーザー単位で全失効。
    トークン・メールアドレスはログ・監査に出さない（監査は `password_reset.requested/completed`）。
  - インプロセス SMTP サーバとの E2E 統合テスト（要求 → メール受信 → リセット → 単回消費・全失効）付き。
- **SEC6 — 自己登録（`/auth/register`）の制御**: 全テナント無条件開放だった自己登録を、テナント設定
  `self_registration_enabled`（migration 0004。**既定 OFF** = fail-closed）で切り替え可能にし、IP 単位の
  レート制限（5 分 10 回、429）を追加。無効テナントでは 403 になり、409 応答によるテナント内メール
  存在の列挙は「有効化したテナントで、レート制限の範囲内」でのみ可能に縮小（完全な秘匿はメール検証
  = SEC6b で対応）。トグルは設定画面のテナント設定区画（`idp.tenant.admin`）から変更する。


## 2026-07-12（MT17: 招待のメール配送）

- **MT17 — ゲスト招待の承諾リンクをメールで配送**: 招待作成（`POST /{tenant_id}/admin/invitations`）
  時に、システム設定の SMTP（MT14）で被招待者へ承諾リンク付きメールを自動送信する。SMTP 未設定・
  送信失敗時は従来どおりトークンの手動伝達（best-effort。応答・結果画面の `email_sent` で成否を報告）。
  - ドメインポート `Mailer`（送信ごとに SMTP 接続情報を受け取る）＋ lettre（rustls）実装を新設。
    `use_tls` は 465 = implicit TLS／それ以外 = STARTTLS 必須。インプロセス SMTP サーバとの実対話
    テストで検証。
  - `SystemSettingsService::smtp_server()`（復号済み接続情報。表示用 `get_smtp` とは別）を追加。
  - web に承諾画面 `GET/POST /{tenant_id}/invitations/accept` を新設（メールリンクの着地点。
    未ログイン時は所属元テナントでのログインを案内）。招待結果画面にメール送信の成否を表示。
  - 承諾リンクの土台 URL は `PUBLIC_WEB_BASE_URL`（既定 = `ISSUER`。単一オリジン構成 ADR-0007）。
  - メール文言は MT19（API 多言語化）まで日英併記の固定文。


## 2026-07-12（REF2: テナント開通のトランザクション境界）

- **REF2 — テナント作成の unit of work 導入**: `create_tenant` が「tenant INSERT → 管理者作成 →
  HOME メンバーシップ → 権限付与」を個別実行しており、途中失敗で管理者のいないテナント（孤立
  テナント）が残り得た。ドメインポート `TenantProvisioningRepository::provision` を新設し、4 行を
  **単一トランザクション**で永続化（途中失敗は全ロールバック。sqlx 実装は各リポジトリと同一の
  INSERT SQL を executor 汎用ヘルパで共用）。`UserManagementService` は構築（検証・パスワード
  生成・ハッシュ化）だけを行う `prepare_user` を分離し、`create_user` と テナント開通の双方が同じ
  構築ロジックを通る（単一の出所は維持）。権限付与が判定キャッシュを迂回する点は、新規生成 ID の
  ためキャッシュに該当キーが存在し得ず安全。実 DB のロールバック検証を `admin_tenants` 統合テストに
  追加。


## 2026-07-12（セキュリティ改修: MT16 レビュー指摘の解消）

- **SEC3 — web（HTML 側）へセキュリティヘッダ付与**: ログイン画面・管理コンソールの全レスポンスに
  `X-Frame-Options: DENY`・`Content-Security-Policy`（`frame-ancestors 'none'`・自オリジン限定。
  現行テンプレートのインライン script/style は許容、nonce 化は後続改善）・`nosniff`・
  `Referrer-Policy` を付与（`crates/web/src/security_headers.rs`）。`HSTS_MAX_AGE` も api と同キーで
  web に追加。
- **REF1 — 統合テスト支援モジュールの共通化**: 9 テストファイルに重複していた
  `setup`（DB 接続・マイグレーション・AppState/ルータ組み立て・署名鍵ブートストラップ）・SSO
  セッション/利用者/クライアント生成・リクエストビルダ・レスポンス読み取りを
  `crates/api/tests/support/mod.rs` へ抽出（テストコード約 1,100 行削減）。マイグレーションと
  鍵ブートストラップの「プロセス内一度だけ」ガード（OnceCell）も一元化。
- **SEC5 — 署名鍵ブートストラップの排他制御**: `ensure_active_key` の「存在確認 → 生成」TOCTOU を、
  `SigningKeyRepository::insert_if_no_active`（MariaDB `GET_LOCK` の排他区間で再確認＋挿入。同一接続で
  取得〜解放）で解消。複数インスタンスの同時起動でも ACTIVE 鍵は 1 本のまま。8 並走のブートストラップ
  レースを keys 統合テストで検証（DB 側で ACTIVE 複数を禁止しない理由: 手動 generate・ローテーション
  遷移では ACTIVE 並存が正当なため、排他はブートストラップ経路に限定する）。
- **SEC4 — `/internal/*` のテナント解決を fail-closed 化**: `tenant_id` 未指定・不正時に root へ
  フォールバックする過渡措置（`internal_tenant`）を撤去し、`require_internal_tenant` が 400 を返す。
  web は全内部呼び出しで `tenant_id` を必須送信（`consent_info` の送信漏れも修正）。あわせて
  過渡運用の `AppState::default_tenant` を撤去（起動時の root 存在確認・ログは維持）。
- **SEC2 — 本番での開発用シークレット使用を fail-fast 化**: `ISSUER` が `https://` のとき、
  `KEY_ENCRYPTION_KEY`／`INTERNAL_SERVICE_TOKEN` が未設定（＝ソース埋め込みの開発用既知値）なら
  api・web とも起動を構成エラーで失敗させる。http（ローカル開発）は従来どおり warning のみ。
- **SEC1 — ゲスト追放時の権限後始末を fail-closed 化**: `InvitationService::revoke_membership` が
  「メンバーシップ削除 → best-effort の権限剥奪（失敗しても成功扱い）」だったのを
  「**権限一括剥奪（失敗時は操作全体を失敗・メンバーシップ維持）→ メンバーシップ削除**」へ反転。
  管理アクセス判定（`RequirePerms`）は権限行のみを見るため、旧順序では後始末失敗時に追放済み
  ゲストが管理権限を保持し続けた。`UserPermissionRepository::revoke_all_for_user_in_tenant`
  （単一トランザクションの SELECT FOR UPDATE + DELETE、剥奪コード返却）を新設し、キャッシュ
  デコレータは返却コードを invalidate する。


## 2026-07-12（MT16: テナント分離・権限境界の統合テスト）

- **統合テスト新設**（ADR-0009 §8 の negative test 必須方針。`crates/api/tests/tenant_isolation.rs`）:
  1. root（`idp.system.admin`）はテナントを作成できるが、作成したテナントの管理 API には一律 403
     （「器は作れるが中身に触れない」）。システム設定は root scope のみ 200。
  2. `idp.tenant.admin` の権限境界は scope テナントとの完全一致（他テナント・root へは 403）。
     `idp.system.admin` の scope = root は DB CHECK 制約でも拒否されることを直接 INSERT で検証。
  3. テナント間データ分離（利用者・クライアントは他テナントの一覧・検索・取得に現れない = 404）。
     利用者・クライアントが残るテナントは root でも削除できない（409）。
  4. ゲスト保護: 招待トークンは「本人 + 当該テナント経路」でのみ承諾可・リプレイ不可・監査ログ非出力。
     参加先管理者はゲストの `users` レコードへ到達できず（404）、解除時は host scope の権限行のみ
     後始末される（本体・他 scope は残る）。HOME メンバーシップは解除不可（403）。
  5. OIDC フロー分離: メンバーシップのない SSO セッションは当該テナントで未認証扱い、テナント A の
     アクセストークン／クライアントはテナント B の `/userinfo`・`/token` で拒否（per-tenant issuer の
     完全一致）。ゲストは承諾後に参加先テナントのフローへ SSO で参加できる。
- **テスト基盤の並走競合を修正**: 新規 DB へ複数テストの setup が並走すると、マイグレーション seed の
  INSERT と `ensure_active_key`（存在確認→生成の TOCTOU）が競合し、seed 重複エラー・ACTIVE 署名鍵の
  複数本化が起きていた。`tokio::sync::OnceCell` でプロセス内一度だけ実行するよう
  `internal_auth.rs`・`oidc_flow.rs`・`tenant_isolation.rs` を直列化。
- **既存テストの更新漏れ修正**: `oidc_flow.rs` の「未登録 redirect_uri」ケースがテナント経路化（MT9）
  以前の `/authorize`（プレフィクスなし）のままで 404/400 不一致になっていたのを
  `/{tenant_id}/authorize` へ修正。

## 2026-07-11（MT14・MT15: 設定画面 + セルフサービス設定）

- **システム設定基盤（MT14）**: `system_settings` テーブル（`0003_system_settings`。key-value + `is_secret`。
  テナント列を持たず IdP 全体に適用）と `SystemSettingsRepository`／`SystemSettingsService` を新設。SMTP 設定
  （host/port/username/password/from/tls）を保持し、秘匿値（パスワード）は `crypto::encrypt`（AES-256-GCM）で
  暗号化保存・参照時は平文非返却（設定済みか否かのみ）。消費側（MT17/MT18）の入口は `get_smtp`。監査イベント
  `SystemSettingsUpdated` を追加。認可は `RequirePerms<IdpSystemAdmin>`（root のみ）。
- **管理設定画面（MT14）**: `GET /{tenant_id}/admin/settings`（web）。テナント設定区画（自テナント表示名の
  更新。`idp.tenant.admin`。api `GET/PATCH /admin/settings/tenant`、`TenantManagementService::get_current`／
  `update_current_name` を追加）と、root のみ表示のシステム設定区画（SMTP。api `GET/PUT /admin/system-settings`）。
  root 判定は web が別途持たず「api への GET が 403 か否か」で区画表示を切り替える（認可の単一の出所を api に集約）。
- **ユーザー設定画面（MT15）**: `GET /{tenant_id}/settings`（web）。セルフサービスのパスワード変更
  （api `POST /internal/account/change-password`。`AccountPasswordService` が SSO セッションで本人解決 → 現行
  パスワード再検証 → 強度検証 → 更新。OIDC フロー外のため code/redirect なし）、MFA（TOTP/Passkey）画面への導線、
  言語設定（`?lang=` を `lang` Cookie に保存。`Locale::resolve` = `?lang=` > Cookie > `Accept-Language`）。
  全画面への言語決定チェーン統一・ユーザー設定 `language` 列・システム既定 `ja` への統一は MT20 に残す。

## 2026-07-11（MT12・MT13: 強制パスワード変更 + web テナント経路化・管理コンソール拡張）

- **強制パスワード変更**（ADR-0009 §5。`application::change_password::ChangePasswordService`）:
  `LoginService::login()` はパスワード検証成功後に `must_change_password` を確認し、真なら SSO を
  発行せず `LoginOutcome::PasswordChangeRequired`（`auth_session_id` 維持）を返す。
  `ChangePasswordService` は現行パスワードを再検証したうえで新パスワードを保存し、`MfaLoginService` と
  同じ SSO 発行 → 同意チェック → code 発行のテールを実行する。管理コンソールログイン
  （`AdminLoginService`）は一時セッションを持たないため、`change_password()` で
  username・現行パスワード・admin 権限をフルに再検証してから SSO を発行する専用フローとした。
  `UserRepository::update_password`（トレイト新設）・共有パスワード強度検証
  （`domain::password::validate_password_strength`）・監査イベント `PasswordChanged` を追加。
  web 側は `/{tenant_id}/password-change`（OIDC フロー）・`/{tenant_id}/admin/password-change`
  （管理コンソール）の 2 画面を新設。DB マイグレーションは不要（`must_change_password` は
  MT9 以前の初期 DDL に既存）。
- **web のテナント経路化**（ADR-0009 §6・§10。MT13）: `idp-web` の全画面 URL を `/{tenant_id}/...`
  へ再構成した（`/healthz`・`/readyz` のみ据え置き）。新設の `capture_tenant` middleware
  （`crates/web/src/tenant.rs`）がパスの `tenant_id`（UUID 形式のみ検証。実在確認は api 側に委ねる）を
  `Extension<WebTenant>` として注入する。管理コンソールは `/admin/console/*` から `/{tenant_id}/admin/*`
  へ改称。`api_client.rs` の `/admin/*` 呼び出しはすべて明示的な `tenant_id` 引数を取るよう書き換え、
  過渡期の root テナント自動解決（`/internal/root-tenant`・`ApiClient::tenant_prefix()`）は削除した
  （api 側の対応エンドポイント・DTO も削除）。`contracts::auth` の内部認証 DTO は全箇所でパス由来
  `tenant_id` を送るようになった。api の `/authorize` も `/login`・`/consent` へのリダイレクトを
  `/{tenant_id}/...` へ修正。
- **管理コンソールの新規画面**（ADR-0009 §3・§5・§6。MT13）: 利用者作成
  （`/{tenant_id}/admin/users/new`。自動生成パスワードを一度だけ表示）・メンバー一覧とゲスト解除
  （`/{tenant_id}/admin/members`）・ゲスト招待作成（`/{tenant_id}/admin/invitations`。招待トークンを
  一度だけ表示）を追加し、web `api_client.rs` に対応するメソッドを配線した。テナント作成・削除の画面は
  MT14（設定画面）で追加する。

## 2026-07-11（MT11: 管理 API（tenants/users/members/invitations）+ テナント作成フロー）

- **テナント管理 API**（ADR-0009 §5・§6。`application::tenant_management::TenantManagementService`・
  `presentation::handlers::admin_tenants`）: `/{tenant_id}/admin/tenants`（GET/POST）・
  `/{tenant_id}/admin/tenants/{child_id}`（GET/PATCH/DELETE）を新設。`RequirePerms<IdpSystemAdmin>`
  （`idp.system.admin`）で保護し、実質 root テナントの system 管理者のみ作成・削除できる。取得・更新・
  削除は**直下の子テナントのみ**を対象とし、他テナントの子・不存在は 404。root は削除不可。配下に
  子テナント・ユーザー・クライアントが残る場合は 409（アプリ層検証 + FK `ON DELETE RESTRICT`）。
- **テナント作成フロー**（ADR-0009 §5）: 作成時に新テナントを所属元とする初期管理者ユーザーを自動生成し
  （自動生成パスワード・`must_change_password = true`）、新テナント scope の `idp.tenant.admin` を付与する。
  `generated_password` はレスポンスに一度だけ平文で返し、ログ・監査には出さない。作成者（root の
  system.admin）はテナント内部を操作できない（テナント独立）。
- **管理者による利用者作成**（ADR-0009 §5。`application::user_management::UserManagementService`）:
  `POST /{tenant_id}/admin/users`（`idp.tenant.admin` 必須）。パスワードを自動生成し `must_change_password`
  を付与、HOME メンバーシップを同時作成、`generated_password` を一度だけ返す。テナント作成フローの
  初期管理者生成もこのサービスを単一の出所とする。
- **メンバー・招待の HTTP エンドポイント**（ADR-0009 §3・§6。ユースケースは MT8 で実装済み）:
  `GET /{tenant_id}/admin/members`（HOME/GUEST 一覧）・`DELETE /{tenant_id}/admin/members/{user_id}`
  （ゲスト解除。HOME 不可）・`POST /{tenant_id}/admin/invitations`（招待作成。招待トークンを一度だけ返す）・
  `POST /{tenant_id}/invitations/accept`（承諾。`RequirePerms` ではなく `AuthenticatedUser` extractor で
  ログイン済み本人を解決）。招待トークン・生成パスワードは監査ログに出さない。
- **監査イベント追加**: `user.created`・`tenant.created`・`tenant.updated`・`tenant.deleted`（生成
  パスワード・招待トークンは reason に含めない）。

## 2026-07-10（MT9・MT10: `/{tenant_id}/...` ルーティング + TenantResolver mount + web テナント伝搬）

- **MT9 — api テナントルーティング**（ADR-0009 §6・§7）: テナントスコープの api エンドポイント
  （`authorize`/`token`/`userinfo`/`introspect`/`revoke`/`logout`/`.well-known/*`/`auth/register`/`admin/*`）を
  `/{tenant_id}/...` 配下へ再構成し、`resolve_tenant` middleware を `route_layer` で mount した。テナント外パス
  （`healthz`/`readyz`/`internal/*`/`api/docs`）はプレフィクス無しで据え置き。各ハンドラと `RequirePerms`
  extractor は `state.default_tenant` から**パス由来の `Extension<ResolvedTenant>`** へ移行し、要求テナントは
  URL から解決する。ネスト経路では `tenant_id` が先頭パスパラメータになるため、ドメインパラメータを取る
  ハンドラの `Path` 抽出子を `(tenant_id, ...)` タプルへ更新した。UUID 不正・未知・DISABLED は一律 404。
- **MT10 — contracts DTO + web api_client テナント対応**（ADR-0009 §8）: 内部認証 API の DTO
  （`InternalAuthenticate*`/`InternalConsent*`/`InternalVerifyTotp`/`InternalPasskeyLoginComplete`/
  `InternalLogout`）へ `tenant_id: Option<String>` を追加。api 内部ハンドラは DTO 由来テナントを使い、未指定は
  既定テナント（root）へフォールバックする（過渡期。`(tenant_id, email)` 一意化）。web `api_client.rs` は
  `/internal/root-tenant`（新設・サービストークン保護）で root テナント UUID を遅延解決・キャッシュし、
  `/{tenant_id}/admin/*` パスに前置する。
- **過渡期（web の画面テナント経路化＝MT13 まで）**: web の画面 URL・テンプレートは従来どおりフラット
  （`/login`・`/admin/console/*`）のままで、管理コンソールは root テナントを対象とする。api の
  `/{tenant_id}/authorize` は引き続き `/login`（web・フラット）へ 302 する。統合テスト・`scripts/e2e.sh` の
  ダイレクト api 呼び出しは `/{root_uuid}/...` へ追随した。

## 2026-07-10（MT8: 招待ユースケース + OIDC フローのメンバーシップ判定）

- **招待ユースケース**（ADR-0009 §3。`application::invitation::InvitationService`）:
  - **招待作成**: 参加先テナントの管理者が既存ユーザーをゲスト招待する。GUEST/INVITED メンバーシップを
    作成し、一度限りの平文トークンを返す（保存はハッシュのみ。ログ・監査には出さない）。既メンバー
    （HOME/GUEST/INVITED）は `AlreadyMember`、不存在ユーザーは `NotFound`。
  - **承諾**: 被招待ユーザー本人がログイン済みセッション + トークン提示で `ACTIVE` 化する。トークンが
    当該テナントの招待でない・期限切れ・不存在は一律 `InvalidOrExpired`、本人でなければ `Forbidden`。
  - **メンバーシップ解除**: ゲストを追放する。HOME は解除不可（`Forbidden`）。解除時に当該テナントを
    scope とする権限行も剥奪する（列挙 → 個別 revoke。権限キャッシュも invalidate）。
  - 監査イベント `tenant_invitation.created` / `.accepted` / `tenant_membership.revoked` を追加。
    HTTP エンドポイント（`/{tenant_id}/admin/invitations` 等）は MT11 で追加する。`AppState.invitations`
    に配線済み。招待 TTL は `INVITATION_TTL_SECS`（既定 7 日）。
- **OIDC フローのメンバーシップ判定**（ADR-0009 §8）: `AuthorizeService` の SSO 復元経路に、要求
  テナントの **ACTIVE メンバーシップ（HOME または GUEST）検証**を追加。メンバーシップのない SSO
  セッションは当該テナントのフローでは未認証として扱う（= ログインへ）。ゲストは所属元テナントで
  ログインしてホスト共有 SSO を確立し、参加先テナントのフローではこの判定で許可される。認証（ログイン）
  自体の所属元テナント限定は MT5 で導入済み。

## 2026-07-10（MT7: per-tenant issuer 合成 + WebAuthn RP ID の基底ホスト分離）

- **per-tenant issuer**（ADR-0009 §6。`domain::issuer::tenant_issuer`）: 発行トークン（ID/Access）・
  discovery・introspection・front-channel logout の `iss` を `<基底 issuer>/<tenant_id>` の canonical
  形式へ移行。基底 issuer は設定値（`config.issuer()`）由来で Host ヘッダから導出しない
  （host header injection 対策）。`TokenService`/`UserInfoService`/`IntrospectionService`/`LogoutService`
  は起動時固定 issuer を保持する構造から、リクエストの `TenantContext` を用いた**毎リクエスト合成**へ
  変更。リソースサーバ（userinfo/introspection）は要求テナントの合成 issuer と `iss`/`aud` を厳密照合し、
  他テナント発行トークンの流用を弾く。
- **WebAuthn RP ID の基底ホスト分離**: WebAuthn はプロトコル上ホスト単位でパスを含められないため、
  RP ID・origin は**基底 issuer のホスト**から導出する（per-tenant issuer は渡さない）。テナント分離は
  「クレデンシャル ⇔ ユーザー ⇔ 所属元テナント」のアプリ層の紐付けで実現する（`state.rs` に明示）。
- **過渡期（MT9 まで）**: ルーティングは未導入のため、各エンドポイントは既定テナント（root）で issuer を
  合成する（`iss` = `<基底>/<root_uuid>`）。MT9 でパス由来 `ResolvedTenant` へ置き換える。

## 2026-07-10（MT6: 汎用 TTL キャッシュ抽象 + TenantResolver + 権限解決のキャッシュ化）

- **汎用 TTL キャッシュ抽象**（ADR-0009 §7）: `domain::cache::Cache<K, V>` trait（`get`/`insert`/
  `invalidate`）と `infrastructure::cache::InMemoryTtlCache`（TTL 判定・`get` 時の期限切れ遅延削除、
  `Clock` 注入でテスト可能）を新設。`InMemoryLoginRateLimiter` と同様に trait 越しに注入し単体
  インスタンス前提、スケールアウト時は共有ストア実装へ差し替える。用途ごとに別インスタンス（別キー
  空間）を注入する。TTL は `TENANT_CACHE_TTL_SECS`／`PERMISSION_CACHE_TTL_SECS`（既定 60 秒）。
- **scope→権限解決のキャッシュ化**: `CachedUserPermissionRepository` デコレータが `has_permission`
  の判定結果を TTL キャッシュし、`grant`/`revoke` 時に該当キー（`(tenant_id, user_id, code)`）を
  即時 invalidate する。`AppState::build` で `SqlxUserPermissionRepository` をラップし、判定
  （`AdminAccessService`）と変更（`PermissionManagementService`）が同一インスタンスを共有するため
  付与直後の反映漏れ（stale allow/deny）が起きない。
- **TenantResolver middleware**（ADR-0009 §7）: `application::tenant_resolution::TenantResolutionService`
  が id → tenant を TTL キャッシュ（テナント実体を格納し、有効性は取り出し後に判定）付きで解決し、
  `presentation::tenant` に `ResolvedTenant` 型と axum middleware `resolve_tenant` を追加。パスの
  `:tenant_id` を UUID として解決し、UUID 不正・未知・`DISABLED` は一律 404、`ACTIVE` は
  `Extension<ResolvedTenant>` を注入する。root も同一経路で解決し特別分岐なし。
- **過渡期（MT9 まで）**: `/{tenant_id}/...` ルーティングは未導入のため本 middleware はまだルーターへ
  mount せず、api は引き続き `AppState::default_tenant`（root）を全リクエストへ適用する。`Cache` 基盤と
  解決サービスは `AppState`（`tenant_resolution`）へ配線済みで、MT9 が middleware をテナントルート群へ
  付与し、`RequirePerms` の要求テナントを `default_tenant` からパス由来 `ResolvedTenant` へ置き換える。

## 2026-07-10（MT5: 全 Repository trait／ユースケースへ tenant_id 追加 — テナント分離の強制）

- **Repository trait のテナントスコープ化**（ADR-0009 §8。MariaDB に RLS がないため、アプリ層が
  唯一の分離防御線）: テナントスコープのテーブルを参照・検索するメソッドへ `tenant_id: TenantId`
  を追加し、sqlx 実装は必ず WHERE 句へ含める（`users` の `(tenant_id, email)` 検索、
  `clients` の `(tenant_id, client_id)` 解決・一覧・更新、auth session／authorization code／
  refresh token／consent／user_permissions／監査ログ参照）。グローバル一意キーによる本人解決
  （`users.id`/`sub`）・SSO セッション（ホスト単位共有）・ユーザー単位の全失効・テナント列を
  持たないテーブルは意図的に除外（根拠は `domain/repositories.rs` のモジュールコメント）。
- **ユースケースの `TenantContext` 対応**: 全サービスの公開メソッドが `TenantContext` を受け取り、
  リポジトリ呼び出しへ必ず伝搬。認証（ログイン・管理ログイン）のユーザー検索は所属元テナント限定、
  認可コード・refresh token の消費／検索は発行テナント一致必須。ドメインモデル
  （`User`（+`must_change_password`）・`Client`・`AuthSession`・`AuthorizationCode`・`RefreshToken`・
  `ClientConsent`・監査イベント）へ `tenant_id` を追加し、監査ログはテナント単位で追跡可能にした。
- **登録時の HOME メンバーシップ自動生成**（ADR-0009 §3）: `RegisterService` がユーザー作成と同時に
  `tenant_memberships` へ HOME/ACTIVE 行を投影する。
- **管理権限を ADR-0009 §4 の完全一致判定へ移行**: `idp.admin` を廃し、`RequirePerms<IdpAdmin>` は
  「要求テナントを scope に持つ `idp.tenant.admin`」の完全一致で判定（`idp.system.admin` は root
  scope のみ存在し root 自身の管理を含むため代替として許可）。`idp.system.admin` の付与・剥奪は
  保有者のみ実行可能（アプリ層で強制。DB の CHECK 制約と二重防御）。
- **過渡期（MT9 まで）の既定テナント**: api は起動時に root テナントを解決（fail-fast）し、
  `AppState::default_tenant` として全リクエストへ適用する。MT9 で `TenantResolver`／パス由来の
  解決へ置き換える。
- DB 統合テスト（`register`／`oidc_flow`／`internal_auth`／`admin_*`）と `scripts/e2e.sh` を
  新スキーマへ追随（root UUID・初期管理者 UUID は動的採番のため DB から解決）。初回ログインは
  F3 の設計どおり同意画面を経由する検証に修正した。e2e.sh はローカル mariadb/mysql クライアントへの
  フォールバックと、WebAuthn RP ID 制約（IP 不可）に伴う `ISSUER=http://localhost:8080` 化を含む。

## 2026-07-10（MT3・MT4: UUIDv7 生成の集約 + Tenant/TenantMembership ドメイン基盤）

- **MT3 — UUIDv7 導入**: `uuid` crate に `v7` feature を追加。エンティティ主キーの生成を
  `domain::id_generator::IdGenerator` トレイト（`infrastructure::id_generator::UuidV7Generator` が
  `Uuid::now_v7()` で実装）へ集約し、`RegisterService`（`User.id`/`sub`）・`ClientManagementService`
  （`Client.id`）・`PasskeyRegistrationService`（`WebAuthnCredential.id`）へ Clock と同様に注入した。
  `jti`／`correlation_id`／`csrf_id`／`PasskeyChallenge.id` 等の揮発トークンは時刻順序性が不要かつ
  生成時刻を露出させたくないため v4 のまま維持する（ADR-0009 §12）。
- **MT4 — テナントのドメイン基盤**: `domain::tenant::{Tenant, TenantId}`・
  `domain::tenant_membership::TenantMembership` エンティティと、`domain::tenant_context::{TenantContext,
  TenantScope}` 値オブジェクト（`TenantScope::matches` で「要求テナント ID と scope の完全一致」判定。
  祖先・配下は考慮しない。ADR-0009 §4）を追加。`domain::repositories::{TenantRepository,
  TenantMembershipRepository}` トレイトと sqlx 実装（`SqlxTenantRepository`／
  `SqlxTenantMembershipRepository`）を追加した。既存の Repository trait／ユースケースへの
  `tenant_id` 波及（MT5）はまだ行っていない。

## 2026-07-10（MT1・MT2: マルチテナントのデータ基盤 — 初期 DDL・seed の刷新）

- **初期マイグレーションを ADR-0009 の定義で全面刷新**（既存 0001〜0012 を廃棄し
  `0001_baseline` + `0002_seed_master_data` へ。全環境 DB 再作成が必要 —
  手順は `docs/OPERATIONS.md`「DB を作り直したいとき」）。
  - `tenants`（`is_root` 番兵列 + UNIQUE で **root を DB レベルで高々 1 行に担保**）・
    `tenant_memberships`（HOME/GUEST・招待トークンハッシュ）を新設。
  - `users`（`tenant_id`＝所属元・`must_change_password`・テナント内一意の email/username）・
    `clients`（テナント内一意の `client_id`）・`user_permissions`（主キーへ scope=`tenant_id`）・
    `auth_sessions`/`authorization_codes`/`refresh_tokens`/`client_consents`
    （`(tenant_id, client_id)` 複合外部キー）・`audit_log`（`tenant_id`）を再定義。
    `sso_sessions` はホスト共有のため tenant なし（境界はメンバーシップ検証。ADR-0009 §8）。
  - MariaDB 10.11 は索引付き生成列で `IF()`/`CASE` を許可しない（ERROR 1901）ため、
    番兵列の式は `(parent_tenant_id IS NULL) OR NULL` とした（ADR-0009 の DDL 例も修正）。
- **seed（冪等）**: root テナントを **UUIDv7 で投入時に動的採番**（固定リテラル廃止）。
  `idp.system.admin` の scope=root を縛る CHECK 制約は解決済み root UUID をリテラル化して
  `PREPARE`/`EXECUTE` で付与（ファイルは静的・チェックサム全環境一致）。権限コード
  （`idp.system.admin`/`idp.tenant.admin`）と初期管理者（root 所属・HOME メンバーシップ・
  `must_change_password=1`・`idp.system.admin` を DB 直接付与）を投入。
  `scripts/init.sh` が root UUID を標準出力へ記録する。
- **統合テスト `schema.rs` を刷新**: 全テーブル存在・seed 検証に加え、negative test
  （2 つ目の root 挿入拒否・`idp.system.admin` の非 root scope 付与拒否・同一テナント内
  email 重複拒否とテナント跨ぎ許容）を MariaDB 10.11 実機で検証。

## 2026-07-10（ADR-0009 再改訂: テナント独立モデル・Entra ID 型）

- **権限 scope のサブツリー伝播を廃止し、完全一致判定へ変更**。各テナントは独立した管理境界であり、
  root（system.admin）はテナントを作成できるが内部は操作できない。機能・URL は root 含め全テナント
  一律で、差は「必要な権限を付与できるユーザーが存在するか」のみ。
- **UUIDv7 を採用**（エンティティ主キー。揮発トークンは v4 のまま）。root テナントの固定 UUID
  （`00…0`）を廃し**投入時に動的採番**。`idp.system.admin` の scope = root を縛る CHECK 制約は、
  投入時に解決した root UUID をリテラル化して付与（`PREPARE`/`EXECUTE`）＋アプリ層で二重に強制し、
  `tenants` の単一 root は生成列 `is_root` + UNIQUE で担保する。
- **招待とメンバーシップ（`tenant_memberships`）を新設**。ユーザーの所属元は 1 テナントに限定し、
  他テナントへは招待（ゲスト）で参加する。ゲストのユーザー状態（パスワード・status・MFA 等）は
  参加先の管理者でも操作できず、所属元テナントと本人のみが管理する。認証は所属元テナントでのみ行い、
  参加先はホスト共有 SSO セッション + メンバーシップ判定で許可する。
- **マイグレーション方針を変更**: 段階的 expand/contract を廃し、初期 DDL・マスタデータを
  マルチテナント対応の定義で全面刷新して既存データは破棄する（全環境 DB 再作成。MVP 期の一度限り）。

## 2026-07-10（ADR-0009 改訂: マルチテナントアーキテクチャ）

- **ADR-0009 をレビューに基づき改訂**。`/root` エイリアスと `/admin` 横断名前空間を廃止し、
  root 含め URL を `/{tenant_id}/...` に完全一律化。権限判定を「要求テナントが権限 scope の
  サブツリー（祖先包含）に含まれるか」の一律判定へ一本化。
- レビュー指摘の反映: SSO セッションのテナント境界（認証は帰属テナント・認可は scope 判定、
  OIDC フローでは帰属テナント一致を検証）、api/web 分割（ADR-0007）との整合（contracts DTO へ
  `tenant_id` 追加）、WebAuthn RP ID はホスト単位でパスを含められない制約、`idp.system.admin` の
  scope = root 強制（CHECK 制約）、DISABLED の階層伝播、追加マイグレーション方式
  （ベースライン書き換え禁止・expand/contract）、テナント削除条件の文言修正 ほか。

## 2026-07-08（F4: Logout / F5: Token 管理）

- **F4 — RP-initiated Logout（設計仕様 §9.3 / OIDC RP-initiated Logout 1.0）**:
  - `clients` テーブルに `post_logout_redirect_uris`（JSON）、`frontchannel_logout_uri`、
    `backchannel_logout_uri`（VARCHAR）を追加（migration 0008）。
  - `LogoutService`: SSO セッション・関連 auth session・有効な authorization code を失効させ、
    back-channel 通知対象（`backchannel_logout_uri` を持つ client）と front-channel URI 一覧を返す。
  - `GET /logout`: SSO Cookie を失効させ、back-channel logout token（`logout+jwt`）を非同期 POST、
    front-channel logout 用 iframe HTML を返す（または `post_logout_redirect_uri` へ 302）。
  - Discovery に `end_session_endpoint`、`frontchannel_logout_supported`、`backchannel_logout_supported` を追加。

- **F5 — Token Revocation / Introspection（RFC 7009 / RFC 7662）**:
  - `revoked_access_tokens` テーブルを追加（migration 0009）。`jti` を PK として JTI ブロックリストを実現。
  - `RevocationService`: Refresh Token（DB の `revoked_at`）と Access Token（JTI ブロックリスト）の両方を
    失効させる。RFC 7009 §2.2 準拠: 失効済み・不存在でも 200 を返す。
  - `IntrospectionService`: confidential client 専用。Access Token（署名検証 + JTI ブロックリスト）と
    Refresh Token（DB 有効性確認）をイントロスペクトし `{ "active": true/false }` を返す。
  - `POST /revoke`（RFC 7009）、`POST /introspect`（RFC 7662）エンドポイントを追加。
  - `UserInfoService` も JTI ブロックリストを確認するよう更新。
  - Discovery に `revocation_endpoint`、`introspection_endpoint` を追加。

## 2026-07-08（F2: Refresh Token）

- **F2 — Refresh Token（設計仕様 §9.1）**:
  - `refresh_tokens` テーブルを追加（migration 0006）。`token_hash = SHA-256(plain_token)` で保存。
    `parent_hash` で rotation チェーンを追跡し reuse detection に使う。
  - `Scope::OfflineAccess`（`offline_access`）を追加。authorization_code フローで `offline_access`
    を要求した場合のみ Refresh Token を発行する。
  - Refresh Token rotation を実装: `POST /token?grant_type=refresh_token` で旧トークンを失効させ
    新トークンを発行する。TTL は旧トークンから引き継ぐ（スライドさせない）。
  - Reuse detection: 同一 token_hash から二重発行を検知した場合は `invalid_grant` を返し
    旧トークンも失効させる（`refresh_token.reuse_detected` 監査ログを記録）。
  - Discovery に `offline_access` scope と `refresh_token` grant type を追加。
  - 設定: `REFRESH_TOKEN_TTL_SECS`（既定 2592000 = 30 日）。

## 2026-07-08（K2: 署名鍵自動ローテーション / S1: SSL アクセラレーター対応）

- **K2 — 署名鍵自動ローテーション**: `KeyService::rotate_if_needed(lead_days)` を追加。
  ACTIVE 鍵の `not_after` まで `KEY_ROTATION_LEAD_DAYS`（既定 30 日）を切った際に新鍵（同アルゴリズム）を
  自動生成し旧鍵を RETIRED に変更する。`lib.rs` で tokio バックグラウンドタスクを起動時に spawn し、
  1 時間ごとに実行する。RETIRED 鍵は `not_after` 経過後に自動的に JWKS 非公開となる（既存挙動）。
  設定: `KEY_ROTATION_LEAD_DAYS`（日数、既定 30）。
- **S1 — SSL アクセラレーター/リバースプロキシ対応**:
  - `TRUST_FORWARDED_HEADERS`（bool、既定 `false`）を追加。有効時のみ `X-Forwarded-For` を信頼して
    実 IP を監査ログ・IP レート制限に使う。未設定時はヘッダを無視（ヘッダ偽装対策）。
  - `HSTS_MAX_AGE`（秒、既定 `0` = 無効）を追加。正値のとき `Strict-Transport-Security: max-age=N`
    をすべてのレスポンスに付与する。
  - セキュリティヘッダミドルウェア（`security_headers.rs`）を新設。全レスポンスに
    `X-Content-Type-Options: nosniff`・`Referrer-Policy: strict-origin-when-cross-origin`・
    `X-Frame-Options: DENY` を付与する。

## 2026-07-08（K1: 署名鍵管理 — ES256 対応・管理 API・管理コンソール）

- **EC(ES256) 対応**: `signing_keys.algorithm` の CHECK 制約に `ES256` を追加（migration 0005）。
  `p256` クレートを追加し、`infrastructure/jwt.rs` を RS256/ES256 両対応に書き換え（`Jwk` の `n`/`e` を
  `Option` 化、EC 用の `crv`/`x`/`y` フィールドを追加、`generate_ec_keypair()`・`ec_public_jwk()` 新設）。
- **複数鍵署名 / JWKS `not_after` フィルタ**: `list_published` を `not_after > UTC_TIMESTAMP(6)` 条件に修正。
  `Domain` 層の `SigningAlgorithm` enum を新設（`Rs256`/`Es256`）。`ActiveSigningKey` に `algorithm` フィールドを追加。
- **管理 API（`/admin/signing-keys`）**: `list_keys`・`generate_key`・`retire_key`・`delete_key` ハンドラを追加。
  `SigningKeyRepository` トレイトを `list_all`・`update_status`・`delete` で拡張し、sqlx 実装を追加。
  `KeyManagementError` を定義し `key_service.rs` に admin ユースケースを追加。
- **管理コンソール画面**: `crates/web` に `/admin/console/signing-keys` 画面を追加（一覧/生成/退役/削除）。
  Askama テンプレート `signing_keys.html`、`admin_dto.rs` の `SigningKeyView`、`api_client.rs` の
  4 メソッド、ハンドラ `admin_signing_keys_console.rs`（`list`・`generate`・`retire`・`delete`）を実装。
  ホーム画面ナビに署名鍵管理リンクを追加。i18n（`en`/`ja` `.ftl`）を追加。



- **web の HTML をコード生成から Askama テンプレートへ移行**。web crate の全画面（利用者ログイン・
  管理コンソール: ホーム/ログイン/クライアント一覧・登録/編集・詳細・secret 表示/利用者検索・権限/
  監査ログ/クライアント状況/共通レイアウト・告知）で `format!` による HTML 組み立てを廃し、
  `crates/web/templates/` 配下の `.html`（`console/layout.html` を継承）へ集約した。テンプレートは
  `.html` 拡張子により `{{ }}` 出力が自動 HTML エスケープされるため、手動エスケープの `html.rs`
  （`escape`）を削除。Askama のコンパイル時型検証で描画の型安全を担保（sqlx のコンパイル時クエリ検証と
  同じ思想）。外形（フォーム項目・CSRF 埋め込み・エスケープ）は不変で、web の全テスト・E2E 経路は維持。
  （エスケープは名前付き実体参照 `&lt;` から数値文字参照 `&#60;` へ変わるが XSS 安全性は同等。）
- **ビルド／デプロイのホスト分離**。ソースがある「ビルド側」と稼働する「デプロイ先」を別ホストとして扱う
  構成に整理した。`scripts/build.sh`（ビルド側）はネイティブ binary／Docker イメージのビルドと
  検証（`--check` = fmt/clippy/test）を行い、**コンテナは起動しない**。イメージ受け渡しはレジストリ
  （`--push`）と tar（`--save`）の両対応。デプロイ先用に `docker-compose.deploy.yml`（`build:` を持たず
  `image:` 参照のみ）を追加し、`init.sh`（初回・DB コンテナ新規作成）／`deploy.sh`（更新）は
  **ソースを持たずビルドせず**、`pull`／`docker load` 済みイメージで起動する。イメージ名は
  `${IMAGE_PREFIX:-idp}/{api,web,migrate}:${IMAGE_TAG:-latest}`（`.env` で設定）。`scripts/README.md`・
  `docs/OPERATIONS.md` を分離構成へ更新。

## 2026-07-06（C1 完了: API/Web サービス分割 — P5 テスト再編・E2E）

- **C1（コンテナ分離）完了**。ADR-0007 の理想形（真のサービス分割）を P0〜P5 まで実装。api（OIDC
  protocol・JSON 管理 API・内部 API・DB 唯一の所有者）と web（全 HTML 画面・API クライアント・DB 非依存）
  を cargo workspace（`core`/`contracts`/`api`/`web`）＋別コンテナ＋単一オリジンのリバースプロキシで分離。
- **P5 テスト再編**。api 単体統合テスト（`oidc_flow` は `/internal/authenticate` 駆動）＋web→api の自動
  E2E ハーネス `scripts/e2e.sh` を新設。e2e はapi・webを別プロセスで起動し、`/authorize`→web `/login`→
  `/token` の OIDC フローと管理コンソール（ログイン・クライアント作成・権限付与・状況/監査）を
  ブラウザ相当の HTTP で通す（実 MariaDB で全項目パスを確認）。
- 外部から見た OIDC 契約（`docs/OIDC_INPUT.md`）は分割の前後で不変。

## 2026-07-06（C1 P3-4・P4 完了: api の HTML 撤去とサービス分離 Compose）

- **api から HTML を撤去**（P3-4）。ログイン画面・管理コンソール 4 画面・i18n・html・`AdminHtmlSession`
  を削除し、api は OIDC protocol・JSON 管理 API・内部 API のみに。JSON 401/403 を返す
  `RequirePerms<IdpAdmin>` は残す。`/login`・`/admin/console/*` ルートを削除。core の未使用
  `admin_csrf_token` を削除。api 統合テストを再編（`oidc_flow` は `/internal/authenticate` 駆動へ、
  HTML 画面テストは web へ移動）。全テスト緑（fresh MariaDB）。
- **api / web / proxy の Compose 分離**（P4、ADR-0007 §2）。Dockerfile を 1 ワークスペース→2 バイナリ
  （`idp`＝api、`idp-web`＝web）＋2 実行ステージ（`runtime-api`・`runtime-web`）に。`docker-compose.yml`
  を `api`（DB 直結・非公開）／`web`（DB 非依存・非公開）／`proxy`（nginx。単一オリジンでパスルーティング）
  へ再構成。`docker/nginx.conf`: `/login`・`/admin/console/*`→web、`/internal/*` 遮断、他→api。
  `INTERNAL_SERVICE_TOKEN` を api・web で共有（`init.sh` が乱数生成、Compose が必須化）。`init.sh`・
  `deploy.sh`・`OPERATIONS.md`・`.env.example` を分離構成へ更新。
  （注: Docker イメージのビルドはサンドボックスの egress 制限〔apt ミラー 405〕で本環境では検証不可。
  ワークスペースはホスト cargo で両バイナリともビルド・実機起動を確認済み、compose config は妥当。）

## 2026-07-06（C1 P3-2 完了: ログイン画面を web crate へ移設）

- **ログイン画面（`/login` GET/POST）と i18n を `web` crate へ移設**（ADR-0007 P3-2）。web はフォーム描画と
  リダイレクトのみを担い、資格情報検証・SSO/code 発行は api の `POST /internal/authenticate` に委ねる。
  web は接続元情報（`X-Forwarded-For` 由来 IP・User-Agent）を転送し、成功時に api が返す `sso_session_id` を
  Cookie 化して `redirect_to` へ 302、`auth_session_id` Cookie を失効させる。エラーはローカライズして再描画。
- **ログイン CSRF 導出を `contracts` に一元化**（`idp_contracts::csrf::login_csrf_token`）。web（フォーム描画）と
  api（`LoginService` 検証）で同一導出を共有し、固定ベクタのユニットテストで齟齬を防ぐ。core は本関数へ委譲。
- web に i18n・cookies・correlation・login ハンドラを実装（api の presentation から移植）。api 側の `/login` は
  当面併存（全部入り E2E 維持のため。撤去は P3-4）。
- 検証: `cargo build`／`clippy` 警告なし／lib テスト（api 31・core 45・contracts 2・web 7）。**api＋web＋MariaDB を
  同時起動した実機 E2E**で、api `/authorize` →（別プロセスの）web `/login` GET/POST → api `/internal/authenticate`
  → SSO Cookie 発行＋`code` 付き RP リダイレクト → api `/token` で `id_token` 発行、まで疎通を確認。web が転送した
  IP が `sso_sessions.ip_address` に記録されることも確認。

## 2026-07-06（C1 P3-1 完了: contracts crate ＋ web crate 土台）

- **`contracts` crate（`idp-contracts`）を新設**（ADR-0007 §6）。内部認証 API（`/internal/authenticate*`）の
  DTO を api の presentation から移設し、**api サーバと web クライアントで同一の serde 型を共有**する
  （コンパイル時に契約整合を保証）。DB/axum/sqlx へは依存しない。
- **`web` crate（`idp-web` / bin=`idp-web`）を新設**。web 固有設定（`API_BASE_URL`・共有サービストークン・
  `WEB_BIND_ADDR` 等）、JSON ログ初期化、**reqwest ベースの API クライアント**（api への唯一の出入口。
  内部認証呼び出しにサービストークンと correlation_id を付与）、ヘルスチェック（`/healthz` liveness、
  `/readyz` は api への到達性で判断）を実装。
- **web は sqlx / idp-core に依存しない**ことを `cargo tree` で確認（crate 境界で分離を強制。ADR の肝）。
  api は無変更で全テスト緑。web バイナリの起動と `/healthz`=200・`/readyz`=503（api 停止時）を実機確認。
- P3 は規模が大きいためステージ分割で進める（本コミットは土台）。ログイン画面・管理コンソール・i18n の
  web 移設と、api からの HTML 撤去は後続ステージ。テスト再編は P5。

## 2026-07-06（C1 P2 完了: 内部認証 API）

- **内部認証エンドポイントを api に新設**（ADR-0007 §3・§5、C1 の P2）。OIDC 標準外の
  `POST /internal/authenticate`（OIDC ログイン）と `POST /internal/authenticate/admin`（管理コンソール）。
  将来の `web` crate が資格情報・`auth_session_id` 参照・接続元情報（IP/User-Agent）を JSON で転送し、api が
  既存の `LoginService`／`AdminLoginService`（資格情報検証・ロックアウト §4.3・IP レート制限・SSO/code 発行・
  監査）を実行して `result` タグ付き JSON を返す。Cookie 組み立て（Secure/HttpOnly/SameSite/TTL）とエラー
  文言のローカライズは呼び出し側（web）の責務。
- **サービス認証トークンで `/internal/*` を保護**（§5）。`X-Internal-Auth-Token` ヘッダを設定
  `INTERNAL_SERVICE_TOKEN`（未設定時は開発用の既定値＋起動時警告）と定数時間比較し、不一致は 401。
  `route_layer` で内部サブルータのみに適用（外部公開しない前提。リバースプロキシ遮断は P4）。
- 内部 DTO は presentation（`dto.rs`）に定義し `result` で判別（`contracts` crate 化は P3）。既存 HTML
  `/login`・`/admin/console/login` は同一プロセスのため引き続きユースケースを直接呼ぶ（API クライアント化は
  P3）。外部から見た OIDC 契約（§4.2）は不変。`docs/OIDC_INPUT.md` §4.3 に実装メモを追記。
- 検証: `cargo build`／`cargo clippy`（警告なし）／ユニットテスト（内部認証 3 件を追加）／MariaDB 実 DB での
  統合テスト `tests/internal_auth.rs`（トークン 401・CSRF 不一致・認証成功で SSO/code 発行・管理認証失敗）と
  既存 E2E（`oidc_flow` 等）を確認。

## 2026-07-06（ADR-0007 Accepted・C1 P1 完了: cargo workspace 化）

- **ADR-0007（API/Web サービス分割）を Accepted** とし、C1 の **P1（workspace 化）** を実施。単一クレート
  `idp` を **cargo workspace** に分割した。`crates/core`（lib=`idp_core`）に domain/application/
  infrastructure と config/telemetry（sqlx・DB 依存）を集約し、`crates/api`（lib=`idp_api` / bin=`idp`）に
  presentation と `run()` を置く。api は core を再エクスポートするため presentation 内の `crate::domain` 等の
  参照は不変。共通依存は `[workspace.dependencies]` で一元管理。
- **all-in-one を保ったままの crate 境界作成**（P1 の方針どおり。web/contracts crate と Web→API HTTP 化は
  後続 P2〜P5）。統合テストは `crates/api/tests/` へ移設（参照は `idp_api::*`）。`migrations/`・`i18n/` は
  リポジトリルート据え置きで、`sqlx::migrate!("../../migrations")`／`include_str!(CARGO_MANIFEST_DIR/../../i18n)`
  により crate から相対参照する。Dockerfile の builder を workspace ビルドへ更新（bin=`idp` は不変）。
- 検証: `cargo build --workspace`／`cargo clippy --workspace --all-targets`（警告なし）／lib ユニットテスト
  45 件パス。外部契約（OIDC・API 経路・バイナリ名）に変更なし。

## 2026-07-06（A3 完了: 状況確認画面）

- **状況確認画面をサーバレンダリングで実装**（A3 完了、設計仕様 §7）。監査／ログインログ一覧
  （`/admin/console/audit-logs`）とクライアント状況一覧（`/admin/console/status`）を追加。画面用
  extractor `AdminHtmlSession` で保護し、共通レイアウト `render_layout`（A2）の上に描画。JSON 管理 API
  （`GET /admin/audit-logs`、OpenAPI の正典）とは経路を分離。ホームから両画面へリンク。
- **監査ログ一覧画面**: `event_type`／`result`（`failure` 等のエラー絞り込みが主眼）／`client_id`／
  `correlation_id`／期間（`from`/`to`、RFC3339）で AND 絞り込みし、新しい順に表示。`offset` による前後
  ページ移動（フィルタ条件は URL エンコードで引き継ぐ）。日時形式が不正なら検索せずエラー表示。データ取得は
  API と同じ `AuditQueryService` を通す（読み取り専用のため CSRF は無い）。
- **クライアント状況一覧画面**: 各クライアントの状態（ACTIVE/DISABLED）・scope・**最終利用時刻**を表示。
  最終利用時刻は `audit_log`（成功した `token.issued`／`authorization_code.issued` の最新 `occurred_at`）
  から導出する（マイグレーション不要・書き込み経路への影響なし）。Application に読み取り専用の
  `ClientStatusService`（`ClientRepository` × `AuditLogQuery`、変更を担う `ClientManagementService` とは
  SRP で分離）を新設し、`AuditLogQuery::last_used_per_client`（client_id 別の最新利用時刻を 1 回の集計で取得）
  を追加。
- 単体テスト（監査行のエスケープ・失敗行の強調・空/日時エラー表示・ページャ・クエリ文字列のエンコード・
  状況一覧の最終利用時刻／未利用の `-`、サービスの突き合わせ）と統合テスト `tests/admin_status_console.rs`
  （未認証→ログイン画面へ 302、非管理者→403、状況一覧で最終利用時刻表示、監査一覧の絞り込み・不正日時→
  エラー）を追加。

## 2026-07-06（A2 完了: 利用者権限の付与・剥奪画面）

- **利用者権限の付与・剥奪のサーバレンダリング画面を実装**（A2 完了、ADR-0006）。`/admin/console/users*` に
  利用者検索（メール／ユーザー名）・保有権限の一覧・付与フォーム（付与可能コードの datalist 付き）・
  剥奪ボタンを提供。画面用 extractor `AdminHtmlSession` で保護し、共通レイアウト `render_layout`（A2）の
  上に描画する。データ操作は JSON API と同じ `PermissionManagementService` を通し、検証・監査記録を二重化しない。
- **経路分離**: ブラウザ向けコンソールは `/admin/console/users*`、JSON 管理 API（OpenAPI の正典）は
  `/admin/users/{user_id}/permissions` のまま。付与・剥奪の POST は Post/Redirect/Get で権限画面へ 302 し、
  失敗（CSRF 不一致・未知コード等）は `error` クエリで伝える（二重送信の回避）。CSRF は SSO セッション id
  由来の同期トークン `console_csrf_token`。利用者入力は `presentation::html::escape` を通し格納型 XSS を防止。
- Application の `PermissionManagementService` に画面用の読み取り（識別子→利用者解決 `find_user_by_identifier`・
  表示用 `get_user`・付与可能コード一覧 `available_codes`）を追加。付与可能コードは `permissions` マスタを
  単一の出所とし、`UserPermissionRepository::list_available_codes` で取得する（許可値の直書き重複なし）。
- 単体テスト（検索結果／権限画面のレンダリングと HTML エスケープ・エラークエリ→i18n キー写像・
  リダイレクト先の検証、サービスの識別子解決／付与可能コード）と統合テスト `tests/admin_users_console.rs`
  （未認証→ログイン画面へ 302、非管理者→403、メール／ユーザー名検索、CSRF 不一致・未知コード→302 error、
  付与／剥奪の 302 と `audit_log` 記録、不存在・非 UUID→404）を追加。

## 2026-07-06（A1: クライアント（RP）管理画面、A2 コンソール基盤の上に実装）

- **クライアント（RP）管理のサーバレンダリング画面を実装**（A1 完了、設計仕様 §9.3）。一覧・新規登録・
  詳細・編集・secret 再発行・無効化（状態 DISABLED）を `/admin/console/clients*` で提供。画面用 extractor
  `AdminHtmlSession` で保護し、共通レイアウト `render_layout`（A2）の上に描画する。データ操作は JSON API と
  同じ `ClientManagementService` を通し、検証・監査記録・secret 発行のロジックを二重化しない。
- **経路分離**: ブラウザ向けコンソールは `/admin/console/*`、JSON 管理 API（OpenAPI の正典）は
  `/admin/*` に整理。これに伴い前コミットの A2 コンソール（ログイン/ホーム/ログアウト）も `/admin/console/*`
  へ移設（`/admin/console/login`・`/admin/console`・`/admin/console/logout`）。
- **セキュリティ**: 利用者入力を HTML へ差し込む箇所は新設の `presentation::html::escape` を通し格納型 XSS を防止。
  ログイン後の状態変更フォームは SSO セッション id 由来の同期トークン `console_csrf_token` で CSRF 対策。
  `client_secret` は confidential の作成・再発行時に**その画面でのみ**平文表示（DB はハッシュのみ）。
- 単体テスト（入力パース・HTML エスケープ・一覧のエスケープ・CSRF 導出）と統合テスト
  `tests/admin_clients_console.rs`（未認証→ログイン画面へ 302、CSRF 不一致・不正 scope→400、
  confidential 作成で secret 一度表示、詳細・編集で DISABLED 反映、secret 再発行、不存在→404、非管理者→403）を追加。

## 2026-07-06（A2: 管理コンソール基盤 UI・管理ログイン、ADR-0006 §6）

- **管理コンソールのサーバレンダリング基盤 UI を実装**（A2、ADR-0006 §6）。管理ログイン
  （`GET/POST /admin/console/login`）・ホーム（`GET /admin/console`）・ログアウト（`POST /admin/console/logout`）を追加。
  文言は既存ログイン画面と同じ `fluent`（en/ja）。
- 管理ログインは OIDC クライアント不要で **SSO セッションを直接発行**する（`/authorize` 由来の
  `auth_session_id`・code 発行・redirect を伴わない）。初回デプロイ時にクライアントが存在しなくても
  コンソールへ入れる（鶏卵問題の回避）。資格情報検証・ロックアウト（§4.3）・IP レート制限は通常ログインと
  同方針で、レート制限器は共有。`idp.admin` 非保有の正当利用者は Forbidden（SSO 非発行）。CSRF は同期
  トークン方式（GET で `admin_csrf_id` Cookie を発行し一方向ハッシュをフォームへ埋め込む）。
- Application に `AdminLoginService`（ログイン／ログアウト。ログアウトは `sso_session.terminated` を監査）、
  Presentation に画面用の認可 extractor `AdminHtmlSession`（未認証→ログイン画面へ 302／権限不足→403 HTML。
  API 用 `RequirePerms<IdpAdmin>` の JSON 401/403 と使い分け）と共通レイアウト `render_layout`
  （A1/A3 の画面はこの上に差し込む）を追加。監査は既存種別のみ使用（§7 の追加なし）。
- 単体テスト（CSRF 導出の決定性・名前空間分離、フォーム／レイアウトのレンダリングと i18n）と統合テスト
  `tests/admin_console.rs`（ログイン画面→CSRF 発行、未認証ホーム→302、CSRF 不一致→400、正当ログイン→
  SSO 発行→ホーム 200→ログアウトで失効、非管理者→403）を追加。

## 2026-07-06（A2: 利用者権限の付与・剥奪 API）

- **利用者権限の付与・剥奪 API を実装**（管理コンソール基盤 A2、ADR-0006、設計仕様 §7）。
  `/admin/users/{user_id}/permissions` の付与（`POST`）・剥奪（`DELETE {permission_code}`）・参照（`GET`）
  （`RequirePerms<IdpAdmin>`）。付与は冪等、未知の権限コードは 400、対象利用者不存在は 404、
  `user_id` が UUID でなければ 400。応答は操作後の保有権限コード一覧。
- 参照（保護判定）の `AdminAccessService` と責務を分離（SRP）し、管理（変更）用の
  `PermissionManagementService`（Application）を新設。付与・剥奪を `AuditEventType::UserPermission*`
  （`user_permission.granted` / `.revoked`、actor を `user_id`・対象と権限コードを `reason` に記録）
  として `audit_log` へ出力する結線を追加。DTO（`GrantPermissionRequest` / `UserPermissionsResponse`）と
  `admin_permissions` ハンドラを追加し OpenAPI（tag `admin`）へ掲載。単体テスト（付与/剥奪の監査記録・
  空/未知コード・対象不存在）と統合テスト `tests/admin_permissions.rs`（401/403/400/404・付与/剥奪・
  冪等・監査記録）を追加。

## 2026-07-06（A3: 監査/ログイン ログ参照 API）

- **監査ログ参照 API を実装**（状況確認画面 A3、設計仕様 §7）。`GET /admin/audit-logs`
  （`RequirePerms<IdpAdmin>`）で `audit_log` を `event_type` / `result`（`failure` 等のエラー絞り込み）/
  期間（`from`/`to`、RFC3339）/ `client_id` / `correlation_id` で AND 絞り込みし、新しい順
  （`occurred_at` 降順・同時刻は `id` 降順）に返す。`limit`（既定 50・上限 200）・`offset` でページング。
- 読み取り境界 `AuditLogQuery`（書き込みの `AuditLogSink` と分離）と読み取りモデル `AuditLogEntry` /
  `AuditLogFilter` をドメインに追加。sqlx 実装は `QueryBuilder` で条件を安全にバインド。Application に
  `AuditQueryService`（limit クランプ・空文字正規化）、Presentation に `admin_audit` ハンドラと DTO を追加。
  OpenAPI に tag `admin` で掲載。単体テスト（limit クランプ・正規化）と統合テスト `tests/admin_audit.rs`
  （絞り込み・新しい順・401/403/400）を追加。

## 2026-07-06（A1: クライアント（RP）登録・管理 API）

- **クライアント管理 API を実装**（設計仕様 §9.3、Progress A1）。`/admin/clients` の CRUD＋シークレット
  再発行（`RequirePerms<IdpAdmin>` で保護）。`client_id` 自動採番、`client_secret` は confidential の
  登録・再発行時に**その応答でのみ**平文表示し DB は argon2 ハッシュのみ。`client_type` に応じ
  `token_endpoint_auth_method`（public=`none`／confidential=`client_secret_basic`）と PKCE を設定。
  redirect_uri は完全一致・複数登録・フラグメント／ワイルドカード禁止をアプリ層で検証。scope は
  `openid` を含む OIDC scope に限定。
- ドメインに `ClientRepository::{create,list,update}` を追加し sqlx 実装、Application に
  `ClientManagementService`（検証・secret 発行・監査記録）、Presentation に `admin_clients` ハンドラ群と
  DTO を追加。`ApiError::NotFound`（404）を追加。監査種別 `client.registered`/`.updated`/
  `.secret_rotated` を追加（§7）。OpenAPI に tag `admin` で自動掲載。
- 単体テスト（redirect_uri／scope／app_name 検証）と統合テスト `tests/admin_clients.rs`
  （401/403/400/CRUD/secret 再発行、権限の無い利用者の 403）を追加。

## 2026-07-06（管理機能の権限モデル基盤・A2 の前提、ADR-0006）

- **利用者権限モデルを実装**（ADR-0006）。OIDC scope（claim 制御）とは別軸の「利用者権限
  （permission code）」を新設。マイグレーション `0003_permissions_and_user_permissions`
  （`permissions` マスタ＋`user_permissions` 多対多）と seed `0004_seed_admin_permission`
  （`idp.admin` の登録と初期管理者への冪等付与）を追加。
- ドメインに値オブジェクト `PermissionCode` と `UserPermissionRepository`（DIP 境界。参照/付与/剥奪）、
  Infrastructure に sqlx 実装、Application に `AdminAccessService`（SSO セッション→利用者解決→権限突合。
  検証は Application 層で完結し Presentation には可否のみ返す）、Presentation に `RequirePerms<IdpAdmin>`
  extractor を追加。保護の疎通確認用に内部エンドポイント `GET /admin/whoami`（`idp.admin` 必須）を追加。
- 監査イベント種別 `user_permission.granted` / `.revoked` を追加（設計仕様 §7）。

## 2026-07-05（インフラ整備 T9〜T13・D2）

- **T9: IdP アプリのコンテナ化と Compose 統合**。マルチステージ `Dockerfile`（`rust:slim` ビルド →
  `debian:bookworm-slim` 実行、非 root、i18n は include_str! で埋め込み、TLS は rustls）を追加。
  `docker-compose.yml` に `web` サービス（`/healthz` の HEALTHCHECK、`mariadb` の service_healthy を
  `depends_on`、`DATABASE_URL` はサービス名 `mariadb` で解決）と、DDL/マスタデータ適用専用の
  ワンショット `migrate` サービス（sqlx-cli。`profiles: [tools]`）を追加。`.dockerignore` も追加。
- **T10: 秘密情報・設定の .env 一元管理**。`.env.example` を全設定（MariaDB パスワード・
  `KEY_ENCRYPTION_KEY`・`TEST_DATABASE_URL` を含む）の単一テンプレートへ拡充。Compose の秘密値を
  `.env` から注入するようパラメータ化。`config.rs` は空文字の環境変数を「未設定」として扱うよう
  堅牢化（Compose の `${VAR:-}` 由来の空値でパースが失敗しないように。単体テスト追加）。
- **T11: 初期設定スクリプト**。`scripts/init.sh`（冪等）でパスワード・鍵を乱数生成して `.env` を作成
  （既存は上書きしない）→ MariaDB 起動 → マイグレーション適用 → web ビルド・起動 → healthz 待機。
  共通処理は `scripts/lib.sh` に集約。
- **T12: 初期管理ユーザーのマスタデータ**。seed マイグレーション
  `migrations/0002_seed_initial_admin`（冪等 upsert。固定 id/sub、既定パスワードは変更前提）を追加。
  password_hash は argon2id（アプリと同一形式）。
- **T13: デプロイスクリプト**。`scripts/deploy.sh`（イメージビルド → DDL/マスタデータ適用の専用ジョブ →
  `up -d web` → `/readyz` 確認、ロールバック方針をコメント記載）。
- **D2: 運用手順を OPERATIONS.md に統合**。初期化・デプロイ・ロールバック・初期管理ユーザーの
  パスワード変更・`KEY_ENCRYPTION_KEY` ローテーション・バックアップ/リストアの手順を追記。

## 2026-07-05

- **T8: テスト & MVP 完了条件の E2E 検証**。`tests/oidc_flow.rs` で設計仕様 §10 の条件 1〜13 を
  通しで検証（登録 → /authorize → /login → code → /token → /userinfo → SSO 復元、code 再利用拒否、
  ロックアウト、client 認証失敗、監査ログの記録）。PKCE は RFC 7636 Appendix B のテストベクタを使用。
  純粋ロジック（PKCE / CSRF / Cookie / redirect URL 構築 / i18n / レート制限 / 認可検証）の
  単体テストを各モジュールへ追加。
- **D1: 付随ドキュメント整備**。`docs/ARCHITECTURE.md`（レイヤー構成・実装パターン）と
  `docs/OPERATIONS.md`（起動・マイグレーション・テスト・環境変数などの手順）を新設。
  utoipa による OpenAPI 自動生成（`/api/openapi.json`）と Swagger UI（`/api/docs`）を追加し、
  API 仕様の唯一の出所とした。
- **T7: 監査ログを横断結線**。`AuditService` が全イベント（login.succeeded/failed/locked、
  authorization_code.issued/used/reuse_detected、token.issued、client.authentication_failed、
  sso_session.created/resumed/expired）を tracing（JSON）と `audit_log` テーブルへ二重出力。
  correlation_id ミドルウェア（`x-request-id`）でリクエストと監査イベントを一気通貫で追跡可能に。
- **T6: Discovery / JWKS / UserInfo を実装**。`GET /.well-known/openid-configuration`（issuer は
  末尾スラッシュ無しで `iss` と完全一致）、`GET /.well-known/jwks.json`（ACTIVE+RETIRED 公開）、
  `GET /userinfo`（Bearer の `typ=at+jwt` JWT を署名・iss・aud・exp（±60s スキュー）で検証し、
  scope（openid/email/profile）に応じたクレームのみ返却）。
- **T5: トークン発行 `POST /token` を実装**。client 認証（confidential=`client_secret_basic`
  （argon2 検証・Basic ヘッダの percent-decode 対応）/ public=なし、header と body の client_id
  不一致は `invalid_request`）、code の原子的 one-time 消費（`UPDATE ... WHERE used_at IS NULL AND
  expires_at > ?` の affected rows 判定。0 行 = `invalid_grant` + `authorization_code.reuse_detected`）、
  PKCE S256 検証（verifier 43〜128 文字・文字種検証）、ID Token（`typ=JWT`、scope に応じた
  email/profile クレーム付与）と Access Token（`typ=at+jwt`、`aud=<issuer>/userinfo`）の RS256 発行、
  `Cache-Control: no-store` / `Pragma: no-cache`。
- **T4: 認可フロー中核を実装**。`GET /authorize`（検証: client 存在/ACTIVE・redirect_uri 完全一致・
  `response_type=code`・scope が openid を含み client 登録 scope の部分集合・state/nonce 必須・
  `code_challenge_method=S256`。client_id/redirect_uri 不正はリダイレクトせず 400、他は redirect_uri
  へエラー返却）、`GET/POST /login`（fluent による en/ja の i18n 画面、CSRF は auth_session_id 由来の
  同期トークン、username 単位 連続 10 回失敗 → 15 分ロック、IP 単位レート制限、成功時リセット）、
  SSO セッション（Cookie は平文 session_id・DB は SHA-256。復元時 idle +8h 延長・absolute 不変・
  `auth_time` は初回値維持）、code 発行共通モジュール（`code_issuance.rs`、256bit 乱数・ハッシュ保存・
  TTL 60s）。Cookie は `HttpOnly`/`Secure`(設定可)/`SameSite=Lax`/`Path=/`。302 Found でリダイレクト。
- **T3: ユーザー登録を実装**。`POST /auth/register`（設計仕様 §4.1）。argon2id でパスワードハッシュ、
  `id`/`sub`(UUID v4) 採番、`status=ACTIVE` / `email_verified=false`。email・preferred_username の
  一意性（DB UNIQUE ＋ 事前チェック、競合は 409）、簡易バリデーション（メール形式・パスワード最小長 8）。
  `PasswordHasher` トレイト（domain）＋ argon2 実装、`UserRepository` の sqlx 実装、`RegisterService`、
  presentation の DTO / `ApiError` / `AppState`（`FromRef`）を追加。統合テスト `tests/register.rs`
  （201 / 409 / 400 と DB 永続化）。
- **T2: 署名鍵と JWT 基盤を実装**。RSA-2048 鍵生成、秘密鍵の AES-256-GCM 暗号化保存、`kid` 採番、
  RS256 署名（ID Token=`typ=JWT` / Access Token=`typ=at+jwt`）、JWKS 構築（公開鍵 PEM→`n`/`e`）、
  検証用 `DecodingKey` を実装（`infrastructure/jwt.rs`・`crypto.rs`）。`SigningKeyRepository` の sqlx 実装、
  `KeyService`（ACTIVE 鍵ブートストラップ＝冪等 / 署名材料取得 / JWKS）、`Clock` トレイトと `SystemClock`、
  `KEY_ENCRYPTION_KEY` 設定を追加。クレートを lib+bin 構成へ変更（`src/lib.rs::run()`）。起動時に署名鍵を
  ブートストラップする。sqlx 互換のためベースラインの照合を `utf8mb4_unicode_ci` に統一（`_bin` は
  VARBINARY 扱いで String デコード不可のため。完全一致比較はアプリ層で担保）。統合テスト `tests/keys.rs`
  で「鍵ブートストラップ→署名→JWKS 検証」を確認。
- **T1: データモデルとマイグレーションを実装**。ベースラインマイグレーション
  `migrations/0001_baseline`（up/down）で 6 テーブル（users / clients / auth_sessions /
  sso_sessions / authorization_codes / signing_keys）＋ `audit_log` を作成（MariaDB 向け型読み替え:
  UUID→`CHAR(36)`、enum→`VARCHAR`+`CHECK`、時刻→UTC `DATETIME(6)`、配列→`JSON`、CITEXT 相当のみ
  大小無視照合、既定は `utf8mb4_bin`）。ドメイン層にエンティティ・列挙・監査イベント型・リポジトリ
  トレイト（DIP 境界、`#[async_trait]`）を追加。DB 接続のセッションタイムゾーンを UTC に固定。
  マイグレーション整合の統合テスト（`tests/schema.rs`）を追加。

- **ドキュメントを実装スタック（Rust + MariaDB）に整合**。CLAUDE.md・db-migration スキルを
  Rust/axum/sqlx 前提へ改訂し、ADR-0005（スタック採用）を追加、ADR-0004 と OIDC_INPUT.md に
  MariaDB 読み替え注記を追加（ADR-0005）。
- **T0: プロジェクト基盤を構築**。単一バイナリクレート（`idp`）を作成し、DDD 4層のモジュール骨格
  （domain / application / infrastructure / presentation）を配置。axum によるサーバ起動、`config`
  モジュール（環境変数 > 既定値、issuer 正規化・各種 TTL）、`tracing` の JSON 構造化ログ、sqlx の
  MariaDB 接続プール、起動時のスキーマ version 照合（`_sqlx_migrations` を SSOT とした fail-fast）、
  `/healthz`・`/readyz` ヘルスチェック、開発用 `docker-compose.yml`（MariaDB 10.11 / 任意 Redis）を実装。

- **F3: Consent（同意画面・同意済み scope 記録、`prompt`/`max_age` 正式対応）**。
  マイグレーション `0007_client_consents`（user_id×client_id の unique 制約付き JSON スコープ保持）を追加。
  ドメイン層に `ClientConsent` エンティティ・`ClientConsentRepository` trait・監査イベント
  `ConsentGranted`/`ConsentDenied` を追加。`AuthorizeRequest` に `prompt`/`max_age` フィールドを追加し、
  `prompt=none`（インタラクション禁止）・`prompt=login`（強制再認証）・`max_age` 超過時の強制再認証を実装。
  `ConsentRequired` を `AuthorizeOutcome`/`LoginOutcome` に追加し、SSO 再利用パスでも同意確認を行う。
  `/internal/consent-info`・`/internal/consent-approve`・`/internal/consent-deny` の 3 エンドポイントを
  api に追加。web 側に `/consent` 画面（Askama テンプレート、CSRF 保護付き POST）を追加。
  i18n（en/ja）の同意画面文言を追加。

## TOTP MFA（任意の二段階認証）実装

ユーザーが自分で TOTP（Google Authenticator 等）を登録・削除できる任意 MFA を実装。
強制ではなくオプション機能として提供する。

- **DB**: `user_totp_secrets`（`secret_encrypted`, `confirmed_at`）テーブルを追加（migration 0010）。
  `auth_sessions` に `password_verified_at` カラムを追加（migration 0011）。
- **Domain**: `TotpSecret` エンティティ、`TotpSecretRepository` トレイト、
  `AuthSession.password_verified_at` フィールド追加。
- **Application**: `TotpRegistrationService`（setup/confirm/delete）、`MfaLoginService`（TOTPステップ）。
  シークレットは AES-256-GCM 暗号化（署名鍵と同方式）。コード検証は `totp-rs 5.x` を使用。
- **API**: `/internal/mfa/totp/setup|confirm|delete|verify` 4 エンドポイントを追加。
  `InternalAuthenticateResponse::MfaRequired` バリアント追加。
- **Web**: `/account/mfa/totp/setup`（セルフ登録）・`/mfa/totp`（ログインフロー TOTP 入力）を追加。
  セットアップ画面は QR コード SVG（サーバサイド生成、`qrcode 0.14`）と生 base32 シークレットの両方を表示
  （QR が使えないユーザーも手動入力できる）。
- **i18n**: MFA 関連文言を en/ja に追加。

## T4: Passkey（WebAuthn）登録・認証（2026-07-08）

- **Migration 0012**: `user_webauthn_credentials`（クレデンシャル保存）・`passkey_challenges`（チャレンジ
  一時保存。TTL 5 分）テーブルを追加。クレデンシャル ID は base64url VARCHAR(512)で保存。
- **Domain**: `WebAuthnCredential`・`PasskeyChallenge` エンティティ、
  `WebAuthnCredentialRepository`・`PasskeyChallengeRepository` トレイト追加。
- **Infrastructure**: `WebAuthnService`（`webauthn-rs 0.5`ラッパー。RP ID/Origin は `config.issuer()` から自動導出）、
  `SqlxWebAuthnCredentialRepository`・`SqlxPasskeyChallengeRepository` 追加。
- **Application**: `PasskeyRegistrationService`（begin/complete/delete/list）、
  `PasskeyAuthenticationService`（begin/complete、Discoverable Credentials flow）追加。
  認証成功後は通常の OIDC フロー（consent → code 発行）と同一パスを通る。
- **API**: `/internal/passkey/register/begin|complete`・`/internal/passkey/delete|list`・
  `/internal/passkey/login/begin|complete` 6 エンドポイント追加。
- **Web**: `/account/passkey`（一覧）・`/account/passkey/register`（登録）・
  `/passkey/register/begin|complete`・`/passkey/login/begin|complete` を追加。
  ログイン画面に「パスキーでサインイン」ボタンを追加（WebAuthn JS API 経由）。
- **i18n**: Passkey 関連文言を en/ja に追加。
