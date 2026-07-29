# ADR-0019: api を兄弟サブドメインへ戻し、WebAuthn RP ID を web オリジンから導出する

- Status: Accepted
- Date: 2026-07-29
- 関連: `docs/adr/0018-cookie-free-api-web-handoff.md`（**§Decision 1「ホスト名を入れ子にする」を
  本 ADR で撤回する**。決定 2〜4 は不変）、`docs/adr/0017-issuer-db-managed-and-console-restart.md`
  （Passkey 無効化の注意の導出元が本 ADR で `ISSUER` から `PUBLIC_WEB_BASE_URL` へ変わる）、
  `docs/adr/0015-domain-split-by-listen-port.md`・`docs/adr/0016-domain-split-as-default-topology.md`（配置）

## Context

ADR-0018 決定 1 は、api を web の**子サブドメイン**（`api.idp.nolumia.com` /
`api.idpstg.nolumia.com`）にすることで Cookie スコープを web ホスト配下へ閉じる、と決めた。
しかし適用作業（Progress.md 旧 T1）を進めたところ、2 つの問題が判明した。

1. **サブサブドメインは証明書運用上使えない。** ワイルドカード証明書は左 1 ラベルしか覆えない
   ため、`*.nolumia.com` は `idp.nolumia.com` と `idpapi.nolumia.com` には一致するが
   `api.idp.nolumia.com` には一致しない。子サブドメイン構成には環境ごとに別証明書
   （SAN 追加または `*.idp.nolumia.com` 等）が必要で、この配置ではそれが用意できない。
2. **決定 1 の前提だった脅威は、決定 2〜4 の実装完了で既に消えている。** 兄弟命名が危険だったのは
   「api/web が共有する `Domain=nolumia.com` の Cookie が apex 配下の全ホスト（stg 含む）へ
   送信される」からだが、決定 2（api はブラウザ Cookie を読み書きしない）と決定 4
   （`COOKIE_DOMAIN` 未設定 = host-only が既定）の実装後は、そもそも Domain 付きのセッション
   Cookie が存在しない。決定 1 は「安価な多層防御」であって、成立条件ではない。

また、domain-split の Passkey に関する独立した不具合も判明した。WebAuthn の RP ID・origin は
`ISSUER`（api のオリジン）のホスト名から導出していた（`infrastructure::webauthn`）が、Passkey の
セレモニー（`navigator.credentials.*`）は **web のページ上**（`/{tenant_id}/account/passkey/*`・
ログイン画面）で実行される。ブラウザは「RP ID は呼び出し元オリジンの登録可能サフィックス」を
要求するため、api ホストが web ホストのサフィックスにならない domain-split では（子・兄弟どちらの
命名でも）セレモニーがブラウザ側で常に失敗し、サーバ側でも clientDataJSON の origin 検証
（web オリジン ≠ issuer オリジン）が通らない。single-origin では両者が同一オリジンのため
顕在化しなかった。

## Decision

### 1. api は web の兄弟サブドメイン（apex 直下の 1 ラベル）にする

| 環境 | web（HTML 画面） | api（protocol・JSON） |
|---|---|---|
| prod | `idp.nolumia.com` | `idpapi.nolumia.com` |
| stg | `idpstg.nolumia.com` | `idpapistg.nolumia.com` |

- ADR-0018 決定 1（入れ子命名）を撤回する。どちらのホストも apex 直下の 1 ラベルなので、
  ワイルドカード証明書 `*.nolumia.com` 1 枚で全ホストを覆える。
- 兄弟命名の**成立条件として `COOKIE_DOMAIN` を設定しないこと**（ADR-0018 決定 4 の既定を
  必須要件へ格上げ）。設定すると共有 `Domain` が apex まで広がり、ADR-0018 Context の
  stg/prod 間セッション露出が復活する。例外は旧 ADR-0012 構成の Domain 付き Cookie を
  掃除する移行期間のみ（削除 Cookie の併送であり、有効なセッション値を Domain 付きで
  発行することはない）。
- ADR-0012 §Decision 1 の「同一の登録可能ドメイン配下のサブドメイン」という制約は維持する。
  公開ポート・同梱プロキシの構成は変えない（変わるのは `.env` の `ISSUER` と DNS・証明書のみ）。

### 2. WebAuthn の RP ID・origin は `PUBLIC_WEB_BASE_URL` から導出する

- `WebAuthnService` の RP ID（ホスト名）と期待 origin は、`ISSUER` ではなく
  **web の公開ベース URL（`PUBLIC_WEB_BASE_URL`。未設定時は issuer に追従）**から導出する。
  セレモニーが実行されるのは web のページであり、RP ID・origin の検証対象は web のオリジンで
  なければならないため。
- single-origin（`PUBLIC_WEB_BASE_URL` 未設定 = issuer と同一オリジン）では従来と同値になり、
  挙動は変わらない。domain-split では RP ID が web ホスト（例 `idp.nolumia.com`）になり、
  Passkey が初めて成立する。
- これに伴い「ホスト名を変えると登録済み Passkey が使えなくなる」注意（ADR-0017）の対象キーは
  `ISSUER` から `PUBLIC_WEB_BASE_URL` へ移る。

## Consequences

**良くなる点**

- 証明書がワイルドカード 1 枚で済み、環境追加（stg 等）も DNS レコードの追加だけで完結する。
- domain-split で Passkey（登録・ログインとも）が動作するようになる。
- `.env.*.example` が実際に配置可能なホスト名になり、Progress.md 旧 T1（入れ子ホスト名の
  適用作業）は不要になって消える。

**コスト・注意点**

- **`ISSUER` が変わる**（既に `api.idp.*` で公開済みの環境のみ）。discovery・ID Token の `iss`・
  SAML メタデータの entityID / SSO URL が変わるため、RP 側の再設定と SAML SP のメタデータ
  再取り込みが必要。メンテナンス枠で実施する。
- domain-split で `PUBLIC_WEB_BASE_URL` のホストを将来変えると、登録済み Passkey は別 RP 扱いに
  なり使えなくなる（従来この注意は `ISSUER` に付いていた。`docs/OPERATIONS.md` 参照）。
- RP ID の導出元変更により、（理論上）issuer ホストの RP ID で登録済みのクレデンシャルは無効に
  なる。ただし domain-split ではそもそもセレモニーが成立していなかったため実害はなく、
  single-origin では導出結果が変わらないため影響しない。
- 兄弟命名は `COOKIE_DOMAIN` 未設定の維持が前提になる（上記決定 1）。起動時検証
  （`crates/contracts/src/cookie_domain.rs`）は引き続き「双方の公開オリジンの親・public suffix
  でない」ことしか見ないため、誤設定を機械的には止めない。`.env.*.example` と
  `docs/OPERATIONS.md` に禁止を明記する。

## Rejected alternatives

### 子サブドメイン（`api.idp.nolumia.com`）を維持し、環境ごとに証明書を追加発行する

多層防御としての価値は認めるが、この配置では追加証明書の発行・更新の運用コストが受け入れられず、
守っている脅威（Domain 付き共有 Cookie）は決定 2〜4 の完了で既に存在しない。

### RP ID を apex（`nolumia.com`）から導出する

兄弟ホスト双方を覆えるが、RP ID は狭いほど良い（apex を RP ID にすると `nolumia.com` 配下の
任意ホストのページからクレデンシャルへ到達し得る）。セレモニーは web のページでしか実行しない
ため、web ホスト単体で必要十分。

### web 側に WebAuthn 検証を移す

セレモニーの実行場所（web）と検証（api の `WebAuthnService`）を同居させる案。web は DB を
持たない（クレデンシャル・チャレンジは api 側の表）ため、検証だけ移しても状態の往復が増える。
導出元 URL の変更だけで足りる。
