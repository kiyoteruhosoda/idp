# DBスキーマ・マスタデータとアプリのバージョン整合性を保証する仕組み

> **注記（ADR-0005 による読み替え）**: 本 ADR は当初 Python/Alembic 前提で書かれているが、
> 本プロジェクトの実装スタックは **Rust + sqlx（MariaDB）** である（`docs/adr/0005-rust-mariadb-stack.md`）。
> 以下の記述は次のように読み替える: **Alembic の revision id → sqlx マイグレーションの version**、
> **`alembic_version` テーブル → `_sqlx_migrations` テーブル**、**`alembic check` → sqlx マイグレーションの
> up/down 往復検証**。判定方針（「DB が期待 version 以上なら OK」の fail-fast）とマスタデータも
> マイグレーションで管理する思想は、スタックに関わらずそのまま維持する。

結論から言うと、**「Alembicのrevision idを単一情報源(SSOT)とし、DDLとマスタデータの両方を同じrevisionレールに乗せて、起動時・readiness時に照合する」** のが一番確実です。以下、具体的な構成を説明します。

## 1. 全体設計の考え方

```
DDL変更・マスタデータ変更 → Alembicマイグレーションファイル(revision id発行)
                              ↓
アプリ側 → イメージに同梱したマイグレーションスクリプトのheadが「期待revision」
                              ↓
起動時/readiness → DB内のalembic_versionテーブルと突合
                    ・DBが期待revisionより古い → fail-fast
                    ・DBが期待revisionと同じか新しい → OK(ローリングデプロイ対応)
```

ポイントは3つです。

- 「バージョン番号(1.0.0など)」ではなく、**Alembicが自動発行するrevision id**を唯一の信頼できる情報源にする。人間が手動採番する番号は間違えやすいが、revision idはズレようがない。
- **マスタデータの変更もAlembicのデータマイグレーションとして管理**する。これにより「WEBアプリ・DDL・マスタデータ」の三点同期が、単一の`alembic_version`照合だけで保証される。
- 判定は「厳密一致」ではなく **「DBがアプリの期待revision以上か」** にする。厳密一致にすると、ローリングデプロイ中(マイグレーション適用後・旧Pod稼働中)に旧Podのreadinessが不一致で落ち、サービス断が発生する。

## 2. Alembicのマイグレーション管理

```bash
# DDLマイグレーション生成
alembic revision --autogenerate -m "add users table"
```

生成されたファイルの `revision = "ae1027a6acf"` のような値がバージョンそのものになります。

```python
# migrations/versions/xxxx_add_users_table.py
revision = "ae1027a6acf"
down_revision = "1975ea83b712"
```

> **SQLiteを使う場合の注意**: SQLiteは`ALTER TABLE`の制約が強いため、`migrations/env.py`の`context.configure(...)`に`render_as_batch=True`を指定してbatchモードを有効にしてください。

## 3. マスタデータもマイグレーションで管理する

マスタデータの投入・更新を手作業やアプリ外のスクリプトにすると、必ずどこかでズレます。**マスタデータの変更も1つのrevisionとして発行**し、冪等なupsertで書きます。

```python
# migrations/versions/xxxx_sync_master_currencies.py
revision = "b7c2d9e1f0aa"
down_revision = "ae1027a6acf"

import csv
from pathlib import Path

import sqlalchemy as sa
from alembic import op


def upgrade() -> None:
    # Master data lives in the repo (version-controlled) next to migrations
    csvPath = Path(__file__).resolve().parent.parent / "masterdata" / "currencies_v3.csv"
    rows = list(csv.DictReader(csvPath.open(encoding="utf-8")))

    conn = op.get_bind()
    for row in rows:
        # Idempotent upsert keyed by the natural key (SQLite / PostgreSQL syntax)
        conn.execute(
            sa.text(
                """
                INSERT INTO currencies (code, name, is_active)
                VALUES (:code, :name, :is_active)
                ON CONFLICT(code) DO UPDATE SET
                    name = excluded.name,
                    is_active = excluded.is_active
                """
            ),
            row,
        )


def downgrade() -> None:
    # Master data downgrade is usually a no-op; document the decision explicitly
    pass
```

- マスタデータの実体はCSV/YAMLとしてリポジトリ管理し、マイグレーションから読み込みます(データ差分もコードレビュー対象になる)。
- 「CSVに存在しない行を削除する」フル同期にする場合は、FK参照があるテーブルでの削除に注意してください。基本は論理削除(`is_active = 0`)を推奨します。
- SQL Serverの場合は`ON CONFLICT`が使えないため`MERGE`文に読み替えてください。

これで、マスタデータの更新漏れも**revision不一致として起動時に検知**されます。追加の仕組みは不要です。

## 4. アプリ起動時・readinessの整合性チェック

FastAPIのlifespanとreadinessプローブで、DBの`alembic_version`とアプリが期待するrevisionを突合します。以下の点を織り込んでいます。

- 期待revisionとスクリプト情報は**キャッシュ**(readinessは数秒おきに叩かれるため、毎回のディスクI/Oを避ける)
- 新規DB(`alembic_version`テーブル未作成)を`actual=None`として扱う
- 複数head(ブランチ分岐)を起動時に検知
- **DBがアプリより新しい場合は許容**(expand/contract前提。ローリングデプロイ中の旧Pod、およびアプリイメージのロールバックを可能にする)

```python
# app/infrastructure/db/version_check.py
import logging
from functools import lru_cache

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger(__name__)


class SchemaVersionMismatchError(Exception):
    def __init__(self, expected: str, actual: str | None):
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Schema version mismatch: expected>={expected}, actual={actual}"
        )


@lru_cache(maxsize=1)
def getScriptDirectory(alembicIniPath: str = "alembic.ini") -> ScriptDirectory:
    """Load migration scripts once and cache (avoid disk I/O on every probe)."""
    config = Config(alembicIniPath)
    return ScriptDirectory.from_config(config)


@lru_cache(maxsize=1)
def getExpectedHeadRevision(alembicIniPath: str = "alembic.ini") -> str:
    """Head revision bundled in this app image = the revision this app requires."""
    heads = getScriptDirectory(alembicIniPath).get_heads()
    if len(heads) != 1:
        # Branched migrations must be merged (alembic merge) before release
        raise RuntimeError(f"Expected exactly one head revision, found: {heads}")
    return heads[0]


async def getActualRevision(engine: AsyncEngine) -> str | None:
    """Current revision recorded in the DB. None if the DB is unmigrated."""
    async with engine.connect() as conn:
        try:
            result = await conn.execute(
                text("SELECT version_num FROM alembic_version")
            )
        except (ProgrammingError, OperationalError):
            # alembic_version table does not exist yet (fresh database)
            return None
        row = result.first()
        return row[0] if row else None


def isCompatibleRevision(
    expected: str, actual: str | None, scriptDir: ScriptDirectory
) -> bool:
    """DB must be at the expected revision or ahead of it.

    - actual == expected            -> OK (normal case)
    - expected is ancestor of actual -> OK (DB is newer; old pod during rollout)
    - actual unknown to this image   -> OK with warning (DB is newer than this
                                        image knows; relies on expand/contract)
    - otherwise (DB behind / empty)  -> NG (migration not applied)
    """
    if actual is None:
        return False
    if actual == expected:
        return True

    knownRevisions = {rev.revision for rev in scriptDir.walk_revisions()}
    if actual not in knownRevisions:
        # DB was migrated by a newer app image than this one
        logger.warning(
            "DB revision %s is unknown to this image (expected head %s); "
            "assuming DB is ahead under expand/contract discipline",
            actual,
            expected,
        )
        return True

    ancestorsOfActual = {
        rev.revision for rev in scriptDir.iterate_revisions(actual, "base")
    }
    return expected in ancestorsOfActual


async def verifySchemaVersion(
    engine: AsyncEngine, alembicIniPath: str = "alembic.ini"
) -> None:
    expected = getExpectedHeadRevision(alembicIniPath)
    actual = await getActualRevision(engine)
    scriptDir = getScriptDirectory(alembicIniPath)

    if not isCompatibleRevision(expected, actual, scriptDir):
        raise SchemaVersionMismatchError(expected=expected, actual=actual)
```

```python
# app/main.py
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from app.infrastructure.db.version_check import (
    SchemaVersionMismatchError,
    verifySchemaVersion,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await verifySchemaVersion(engine)
    except SchemaVersionMismatchError as ex:
        # Fail fast: never serve traffic against an older schema
        logger.critical(str(ex))
        raise SystemExit(1)
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/health/ready")
async def readinessCheck():
    try:
        await verifySchemaVersion(engine)
    except SchemaVersionMismatchError:
        raise HTTPException(status_code=503, detail="Schema not ready")
    return {"status": "ok"}
```

これにより、**マイグレーション未適用のDBに対して新アプリが起動すること自体を防止**しつつ、マイグレーション適用直後も旧Podはreadyのまま維持されます。Kubernetes/Azure Container Appsでは新Podの起動失敗→再起動ループになるので、不整合なデプロイは自動的にブロックされます。

## 5. CI/CDパイプラインでの適用順序と自動検証(重要)

手順ミスと「作り忘れ」を機械的に排除するため、以下をパイプラインに固定します。

```
1. 検証ステージ(PR時にも実行)
   - alembic upgrade head を使い捨てDBに適用
   - alembic check でモデルとマイグレーションのドリフトを検知
     (DDLを変えたのにマイグレーションを作り忘れた場合、ここで落ちる)
   - headが1つであることを確認(ブランチ分岐の検知)
   ↓ 成功確認
2. マイグレーション適用ジョブ(alembic upgrade head)を単独実行
   - 必ず1ジョブのみで実行する(複数Podの起動時実行や並行実行は禁止。
     upgrade の競合を防ぐ)
   ↓ 成功確認
3. アプリのデプロイ(新しいコンテナイメージの展開)
   ↓
4. readinessプローブでバージョン整合を確認してからトラフィック切替
```

```yaml
stages:
  - stage: Verify
    jobs:
      - job: CheckMigrations
        steps:
          - script: |
              # Apply all migrations to a disposable DB, then detect drift
              alembic upgrade head
              alembic check
              # Exactly one head must exist (no branched migrations)
              test "$(alembic heads | wc -l)" -eq 1

  - stage: Migrate
    dependsOn: Verify
    condition: succeeded()
    jobs:
      - job: RunAlembicUpgrade   # single job, no parallelism
        steps:
          - script: alembic upgrade head

  - stage: Deploy
    dependsOn: Migrate
    condition: succeeded()
    jobs:
      - job: DeployApp
        steps:
          - script: az containerapp update ...
```

> アプリの起動処理内で`alembic upgrade`を自動実行する構成は、複数レプリカ環境では競合の原因になるため採用しません。適用は必ずパイプラインの専用ジョブ(またはレプリカ数1のinitジョブ)で行います。

## 6. 後方互換性の設計原則(ローリングデプロイ対応)

ダウンタイムなしデプロイの前提として、DDL変更は必ず**expand/contractパターン**にします。セクション4の「DBが新しい側は許容する」判定は、この規律が守られていることを前提にしています。

- **Expand**: カラム追加など、旧アプリからも新DBが読める変更を先にデプロイ
- **Contract**: 旧カラム削除など、破壊的変更は旧アプリが完全にいなくなってから(別リリースに分ける)

マスタデータも同様で、「旧アプリが参照している行の削除」はcontract側の変更として扱ってください。

## まとめ:最低限入れるべき仕組み

| 仕組み | 目的 |
|---|---|
| Alembicのrevision id管理 | DDL+マスタデータのバージョン単一情報源(SSOT) |
| マスタデータのデータマイグレーション化(冪等upsert) | WEB・DDL・マスタデータの三点同期を単一照合で保証 |
| 起動時のversion突合(fail-fast、新規DB・複数head対応) | 不整合な状態でアプリが動くことを防止 |
| readinessプローブは「DBが期待revision以上」で判定 | ローリングデプロイ中の旧Pod維持・イメージロールバック対応 |
| CIでの`alembic check`+head数検証 | マイグレーション作り忘れ・ブランチ分岐の自動検知 |
| マイグレーション適用は専用ジョブで単独実行 | 並行`upgrade`の競合防止 |
| expand/contractパターン | 無停止デプロイ時の後方互換性確保 |
