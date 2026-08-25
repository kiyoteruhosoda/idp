//! ヘルス情報の DTO と、公開してよい範囲の線引き（ADR-0031）。
//!
//! `/healthz`（liveness）は**どのサービスが答えたか**までを無認証で返す。それ以上（ビルド版数・
//! 稼働時間・依存先の検査結果）は `/internal/health` に置き、内部トークンの内側でしか読めない。
//!
//! api と web が同じ形で組み立てるため、両者が使う型をここに単一定義する。片方だけ形が変わると
//! 運用の見方（監視・切り分け手順）が service ごとに割れるため。

use crate::version::VersionInfo;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// サービスの識別子。`/healthz` の応答に載せ、どちらのサービスが答えたかを一目で分かるようにする。
///
/// domain-split（ADR-0016・ADR-0019）では web と api が別ホストだが、前段プロキシの設定ミスや
/// DNS の向き先違いで「叩いたつもりのサービスと違う方が答える」ことは起こり得る。ホスト名ではなく
/// **応答そのもの**に載せておかないと、その取り違えは切り分けの最後まで残る。
pub mod service {
    pub const API: &str = "api";
    pub const WEB: &str = "web";
}

/// `/healthz`（liveness）の応答。**無認証で全世界から読める**ので、ここへ増やしてよいのは
/// 「秘密ではなく、かつ攻撃者の役に立たない」ものだけである（ADR-0031 決定 1）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivenessResponse {
    /// 常に `"ok"`（この応答が返っている時点でプロセスは生きている）。
    pub status: String,
    /// [`service`] のいずれか。
    pub service: String,
}

impl LivenessResponse {
    pub fn ok(service: &str) -> Self {
        Self {
            status: "ok".to_string(),
            service: service.to_string(),
        }
    }
}

/// 依存先 1 つ分の検査結果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheck {
    /// 検査対象の名前（`"database"`・`"api"` 等）。
    pub name: String,
    /// `"pass"` / `"fail"`。
    pub status: String,
    /// 人が読む補足（失敗理由・付随する値）。**内部エラーの原文は入れない**
    /// （この応答は内部トークンの内側だが、運用ログとの二重管理を避けるため要約に留める）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl HealthCheck {
    pub fn pass(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: "pass".to_string(),
            detail: None,
        }
    }

    pub fn fail(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status: "fail".to_string(),
            detail: Some(detail.into()),
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn is_pass(&self) -> bool {
        self.status == "pass"
    }
}

/// `/internal/health` の応答（内部トークンの内側）。
///
/// 運用者が 1 回の要求で「どのサービスの・どの版が・いつから動いていて・依存先はどうか」を
/// 取れるようにする。切り分けのたびに複数のエンドポイントを叩き回らずに済ませるのが狙い。
///
/// 送信専用（`Deserialize` を持たない）。埋め込む [`VersionInfo`] がビルド時の静的文字列を
/// 借用しているためで、読み手はどのみち JSON として扱う（web がこの型を受け取る経路も無い）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceHealth {
    /// [`service`] のいずれか。
    pub service: String,
    /// 全 `checks` が pass なら `"pass"`、1 つでも落ちていれば `"fail"`。
    pub status: String,
    /// 実行中のバイナリのビルド情報。
    pub version: VersionInfo,
    /// プロセスの起動時刻（UTC）。
    pub started_at: DateTime<Utc>,
    /// 起動からの経過秒。再起動が起きたかを一目で判断するために持つ
    /// （`started_at` との差は読み手が計算せずに済む）。
    pub uptime_seconds: i64,
    /// 応答時点のサーバー時刻（UTC）。クライアントとの時計ずれの切り分けに使う ——
    /// `private_key_jwt` の assertion は `exp` 5 分・許容 60 秒で判定するため（ADR-0030）、
    /// 時計のずれは「理由の分からない `invalid_client`」として現れる。
    pub server_time: DateTime<Utc>,
    /// 依存先の検査結果。依存を持たないサービスでは空。
    pub checks: Vec<HealthCheck>,
}

impl ServiceHealth {
    /// `checks` から全体の `status` を決めて組み立てる。
    pub fn new(
        service: &str,
        version: VersionInfo,
        started_at: DateTime<Utc>,
        server_time: DateTime<Utc>,
        checks: Vec<HealthCheck>,
    ) -> Self {
        let status = if checks.iter().all(HealthCheck::is_pass) {
            "pass"
        } else {
            "fail"
        };
        Self {
            service: service.to_string(),
            status: status.to_string(),
            version,
            started_at,
            uptime_seconds: (server_time - started_at).num_seconds().max(0),
            server_time,
            checks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    fn version() -> VersionInfo {
        VersionInfo {
            package_version: "0.1.0",
            git_version: "abc1234",
            build_number: "312",
        }
    }

    #[test]
    fn liveness_names_the_service_that_answered() {
        let body = serde_json::to_value(LivenessResponse::ok(service::WEB)).unwrap();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["service"], "web");
    }

    #[test]
    fn the_overall_status_follows_the_checks() {
        let healthy = ServiceHealth::new(
            service::API,
            version(),
            at(1000),
            at(1060),
            vec![HealthCheck::pass("database")],
        );
        assert_eq!(healthy.status, "pass");
        assert_eq!(healthy.uptime_seconds, 60);

        let broken = ServiceHealth::new(
            service::API,
            version(),
            at(1000),
            at(1060),
            vec![
                HealthCheck::pass("database"),
                HealthCheck::fail("schema", "DB が期待 version に達していない"),
            ],
        );
        assert_eq!(broken.status, "fail");
    }

    /// 検査を持たないサービスは pass（「依存が無い」を「壊れている」と読ませない）。
    #[test]
    fn a_service_without_dependencies_is_pass() {
        let health = ServiceHealth::new(service::WEB, version(), at(1000), at(1000), vec![]);
        assert_eq!(health.status, "pass");
        assert_eq!(health.uptime_seconds, 0);
    }

    /// 時計が巻き戻っても稼働時間は負にしない（NTP の補正で `server_time < started_at` は起こり得る）。
    #[test]
    fn uptime_never_goes_negative() {
        let health = ServiceHealth::new(service::API, version(), at(1000), at(900), vec![]);
        assert_eq!(health.uptime_seconds, 0);
    }
}
