//! サービス間の内部呼び出し（`/internal/*`）の認証（ADR-0007 §5）。
//!
//! ヘッダ名と照合のしかたを api（検証側）と web（提示側・および自身の `/internal/*` の検証側）で
//! 共有する。片方だけ変えると内部経路が丸ごと通らなくなる値であり、照合を各サービスで書き直すと
//! **片方だけ定数時間でなくなる**危険もあるため、contracts に単一定義する。

/// 内部サービス認証トークンを載せるヘッダ名（小文字。`HeaderMap` は大小無視で引ける）。
pub const SERVICE_TOKEN_HEADER: &str = "x-internal-auth-token";

/// 提示されたトークンが期待値と一致するか、**定数時間**で判定する。
///
/// 素朴な `==` は先頭から一致した長さで所要時間が変わるため、繰り返し試行から 1 バイトずつ
/// 正解を絞り込める。長さの違いは早期に返してよい（長さ自体は秘密ではなく、隠しても
/// 応答サイズ等から推し量れる）。
pub fn service_token_matches(presented: &str, expected: &str) -> bool {
    let (a, b) = (presented.as_bytes(), expected.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_only_identical_tokens() {
        assert!(service_token_matches("secret-token", "secret-token"));
        assert!(!service_token_matches("secret-token", "secret-tokeN"));
        assert!(!service_token_matches("secret", "secret-token"));
        assert!(!service_token_matches("", "x"));
        assert!(service_token_matches("", ""));
    }
}
