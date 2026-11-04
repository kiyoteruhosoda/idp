//! 利用者が自分で登録する SSH の公開鍵（task #885。ADR-0072）。
//!
//! 持ち主の PC がウイルスに乗っ取られても SSH の鍵を持ち出せないよう、登録できるのは **sk 型**
//! （`sk-ssh-ed25519@openssh.com`・`sk-ecdsa-sha2-nistp256@openssh.com`）だけにする。sk 型の秘密鍵は
//! セキュリティキー・TPM（Windows Hello）・スマホのパスキーの中にあり、PC のファイルには「鍵の持ち手」しか
//! 残らない。使うたびに機器での確認（触れる・指紋・PIN）が要る。
//!
//! # ここで確かめること
//!
//! - authorized_keys の 1 行の形（`型 本体 [コメント]`。前にオプションを付けた行は受け付けない）
//! - 本体（base64）を開き、OpenSSH の公開鍵の並び（RFC 4253 §6.6 の string の連なり）として読めること、
//!   中に書かれた型が 1 つ目の欄と一致すること、鍵の長さが型どおりであること、後ろに余りが無いこと
//! - 秘密鍵らしきもの（`-----BEGIN … PRIVATE KEY-----`）は**中身を読まずに**断る
//!
//! 指紋は `ssh-keygen -l` と同じ `SHA256:` ＋ 本体の SHA-256 の base64（パディング無し）。

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain::tenant::TenantId;

/// 鍵の名前の長さの上限（文字数）。
pub const MAX_SSH_KEY_NAME_CHARS: usize = 100;

/// 1 人が 1 つの組織に登録できる鍵の数の上限（配る先の authorized_keys を膨らませない）。
pub const MAX_SSH_KEYS_PER_USER: usize = 10;

/// 貼り付けた文字列の長さの上限（バイト）。sk 型の公開鍵は 1 行 300 バイトに満たない。
const MAX_INPUT_BYTES: usize = 4096;

/// 本体を開いた長さの上限（バイト）。
const MAX_BLOB_BYTES: usize = 300;

/// sk 型の `application`（FIDO の rp id。既定は `ssh:`）の長さの上限（バイト）。
const MAX_APPLICATION_BYTES: usize = 128;

/// 受け付ける鍵の型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshKeyType {
    /// `ssh-keygen -t ed25519-sk`（セキュリティキー）。
    SkEd25519,
    /// `ssh-keygen -t ecdsa-sk`（Windows Hello・スマホのパスキー・多くのセキュリティキー）。
    SkEcdsaP256,
}

impl SshKeyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SkEd25519 => "sk-ssh-ed25519@openssh.com",
            Self::SkEcdsaP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "sk-ssh-ed25519@openssh.com" => Some(Self::SkEd25519),
            "sk-ecdsa-sha2-nistp256@openssh.com" => Some(Self::SkEcdsaP256),
            _ => None,
        }
    }
}

/// 公開鍵を断った理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshKeyRejection {
    /// 秘密鍵らしきものが貼られた（中身は読まず、保存もしない）。
    LooksLikePrivateKey,
    /// sk 型ではない（`ssh-ed25519`・`ssh-rsa`・`ecdsa-sha2-nistp256` など、ファイルに秘密鍵がある型）。
    NotSecurityKeyType,
    /// 形が壊れている（base64 でない・並びが読めない・型が食い違う・長さが違う・空）。
    Malformed,
}

/// 確かめ終えた公開鍵。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPublicKey {
    key_type: SshKeyType,
    /// 本体（base64。パディング付きの標準形へ揃えた値）。
    blob: String,
    fingerprint: String,
}

impl SshPublicKey {
    /// 貼り付けられた authorized_keys の 1 行を確かめる。コメントは捨てる。
    pub fn parse(raw: &str) -> Result<Self, SshKeyRejection> {
        if raw.contains("PRIVATE KEY") {
            return Err(SshKeyRejection::LooksLikePrivateKey);
        }
        if raw.len() > MAX_INPUT_BYTES {
            return Err(SshKeyRejection::Malformed);
        }
        // 1 行だけ（前後の空白・改行は落とす。2 行以上は断る）。
        let line = raw.trim();
        if line.is_empty() || line.contains('\n') || line.contains('\r') {
            return Err(SshKeyRejection::Malformed);
        }
        let mut fields = line.split_ascii_whitespace();
        let (Some(type_field), Some(blob_field)) = (fields.next(), fields.next()) else {
            return Err(SshKeyRejection::Malformed);
        };
        let Some(key_type) = SshKeyType::parse(type_field) else {
            return Err(if looks_like_key_type(type_field) {
                SshKeyRejection::NotSecurityKeyType
            } else {
                SshKeyRejection::Malformed
            });
        };
        let bytes = STANDARD
            .decode(blob_field)
            .map_err(|_| SshKeyRejection::Malformed)?;
        if bytes.is_empty() || bytes.len() > MAX_BLOB_BYTES {
            return Err(SshKeyRejection::Malformed);
        }
        check_blob(key_type, &bytes)?;
        Ok(Self {
            key_type,
            blob: STANDARD.encode(&bytes),
            fingerprint: fingerprint_of(&bytes),
        })
    }

    /// DB から読んだ値を包む（保存したときに確かめてある）。
    pub fn from_stored(key_type: SshKeyType, blob: String, fingerprint: String) -> Self {
        Self {
            key_type,
            blob,
            fingerprint,
        }
    }

    pub fn key_type(&self) -> SshKeyType {
        self.key_type
    }

    pub fn blob(&self) -> &str {
        &self.blob
    }

    /// `SHA256:…`（`ssh-keygen -l -E sha256` と同じ）。
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// authorized_keys に書く形（`型 本体`。コメント・オプションは付けない）。
    pub fn authorized_key(&self) -> String {
        format!("{} {}", self.key_type.as_str(), self.blob)
    }
}

/// ファイルに秘密鍵を置く型の名前か（「sk 型ではない」と「壊れている」を言い分けるため）。
fn looks_like_key_type(field: &str) -> bool {
    field.starts_with("ssh-")
        || field.starts_with("ecdsa-sha2-")
        || field.starts_with("sk-")
        || field.starts_with("rsa-sha2-")
}

/// 指紋（`SHA256:` ＋ base64、パディング無し）。
pub fn fingerprint_of(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}

/// 本体の並びを読む（RFC 4253 §6.6・OpenSSH PROTOCOL.u2f）。
///
/// - `sk-ssh-ed25519@openssh.com`: string 型・string 公開鍵（32 バイト）・string application
/// - `sk-ecdsa-sha2-nistp256@openssh.com`: string 型・string `nistp256`・string 点（非圧縮 65 バイト）・
///   string application
fn check_blob(key_type: SshKeyType, bytes: &[u8]) -> Result<(), SshKeyRejection> {
    let mut reader = WireReader(bytes);
    if reader.string()? != key_type.as_str().as_bytes() {
        return Err(SshKeyRejection::Malformed);
    }
    match key_type {
        SshKeyType::SkEd25519 => {
            if reader.string()?.len() != 32 {
                return Err(SshKeyRejection::Malformed);
            }
        }
        SshKeyType::SkEcdsaP256 => {
            if reader.string()? != b"nistp256" {
                return Err(SshKeyRejection::Malformed);
            }
            let point = reader.string()?;
            if point.len() != 65 || point[0] != 0x04 {
                return Err(SshKeyRejection::Malformed);
            }
        }
    }
    let application = reader.string()?;
    if application.is_empty()
        || application.len() > MAX_APPLICATION_BYTES
        || std::str::from_utf8(application).is_err()
    {
        return Err(SshKeyRejection::Malformed);
    }
    if !reader.0.is_empty() {
        return Err(SshKeyRejection::Malformed);
    }
    Ok(())
}

/// SSH の wire 形式の string（4 バイトの長さ＋中身）を前から読む。
struct WireReader<'a>(&'a [u8]);

impl<'a> WireReader<'a> {
    fn string(&mut self) -> Result<&'a [u8], SshKeyRejection> {
        if self.0.len() < 4 {
            return Err(SshKeyRejection::Malformed);
        }
        let (len, rest) = self.0.split_at(4);
        let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
        if rest.len() < len {
            return Err(SshKeyRejection::Malformed);
        }
        let (value, rest) = rest.split_at(len);
        self.0 = rest;
        Ok(value)
    }
}

/// 名前を整える。前後の空白を落とし、空・長すぎ・制御文字入りは `None`。
pub fn normalize_ssh_key_name(raw: &str) -> Option<String> {
    let name = raw.trim();
    if name.is_empty()
        || name.chars().count() > MAX_SSH_KEY_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return None;
    }
    Some(name.to_string())
}

/// 登録済みの SSH の鍵。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSshKey {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    pub name: String,
    pub key: SshPublicKey,
    pub created_at: DateTime<Utc>,
}

/// 配る機械へ渡す 1 行（利用者名つき）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedSshKey {
    /// assay の利用者名（`preferred_username`）。
    pub username: String,
    pub name: String,
    pub key: SshPublicKey,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
pub(crate) mod testing {
    //! 試験用の鍵を組み立てる（本物の `ssh-keygen` の出力と同じ並び）。
    use super::*;

    fn put(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }

    /// `sk-ssh-ed25519@openssh.com` の 1 行（`seed` で鍵を変える）。
    pub fn ed25519_sk_line(seed: u8) -> String {
        let mut blob = Vec::new();
        put(&mut blob, b"sk-ssh-ed25519@openssh.com");
        put(&mut blob, &[seed; 32]);
        put(&mut blob, b"ssh:");
        format!(
            "sk-ssh-ed25519@openssh.com {} kyon@kyon-pc",
            STANDARD.encode(blob)
        )
    }

    /// `sk-ecdsa-sha2-nistp256@openssh.com` の 1 行。
    pub fn ecdsa_sk_line(seed: u8) -> String {
        let mut point = vec![0x04];
        point.extend_from_slice(&[seed; 64]);
        let mut blob = Vec::new();
        put(&mut blob, b"sk-ecdsa-sha2-nistp256@openssh.com");
        put(&mut blob, b"nistp256");
        put(&mut blob, &point);
        put(&mut blob, b"ssh:");
        format!(
            "sk-ecdsa-sha2-nistp256@openssh.com {} windows-hello",
            STANDARD.encode(blob)
        )
    }

    /// `ssh-ed25519`（ファイルの鍵）の 1 行。
    pub fn ed25519_file_line() -> String {
        let mut blob = Vec::new();
        put(&mut blob, b"ssh-ed25519");
        put(&mut blob, &[7; 32]);
        format!("ssh-ed25519 {} kyon@kyon-pc", STANDARD.encode(blob))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn security_key_types_are_accepted_and_comments_are_dropped() {
        let key = SshPublicKey::parse(&ed25519_sk_line(1)).unwrap();
        assert_eq!(key.key_type(), SshKeyType::SkEd25519);
        assert!(key
            .authorized_key()
            .starts_with("sk-ssh-ed25519@openssh.com AAAA"));
        assert!(!key.authorized_key().contains("kyon@kyon-pc"));

        let key = SshPublicKey::parse(&format!("  {}\n", ecdsa_sk_line(2))).unwrap();
        assert_eq!(key.key_type(), SshKeyType::SkEcdsaP256);
        assert!(!key.authorized_key().contains("windows-hello"));
    }

    #[test]
    fn fingerprint_matches_ssh_keygen() {
        // ssh-keygen -l は SHA-256 の base64（パディング無し）に `SHA256:` を付ける。
        let key = SshPublicKey::parse(&ed25519_sk_line(1)).unwrap();
        let blob = STANDARD.decode(key.blob()).unwrap();
        let expected = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob)));
        assert_eq!(key.fingerprint(), expected);
        assert_eq!(key.fingerprint().len(), 50);
        assert_ne!(
            key.fingerprint(),
            SshPublicKey::parse(&ed25519_sk_line(2))
                .unwrap()
                .fingerprint()
        );
    }

    /// `ssh-keygen -l -E sha256` が同じ行に出した指紋（OpenSSH 10 で実測。公開鍵の並びは
    /// [`ed25519_sk_line`] の `seed = 1` と同じ）。
    #[test]
    fn fingerprint_is_the_one_ssh_keygen_prints() {
        let line = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAABHNzaDo= test";
        let key = SshPublicKey::parse(line).unwrap();
        assert_eq!(key.key_type(), SshKeyType::SkEd25519);
        assert_eq!(
            key.fingerprint(),
            "SHA256:1rYiSPZV2H9QsZrfrX/5nhreVmcpuSKQQYA/CKjnPfU"
        );
        assert_eq!(key, SshPublicKey::parse(&ed25519_sk_line(1)).unwrap());
    }

    #[test]
    fn file_keys_are_refused_as_not_security_keys() {
        assert_eq!(
            SshPublicKey::parse(&ed25519_file_line()),
            Err(SshKeyRejection::NotSecurityKeyType)
        );
        assert_eq!(
            SshPublicKey::parse("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 kyon"),
            Err(SshKeyRejection::NotSecurityKeyType)
        );
        assert_eq!(
            SshPublicKey::parse("ecdsa-sha2-nistp256 AAAAE2VjZHNh kyon"),
            Err(SshKeyRejection::NotSecurityKeyType)
        );
    }

    #[test]
    fn private_keys_are_refused_without_reading_them() {
        let pasted = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
        assert_eq!(
            SshPublicKey::parse(pasted),
            Err(SshKeyRejection::LooksLikePrivateKey)
        );
        assert_eq!(
            SshPublicKey::parse("-----BEGIN PRIVATE KEY-----"),
            Err(SshKeyRejection::LooksLikePrivateKey)
        );
    }

    #[test]
    fn broken_keys_are_refused() {
        let good = ed25519_sk_line(1);
        let blob = good.split(' ').nth(1).unwrap();
        for bad in [
            String::new(),
            "   ".to_string(),
            "sk-ssh-ed25519@openssh.com".to_string(),
            "sk-ssh-ed25519@openssh.com !!!notbase64".to_string(),
            // 1 つ目の欄と中の型が食い違う
            format!("sk-ecdsa-sha2-nistp256@openssh.com {blob}"),
            // 切り詰めた本体
            format!("sk-ssh-ed25519@openssh.com {}", &blob[..blob.len() - 8]),
            // 2 行
            format!("{good}\n{good}"),
            // オプション付きの行
            format!("from=\"10.0.0.0/8\" {good}"),
            "hello world".to_string(),
        ] {
            assert!(SshPublicKey::parse(&bad).is_err(), "{bad:?}");
        }
        // 後ろに余りのある本体
        let mut bytes = STANDARD.decode(blob).unwrap();
        bytes.push(0);
        assert_eq!(
            SshPublicKey::parse(&format!(
                "sk-ssh-ed25519@openssh.com {}",
                STANDARD.encode(bytes)
            )),
            Err(SshKeyRejection::Malformed)
        );
    }

    #[test]
    fn key_names_are_trimmed_and_bounded() {
        assert_eq!(
            normalize_ssh_key_name("  kyon-pc ").as_deref(),
            Some("kyon-pc")
        );
        assert!(normalize_ssh_key_name("").is_none());
        assert!(normalize_ssh_key_name("a\tb").is_none());
        assert!(normalize_ssh_key_name(&"あ".repeat(MAX_SSH_KEY_NAME_CHARS + 1)).is_none());
    }
}
