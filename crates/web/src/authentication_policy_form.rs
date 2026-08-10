//! 認証ポリシーの条件を **HTML フォームで往復できる文字列**へ写す（AP1）。
//!
//! 認証ポリシーの条件は「文字列のリスト」（対象クライアント・利用者・CIDR・`acr_values`）と
//! 「時間帯のリスト」（曜日 × 時刻帯 × UTC オフセット）でできている。どちらも**個数が可変**で、
//! HTML のフォームには 1 対 1 で置けない。
//!
//! 個数固定の入力欄（例: 時間帯は 1 つだけ）にすると、API から 2 つ設定されたポリシーを管理画面で
//! 開いて保存した瞬間に**もう 1 つが黙って消える**。編集画面は全項目置換で送るため、表示できない
//! 値は保存時に失われる。そこで可変長の条件はテキスト領域に文字列として出し、**読める形のまま
//! 往復させる**。
//!
//! # 時間帯の書式
//!
//! 1 行 1 帯で `曜日 開始-終了 オフセット` と書く。曜日は `sun`〜`sat` のカンマ区切り、`*` は全曜日。
//! 時刻は `HH:MM`（終了が開始より小さい行は日をまたぐ帯）。オフセットは `+09:00` 形式で、省略時は
//! `+00:00`（UTC）。
//!
//! ```text
//! mon,tue,wed,thu,fri 09:00-18:00 +09:00
//! * 22:00-06:00 +00:00
//! ```

use idp_contracts::admin::TimeWindowPayload;

/// 曜日の表記（0 = 日曜 … 6 = 土曜）。API の数値表現との唯一の対応表。
const DAY_NAMES: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/// 改行・カンマ区切りのテキストを値のリストへ写す（空行と前後の空白は捨てる）。
pub fn parse_list(raw: &str) -> Vec<String> {
    raw.split(['\n', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// 値のリストをテキスト領域の初期値へ戻す（1 行 1 件）。
pub fn format_list(values: &[String]) -> String {
    values.join("\n")
}

/// 時間帯のテキストを解析する。1 行でも読めなければ**全体を拒否**し、その行番号（1 始まり）を返す。
///
/// 読めた行だけ通す作りにしない。全項目置換で保存するため、読み飛ばした行はそのまま消える。
pub fn parse_time_windows(raw: &str) -> Result<Vec<TimeWindowPayload>, usize> {
    let mut windows = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        windows.push(parse_time_window(line).ok_or(index + 1)?);
    }
    Ok(windows)
}

/// 時間帯のリストをテキスト領域の初期値へ戻す（[`parse_time_windows`] が読み直せる形）。
pub fn format_time_windows(windows: &[TimeWindowPayload]) -> String {
    windows
        .iter()
        .map(format_time_window)
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_time_window(line: &str) -> Option<TimeWindowPayload> {
    let mut parts = line.split_whitespace();
    let days = parse_days(parts.next()?)?;
    let (start, end) = parts.next()?.split_once('-')?;
    let start_minute = parse_hhmm(start)?;
    let end_minute = parse_hhmm(end)?;
    let utc_offset_minutes = match parts.next() {
        Some(offset) => parse_offset(offset)?,
        None => 0,
    };
    // 余分な語が続く行は書式違いとして弾く（黙って無視すると、書いたつもりの条件が効かない）。
    if parts.next().is_some() {
        return None;
    }
    Some(TimeWindowPayload {
        days,
        start_minute,
        end_minute,
        utc_offset_minutes,
    })
}

fn format_time_window(window: &TimeWindowPayload) -> String {
    let days = if window.days.is_empty() {
        "*".to_string()
    } else {
        window
            .days
            .iter()
            .filter_map(|d| DAY_NAMES.get(usize::from(*d)).copied())
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "{days} {}-{} {}",
        format_hhmm(window.start_minute),
        format_hhmm(window.end_minute),
        format_offset(window.utc_offset_minutes)
    )
}

fn parse_days(raw: &str) -> Option<Vec<u8>> {
    if raw == "*" {
        return Some(Vec::new());
    }
    let mut days = Vec::new();
    for name in raw.split(',') {
        let name = name.trim().to_ascii_lowercase();
        let index = DAY_NAMES.iter().position(|d| *d == name)?;
        let index = index as u8;
        if !days.contains(&index) {
            days.push(index);
        }
    }
    (!days.is_empty()).then_some(days)
}

fn parse_hhmm(raw: &str) -> Option<u16> {
    let (hh, mm) = raw.trim().split_once(':')?;
    let hours: u16 = hh.parse().ok()?;
    let minutes: u16 = mm.parse().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(hours * 60 + minutes)
}

fn format_hhmm(minute: u16) -> String {
    format!("{:02}:{:02}", minute / 60, minute % 60)
}

fn parse_offset(raw: &str) -> Option<i16> {
    let raw = raw.trim();
    let (sign, rest) = match raw.strip_prefix('-') {
        Some(rest) => (-1i16, rest),
        None => (1i16, raw.strip_prefix('+').unwrap_or(raw)),
    };
    let minutes = i16::try_from(parse_hhmm(rest)?).ok()?;
    Some(sign * minutes)
}

fn format_offset(minutes: i16) -> String {
    let sign = if minutes < 0 { '-' } else { '+' };
    let abs = minutes.unsigned_abs();
    format!("{sign}{:02}:{:02}", abs / 60, abs % 60)
}

/// 方式ごとのチェックボックス（`Option<String>`）を、api へ送るコードの一覧へ写す。
///
/// 並びは [`idp_contracts::admin::AUTHENTICATION_METHOD_CODES`] に従える（表示順と保存順を
/// 揃え、更新のたびに順序だけが変わる差分を出さない）。
pub fn selected_methods(form: &crate::dto::AdminAuthenticationPolicyForm) -> Vec<String> {
    [
        ("password", &form.method_password),
        ("totp", &form.method_totp),
        ("webauthn", &form.method_webauthn),
        ("recovery_code", &form.method_recovery_code),
        ("email_otp", &form.method_email_otp),
        ("sms_otp", &form.method_sms_otp),
        ("external_idp", &form.method_external_idp),
    ]
    .into_iter()
    .filter(|(_, checked)| checked.is_some())
    .map(|(code, _)| code.to_string())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_lists_on_newlines_and_commas_and_drops_blanks() {
        assert_eq!(
            parse_list(" a, b \n\n c \n"),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        assert!(parse_list("   \n  ").is_empty());
    }

    #[test]
    fn time_windows_round_trip_through_their_text_form() {
        let text = "mon,tue,wed,thu,fri 09:00-18:00 +09:00\n* 22:00-06:00 +00:00";
        let parsed = parse_time_windows(text).expect("parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].days, vec![1, 2, 3, 4, 5]);
        assert_eq!(parsed[0].start_minute, 540);
        assert_eq!(parsed[0].end_minute, 1080);
        assert_eq!(parsed[0].utc_offset_minutes, 540);
        // 全曜日は空リスト（API の「空 = 全曜日」と同じ表現）。
        assert!(parsed[1].days.is_empty());
        assert_eq!(format_time_windows(&parsed), text);
    }

    #[test]
    fn an_omitted_offset_means_utc() {
        let parsed = parse_time_windows("* 00:00-12:00").expect("parse");
        assert_eq!(parsed[0].utc_offset_minutes, 0);
        assert_eq!(format_time_windows(&parsed), "* 00:00-12:00 +00:00");
    }

    #[test]
    fn a_negative_offset_round_trips() {
        let parsed = parse_time_windows("mon 08:00-17:00 -05:30").expect("parse");
        assert_eq!(parsed[0].utc_offset_minutes, -330);
        assert_eq!(format_time_windows(&parsed), "mon 08:00-17:00 -05:30");
    }

    /// 1 行でも読めなければ全体を拒否する。読める行だけ保存すると、書いたはずの条件が
    /// 黙って消えたまま「保存しました」と表示されてしまう。
    #[test]
    fn one_unreadable_line_rejects_the_whole_field_with_its_line_number() {
        assert_eq!(parse_time_windows("* 09:00-18:00\nnonsense"), Err(2));
        assert_eq!(parse_time_windows("mon 25:00-26:00"), Err(1));
        assert_eq!(parse_time_windows("funday 09:00-18:00"), Err(1));
        assert_eq!(parse_time_windows("* 09:00-18:00 +09:00 extra"), Err(1));
    }

    #[test]
    fn blank_input_means_no_restriction() {
        assert!(parse_time_windows("").expect("parse").is_empty());
        assert!(parse_time_windows("\n  \n").expect("parse").is_empty());
        assert_eq!(format_time_windows(&[]), "");
    }
}
