//! Maps authentication policy conditions to **strings that can round-trip through an HTML form** (AP1).
//!
//! Authentication policy conditions consist of "lists of strings" (target clients, users, CIDRs, `acr_values`) and
//! "lists of time windows" (days of week x time range x UTC offset). Both have a **variable count**
//! and can't be placed 1:1 in an HTML form.
//!
//! With fixed-count inputs (e.g. only one time window), opening and saving in the admin screen a policy configured with 2 via the API
//! would **silently drop the other one**. The edit screen submits a full replacement, so values that can't be shown
//! are lost on save. So variable-length conditions are put in text areas as strings and **round-trip in
//! readable form**.
//!
//! # Time window format
//!
//! One window per line, written as `days start-end offset`. Days are comma-separated `sun`..`sat`; `*` means all days.
//! Times are `HH:MM` (a line whose end is earlier than its start spans midnight). The offset is `+09:00` style, defaulting to
//! `+00:00` (UTC) when omitted.
//!
//! ```text
//! mon,tue,wed,thu,fri 09:00-18:00 +09:00
//! * 22:00-06:00 +00:00
//! ```

use assay_contracts::admin::TimeWindowPayload;

/// Day-of-week notation (0 = Sunday ... 6 = Saturday). The only mapping to the API's numeric representation.
const DAY_NAMES: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/// Maps newline/comma-separated text to a list of values (empty lines and surrounding whitespace are dropped).
pub fn parse_list(raw: &str) -> Vec<String> {
    raw.split(['\n', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Turns a list of values back into the text area's initial value (one per line).
pub fn format_list(values: &[String]) -> String {
    values.join("\n")
}

/// Parses time window text. If even one line can't be read, **the whole thing is rejected** and that line number (1-based) is returned.
///
/// It doesn't pass just the readable lines. Saving is a full replacement, so skipped lines would simply vanish.
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

/// Turns a list of time windows back into the text area's initial value (a form [`parse_time_windows`] can re-read).
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
    // Lines with extra words are rejected as malformed (silently ignoring them would leave intended conditions ineffective).
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

/// Maps per-method checkboxes (`Option<String>`) to the list of codes sent to the api.
///
/// The order follows [`assay_contracts::admin::AUTHENTICATION_METHOD_CODES`] (aligning display and save order
/// so no diff that only changes the order appears on every update).
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
        // All days is an empty list (same representation as the API's "empty = all days").
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

    /// If even one line can't be read the whole is rejected. Saving only readable lines would show "saved"
    /// while the intended conditions silently vanished.
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
