//! Screen color scheme setting (light / dark / follow the OS).
//!
//! Resolution order matches the display language ([`crate::display_preferences`]). First wins:
//! `?theme=` > user setting (DB `users.theme`) > Cookie (`theme`) > OS setting.
//! Invalid or unsupported values are ignored and fall through to the next.
//!
//! **Applied on the browser side** (`assets/theme.js` sets `<html data-bs-theme>`).
//! The server cannot write the attribute because the shared layouts (`page.html` / `console/layout.html`)
//! do not receive values from every screen's template struct, so a color scheme field would have to be
//! added to nearly 40 structs. The server sticks to keeping the Cookie correct.

/// Color schemes users can choose. `System` is a **choice** to "follow the OS", distinct from no choice
/// (with no choice the device Cookie may be respected, but `System` keeps following the OS across devices).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Light,
    Dark,
    System,
}

impl Theme {
    /// Reads from a stored value (`light` / `dark` / `system`). Unsupported or invalid values give `None`.
    pub fn from_tag(tag: &str) -> Option<Theme> {
        match tag.trim().to_ascii_lowercase().as_str() {
            "light" => Some(Theme::Light),
            "dark" => Some(Theme::Dark),
            "system" => Some(Theme::System),
            _ => None,
        }
    }

    /// Stored value used in Cookies, the DB and forms.
    pub fn as_tag(&self) -> &'static str {
        match self {
            Theme::Light => "light",
            Theme::Dark => "dark",
            Theme::System => "system",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_only_the_three_supported_values() {
        assert_eq!(Theme::from_tag("dark"), Some(Theme::Dark));
        assert_eq!(Theme::from_tag(" Light "), Some(Theme::Light));
        assert_eq!(Theme::from_tag("system"), Some(Theme::System));
        assert_eq!(Theme::from_tag("solarized"), None);
        assert_eq!(Theme::from_tag(""), None);
    }

    #[test]
    fn the_tag_round_trips() {
        for theme in [Theme::Light, Theme::Dark, Theme::System] {
            assert_eq!(Theme::from_tag(theme.as_tag()), Some(theme));
        }
    }
}
