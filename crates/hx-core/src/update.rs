//! Opt-in update checking configuration and version comparison (M9).
//!
//! ## Why this lives here and the task lives in `hxd`
//!
//! `hx-core` is deliberately **IO-free** — no `tokio`, no `reqwest`. So this module keeps what
//! is pure and testable: the config surface and the version comparison that decides "is the remote
//! release newer?". The actual fetch loop and the `info!`/"`debug!`" logging live in
//! `apps/hxd/src/main.rs` ([`crate::`][hxd]), which owns the runtime and the logger. Keeping the
//! comparison here means it is a pure function a unit test can pin down exhaustively without a network.
//!
//! [hxd]: https://github.com/phantomic12/hx-harness/blob/main/apps/hxd/src/main.rs

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// The GitHub releases API for the hx harness. Returns a JSON payload whose `tag_name` (e.g.
/// `v0.1.2`) is the newest published release.
pub const DEFAULT_UPDATE_URL: &str =
    "https://api.github.com/repos/phantomic12/hx-harness/releases/latest";

/// The default check cadence: once a day. A release cadence shorter than a day is noise; anything
/// longer delays a fix an operator opted into hearing about.
pub const DEFAULT_UPDATE_INTERVAL_SECS: u64 = 86_400; // 24h

/// Opt-in, non-intrusive update checking.
///
/// **Off by default.** Listing the fields with their defaults is the whole point: a config that says
/// nothing about `update` gets `enabled: false`, so a daemon upgrading onto this code performs no
/// fetch and spawns no task until an operator turns it on. The constraint that "default off, no
/// surprise network traffic" is a property of these defaults, not a promise about how they are used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfig {
    /// Whether to check for a newer release at all. `false` means the `hxd` task is not even
    /// spawned, so no request is ever made.
    #[serde(default)]
    pub enabled: bool,

    /// The releases API endpoint to query. Only the default is known-good; an operator who wants to
    /// point at a mirror or a pre-release feed sets their own.
    #[serde(default = "default_update_url")]
    pub url: String,

    /// How often to check, in seconds. The default is 24h.
    #[serde(default = "default_update_interval")]
    pub interval_secs: u64,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_update_url(),
            interval_secs: default_update_interval(),
        }
    }
}

fn default_update_url() -> String {
    DEFAULT_UPDATE_URL.to_string()
}

fn default_update_interval() -> u64 {
    DEFAULT_UPDATE_INTERVAL_SECS
}

impl UpdateConfig {
    /// Reject a configuration that would arm a zero-period ticker.
    ///
    /// `tokio::time::interval(Duration::from_secs(0))` panics, so `enabled: true` with
    /// `interval_secs: 0` would crash the daemon one interval after startup — the worst kind of
    /// misconfiguration, one that passes every check and then kills the process. A disabled
    /// checker spawns no task and needs no interval, so zero is only refused when enabled.
    /// `hxd` calls this at startup (fail closed, before binding); the spawned checker re-checks
    /// defensively because this type is also constructed programmatically.
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.interval_secs == 0 {
            return Err(
                "update.interval_secs must be greater than zero when update checking is enabled \
                 (a zero interval would panic the check ticker; set a positive number of seconds \
                 or disable the checker)"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// Compare two dotted numeric versions, after stripping a leading `v` from either.
///
/// `v0.1.2` and `0.1.2` compare equal; a missing trailing component counts as `0`, so
/// `0.1` and `0.1.0` compare equal. Returns `None` when either string is not a dotted
/// sequence of non-negative integers — a release `tag_name` that is not a plain version cannot
/// be compared and must not be claimed to be "newer" (that way lies an upgrade to garbage).
pub fn compare_versions(a: &str, b: &str) -> Option<Ordering> {
    let parse = |s: &str| -> Option<Vec<u64>> {
        s.strip_prefix('v')
            .unwrap_or(s)
            .split('.')
            .map(|part| part.parse::<u64>().ok())
            .collect()
    };
    let a = parse(a)?;
    let b = parse(b)?;

    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return Some(x.cmp(&y));
        }
    }
    Some(Ordering::Equal)
}

/// Extract the `tag_name` field from GitHub's `/releases/latest` JSON payload.
///
/// Pure and IO-free, so it lives here where a unit test can pin it: a release that is not the
/// shape the API returns (no `tag_name`, or a non-string `tag_name`) yields `None`, and a
/// checker must treat that as "no usable version", never as "the latest".
pub fn release_tag_name(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value
        .get("tag_name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn the_default_update_config_is_disabled() {
        // The property the whole milestone stands on: default off. Nothing is fetched and no task is
        // spawned until an operator turns `enabled` on.
        let cfg = UpdateConfig::default();
        assert!(!cfg.enabled, "auto-update must be off by default");
    }

    #[test]
    fn the_defaults_point_at_the_shipped_release_feed_once_a_day() {
        let cfg = UpdateConfig::default();
        assert_eq!(cfg.url, DEFAULT_UPDATE_URL);
        assert_eq!(cfg.interval_secs, DEFAULT_UPDATE_INTERVAL_SECS);
        assert_eq!(cfg.interval_secs, 86_400, "24h");
    }

    #[test]
    fn an_explicit_update_block_round_trips() {
        let cfg = UpdateConfig {
            enabled: true,
            url: "https://example.com/releases/latest".into(),
            interval_secs: 3600,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: UpdateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn a_version_with_a_leading_v_and_without_one_compare_equal() {
        assert_eq!(compare_versions("v0.1.2", "0.1.2"), Some(Ordering::Equal));
    }

    #[test]
    fn a_missing_trailing_component_counts_as_zero() {
        assert_eq!(compare_versions("0.1", "0.1.0"), Some(Ordering::Equal));
    }

    #[test]
    fn a_higher_patch_wins_over_a_higher_minor() {
        // The brief's explicit case: 0.1.10 is *newer* than 0.1.2, because the third
        // component is 10, not a decimal of the second.
        assert_eq!(compare_versions("0.1.10", "0.1.2"), Some(Ordering::Greater));
        assert_eq!(
            compare_versions("0.2.0", "0.1.99"),
            Some(Ordering::Greater),
            "a minor bump beats any patch count"
        );
    }

    #[test]
    fn the_version_ladder_orders_correctly() {
        // 0.1.0 < 0.2.0 < 1.0.0
        assert_eq!(compare_versions("0.1.0", "0.2.0"), Some(Ordering::Less));
        assert_eq!(compare_versions("0.2.0", "1.0.0"), Some(Ordering::Less));
        assert_eq!(compare_versions("1.0.0", "0.2.0"), Some(Ordering::Greater));
        // The four from the brief, pairwise distinct.
        let versions = ["0.1.0", "0.2.0", "0.1.10", "1.0.0"];
        assert_eq!(
            compare_versions(versions[0], versions[1]),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_versions(versions[1], versions[2]),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_versions(versions[2], versions[3]),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn a_tag_name_that_is_not_a_version_cannot_be_compared() {
        assert_eq!(compare_versions("release-2", "0.1.0"), None); // not numeric
        assert_eq!(compare_versions("0.1.2", "1.2.3-beta"), None); // pre-release is not numeric
        assert_eq!(compare_versions("0..1", "0.1.0"), None); // empty component
    }

    #[test]
    fn an_unknown_key_in_the_update_block_is_rejected() {
        // `deny_unknown_fields`, like every config section: a typo'd `intervall` is a loud parse
        // error, not a silently-ignored setting that would check every second forever.
        let err = serde_yaml::from_str::<UpdateConfig>("enabled: true\nintervall: 60\n");
        assert!(err.is_err());
    }

    #[test]
    fn release_tag_name_is_read_out_of_a_github_release_payload() {
        // The shape the GitHub /releases/latest endpoint returns — only `tag_name` is read.
        let payload = r#"{
            "tag_name": "v0.1.2",
            "name": "0.1.2",
            "html_url": "https://github.com/phantomic12/hx-harness/releases/tag/v0.1.2"
        }"#;
        assert_eq!(release_tag_name(payload).as_deref(), Some("v0.1.2"));
    }

    #[test]
    fn release_tag_name_yields_none_for_a_non_release_payload() {
        assert_eq!(release_tag_name("not json"), None);
        assert_eq!(
            release_tag_name("{\"name\": \"0.1.2\"}"),
            None,
            "no tag_name"
        );
        assert_eq!(
            release_tag_name("{\"tag_name\": 123}"),
            None,
            "non-string tag_name"
        );
    }

    #[test]
    fn an_enabled_checker_with_a_zero_interval_is_rejected() {
        // `tokio::time::interval(0)` panics: enabled + zero must never reach the spawn path.
        let cfg = UpdateConfig {
            enabled: true,
            url: DEFAULT_UPDATE_URL.to_string(),
            interval_secs: 0,
        };
        let err = cfg.validate().expect_err("enabled + interval 0 must fail validation");
        assert!(err.contains("interval_secs"), "{err}");
    }

    #[test]
    fn a_disabled_checker_needs_no_interval_and_a_positive_one_passes() {
        let off = UpdateConfig {
            enabled: false,
            url: DEFAULT_UPDATE_URL.to_string(),
            interval_secs: 0,
        };
        assert!(off.validate().is_ok(), "disabled spawns no task, so zero is harmless");
        let on = UpdateConfig {
            enabled: true,
            url: DEFAULT_UPDATE_URL.to_string(),
            interval_secs: 60,
        };
        assert!(on.validate().is_ok());
        assert!(UpdateConfig::default().validate().is_ok());
    }
}
