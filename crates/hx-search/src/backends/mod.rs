//! Concrete backends — one file per engine, plus the scraping helpers they share.
//!
//! ## Why one file per engine
//!
//! A backend is the unit of change here. Engines change their markup, tighten their bot
//! detection, or retire an endpoint one at a time; when one breaks, the fix is a parser, a
//! captured fixture and a test — three things that belong next to each other and nowhere near
//! the other engines. A single `backends.rs` grew past the point where that was true.
//!
//! ## Why the helpers are shared rather than copied
//!
//! Every scraper needs the same four things, and three of them are subtle enough that a
//! per-backend copy would drift:
//!
//! - [`USER_AGENT`] — keyless endpoints reject obvious library strings, and DDG in particular
//!   serves a bot check to `reqwest/0.x`.
//! - [`clean_text`] and [`decode_entities`] — scraped titles carry entities (`&mdash;`,
//!   `&#233;`) and inline markup, and an unknown entity must pass through unchanged rather than
//!   be deleted, because deleting text from a title looks like a parsing bug to whoever reads
//!   the transcript.
//! - [`looks_like_a_bot_check`] — the signal that turns "no results" into a *named failure*.
//!   Without it a bot wall is indistinguishable from "the web has nothing about this".
//!
//! ## Parsing stays in free functions
//!
//! `parse_ddg_lite`, `parse_mojeek_html`, `searxng_search_url` and friends are pure and public
//! rather than private helpers of a `search` method. Scraped HTML is the most fragile part of
//! this crate and the part most likely to need fixing at short notice; keeping it pure means it
//! is tested against a saved fixture with no network, which is what makes that fix a two-minute
//! job instead of an afternoon.

mod duckduckgo;
mod searxng;

pub use duckduckgo::{parse_ddg_lite, unwrap_ddg_redirect, DuckDuckGoBackend};
pub use searxng::{searxng_search_url, SearxngBackend};

use regex::Regex;
use std::sync::OnceLock;

/// A current desktop user-agent. Keyless endpoints reject obvious library strings, and DDG in
/// particular serves a bot check to `reqwest/0.x`.
pub const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// Rough signal that a response is an anti-bot page rather than a result page.
///
/// Deliberately a *signal* and not a verdict: the caller pairs it with "and there were no
/// results", because a real result page can contain the word "captcha" in a result about
/// captchas. Marking a page that did produce results as a bot check would throw away good data.
pub fn looks_like_a_bot_check(html: &str) -> bool {
    let lower = html.to_ascii_lowercase();
    lower.contains("anomaly")
        || lower.contains("unusual traffic")
        || lower.contains("enable javascript")
        || lower.contains("challenge-form")
        || lower.contains("captcha")
}

pub(crate) fn tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<[^>]*>").expect("valid regex"))
}

/// Strip tags, decode entities, and collapse whitespace.
pub fn clean_text(html: &str) -> String {
    let without_tags = tag_re().replace_all(html, " ");
    let decoded = decode_entities(&without_tags);
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Decode the HTML entities that appear in scraped titles and snippets.
///
/// Hand-rolled rather than pulling in an HTML library: the entity set that actually shows up in
/// search results is tiny, and an unknown entity is passed through unchanged rather than dropped.
pub fn decode_entities(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < chars.len() {
        if chars[i] != '&' {
            out.push(chars[i]);
            i += 1;
            continue;
        }

        // Find the terminating ';' within a plausible entity length, stopping at a nested '&'.
        let mut end = None;
        for (offset, ch) in chars.iter().enumerate().skip(i + 1).take(10) {
            if *ch == ';' {
                end = Some(offset);
                break;
            }
            if *ch == '&' {
                break;
            }
        }

        let Some(end) = end else {
            out.push(chars[i]);
            i += 1;
            continue;
        };

        let entity: String = chars[i + 1..end].iter().collect();
        match lookup_entity(&entity) {
            Some(decoded) => {
                out.push(decoded);
                i = end + 1;
            }
            None => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }

    out
}

fn lookup_entity(entity: &str) -> Option<char> {
    // The markup backbone.
    match entity {
        "amp" => return Some('&'),
        "lt" => return Some('<'),
        "gt" => return Some('>'),
        "quot" => return Some('"'),
        "apos" => return Some('\''),
        "nbsp" => return Some(' '),
        _ => {}
    }

    // Typographic entities that turn up constantly in scraped titles and snippets. Without
    // these, a title reads "Docs &mdash; Getting Started", which looks like a bug to anyone
    // reading the transcript.
    match entity {
        "mdash" => return Some('—'),
        "ndash" => return Some('–'),
        "hellip" => return Some('…'),
        "lsquo" => return Some('\u{2018}'),
        "rsquo" => return Some('\u{2019}'),
        "ldquo" => return Some('\u{201C}'),
        "rdquo" => return Some('\u{201D}'),
        "laquo" => return Some('«'),
        "raquo" => return Some('»'),
        "middot" => return Some('·'),
        "bull" => return Some('•'),
        "times" => return Some('×'),
        "divide" => return Some('÷'),
        "deg" => return Some('°'),
        "plusmn" => return Some('±'),
        "euro" => return Some('€'),
        "pound" => return Some('£'),
        "yen" => return Some('¥'),
        "cent" => return Some('¢'),
        "copy" => return Some('©'),
        "reg" => return Some('®'),
        "trade" => return Some('™'),
        "sect" => return Some('§'),
        "para" => return Some('¶'),
        "prime" => return Some('′'),
        "Prime" => return Some('″'),
        "ne" => return Some('≠'),
        "le" => return Some('≤'),
        "ge" => return Some('≥'),
        "eacute" => return Some('é'),
        "egrave" => return Some('è'),
        "agrave" => return Some('à'),
        "ccedil" => return Some('ç'),
        "uuml" => return Some('ü'),
        "ouml" => return Some('ö'),
        "auml" => return Some('ä'),
        "szlig" => return Some('ß'),
        "ntilde" => return Some('ñ'),
        _ => {}
    }

    if let Some(hex) = entity
        .strip_prefix("#x")
        .or_else(|| entity.strip_prefix("#X"))
    {
        return u32::from_str_radix(hex, 16).ok().and_then(char::from_u32);
    }

    entity
        .strip_prefix('#')
        .and_then(|dec| dec.parse::<u32>().ok())
        .and_then(char::from_u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typographic_entities_are_decoded() {
        assert_eq!(decode_entities("Docs &mdash; Start"), "Docs — Start");
        assert_eq!(decode_entities("a&hellip;"), "a…");
        assert_eq!(decode_entities("it&rsquo;s"), "it’s");
    }

    #[test]
    fn entities_are_decoded_including_numeric_and_hex() {
        assert_eq!(decode_entities("a &amp; b"), "a & b");
        assert_eq!(decode_entities("&lt;tag&gt;"), "<tag>");
        assert_eq!(decode_entities("caf&#233;"), "café");
        assert_eq!(decode_entities("caf&#xe9;"), "café");
        assert_eq!(decode_entities("x&nbsp;y"), "x y");
    }

    #[test]
    fn unknown_and_unterminated_entities_pass_through_unchanged() {
        // Better a stray "&" in a title than silently deleting text.
        assert_eq!(decode_entities("a &foo; b"), "a &foo; b");
        assert_eq!(decode_entities("a & b"), "a & b");
        assert_eq!(decode_entities("R&D"), "R&D");
    }

    #[test]
    fn clean_text_strips_markup_and_collapses_whitespace() {
        assert_eq!(
            clean_text("  <b>bold</b>\n   text  <i>x</i> "),
            "bold text x"
        );
    }

    #[test]
    fn bot_check_pages_are_recognised() {
        assert!(looks_like_a_bot_check(
            "<html><body>Our systems have detected unusual traffic from your network</body></html>"
        ));
        assert!(looks_like_a_bot_check("<div class=\"challenge-form\">"));
        assert!(looks_like_a_bot_check(
            "<html><head><title>Captcha</title></head></html>"
        ));
        assert!(!looks_like_a_bot_check(
            "<html><body>a normal page</body></html>"
        ));
    }
}
