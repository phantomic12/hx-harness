//! Per-server tool namespacing: two servers may both expose `search`, and the model must be able to
//! tell which one it is calling.
//!
//! ## The problem, stated exactly
//!
//! MCP tool names are chosen by each server independently and are only required to be unique
//! *within* that server. Point `hx` at a filesystem server and a GitHub server and both will
//! plausibly offer `search`; a registry keyed by the server's own name would silently keep one and
//! drop the other, and the model would call "search" and get an answer from a server it never
//! chose. That is the failure this module exists to make impossible.
//!
//! So every remote tool is renamed to `namespace__tool` — `files__search`, `github__search` — and
//! the namespace is the server's, which the model can read. The name is the *only* channel through
//! which a model learns where a tool came from, so it has to carry the answer rather than a hash of
//! it.
//!
//! ## Why `__` and not `/`, `.` or `-`
//!
//! Because those are all *legal inside* MCP tool names. `github.create_issue` and `github-create`
//! are real shapes, so any separator that can also appear in a tool name makes the split
//! ambiguous — and an ambiguous split is how `a.b__c` gets routed to the wrong server. A double
//! underscore is the one sequence a *namespace* cannot contain ([`sanitize`] collapses it), which
//! makes the split on the first `__` exact.
//!
//! The cost is that `__` is *not* forbidden inside a tool's own name, and does not need to be: the
//! split takes the first occurrence, and the namespace on the left is known to hold none. A tool
//! genuinely named `a__b` on server `files` becomes `files__a__b`, which splits back correctly.
//!
//! ## Why names are sanitised and then checked rather than trusted
//!
//! Model APIs restrict function names to a narrow charset — OpenAI's tool schema caps them at
//! `[a-zA-Z0-9_-]{1,64}`, Anthropic's is similar — and a name that violates it is a request the
//! provider rejects, which reads to the operator like "MCP is broken". So the namespace is folded
//! to `[a-z0-9_]` and length-capped here.
//!
//! That folding is **lossy**, which is the part worth being honest about: `github-work` and
//! `github_work` both fold to `github_work`. Sanitising is therefore not by itself a guarantee of
//! uniqueness, and [`crate::McpHost`] refuses a config whose servers fold onto the same namespace
//! rather than letting the second one quietly replace the first. The check is what makes the
//! property true; the folding is only what makes the names legal.

/// The separator between a server's namespace and a tool's own name.
pub const SEPARATOR: &str = "__";

/// The longest name a model API will accept for a tool, and therefore the longest name emitted
/// here. 64 is OpenAI's limit; it is the tightest of the mainstream ones, so satisfying it satisfies
/// the others.
pub const MAX_NAME_CHARS: usize = 64;

/// The longest namespace this module will emit, leaving room for a tool name beside it.
///
/// A cap rather than no cap because a 64-character namespace would leave nothing for the tool, and
/// the tool's own name is the half a model actually reasons about.
pub const MAX_NAMESPACE_CHARS: usize = 24;

/// Fold a configured server name into a namespace that is legal in a tool name.
///
/// Lowercase because model APIs and models themselves treat tool names case-insensitively in
/// practice, so `Files` and `files` must not be two different namespaces. Everything outside
/// `[a-z0-9_]` becomes `_`, runs of `_` collapse to one (which is what guarantees the namespace
/// never contains [`SEPARATOR`]), and the result is truncated to [`MAX_NAMESPACE_CHARS`].
///
/// The truncation is the second lossy step, and it is why the caller checks for collisions instead
/// of assuming this is injective. An empty result — a name like `""` or `"---"` — is not allowed
/// through: it becomes `server`, because a nameless namespace would produce names like `__search`.
pub fn sanitize(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    // A leading or trailing `_` is legal in a tool name but reads badly and wastes a character of
    // the cap, so it goes. Trailing only — trimming both would let `a_` and `a` collide silently.
    let out = out.trim_start_matches('_').to_string();
    let out = if out.is_empty() {
        "server".to_string()
    } else {
        out
    };
    out.chars().take(MAX_NAMESPACE_CHARS).collect()
}

/// `search` on the server `files` becomes `files__search`.
///
/// The tool half is sanitised too, for the same provider-charset reason, and the pair is capped at
/// [`MAX_NAME_CHARS`] with a short stable suffix when the tool name alone would overflow. The suffix
/// is a hash rather than a truncation because two long tool names that share a prefix are exactly
/// the pair a truncation would merge.
pub fn namespaced(server: &str, tool: &str) -> String {
    let namespace = sanitize(server);
    let tool = sanitize_tool(tool);
    let full = format!("{namespace}{SEPARATOR}{tool}");
    if full.chars().count() <= MAX_NAME_CHARS {
        return full;
    }

    // Keep the namespace and as much of the tool as fits, then a `~` and four hex digits of a hash
    // over the *original* pair. FNV-1a because it is five lines and its value never changes; a
    // `DefaultHasher` would be shorter to write and is explicitly allowed to differ between Rust
    // versions, which would rename a tool between builds and silently invalidate every approval rule
    // written against the old name.
    let suffix = format!("~{:04x}", fnv1a(&format!("{server}\u{0}{tool}")) & 0xffff);
    let room = MAX_NAME_CHARS
        .saturating_sub(namespace.chars().count() + SEPARATOR.len() + suffix.chars().count());
    let kept: String = tool.chars().take(room).collect();
    format!("{namespace}{SEPARATOR}{kept}{suffix}")
}

/// Split a namespaced name back into `(namespace, tool)`, or `None` when it is not namespaced.
///
/// Splits on the *first* separator, which is the only correct choice given [`sanitize`] guarantees
/// the namespace contains none — see the module doc.
pub fn split(name: &str) -> Option<(&str, &str)> {
    let (namespace, tool) = name.split_once(SEPARATOR)?;
    if namespace.is_empty() || tool.is_empty() {
        return None;
    }
    Some((namespace, tool))
}

/// Fold a tool's own name to the provider charset.
///
/// Not lowercased, unlike a namespace: MCP tool names are conventionally snake_case already, and
/// lowercasing them would rename `searchIssues` to `searchissues`, which is a *different* name than
/// the server documented. The namespace is ours to choose; the tool name is the server's.
fn sanitize_tool(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        // A server that offered a tool with an empty or entirely-illegal name. Naming it something
        // is better than dropping it silently — the model at least sees that it exists.
        "unnamed".to_string()
    } else {
        out
    }
}

/// FNV-1a over the bytes, used only to keep two long tool names apart. Not a security primitive and
/// not treated as one.
fn fnv1a(input: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in input.as_bytes() {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_servers_exposing_the_same_tool_get_names_a_model_can_tell_apart() {
        // The property the whole module exists for.
        let files = namespaced("files", "search");
        let github = namespaced("github", "search");
        assert_eq!(files, "files__search");
        assert_eq!(github, "github__search");
        assert_ne!(files, github);
        assert_eq!(split(&files), Some(("files", "search")));
        assert_eq!(split(&github), Some(("github", "search")));
    }

    #[test]
    fn the_name_says_which_server_it_came_from() {
        // Not a hash, not an index: the model has to be able to read the origin off the name.
        let name = namespaced("filesystem", "read_file");
        assert!(name.starts_with("filesystem"), "{name}");
        assert!(name.contains("read_file"), "{name}");
    }

    #[test]
    fn a_tool_name_containing_the_separator_still_splits_back_to_its_own_server() {
        // The reason the split is on the *first* occurrence and the namespace may not contain `__`.
        let name = namespaced("files", "a__b");
        assert_eq!(name, "files__a__b");
        assert_eq!(split(&name), Some(("files", "a__b")));
    }

    #[test]
    fn a_namespace_never_contains_the_separator() {
        for raw in [
            "a__b",
            "a___b",
            "a-__-b",
            "  spaced  ",
            "Camel__Case",
            "..--..",
        ] {
            let namespace = sanitize(raw);
            assert!(
                !namespace.contains(SEPARATOR),
                "{raw:?} folded to {namespace:?}, which would make the split ambiguous"
            );
        }
    }

    #[test]
    fn a_namespace_is_folded_to_the_provider_charset() {
        // `github-work` is a natural config key and `github-work__x` is not a name OpenAI accepts.
        assert_eq!(sanitize("github-work"), "github_work");
        assert_eq!(sanitize("github.work"), "github_work");
        assert_eq!(sanitize("GitHub Work"), "github_work");
        assert_eq!(sanitize("__leading"), "leading");
    }

    #[test]
    fn a_namespace_that_folds_to_nothing_becomes_something() {
        // A nameless namespace would produce `__search`, which splits back to nothing.
        assert_eq!(sanitize(""), "server");
        assert_eq!(sanitize("---"), "server");
        assert_eq!(sanitize("  "), "server");
        assert!(split(&namespaced("", "search")).is_some());
    }

    #[test]
    fn a_tool_name_is_left_readable_because_it_is_the_servers_name_not_ours() {
        assert_eq!(sanitize_tool("searchIssues"), "searchIssues");
        assert_eq!(sanitize_tool("read_file"), "read_file");
        assert_eq!(sanitize_tool("create-issue"), "create-issue");
        // Illegal characters are replaced, not dropped, so two distinct names stay distinct here.
        assert_eq!(sanitize_tool("a b"), "a_b");
        assert_eq!(sanitize_tool("a/b"), "a_b");
        assert_eq!(sanitize_tool(""), "unnamed");
    }

    #[test]
    fn a_long_pair_is_capped_and_stays_distinct() {
        let long_a = "a".repeat(80);
        let long_b = format!("{}b", "a".repeat(79));
        let a = namespaced("server", &long_a);
        let b = namespaced("server", &long_b);

        for name in [&a, &b] {
            assert!(
                name.chars().count() <= MAX_NAME_CHARS,
                "{name} is {} chars",
                name.chars().count()
            );
            assert!(split(name).is_some(), "{name} must still split");
        }
        assert_ne!(
            a, b,
            "two names sharing a prefix must not truncate to the same thing"
        );
    }

    #[test]
    fn the_cap_is_stable_across_calls_so_an_approval_rule_survives_a_restart() {
        // A hash that changed between builds would silently invalidate every rule written against
        // the old name, which is why this is FNV-1a and not `DefaultHasher`.
        let name = namespaced("server", &"x".repeat(90));
        assert_eq!(name, namespaced("server", &"x".repeat(90)));

        // The exact shape, so a change to the cap or the suffix is a visible diff rather than a
        // silently shorter name: `server__` + 51 `x` + `~hhhh`. The suffix starts at byte 59 —
        // 8 for `server__`, 51 for the kept prefix — and it is 5 characters, so the two add up to
        // exactly `MAX_NAME_CHARS`.
        let suffix_at = 8 + 51;
        let expected = format!("server__{}{}", "x".repeat(51), &name[suffix_at..]);
        assert_eq!(name, expected, "{name}");
        assert_eq!(name.chars().count(), MAX_NAME_CHARS);
        assert!(
            name[suffix_at..].starts_with('~'),
            "the suffix marks the truncation"
        );
    }

    #[test]
    fn an_unnamespaced_name_splits_to_nothing_rather_than_to_a_wrong_server() {
        assert_eq!(split("search"), None, "a local tool is not a remote one");
        assert_eq!(
            split("__search"),
            None,
            "an empty namespace is not a server"
        );
        assert_eq!(split("files__"), None, "an empty tool is not a tool");
    }

    #[test]
    fn a_namespace_that_folds_onto_another_is_detectable() {
        // The honest limit of sanitising: it is lossy, so uniqueness is *checked* by the host rather
        // than assumed here. This test pins the fact that the check has something to catch — the two
        // keys produce one and the same tool name, which is exactly why `McpHost::from_config`
        // refuses the config instead of letting the second server silently take over the first's
        // names. The assertion is deliberately `eq`: if this ever became `ne`, the collision check
        // would have nothing to catch and would be dead code.
        assert_eq!(sanitize("github-work"), sanitize("github_work"));
        assert_eq!(
            namespaced("github-work", "search"),
            namespaced("github_work", "search"),
            "two keys that fold onto one namespace publish one and the same tool name, so the host \
             has to refuse the pair rather than trusting `sanitize` to keep them apart"
        );
    }
}
